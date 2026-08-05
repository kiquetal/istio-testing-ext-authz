package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Config holds environmental variables/configuration
type Config struct {
	Port         string
	NomosService string
	RulesTTL     time.Duration
}

// Global configuration
var config = Config{
	Port:         "8080",
	NomosService: "http://nomos-service.default.svc.cluster.local:8080",
	RulesTTL:     1 * time.Hour,
}

var httpClient *http.Client

func init() {
	transport := &http.Transport{
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 200,
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 2 * time.Second,
	}

	httpClient = &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
}

// Nomos Response Structs
type EnrichmentContract struct {
	ConditionJsonPath string `json:"conditionJsonPath"`
	ConditionEquals   any    `json:"conditionEquals"`
	Endpoint          string `json:"endpoint"`
	DomainFrom        string `json:"domainFrom"`
	ResponseJsonPath  string `json:"responseJsonPath"`
	CacheTtlSeconds   int    `json:"cacheTtlSeconds"`
}

type ValidationContract struct {
	Order       int                 `json:"order"`
	Level       int                 `json:"level"`
	ParamName   string              `json:"paramName"`
	JwtJsonPath string              `json:"jwtJsonPath"`
	Validation  string              `json:"validation"` // "equals" or "contains"
	Enrichment  *EnrichmentContract `json:"enrichment,omitempty"`
}

type RuleContract struct {
	ID          string               `json:"id"`
	PathPattern string               `json:"pathPattern"`
	Methods     []string             `json:"methods"`
	Validations []ValidationContract `json:"validations"`
}

type RulesResponse struct {
	Proxy         string         `json:"proxy"`
	AppID         string         `json:"appId,omitempty"`
	IDP           string         `json:"idp,omitempty"`
	DefaultPolicy string         `json:"defaultPolicy"` // "allow" or "deny"
	Rules         []RuleContract `json:"rules"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Param   string `json:"param,omitempty"`
}

func main() {
	if p := os.Getenv("PORT"); p != "" {
		config.Port = p
	}
	if ns := os.Getenv("NOMOS_SVC_URL"); ns != "" {
		config.NomosService = ns
	}

	http.HandleFunc("/check", handleCheck)
	http.HandleFunc("/healthz", handleHealthz)

	log.Printf("Starting Nomos ext_authz sidecar middleware on port %s", config.Port)
	log.Printf("Target Nomos service URL: %s", config.NomosService)

	if err := http.ListenAndServe(":"+config.Port, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// handleCheck intercepts the Envoy ext_authz request
func handleCheck(w http.ResponseWriter, r *http.Request) {
	// 1. Log request details
	log.Printf("[Incoming] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	targetService := r.Header.Get("x-target-service")
	authHeader := r.Header.Get("authorization")

	// Get original requested URI/path & method from Envoy forwarded headers
	originalPath := r.Header.Get("x-original-uri")
	if originalPath == "" {
		originalPath = r.Header.Get("x-original-path")
	}
	if originalPath == "" {
		originalPath = r.URL.Path
	}

	originalMethod := r.Header.Get("x-original-method")
	if originalMethod == "" {
		originalMethod = r.Method
	}

	log.Printf("Context: Service=%s, OriginalPath=%s, OriginalMethod=%s", targetService, originalPath, originalMethod)

	// Validate required middleware headers
	if targetService == "" {
		respondDeny(w, http.StatusForbidden, "MISSING_X_TARGET_SERVICE_HEADER", "x-target-service header is required")
		return
	}
	if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		respondDeny(w, http.StatusUnauthorized, "MISSING_BEARER_TOKEN", "Valid Authorization Bearer token is required")
		return
	}

	token := authHeader[7:]
	decodedJwt, err := decodeJWTClaims(token)
	if err != nil {
		respondDeny(w, http.StatusUnauthorized, "INVALID_JWT_STRUCTURE", "Failed to decode JWT claims: "+err.Error())
		return
	}

	// Extract standard audience & issuer
	var audience string
	if aud, ok := decodedJwt["aud"]; ok {
		switch v := aud.(type) {
		case string:
			audience = v
		case []any:
			if len(v) > 0 {
				if s, ok := v[0].(string); ok {
					audience = s
				}
			}
		}
	}
	issuer, _ := decodedJwt["iss"].(string)

	// 2. Resolve Rules — L1 → (L2 Redis) → L3 Nomos
	cacheKey := buildCacheKey(targetService, audience, issuer)
	var rulesData *RulesResponse

	if cached, found := rulesCache.Get(cacheKey); found {
		// L1 cache hit
		result := cached.(*CachedResult)
		if result.Denied {
			respondDeny(w, http.StatusForbidden, result.DenyCode, result.DenyMessage)
			return
		}
		rulesData = result.Rules
	} else {
		// L1 miss → call Nomos (with singleflight dedup)
		val, err, _ := flight.Do(cacheKey, func() (interface{}, error) {
			resp, err := fetchRulesFromNomos(targetService, audience, issuer)
			if err != nil {
				// Nomos returned 403 — cache the denial
				if strings.Contains(err.Error(), "status code 403") {
					denied := &CachedResult{Denied: true, DenyCode: "NOMOS_FORBIDDEN", DenyMessage: err.Error()}
					rulesCache.Set(cacheKey, denied, L1DenialTTL)
					// redisSet(cacheKey, denied, L2DenialTTL)
					return denied, nil
				}
				// Real error (timeout, unreachable) — don't cache
				return nil, err
			}
			// Nomos returned 200 — cache the rules
			success := &CachedResult{Rules: resp}
			rulesCache.Set(cacheKey, success, L1SuccessTTL)
			// redisSet(cacheKey, success, L2SuccessTTL)
			return success, nil
		})

		if err != nil {
			log.Printf("Nomos connectivity error: %v", err)
			respondDeny(w, http.StatusInternalServerError, "NOMOS_CONNECTIVITY_ERROR", "Error communicating with rule store: "+err.Error())
			return
		}

		result := val.(*CachedResult)
		if result.Denied {
			respondDeny(w, http.StatusForbidden, result.DenyCode, result.DenyMessage)
			return
		}
		rulesData = result.Rules
	}

	// 3. Match rule by Path Pattern + Method
	var matchedRule *RuleContract
	var extractedParams map[string]string

	for i := range rulesData.Rules {
		rule := &rulesData.Rules[i]
		if !matchesMethod(rule.Methods, originalMethod) {
			continue
		}
		params := extractParams(rule.PathPattern, originalPath)
		if params != nil {
			matchedRule = rule
			extractedParams = params
			break
		}
	}

	if matchedRule == nil {
		if strings.ToLower(rulesData.DefaultPolicy) == "allow" {
			log.Printf("ALLOW: No matching rule, fallback to default policy: allow")
			respondAllow(w, rulesData.AppID, rulesData.IDP)
			return
		}
		respondDeny(w, http.StatusForbidden, "NO_MATCHING_RULE", "Request path does not match any active authorization policies")
		return
	}

	log.Printf("Matched Rule ID: %s (Pattern: %s)", matchedRule.ID, matchedRule.PathPattern)

	// 4. LEVEL 1 VALIDATION (Fail-Early, e.g. Country checks)
	for _, val := range matchedRule.Validations {
		if val.Level != 1 {
			continue
		}
		pathValue := extractedParams[val.ParamName]
		claimValue := queryClaim(decodedJwt, val.JwtJsonPath)

		log.Printf("Evaluating Level 1: Parameter '%s' = '%s', Claim JSONPath '%s' resolved to '%v'", val.ParamName, pathValue, val.JwtJsonPath, claimValue)

		if val.Validation == "equals" {
			if pathValue != fmt.Sprintf("%v", claimValue) {
				respondDenyWithParam(w, http.StatusForbidden, "L1_COUNTRY_MISMATCH", fmt.Sprintf("URL parameter '%s' does not match claim value", val.ParamName), val.ParamName)
				return
			}
		} else if val.Validation == "contains" {
			if !containsValue(claimValue, pathValue) {
				respondDenyWithParam(w, http.StatusForbidden, "L1_COUNTRY_MISMATCH", fmt.Sprintf("URL parameter '%s' not found in claims list", val.ParamName), val.ParamName)
				return
			}
		}
	}

	// 5. LEVEL 2 VALIDATION (Deep / Ownership checks + optional Enrichment)
	for _, val := range matchedRule.Validations {
		if val.Level != 2 {
			continue
		}
		pathValue := extractedParams[val.ParamName]
		claimValue := queryClaim(decodedJwt, val.JwtJsonPath)

		// Check if enrichment fallback is defined and triggered
		if val.Enrichment != nil {
			conditionValue := queryClaim(decodedJwt, val.Enrichment.ConditionJsonPath)
			// Trigger enrichment if condition matches target value
			if fmt.Sprintf("%v", conditionValue) == fmt.Sprintf("%v", val.Enrichment.ConditionEquals) {
				log.Printf("Enrichment fallback triggered because %s == %v", val.Enrichment.ConditionJsonPath, val.Enrichment.ConditionEquals)

				enrichmentCacheKey := fmt.Sprintf("%s:%s", token, val.Enrichment.Endpoint)
				var enrichedData map[string]any

				if cached, found := enrichmentCache.Get(enrichmentCacheKey); found {
					enrichedData = cached.(map[string]any)
				} else {
					var err error
					domain := config.NomosService
					if val.Enrichment.DomainFrom == "jwtIssuer" {
						domain = issuer
					}
					enrichedData, err = callEnrichmentEndpoint(domain, val.Enrichment.Endpoint, token)
					if err != nil {
						log.Printf("Enrichment call failed: %v", err)
						respondDeny(w, http.StatusForbidden, "ENRICHMENT_FAILED", "Failed to resolve deep claim verification: "+err.Error())
						return
					}
					ttl := time.Duration(val.Enrichment.CacheTtlSeconds) * time.Second
					if ttl <= 0 {
						ttl = 2 * time.Minute
					}
					enrichmentCache.Set(enrichmentCacheKey, enrichedData, ttl)
				}

				// Resolve target validation list from enriched data
				claimValue = queryClaim(enrichedData, val.Enrichment.ResponseJsonPath)
			}
		}

		log.Printf("Evaluating Level 2: Parameter '%s' = '%s', Claim resolved to '%v'", val.ParamName, pathValue, claimValue)

		if val.Validation == "equals" {
			if pathValue != fmt.Sprintf("%v", claimValue) {
				respondDenyWithParam(w, http.StatusForbidden, "L2_OWNERSHIP_VERIFICATION_FAILED", fmt.Sprintf("Target ownership verification failed for parameter '%s'", val.ParamName), val.ParamName)
				return
			}
		} else if val.Validation == "contains" {
			if !containsValue(claimValue, pathValue) {
				respondDenyWithParam(w, http.StatusForbidden, "L2_OWNERSHIP_VERIFICATION_FAILED", fmt.Sprintf("Target ownership verification failed for parameter '%s'", val.ParamName), val.ParamName)
				return
			}
		}
	}

	// 6. ALLOW ACCESS!
	log.Printf("ALLOW: All validation levels successfully passed")
	respondAllow(w, rulesData.AppID, rulesData.IDP)
}

// Decodes a base64 encoded JWT token claims segment without validation
func decodeJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	var payloadSegment string
	if len(parts) == 3 {
		payloadSegment = parts[1]
	} else if len(parts) == 1 {
		payloadSegment = parts[0]
	} else {
		return nil, fmt.Errorf("invalid token segment length")
	}

	if l := len(payloadSegment) % 4; l > 0 {
		payloadSegment += strings.Repeat("=", 4-l)
	}

	decoded, err := base64.URLEncoding.DecodeString(payloadSegment)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(payloadSegment)
	}
	if err != nil {
		return nil, fmt.Errorf("base64 decode error: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("json parsing error: %w", err)
	}

	return claims, nil
}

// Matches route segment templates and extracts parameters
func extractParams(pattern, actualPath string) map[string]string {
	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")
	pathParts := strings.Split(strings.Trim(actualPath, "/"), "/")

	if len(patternParts) != len(pathParts) {
		return nil
	}

	params := make(map[string]string)
	for i, part := range patternParts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			key := part[1 : len(part)-1]
			params[key] = pathParts[i]
		} else if part != pathParts[i] {
			return nil // Static segment mismatch
		}
	}
	return params
}

// Resolves path dot queries e.g. "$.accountDetail.subscriptions"
func queryClaim(payload map[string]any, jsonPath string) any {
	path := strings.Replace(jsonPath, "$.", "", 1)
	if path == "" {
		return payload
	}

	// Strip array suffixes like [*] or [0] to match map structure
	parts := strings.Split(path, ".")
	var current any = payload

	for _, part := range parts {
		// Strip array wildcard notation (simple list support)
		part = strings.ReplaceAll(part, "[*]", "")

		if m, ok := current.(map[string]any); ok {
			current = m[part]
		} else if m, ok := current.(map[string]interface{}); ok {
			current = m[part]
		} else {
			return nil
		}
	}
	return current
}

// Check if a slice contains a string
func containsValue(claimValue any, target string) bool {
	switch v := claimValue.(type) {
	case []any:
		for _, val := range v {
			if fmt.Sprintf("%v", val) == target {
				return true
			}
		}
	case []string:
		for _, val := range v {
			if val == target {
				return true
			}
		}
	case string:
		return v == target
	}
	return false
}

// Fetch rules contract from the centralized Nomos Service
func fetchRulesFromNomos(proxy, aud, iss string) (*RulesResponse, error) {
	req, err := http.NewRequest("GET", config.NomosService+"/nomos/v1/api/rules", nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("proxy", proxy)
	q.Add("aud", aud)
	q.Add("iss", iss)
	req.URL.RawQuery = q.Encode()

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("nomos rules api returned status code %d: %s", resp.StatusCode, string(body))
	}

	var rulesRules RulesResponse
	if err := json.NewDecoder(resp.Body).Decode(&rulesRules); err != nil {
		return nil, err
	}
	return &rulesRules, nil
}

// Executes background API Enrichment lookup
func callEnrichmentEndpoint(domain, endpoint, token string) (map[string]any, error) {
	url := fmt.Sprintf("%s%s", strings.TrimSuffix(domain, "/"), endpoint)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("enrichment api returned status code %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func respondAllow(w http.ResponseWriter, appID, idp string) {
	w.Header().Set("X-Nomos-Authorization", "Success")
	if appID != "" {
		w.Header().Set("X-Nomos-App-Id", appID)
	}
	if idp != "" {
		w.Header().Set("X-Nomos-Idp", idp)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func respondDeny(w http.ResponseWriter, status int, errorCode, message string) {
	respondDenyWithParam(w, status, errorCode, message, "")
}

func respondDenyWithParam(w http.ResponseWriter, status int, errorCode, message, param string) {
	log.Printf("Action: DENY - Error: %s | Message: %s | Param: %s", errorCode, message, param)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Nomos-Error", errorCode)
	if param != "" {
		w.Header().Set("X-Nomos-Param", param)
	}
	w.WriteHeader(status)

	errResp := ErrorResponse{
		Error:   errorCode,
		Message: message,
		Param:   param,
	}
	_ = json.NewEncoder(w).Encode(errResp)
}
