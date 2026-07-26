package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

type JWTPayload struct {
	Name   string `json:"name"`
	Msisdn string `json:"msisdn"`
}

type DenyResponse struct {
	Status  int    `json:"status"`
	Error   string `json:"error"`
	Message string `json:"message"`
	Reason  string `json:"reason"`
}

func respondDeny(w http.ResponseWriter, status int, reason string, msg string) {
	log.Printf("Action: DENY - Reason: %s | Message: %s", reason, msg)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Auth-Reason", reason)
	w.WriteHeader(status)
	
	resp := DenyResponse{
		Status:  status,
		Error:   http.StatusText(status),
		Message: msg,
		Reason:  reason,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request from %s %s", r.RemoteAddr, r.URL.Path)
	log.Println("--- Incoming Headers ---")
	for name, values := range r.Header {
		for _, value := range values {
			log.Printf("%s: %s", name, value)
		}
	}
	log.Println("------------------------")

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		respondDeny(w, http.StatusForbidden, "missing-authorization-header", "The Authorization header is required.")
		return
	}

	// 1. Parse MSISDN from request path (e.g. /v1/customer/123456789)
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 3 || pathParts[0] != "v1" || pathParts[1] != "customer" {
		respondDeny(w, http.StatusForbidden, "invalid-path-format", "The requested path format is invalid.")
		return
	}
	pathMsisdn := pathParts[2]

	// 2. Parse Fake JWT: Bearer <header>.<payload>.<signature>
	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || strings.ToLower(tokenParts[0]) != "bearer" {
		respondDeny(w, http.StatusForbidden, "invalid-authorization-format", "Authorization header must use Bearer scheme.")
		return
	}

	jwtParts := strings.Split(tokenParts[1], ".")
	var payloadSegment string
	if len(jwtParts) == 3 {
		payloadSegment = jwtParts[1]
	} else if len(jwtParts) == 1 {
		payloadSegment = jwtParts[0]
	} else {
		respondDeny(w, http.StatusForbidden, "invalid-jwt-structure", "The provided JWT token has an invalid structure.")
		return
	}

	// Base64 decode the payload
	if l := len(payloadSegment) % 4; l > 0 {
		payloadSegment += strings.Repeat("=", 4-l)
	}

	decodedBytes, err := base64.URLEncoding.DecodeString(payloadSegment)
	if err != nil {
		decodedBytes, err = base64.StdEncoding.DecodeString(payloadSegment)
	}

	if err != nil {
		respondDeny(w, http.StatusForbidden, "failed-to-decode-jwt", "Failed to base64-decode the token payload segment.")
		return
	}

	var payload JWTPayload
	if err := json.Unmarshal(decodedBytes, &payload); err != nil {
		respondDeny(w, http.StatusForbidden, "failed-to-parse-jwt-json", "Failed to parse JWT payload JSON.")
		return
	}

	log.Printf("Parsed JWT: Name=%s, TokenMSISDN=%s | Requested Path MSISDN: %s", payload.Name, payload.Msisdn, pathMsisdn)

	// 3. Match Token MSISDN against Path MSISDN
	if payload.Msisdn == pathMsisdn {
		log.Printf("Action: ALLOW - Token MSISDN matches Path MSISDN! User=%s", payload.Name)
		w.Header().Set("X-Auth-User", payload.Name)
		w.Header().Set("X-Auth-Email", strings.ToLower(payload.Name)+"@example.com")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("allowed"))
	} else {
		respondDeny(w, http.StatusForbidden, "path-msisdn-mismatch", "The token's MSISDN does not match the requested path's MSISDN.")
	}
}

func main() {
	http.HandleFunc("/", handleAuth)
	log.Println("Starting dummy external auth server on :8000...")
	if err := http.ListenAndServe(":8000", nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
