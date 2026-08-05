package main

// ─────────────────────────────────────────────────────────────────────────────
// Cache Structure for nomos-middleware
//
// Key: "proxy:audience:issuer"
//   - proxy:    x-target-service header (which backend)
//   - audience: JWT aud claim (which credential)
//   - issuer:   JWT iss claim (which IDP)
//
// This triplet is exactly what we send to Nomos: GET /rules?proxy=X&aud=Y&iss=Z
// Same input → same response → same cache entry.
//
// NOT in the key:
//   - method:  Nomos returns ALL rules regardless of method. Filter post-cache.
//   - appId:   Middleware doesn't know it. Nomos resolves it. It's output.
// ─────────────────────────────────────────────────────────────────────────────

import "time"

// ─────────────────────────────────────────────────────────────────────────────
// CachedResult — the single value stored at each cache key
// Represents BOTH success (200) and denial (403) from Nomos.
// ─────────────────────────────────────────────────────────────────────────────

type CachedResult struct {
	// ── Success (Nomos returned 200) ──
	Rules *RulesResponse // full response: proxy, appId, idp, defaultPolicy, rules[]

	// ── Denial (Nomos returned 403) ──
	Denied      bool   // true if Nomos denied this triplet
	DenyCode    string // "UNKNOWN_AUDIENCE" or "PROXY_NOT_ALLOWED"
	DenyMessage string
}

// ─────────────────────────────────────────────────────────────────────────────
// What Nomos returns (already defined in main.go, shown here for reference)
// ─────────────────────────────────────────────────────────────────────────────
//
// type RulesResponse struct {
//     Proxy         string         `json:"proxy"`
//     AppID         string         `json:"appId"`
//     IDP           string         `json:"idp"`
//     DefaultPolicy string         `json:"defaultPolicy"`
//     Rules         []RuleContract `json:"rules"`
// }
//
// type RuleContract struct {
//     ID          string               `json:"id"`
//     PathPattern string               `json:"pathPattern"`
//     Methods     []string             `json:"methods"`       // ["GET","POST"]
//     Validations []ValidationContract `json:"validations"`
// }

// ─────────────────────────────────────────────────────────────────────────────
// Cache Key construction
// ─────────────────────────────────────────────────────────────────────────────

func buildCacheKey(proxy, audience, issuer string) string {
	return proxy + ":" + audience + ":" + issuer
}

// ─────────────────────────────────────────────────────────────────────────────
// How each layer stores it
// ─────────────────────────────────────────────────────────────────────────────
//
// ┌────────────────────────────────────────────────────────────────────────┐
// │ L1 — Go in-memory (per node)                                          │
// │                                                                        │
// │   Key:   "tigo-mobile-pa-billing-v1:bZZwD10J...:https://id.tigo.com.pa"│
// │   Value: *CachedResult (pointer, zero-copy)                            │
// │   TTL:   30 seconds                                                    │
// │                                                                        │
// │   Why 30s: short enough to re-sync with Redis if entry was invalidated │
// │   Memory: ~1.7KB per entry × 750 entries = ~1.3MB per node             │
// └────────────────────────────────────────────────────────────────────────┘
//
// ┌────────────────────────────────────────────────────────────────────────┐
// │ L2 — Redis (shared across all nodes)                                   │
// │                                                                        │
// │   Key:   "nomos:rules:tigo-mobile-pa-billing-v1:bZZwD10J...:https://id.tigo.com.pa"
// │   Value: JSON serialized CachedResult                                  │
// │   TTL:   1 hour (success) / 5 minutes (denial)                         │
// │                                                                        │
// │   Why prefix "nomos:rules:": namespace in shared Redis                 │
// │   Why 1h: rules are stable config, change via admin API only           │
// │   Why 5min for denial: revoked access shouldn't linger long,           │
// │           but still protects Nomos from repeated invalid queries        │
// └────────────────────────────────────────────────────────────────────────┘
//
// ┌────────────────────────────────────────────────────────────────────────┐
// │ L3 — Nomos service (source of truth)                                   │
// │                                                                        │
// │   GET /nomos/v1/api/rules?proxy=X&aud=Y&iss=Z                         │
// │                                                                        │
// │   Returns:                                                             │
// │     200 → { proxy, appId, idp, defaultPolicy, rules[] }               │
// │     403 → { error: "UNKNOWN_AUDIENCE" | "PROXY_NOT_ALLOWED" }          │
// │                                                                        │
// │   Called ONLY on L1 miss + L2 miss                                     │
// │   At steady state: ~0 calls/hour (everything served from cache)        │
// └────────────────────────────────────────────────────────────────────────┘

// ─────────────────────────────────────────────────────────────────────────────
// Lookup flow (pseudocode)
// ─────────────────────────────────────────────────────────────────────────────
//
//   func resolveRules(proxy, audience, issuer string) (*CachedResult, error) {
//       key := buildCacheKey(proxy, audience, issuer)
//
//       // ── L1: in-memory (sub-microsecond) ──
//       if result, found := l1Cache.Get(key); found {
//           return result.(*CachedResult), nil
//       }
//
//       // ── L2: Redis (0.1-0.5ms) ──
//       if data, err := redis.Get(ctx, "nomos:rules:"+key).Bytes(); err == nil {
//           var result CachedResult
//           json.Unmarshal(data, &result)
//           l1Cache.Set(key, &result, 30*time.Second)  // promote to L1
//           return &result, nil
//       }
//
//       // ── L3: Nomos (5-10ms) ──
//       // Use singleflight to avoid thundering herd
//       val, err, _ := flight.Do(key, func() (interface{}, error) {
//           return fetchFromNomos(proxy, audience, issuer)
//       })
//
//       if err != nil {
//           // Nomos returned 403 — cache the denial
//           denied := &CachedResult{Denied: true, DenyCode: "...", DenyMessage: "..."}
//           l1Cache.Set(key, denied, 5*time.Minute)
//           redisSet("nomos:rules:"+key, denied, 5*time.Minute)
//           return denied, nil
//       }
//
//       // Nomos returned 200 — cache success
//       success := &CachedResult{Rules: val.(*RulesResponse)}
//       l1Cache.Set(key, success, 30*time.Second)
//       redisSet("nomos:rules:"+key, success, 1*time.Hour)
//       return success, nil
//   }

// ─────────────────────────────────────────────────────────────────────────────
// After cache resolution — method filtering and rule matching
// ─────────────────────────────────────────────────────────────────────────────
//
//   result := resolveRules(proxy, audience, issuer)
//
//   if result.Denied {
//       respondDeny(w, 403, result.DenyCode, result.DenyMessage)
//       return
//   }
//
//   // Match path + method against cached rules
//   for _, rule := range result.Rules.Rules {
//       if !slices.Contains(rule.Methods, originalMethod) {
//           continue  // method doesn't apply to this rule
//       }
//       params := extractParams(rule.PathPattern, originalPath)
//       if params != nil {
//           matchedRule = &rule
//           extractedParams = params
//           break
//       }
//   }
//
//   // No match → use defaultPolicy
//   if matchedRule == nil {
//       if result.Rules.DefaultPolicy == "allow" {
//           respondAllow(...)
//       } else {
//           respondDeny(...)
//       }
//       return
//   }
//
//   // Matched → run L1/L2 validations as before...

// ─────────────────────────────────────────────────────────────────────────────
// TTL Summary
// ─────────────────────────────────────────────────────────────────────────────

const (
	L1SuccessTTL = 30 * time.Second  // L1 re-syncs with Redis frequently
	L1DenialTTL  = 5 * time.Minute   // same as L2 denial
	L2SuccessTTL = 1 * time.Hour     // rules are stable
	L2DenialTTL  = 5 * time.Minute   // don't block new access grants too long
)
