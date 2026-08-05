package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	// "github.com/redis/go-redis/v9"
	// "context"

	"golang.org/x/sync/singleflight"
)

// ─────────────────────────────────────────────────────────────────────────────
// Cache Key: "proxy:audience:issuer"
// NOT method (Nomos returns all rules, filter post-cache)
// NOT appId (middleware doesn't know it, Nomos resolves it)
// ─────────────────────────────────────────────────────────────────────────────

func buildCacheKey(proxy, audience, issuer string) string {
	return proxy + ":" + audience + ":" + issuer
}

// ─────────────────────────────────────────────────────────────────────────────
// CachedResult — stores both 200 (success) and 403 (denial) from Nomos
// ─────────────────────────────────────────────────────────────────────────────

type CachedResult struct {
	Rules       *RulesResponse `json:"rules,omitempty"`
	Denied      bool           `json:"denied"`
	DenyCode    string         `json:"denyCode,omitempty"`
	DenyMessage string         `json:"denyMessage,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// TTLs
// ─────────────────────────────────────────────────────────────────────────────

const (
	L1SuccessTTL = 30 * time.Second
	L1DenialTTL  = 5 * time.Minute
	// L2SuccessTTL = 1 * time.Hour    // Redis
	// L2DenialTTL  = 5 * time.Minute  // Redis
)

// ─────────────────────────────────────────────────────────────────────────────
// L1 Cache (in-memory, per node)
// ─────────────────────────────────────────────────────────────────────────────

type L1Cache struct {
	mu    sync.RWMutex
	items map[string]l1Entry
}

type l1Entry struct {
	result     *CachedResult
	expiration int64
}

func NewL1Cache() *L1Cache {
	c := &L1Cache{items: make(map[string]l1Entry)}
	go c.cleanup()
	return c
}

func (c *L1Cache) Get(key string) (*CachedResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, found := c.items[key]
	if !found || time.Now().UnixNano() > entry.expiration {
		return nil, false
	}
	return entry.result, true
}

func (c *L1Cache) Set(key string, result *CachedResult, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = l1Entry{
		result:     result,
		expiration: time.Now().Add(ttl).UnixNano(),
	}
}

func (c *L1Cache) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		c.mu.Lock()
		now := time.Now().UnixNano()
		for k, v := range c.items {
			if now > v.expiration {
				delete(c.items, k)
			}
		}
		c.mu.Unlock()
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Redis L2 (commented out — uncomment when ready)
// ─────────────────────────────────────────────────────────────────────────────

// var redisClient *redis.Client
//
// func initRedis() {
//     redisClient = redis.NewClient(&redis.Options{
//         Addr: os.Getenv("REDIS_ADDR"), // e.g. "redis:6379"
//     })
// }
//
// func redisGet(key string) (*CachedResult, bool) {
//     ctx := context.Background()
//     data, err := redisClient.Get(ctx, "nomos:rules:"+key).Bytes()
//     if err != nil {
//         return nil, false
//     }
//     var result CachedResult
//     if err := json.Unmarshal(data, &result); err != nil {
//         return nil, false
//     }
//     return &result, true
// }
//
// func redisSet(key string, result *CachedResult, ttl time.Duration) {
//     ctx := context.Background()
//     data, err := json.Marshal(result)
//     if err != nil {
//         return
//     }
//     redisClient.Set(ctx, "nomos:rules:"+key, data, ttl)
// }

// ─────────────────────────────────────────────────────────────────────────────
// Resolver — the single function main.go calls
// ─────────────────────────────────────────────────────────────────────────────

var (
	l1        = NewL1Cache()
	flight    singleflight.Group
)

// ResolveRules is the entry point called from handleCheck.
// It handles L1 → (L2 Redis) → L3 Nomos with singleflight dedup.
func ResolveRules(proxy, audience, issuer string) (*CachedResult, error) {
	key := buildCacheKey(proxy, audience, issuer)

	// ── L1: in-memory (sub-microsecond) ──
	if result, found := l1.Get(key); found {
		return result, nil
	}

	// ── L2: Redis (uncomment when ready) ──
	// if result, found := redisGet(key); found {
	//     l1.Set(key, result, L1SuccessTTL)
	//     return result, nil
	// }

	// ── L3: Nomos (with singleflight to prevent thundering herd) ──
	val, err, _ := flight.Do(key, func() (interface{}, error) {
		return fetchAndCache(proxy, audience, issuer, key)
	})

	if err != nil {
		return nil, err
	}

	return val.(*CachedResult), nil
}

// fetchAndCache calls Nomos and stores the result in L1 (and L2 when enabled).
func fetchAndCache(proxy, audience, issuer, key string) (*CachedResult, error) {
	rulesData, err := fetchRulesFromNomos(proxy, audience, issuer, "")

	if err != nil {
		// Check if Nomos returned 403
		if strings.Contains(err.Error(), "status code 403") {
			denied := &CachedResult{
				Denied:      true,
				DenyCode:    "NOMOS_FORBIDDEN",
				DenyMessage: err.Error(),
			}
			l1.Set(key, denied, L1DenialTTL)
			// redisSet(key, denied, L2DenialTTL)
			return denied, nil
		}
		// Real error (timeout, unreachable) — don't cache, let caller handle
		return nil, err
	}

	// Success — cache the rules
	success := &CachedResult{Rules: rulesData}
	l1.Set(key, success, L1SuccessTTL)
	// redisSet(key, success, L2SuccessTTL)

	log.Printf("Cached rules for key='%s': %d rules, defaultPolicy='%s'",
		key, len(rulesData.Rules), rulesData.DefaultPolicy)

	return success, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Debug endpoint — dump cache contents (optional, remove in prod)
// ─────────────────────────────────────────────────────────────────────────────

func handleDebugCache(w interface{ Write([]byte) (int, error) }) {
	l1.mu.RLock()
	defer l1.mu.RUnlock()

	type debugEntry struct {
		Key     string        `json:"key"`
		Denied  bool          `json:"denied"`
		Rules   int           `json:"rules"`
		TTLLeft time.Duration `json:"ttl_left"`
	}

	now := time.Now().UnixNano()
	entries := make([]debugEntry, 0, len(l1.items))
	for k, v := range l1.items {
		ruleCount := 0
		if v.result.Rules != nil {
			ruleCount = len(v.result.Rules.Rules)
		}
		entries = append(entries, debugEntry{
			Key:     k,
			Denied:  v.result.Denied,
			Rules:   ruleCount,
			TTLLeft: time.Duration(v.expiration-now) / time.Millisecond,
		})
	}
	json.NewEncoder(w).Encode(entries)
}

// ─────────────────────────────────────────────────────────────────────────────
// Usage from handleCheck (replace the current cache block):
// ─────────────────────────────────────────────────────────────────────────────
//
//   result, err := ResolveRules(targetService, audience, issuer)
//   if err != nil {
//       respondDeny(w, 500, "NOMOS_CONNECTIVITY_ERROR", err.Error())
//       return
//   }
//   if result.Denied {
//       respondDeny(w, 403, result.DenyCode, result.DenyMessage)
//       return
//   }
//
//   rulesData := result.Rules
//
//   // Match path + filter by method
//   for i := range rulesData.Rules {
//       rule := &rulesData.Rules[i]
//       if !matchesMethod(rule.Methods, originalMethod) {
//           continue
//       }
//       params := extractParams(rule.PathPattern, originalPath)
//       if params != nil {
//           matchedRule = rule
//           extractedParams = params
//           break
//       }
//   }
//   // ... rest of validation as before ...

// matchesMethod checks if the request method is in the rule's allowed methods.
// Empty methods list means all methods are allowed.
func matchesMethod(methods []string, requestMethod string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, m := range methods {
		if strings.EqualFold(m, requestMethod) {
			return true
		}
	}
	return false
}

// Suppress unused import warning for json
var _ = fmt.Sprintf
var _ = json.Marshal
