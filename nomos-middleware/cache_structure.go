package main

import (
	"encoding/json"
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
// MemoryCache — generic in-memory TTL cache (used for rules AND enrichment)
// ─────────────────────────────────────────────────────────────────────────────

type CacheItem struct {
	Value      interface{}
	Expiration int64
}

type MemoryCache struct {
	mu    sync.RWMutex
	items map[string]CacheItem
}

func NewMemoryCache() *MemoryCache {
	c := &MemoryCache{
		items: make(map[string]CacheItem),
	}
	go c.cleanup()
	return c
}

func (c *MemoryCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, found := c.items[key]
	if !found {
		return nil, false
	}
	if time.Now().UnixNano() > item.Expiration {
		return nil, false
	}
	return item.Value, true
}

func (c *MemoryCache) Set(key string, val interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = CacheItem{
		Value:      val,
		Expiration: time.Now().Add(ttl).UnixNano(),
	}
}

func (c *MemoryCache) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		c.mu.Lock()
		now := time.Now().UnixNano()
		for k, v := range c.items {
			if now > v.Expiration {
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
// Global caches + singleflight
// ─────────────────────────────────────────────────────────────────────────────

var (
	rulesCache      = NewMemoryCache() // L1 for rules (key: proxy:aud:iss)
	enrichmentCache = NewMemoryCache() // L1 for enrichment (key: token:endpoint)
	flight          singleflight.Group
)

// ─────────────────────────────────────────────────────────────────────────────
// ResolveRules — the single function handleCheck calls
// L1 cache → (L2 Redis) → L3 Nomos, with singleflight dedup
// ─────────────────────────────────────────────────────────────────────────────

func ResolveRules(proxy, audience, issuer string) (*CachedResult, error) {
	key := buildCacheKey(proxy, audience, issuer)

	// ── L1: in-memory (sub-microsecond) ──
	if cached, found := rulesCache.Get(key); found {
		return cached.(*CachedResult), nil
	}

	// ── L2: Redis (uncomment when ready) ──
	// if result, found := redisGet(key); found {
	//     rulesCache.Set(key, result, L1SuccessTTL)
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
	rulesData, err := fetchRulesFromNomos(proxy, audience, issuer)

	if err != nil {
		if strings.Contains(err.Error(), "status code 403") {
			denied := &CachedResult{
				Denied:      true,
				DenyCode:    "NOMOS_FORBIDDEN",
				DenyMessage: err.Error(),
			}
			rulesCache.Set(key, denied, L1DenialTTL)
			// redisSet(key, denied, L2DenialTTL)
			return denied, nil
		}
		return nil, err
	}

	success := &CachedResult{Rules: rulesData}
	rulesCache.Set(key, success, L1SuccessTTL)
	// redisSet(key, success, L2SuccessTTL)

	log.Printf("Cached rules for key='%s': %d rules, defaultPolicy='%s'",
		key, len(rulesData.Rules), rulesData.DefaultPolicy)

	return success, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// matchesMethod — filter rules by HTTP method after cache lookup
// Empty methods list means all methods are allowed.
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Debug endpoint — dump L1 cache contents
// ─────────────────────────────────────────────────────────────────────────────

func handleDebugCache(w interface{ Write([]byte) (int, error) }) {
	rulesCache.mu.RLock()
	defer rulesCache.mu.RUnlock()

	type debugEntry struct {
		Key     string `json:"key"`
		Denied  bool   `json:"denied"`
		Rules   int    `json:"rules"`
		TTLLeft int64  `json:"ttl_left_ms"`
	}

	now := time.Now().UnixNano()
	entries := make([]debugEntry, 0, len(rulesCache.items))
	for k, v := range rulesCache.items {
		result := v.Value.(*CachedResult)
		ruleCount := 0
		if result.Rules != nil {
			ruleCount = len(result.Rules.Rules)
		}
		entries = append(entries, debugEntry{
			Key:     k,
			Denied:  result.Denied,
			Rules:   ruleCount,
			TTLLeft: (v.Expiration - now) / int64(time.Millisecond),
		})
	}
	json.NewEncoder(w).Encode(entries)
}
