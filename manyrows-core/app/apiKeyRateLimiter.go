package app

import (
	"math"
	"net/http"
	"sync"
	"time"

	"manyrows-core/api"
	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
)

// defaultAPIRatePerMinute is the per-key request budget when the operator
// hasn't set MANYROWS_API_RATE_PER_MINUTE. Generous enough that normal
// server-to-server traffic (permission checks, user lookups, config polls)
// never trips it, low enough to blunt a runaway loop or a leaked key.
const defaultAPIRatePerMinute = 1200

// apiKeyRateLimiter is a token-bucket rate limiter keyed by API key ID,
// throttling the server-to-server API per key.
//
// State is in-memory by design: ManyRows runs as a single binary, and the
// set of API keys is bounded by what's provisioned (a handful per
// workspace), so the bucket map can't grow unbounded the way an
// IP-keyed limiter would — no eviction needed.
//
// Semantics: each key gets `perMinute` requests per minute, and unused
// budget accumulates up to one minute's worth (the bucket capacity), so a
// client that's been idle can briefly burst before settling to the steady
// rate.
type apiKeyRateLimiter struct {
	mu      sync.Mutex
	buckets map[uuid.UUID]*tokenBucket

	capacity   float64 // max tokens (== perMinute): the largest instantaneous burst
	refillRate float64 // tokens added per second (perMinute / 60)

	now func() time.Time // injectable for tests; defaults to time.Now
}

type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
}

func newAPIKeyRateLimiter(perMinute int) *apiKeyRateLimiter {
	if perMinute <= 0 {
		perMinute = defaultAPIRatePerMinute
	}
	return &apiKeyRateLimiter{
		buckets:    make(map[uuid.UUID]*tokenBucket),
		capacity:   float64(perMinute),
		refillRate: float64(perMinute) / 60.0,
		now:        func() time.Time { return time.Now() },
	}
}

// Allow consumes one token for the given key. It returns true when the
// request is within budget; otherwise false plus how long the caller should
// wait before the next token is available (for the Retry-After header).
func (l *apiKeyRateLimiter) Allow(keyID uuid.UUID) (bool, time.Duration) {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[keyID]
	if !ok {
		// First sight of this key: start full so a freshly provisioned key
		// isn't penalised, then immediately spend one token.
		l.buckets[keyID] = &tokenBucket{tokens: l.capacity - 1, lastRefill: now}
		return true, 0
	}

	// Refill based on elapsed time, capped at capacity.
	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed > 0 {
		b.tokens = math.Min(l.capacity, b.tokens+elapsed*l.refillRate)
		b.lastRefill = now
	}

	if b.tokens >= 1 {
		b.tokens -= 1
		return true, 0
	}

	// Not enough budget: time until one full token has accrued.
	deficit := 1 - b.tokens
	retryAfter := time.Duration(deficit / l.refillRate * float64(time.Second))
	return false, retryAfter
}

// apiKeyRateLimitMiddleware throttles per API key. It must run AFTER
// apiKeyMiddleware so the authenticated key is in context.
func apiKeyRateLimitMiddleware(limiter *apiKeyRateLimiter) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key, ok := core.APIKeyFromContext(r.Context())
			if !ok || key == nil {
				// No key in context means the middleware chain is wired
				// wrong; fail closed rather than silently skip the limit.
				api.WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
				return
			}

			allowed, retryAfter := limiter.Allow(key.ID)
			if !allowed {
				secs := int(math.Ceil(retryAfter.Seconds()))
				if secs < 1 {
					secs = 1
				}
				api.WriteRateLimitError(w, r, secs)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
