package app

import (
	"context"
	"math"
	"net/http"
	"time"

	"manyrows-core/api"
	"manyrows-core/core"
	"manyrows-core/core/repo"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// defaultAPIRatePerMinute is the per-key request budget when the operator
// hasn't set MANYROWS_API_RATE_PER_MINUTE. Generous enough that normal
// server-to-server traffic (permission checks, user lookups, config polls)
// never trips it, low enough to blunt a runaway loop or a leaked key.
const defaultAPIRatePerMinute = 1200

// apiKeyRateLimiter is a token-bucket rate limiter keyed by API key ID,
// throttling the server-to-server API per key.
//
// Bucket state is persisted in Postgres (Repo.ConsumeAPIKeyToken), not in
// process memory, so the budget is SHARED across all replicas — a leaked or
// runaway key is held to the configured rate no matter how many instances
// serve its traffic. (The previous in-memory map gave each instance its own
// full budget, so the effective limit scaled with the replica count.)
//
// Semantics: each key gets `perMinute` requests per minute, and unused
// budget accumulates up to one minute's worth (the bucket capacity), so a
// client that's been idle can briefly burst before settling to the steady
// rate.
type apiKeyRateLimiter struct {
	repo *repo.Repo

	capacity   float64 // max tokens (== perMinute): the largest instantaneous burst
	refillRate float64 // tokens added per second (perMinute / 60)
}

func newAPIKeyRateLimiter(repo *repo.Repo, perMinute int) *apiKeyRateLimiter {
	if perMinute <= 0 {
		perMinute = defaultAPIRatePerMinute
	}
	return &apiKeyRateLimiter{
		repo:       repo,
		capacity:   float64(perMinute),
		refillRate: float64(perMinute) / 60.0,
	}
}

// Allow consumes one token for the given key. It returns true when the
// request is within budget; otherwise false plus how long the caller should
// wait before the next token is available (for the Retry-After header).
//
// On a storage error it fails OPEN (allows the request): a transient DB blip
// must not turn the rate limiter into a single point of failure that locks
// every backend out of the API. The request's real work hits the DB next
// and will surface a genuine outage there.
func (l *apiKeyRateLimiter) Allow(ctx context.Context, keyID uuid.UUID) (bool, time.Duration) {
	allowed, err := l.repo.ConsumeAPIKeyToken(ctx, keyID, l.capacity, l.refillRate)
	if err != nil {
		log.Err(err).Msg("api key rate limiter: token consume failed, allowing request (fail-open)")
		return true, 0
	}
	if allowed {
		return true, 0
	}
	// Empty bucket: roughly one token's worth of wait until the next is
	// available. (Exact partial-token accrual is elided; the middleware
	// rounds up to at least one second anyway.)
	retryAfter := time.Duration(float64(time.Second) / l.refillRate)
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

			allowed, retryAfter := limiter.Allow(r.Context(), key.ID)
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
