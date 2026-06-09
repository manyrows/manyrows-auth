package app

import "testing"

// The token-bucket allow/deny/refill behaviour now lives in Postgres and is
// covered by the Repo.ConsumeAPIKeyToken integration tests (see
// api/api_key_rate_limit_repo_test.go). These unit tests cover the limiter's
// pure construction math, which is independent of storage.

func TestAPIKeyRateLimiter_ZeroUsesDefault(t *testing.T) {
	l := newAPIKeyRateLimiter(nil, 0)
	if int(l.capacity) != defaultAPIRatePerMinute {
		t.Fatalf("expected default capacity %d, got %v", defaultAPIRatePerMinute, l.capacity)
	}
}

func TestAPIKeyRateLimiter_RefillRateFromPerMinute(t *testing.T) {
	l := newAPIKeyRateLimiter(nil, 60)
	if l.capacity != 60 {
		t.Fatalf("expected capacity 60, got %v", l.capacity)
	}
	if l.refillRate != 1 {
		t.Fatalf("expected refillRate 1 token/sec at 60/min, got %v", l.refillRate)
	}
}
