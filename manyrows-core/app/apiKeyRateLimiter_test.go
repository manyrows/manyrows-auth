package app

import (
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
)

// newTestLimiter builds a limiter with a controllable clock so tests can
// advance time deterministically instead of sleeping.
func newTestLimiter(perMinute int) (*apiKeyRateLimiter, *time.Time) {
	l := newAPIKeyRateLimiter(perMinute)
	clock := time.Unix(0, 0).UTC()
	l.now = func() time.Time { return clock }
	return l, &clock
}

func TestAPIKeyRateLimiter_AllowsUpToCapacityThenThrottles(t *testing.T) {
	l, _ := newTestLimiter(60) // capacity 60, 1 token/sec
	key := uuid.Must(uuid.NewV4())

	for i := 0; i < 60; i++ {
		allowed, _ := l.Allow(key)
		if !allowed {
			t.Fatalf("request %d should be allowed within the 60-token budget", i+1)
		}
	}

	allowed, retryAfter := l.Allow(key)
	if allowed {
		t.Fatal("request 61 should be throttled once the bucket is empty")
	}
	if retryAfter <= 0 {
		t.Fatalf("throttled request must return a positive Retry-After, got %v", retryAfter)
	}
	// At 1 token/sec, one token costs ~1s.
	if retryAfter > 2*time.Second {
		t.Fatalf("Retry-After should be ~1s at 60/min, got %v", retryAfter)
	}
}

func TestAPIKeyRateLimiter_RefillsOverTime(t *testing.T) {
	l, clock := newTestLimiter(60) // 1 token/sec
	key := uuid.Must(uuid.NewV4())

	// Drain the bucket.
	for i := 0; i < 60; i++ {
		l.Allow(key)
	}
	if allowed, _ := l.Allow(key); allowed {
		t.Fatal("bucket should be empty")
	}

	// Advance 5 seconds → ~5 tokens back.
	*clock = clock.Add(5 * time.Second)
	for i := 0; i < 5; i++ {
		if allowed, _ := l.Allow(key); !allowed {
			t.Fatalf("request %d after refill should be allowed", i+1)
		}
	}
	if allowed, _ := l.Allow(key); allowed {
		t.Fatal("6th request after a 5-token refill should be throttled")
	}
}

func TestAPIKeyRateLimiter_CapacityDoesNotExceedMax(t *testing.T) {
	l, clock := newTestLimiter(60)
	key := uuid.Must(uuid.NewV4())

	// Spend one (creates the bucket at capacity-1), then idle a long time.
	l.Allow(key)
	*clock = clock.Add(1 * time.Hour) // would overflow if uncapped

	allowed := 0
	for i := 0; i < 1000; i++ {
		if ok, _ := l.Allow(key); ok {
			allowed++
		} else {
			break
		}
	}
	if allowed > 60 {
		t.Fatalf("accumulated budget must cap at capacity (60), allowed %d", allowed)
	}
}

func TestAPIKeyRateLimiter_PerKeyIsolation(t *testing.T) {
	l, _ := newTestLimiter(60)
	a := uuid.Must(uuid.NewV4())
	b := uuid.Must(uuid.NewV4())

	for i := 0; i < 60; i++ {
		l.Allow(a)
	}
	if ok, _ := l.Allow(a); ok {
		t.Fatal("key A should be throttled")
	}
	if ok, _ := l.Allow(b); !ok {
		t.Fatal("key B must have its own independent budget")
	}
}

func TestAPIKeyRateLimiter_ZeroUsesDefault(t *testing.T) {
	l := newAPIKeyRateLimiter(0)
	if int(l.capacity) != defaultAPIRatePerMinute {
		t.Fatalf("expected default capacity %d, got %v", defaultAPIRatePerMinute, l.capacity)
	}
}
