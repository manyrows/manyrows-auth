package app

import (
	"sync"
	"time"

	"github.com/gofrs/uuid/v5"
)

// lastUsedThrottle gates how often an API key's last_used_at is persisted.
// The repo UPDATE is already throttled by a WHERE clause, but that still
// costs a pool connection + round-trip on every request; this in-memory gate
// skips the DB entirely between writes, leaving the WHERE clause as the
// multi-process backstop.
//
// State is bounded by the number of provisioned API keys (like
// apiKeyRateLimiter), so the map can't grow unbounded and needs no eviction.
type lastUsedThrottle struct {
	mu       sync.Mutex
	lastSeen map[uuid.UUID]time.Time
	interval time.Duration
	now      func() time.Time // injectable for tests
}

func newLastUsedThrottle(interval time.Duration) *lastUsedThrottle {
	return &lastUsedThrottle{
		lastSeen: make(map[uuid.UUID]time.Time),
		interval: interval,
		now:      time.Now,
	}
}

// shouldWrite reports whether enough time has elapsed to persist a fresh
// last_used_at for the key, recording "now" as the last write when it
// returns true.
func (t *lastUsedThrottle) shouldWrite(keyID uuid.UUID) bool {
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()

	if last, ok := t.lastSeen[keyID]; ok && now.Sub(last) < t.interval {
		return false
	}
	t.lastSeen[keyID] = now
	return true
}
