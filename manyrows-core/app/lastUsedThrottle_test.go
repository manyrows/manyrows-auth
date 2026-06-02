package app

import (
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
)

func TestLastUsedThrottle(t *testing.T) {
	clock := time.Unix(0, 0).UTC()
	thr := newLastUsedThrottle(time.Minute)
	thr.now = func() time.Time { return clock }

	key := uuid.Must(uuid.NewV4())

	if !thr.shouldWrite(key) {
		t.Fatal("first sight should write")
	}
	if thr.shouldWrite(key) {
		t.Fatal("second call within the interval should be throttled")
	}

	clock = clock.Add(time.Minute)
	if !thr.shouldWrite(key) {
		t.Fatal("call after the interval should write again")
	}

	// A different key has its own independent gate.
	if !thr.shouldWrite(uuid.Must(uuid.NewV4())) {
		t.Fatal("a different key should write on first sight")
	}
}
