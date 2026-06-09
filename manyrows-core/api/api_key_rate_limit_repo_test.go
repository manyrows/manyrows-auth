package api_test

import (
	"context"
	"testing"

	"github.com/gofrs/uuid/v5"
)

func clearAPIKeyBucket(t *testing.T, keyID uuid.UUID) {
	t.Helper()
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`DELETE FROM api_key_rate_limits WHERE api_key_id = $1`, keyID); err != nil {
		t.Fatalf("clear bucket: %v", err)
	}
}

// TestConsumeAPIKeyToken_AllowsUpToCapacityThenRejects: a fresh key gets
// exactly `capacity` requests before the bucket empties (refill disabled).
func TestConsumeAPIKeyToken_AllowsUpToCapacityThenRejects(t *testing.T) {
	keyID := uuid.Must(uuid.NewV4())
	defer clearAPIKeyBucket(t, keyID)
	ctx := context.Background()
	const capacity = 3.0

	for i := 0; i < int(capacity); i++ {
		allowed, err := testEnv.Repo.ConsumeAPIKeyToken(ctx, keyID, capacity, 0)
		if err != nil {
			t.Fatalf("consume %d: %v", i+1, err)
		}
		if !allowed {
			t.Fatalf("request %d should be allowed within capacity %d", i+1, int(capacity))
		}
	}

	allowed, err := testEnv.Repo.ConsumeAPIKeyToken(ctx, keyID, capacity, 0)
	if err != nil {
		t.Fatalf("consume beyond capacity: %v", err)
	}
	if allowed {
		t.Fatal("request beyond capacity should be rejected")
	}
}

// TestConsumeAPIKeyToken_RefillsOverTime: after draining, simulating one
// second of elapsed time (by backdating last_refill) accrues ~1 token, so
// exactly one more request is allowed.
func TestConsumeAPIKeyToken_RefillsOverTime(t *testing.T) {
	keyID := uuid.Must(uuid.NewV4())
	defer clearAPIKeyBucket(t, keyID)
	ctx := context.Background()
	const capacity, refill = 2.0, 1.0

	for i := 0; i < int(capacity); i++ {
		if allowed, err := testEnv.Repo.ConsumeAPIKeyToken(ctx, keyID, capacity, refill); err != nil || !allowed {
			t.Fatalf("drain %d: allowed=%v err=%v", i+1, allowed, err)
		}
	}
	if allowed, _ := testEnv.Repo.ConsumeAPIKeyToken(ctx, keyID, capacity, refill); allowed {
		t.Fatal("bucket should be empty after draining capacity")
	}

	// Simulate one second elapsed → ~1 token refills.
	if _, err := testEnv.DB.Pool().Exec(ctx,
		`UPDATE api_key_rate_limits SET last_refill = last_refill - interval '1 second' WHERE api_key_id = $1`,
		keyID); err != nil {
		t.Fatalf("backdate last_refill: %v", err)
	}

	if allowed, err := testEnv.Repo.ConsumeAPIKeyToken(ctx, keyID, capacity, refill); err != nil || !allowed {
		t.Fatalf("after a 1s refill one request should be allowed: allowed=%v err=%v", allowed, err)
	}
	if allowed, _ := testEnv.Repo.ConsumeAPIKeyToken(ctx, keyID, capacity, refill); allowed {
		t.Fatal("only ~1 token should have refilled; the next request should be rejected")
	}
}

// TestConsumeAPIKeyToken_PerKeyIsolation: keys have independent buckets.
func TestConsumeAPIKeyToken_PerKeyIsolation(t *testing.T) {
	a := uuid.Must(uuid.NewV4())
	b := uuid.Must(uuid.NewV4())
	defer clearAPIKeyBucket(t, a)
	defer clearAPIKeyBucket(t, b)
	ctx := context.Background()
	const capacity = 1.0

	if allowed, _ := testEnv.Repo.ConsumeAPIKeyToken(ctx, a, capacity, 0); !allowed {
		t.Fatal("key A first request should be allowed")
	}
	if allowed, _ := testEnv.Repo.ConsumeAPIKeyToken(ctx, a, capacity, 0); allowed {
		t.Fatal("key A second request should be rejected (capacity 1)")
	}
	if allowed, _ := testEnv.Repo.ConsumeAPIKeyToken(ctx, b, capacity, 0); !allowed {
		t.Fatal("key B must have its own independent budget")
	}
}
