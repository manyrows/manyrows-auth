package api_test

import (
	"context"
	"testing"
	"time"

	"manyrows-core/core/repo"
	"manyrows-core/utils"
)

func TestAccountDeleteRequestRepo_UpsertGetConsume(t *testing.T) {
	ctx := context.Background()
	emailAddr := "adr-" + GenerateUniqueSlug("t") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "ADR WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, "invited")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM account_delete_requests WHERE user_id = $1", user.ID)
		_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	})

	otpID := utils.NewUUID()
	exp := time.Now().UTC().Add(15 * time.Minute)
	if err := testEnv.Repo.UpsertAccountDeleteRequest(ctx, otpID, user.ID, app.ID, "hash-1", exp); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := testEnv.Repo.GetAccountDeleteRequest(ctx, user.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != otpID || got.CodeHash != "hash-1" || !got.IsActive(time.Now().UTC()) {
		t.Fatalf("unexpected request: %+v", got)
	}

	// Re-request overwrites with a new id + hash.
	otpID2 := utils.NewUUID()
	if err := testEnv.Repo.UpsertAccountDeleteRequest(ctx, otpID2, user.ID, app.ID, "hash-2", exp); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	got2, _ := testEnv.Repo.GetAccountDeleteRequest(ctx, user.ID)
	if got2.ID != otpID2 || got2.CodeHash != "hash-2" {
		t.Fatalf("re-upsert did not overwrite: %+v", got2)
	}

	// Consume by wrong id fails; by right id succeeds once.
	if ok, _ := testEnv.Repo.ConsumeAccountDeleteRequest(ctx, user.ID, otpID); ok {
		t.Fatal("consume with stale id should fail")
	}
	ok, err := testEnv.Repo.ConsumeAccountDeleteRequest(ctx, user.ID, otpID2)
	if err != nil || !ok {
		t.Fatalf("consume: ok=%v err=%v", ok, err)
	}
	if _, err := testEnv.Repo.GetAccountDeleteRequest(ctx, user.ID); err != repo.ErrAccountDeleteRequestNotFound {
		t.Fatalf("expected ErrAccountDeleteRequestNotFound after consume, got %v", err)
	}
}

func TestAccountDeleteRequestRepo_SweepExpired(t *testing.T) {
	ctx := context.Background()
	emailAddr := "adr2-" + GenerateUniqueSlug("t") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "ADR2 WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, "invited")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM account_delete_requests WHERE user_id = $1", user.ID)
		_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	})

	// expired 1 minute ago
	expired := time.Now().UTC().Add(-1 * time.Minute)
	if err := testEnv.Repo.UpsertAccountDeleteRequest(ctx, utils.NewUUID(), user.ID, app.ID, "h", expired); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	n, err := testEnv.Repo.DeleteExpiredAccountDeleteRequests(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n < 1 {
		t.Fatalf("expected >=1 swept, got %d", n)
	}
	if _, err := testEnv.Repo.GetAccountDeleteRequest(ctx, user.ID); err != repo.ErrAccountDeleteRequestNotFound {
		t.Fatalf("expected swept row gone, got %v", err)
	}
}