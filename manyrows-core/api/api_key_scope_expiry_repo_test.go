package api_test

import (
	"context"
	"testing"
	"time"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
)

// InsertAPIKey persists scope + expiresAt and the getters read them back.
func TestAPIKeyRepo_ScopeExpiryRoundTrip(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "apikey-se-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "AK WS", GenerateUniqueSlug("ws"))
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	exp := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	key := &core.APIKey{
		ID:          uuid.Must(uuid.NewV4()),
		WorkspaceID: ws.ID,
		Name:        "scoped",
		Prefix:      "abcd1234",
		Hash:        "deadbeefhash",
		Scope:       core.APIKeyScopeRead,
		ExpiresAt:   &exp,
		CreatedAt:   time.Now().UTC(),
		CreatedBy:   acc.ID,
	}
	if err := testEnv.Repo.InsertAPIKey(ctx, key); err != nil {
		t.Fatalf("InsertAPIKey: %v", err)
	}
	defer func() { _ = testEnv.Repo.DeleteAPIKey(ctx, ws.ID, key.ID) }()

	got, err := testEnv.Repo.GetAPIKey(ctx, ws.ID, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey: %v", err)
	}
	if got.Scope != core.APIKeyScopeRead {
		t.Errorf("scope: got %q, want %q", got.Scope, core.APIKeyScopeRead)
	}
	if got.ExpiresAt == nil {
		t.Fatalf("expiresAt: got nil, want ~%v", exp)
	}
	if d := got.ExpiresAt.Sub(exp); d < -time.Second || d > time.Second {
		t.Errorf("expiresAt: got %v, want ~%v (diff %v)", got.ExpiresAt, exp, d)
	}
}

// A key inserted without an explicit scope defaults to read_write (so
// existing callers keep full access).
func TestAPIKeyRepo_DefaultScopeReadWrite(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "apikey-def-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "AK WS", GenerateUniqueSlug("ws"))
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	key := &core.APIKey{
		ID:          uuid.Must(uuid.NewV4()),
		WorkspaceID: ws.ID,
		Name:        "legacy",
		Prefix:      "wxyz5678",
		Hash:        "legacyhash",
		// Scope intentionally left empty.
		CreatedAt: time.Now().UTC(),
		CreatedBy: acc.ID,
	}
	if err := testEnv.Repo.InsertAPIKey(ctx, key); err != nil {
		t.Fatalf("InsertAPIKey: %v", err)
	}
	defer func() { _ = testEnv.Repo.DeleteAPIKey(ctx, ws.ID, key.ID) }()

	got, err := testEnv.Repo.GetAPIKey(ctx, ws.ID, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey: %v", err)
	}
	if got.Scope != core.APIKeyScopeReadWrite {
		t.Errorf("default scope: got %q, want %q", got.Scope, core.APIKeyScopeReadWrite)
	}
}
