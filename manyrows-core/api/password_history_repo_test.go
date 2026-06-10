package api_test

import (
	"context"
	"fmt"
	"testing"

	"manyrows-core/core"
)

// TestPasswordHistory_AppendAndPrune: appending 6 hashes keeps only the
// newest 5, returned newest-first.
func TestPasswordHistory_AppendAndPrune(t *testing.T) {
	ctx := context.Background()

	emailAddr := "pwhistory-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM users WHERE id = $1", user.ID)
	}()

	userID := user.ID

	for i := 1; i <= 6; i++ {
		if err := testEnv.Repo.AppendPasswordHistory(ctx, userID, fmt.Sprintf("hash-%d", i)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	hashes, err := testEnv.Repo.GetRecentPasswordHistory(ctx, userID, 5)
	if err != nil {
		t.Fatalf("get history: %v", err)
	}
	if len(hashes) != 5 {
		t.Fatalf("want 5 hashes, got %d", len(hashes))
	}
	want := []string{"hash-6", "hash-5", "hash-4", "hash-3", "hash-2"}
	for i, w := range want {
		if hashes[i] != w {
			t.Fatalf("hashes[%d] = %q, want %q", i, hashes[i], w)
		}
	}
}
