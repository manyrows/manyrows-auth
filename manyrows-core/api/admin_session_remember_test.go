package api_test

import (
	"context"
	"testing"
)

// TestSessionRepo_RememberMeRoundTrips pins that the remember_me column is
// written and read back through the repo.
func TestSessionRepo_RememberMeRoundTrips(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "rmrt-"+GenerateUniqueSlug("u")+"@example.com")
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc})

	sess, claims := testEnv.CreateTestSession(t, acc)

	// Flip remember_me on directly, then read it back through the repo.
	if _, err := testEnv.DB.Pool().Exec(ctx,
		`UPDATE sessions SET remember_me = true WHERE id = $1`, sess.ID); err != nil {
		t.Fatalf("set remember_me: %v", err)
	}

	got, err := testEnv.Repo.GetSessionByToken(ctx, claims)
	if err != nil {
		t.Fatalf("GetSessionByToken: %v", err)
	}
	if got == nil || !got.RememberMe {
		t.Fatalf("expected RememberMe=true, got %+v", got)
	}
}
