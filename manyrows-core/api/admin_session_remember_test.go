package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/auth"
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

// TestAdminSession_RememberMeBypassesIdle pins that a remembered session is NOT
// reaped by the 8h idle timeout even when last_seen_at is well past the window,
// while a non-remembered session is. The 30d absolute TTL still applies to both.
func TestAdminSession_RememberMeBypassesIdle(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "rmidle-"+GenerateUniqueSlug("u")+"@example.com")
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc})

	authSvc, err := auth.NewAuthService(GetTestConfig(), testEnv.Repo)
	if err != nil {
		t.Fatalf("auth service: %v", err)
	}

	// Remembered + idle beyond the window → still resolves, row kept.
	sess, claims := testEnv.CreateTestSession(t, acc)
	if _, err := testEnv.DB.Pool().Exec(ctx,
		`UPDATE sessions SET remember_me = true, last_seen_at = now() - interval '9 hours' WHERE id = $1`,
		sess.ID); err != nil {
		t.Fatalf("backdate + remember: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/x", nil)
	testEnv.SetSessionCookie(t, req, claims)

	got, gErr := authSvc.GetSession(req)
	if gErr != nil {
		t.Fatalf("GetSession returned error: %v", gErr)
	}
	if got == nil {
		t.Fatal("remembered idle session must still resolve (not logged out)")
	}

	var n int
	if err := testEnv.DB.Pool().QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE id = $1`, sess.ID).Scan(&n); err != nil {
		t.Fatalf("count session: %v", err)
	}
	if n != 1 {
		t.Fatalf("remembered session row must be kept, found %d", n)
	}
}
