package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/auth"
)

// TestAdminSession_IdleTimeout pins the sliding inactivity window: a fresh admin
// session resolves, but one whose last_seen_at predates the idle window resolves
// to nil (logged out) and its row is reaped — bounding how long a lifted
// MRSESSION cookie stays usable on an unattended console.
func TestAdminSession_IdleTimeout(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "idle-"+GenerateUniqueSlug("u")+"@example.com")
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc})

	authSvc, err := auth.NewAuthService(GetTestConfig(), testEnv.Repo)
	if err != nil {
		t.Fatalf("auth service: %v", err)
	}

	// Fresh session (last_seen defaults to now()) resolves normally.
	_, freshClaims := testEnv.CreateTestSession(t, acc)
	reqFresh := httptest.NewRequest(http.MethodGet, "/admin/x", nil)
	testEnv.SetSessionCookie(t, reqFresh, freshClaims)
	if got, gErr := authSvc.GetSession(reqFresh); gErr != nil || got == nil {
		t.Fatalf("fresh session should resolve, got (%v, %v)", got, gErr)
	}

	// Session idle beyond the window → logged out + row deleted.
	idleSess, idleClaims := testEnv.CreateTestSession(t, acc)
	if _, err := testEnv.DB.Pool().Exec(ctx,
		`UPDATE sessions SET last_seen_at = now() - interval '9 hours' WHERE id = $1`, idleSess.ID); err != nil {
		t.Fatalf("backdate last_seen: %v", err)
	}
	reqIdle := httptest.NewRequest(http.MethodGet, "/admin/x", nil)
	testEnv.SetSessionCookie(t, reqIdle, idleClaims)
	got, gErr := authSvc.GetSession(reqIdle)
	if gErr != nil {
		t.Fatalf("idle GetSession returned error: %v", gErr)
	}
	if got != nil {
		t.Fatalf("idle session must resolve to nil (logged out), got %+v", got)
	}

	var n int
	if err := testEnv.DB.Pool().QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE id = $1`, idleSess.ID).Scan(&n); err != nil {
		t.Fatalf("count idle session: %v", err)
	}
	if n != 0 {
		t.Fatalf("idle session row should be deleted, found %d", n)
	}
}
