package api_test

// Regression test for Repo.UpdateAppSessionCookieSameSite.
//
// The method previously shipped a malformed UPDATE — its SET clause was a
// copy of the column *list* ("set session_cookie_samesite, qr_sign_in_enabled,
// ... as user_pool_name = $4") instead of an assignment — so it errored on
// every call and left PUT .../session-cookie-samesite dead in production. No
// test covered it. This round-trips both allowed values through the DB.
//
// Exercises the repo method directly rather than the HTTP handler so the
// handler's "Strict + magic-link/OAuth is invalid" precondition doesn't get
// in the way of asserting the query itself is well-formed and persists.

import (
	"context"
	"testing"

	"manyrows-core/core"
)

func TestUpdateAppSessionCookieSameSite_Persists(t *testing.T) {
	acc := testEnv.CreateTestAccount(t, "samesite-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, _ := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	ctx := context.Background()
	for _, mode := range []string{core.SessionCookieSameSiteStrict, core.SessionCookieSameSiteLax} {
		out, err := testEnv.Repo.UpdateAppSessionCookieSameSite(ctx, ws.ID, app.ProjectID, app.ID, mode)
		if err != nil {
			t.Fatalf("UpdateAppSessionCookieSameSite(%q): %v", mode, err)
		}
		if out.SessionCookieSameSite != mode {
			t.Errorf("returned app SameSite = %q, want %q", out.SessionCookieSameSite, mode)
		}

		got, err := testEnv.Repo.GetAppByID(ctx, app.ID)
		if err != nil {
			t.Fatalf("reload app: %v", err)
		}
		if got.SessionCookieSameSite != mode {
			t.Errorf("persisted SameSite = %q, want %q", got.SessionCookieSameSite, mode)
		}
	}
}
