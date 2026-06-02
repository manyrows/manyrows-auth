package api_test

// Round-trip tests for the cookie-mode session lifecycle:
//   - POST /auth/refresh accepting the mr_rt cookie when JSON body is empty
//   - POST /auth/logout (WorkspacePublicLogout) revoking via mr_rt cookie
//     and clearing both cookies on the way out
//   - Idempotent /auth/logout when the cookie / body is missing or the
//     token is unknown

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/auth/client"
	"manyrows-core/core"
)

// issueClientTokenPair spins up a real client session + token pair so
// the cookie-mode tests have valid mr_at / mr_rt values.
func issueClientTokenPair(t *testing.T, ws *core.Workspace, app *core.App, accEmail string) (*client.TokenPair, *core.ClientSession) {
	t.Helper()
	cfg := GetTestConfig()
	clientAuth, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("client auth service: %v", err)
	}
	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, accEmail, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { cleanupUser(t, user.ID) })
	ses, err := clientAuth.CreateSession(ctx, user.ID, app.ID, "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("create client session: %v", err)
	}
	tp, err := clientAuth.IssueTokenPair(ctx, ses, "test-agent", "127.0.0.1", 0, 0, "", "")
	if err != nil {
		t.Fatalf("issue token pair: %v", err)
	}
	t.Cleanup(func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM client_refresh_tokens WHERE session_id = $1", ses.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
	})
	return tp, ses
}

func cookieValue(rr *httptest.ResponseRecorder, name string) string {
	for _, c := range rr.Result().Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func cookieMaxAge(rr *httptest.ResponseRecorder, name string) (int, bool) {
	for _, c := range rr.Result().Cookies() {
		if c.Name == name {
			return c.MaxAge, true
		}
	}
	return 0, false
}

// =====================
// WorkspaceRefresh — cookie path
// =====================

func TestWorkspaceRefresh_FromCookie_NoBody(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "refresh-cookie-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	tp, _ := issueClientTokenPair(t, ws, app, acc.Email)

	// Empty body, refresh token comes via the mr_rt cookie. Pre-fix
	// behaviour was 400 (utils.ReadJson rejected empty body before any
	// cookie was consulted).
	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/refresh", bytes.NewReader([]byte{}))
	req.AddCookie(&http.Cookie{Name: client.RefreshCookieName(app.ID), Value: tp.RefreshToken})
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 from cookie-only refresh, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if resp["accessToken"] == nil || resp["accessToken"] == "" {
		t.Error("expected accessToken in response")
	}
	if resp["refreshToken"] == nil || resp["refreshToken"] == "" {
		t.Error("expected refreshToken in response")
	}

	// Cookie-mode clients also expect the response to re-set the
	// rotated cookies.
	if v := cookieValue(rr, client.AccessCookieName(app.ID)); v == "" {
		t.Errorf("expected mr_at cookie set on refresh response")
	}
	if v := cookieValue(rr, client.RefreshCookieName(app.ID)); v == "" || v == tp.RefreshToken {
		t.Errorf("expected mr_rt cookie rotated on refresh response (got %q)", v)
	}
}

// =====================
// WorkspacePublicLogout
// =====================

func TestPublicLogout_FromCookie_RevokesAndClears(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "logout-cookie-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	tp, ses := issueClientTokenPair(t, ws, app, acc.Email)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: client.RefreshCookieName(app.ID), Value: tp.RefreshToken})

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Both cookies should be cleared (MaxAge=-1).
	for _, name := range []string{client.AccessCookieName(app.ID), client.RefreshCookieName(app.ID)} {
		ma, ok := cookieMaxAge(rr, name)
		if !ok {
			t.Errorf("expected %s deletion cookie on response", name)
			continue
		}
		if ma >= 0 {
			t.Errorf("%s MaxAge = %d, want negative (delete)", name, ma)
		}
	}

	// Server-side: refresh token + session should be gone. A second
	// refresh attempt with the same token should now fail.
	req2 := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/refresh", bytes.NewReader([]byte{}))
	req2.AddCookie(&http.Cookie{Name: client.RefreshCookieName(app.ID), Value: tp.RefreshToken})
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("expected refresh after logout to fail with 401, got %d", rr2.Code)
	}

	// Direct repo check: session should be gone.
	if found, err := testEnv.Repo.GetClientSessionByID(context.Background(), ses.ID); err == nil && found != nil {
		t.Errorf("session %s should be deleted after logout", ses.ID)
	}
}

func TestPublicLogout_FromBody_Works(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "logout-body-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	tp, _ := issueClientTokenPair(t, ws, app, acc.Email)

	body, _ := json.Marshal(map[string]string{"refreshToken": tp.RefreshToken})
	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/logout", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestPublicLogout_NoTokenIsIdempotent(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "logout-empty-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	// No cookie, no body. Logout must still 200 + emit deletion cookies
	// — the goal is "this browser is logged out," not "this token was
	// recognised."
	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/logout", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	for _, name := range []string{client.AccessCookieName(app.ID), client.RefreshCookieName(app.ID)} {
		if _, ok := cookieMaxAge(rr, name); !ok {
			t.Errorf("expected %s deletion cookie even on empty logout", name)
		}
	}
}

func TestPublicLogout_UnknownTokenIsIdempotent(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "logout-unknown-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	body, _ := json.Marshal(map[string]string{"refreshToken": "not-a-real-token"})
	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/logout", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 on unknown token (idempotent), got %d: %s", rr.Code, rr.Body.String())
	}
}
