package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/auth/client"
	"manyrows-core/core"
)

// =====================
// DeleteMyOtherSessions Tests
// =====================

// TestDeleteMyOtherSessions_RevokesOthersKeepsCurrent verifies that
// DELETE /me/sessions revokes all sessions except the calling session,
// and that the calling session remains valid afterwards.
func TestDeleteMyOtherSessions_RevokesOthersKeepsCurrent(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "bulk-revoke-multi-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_refresh_tokens WHERE session_id IN (SELECT id FROM client_sessions WHERE workspace_id = $1)", ws.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
	}()

	ctx := context.Background()
	cfg := GetTestConfig()
	clientAuthService, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("failed to create client auth service: %v", err)
	}

	// Create (or reuse) the app user.
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM users WHERE id = $1", user.ID)
	}()

	// Session 1 — this is the "current" session we will authenticate with.
	ses1, err := clientAuthService.CreateSession(ctx, user.ID, app.ID, "agent-1", "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to create session 1: %v", err)
	}
	tokenPair1, err := clientAuthService.IssueTokenPair(ctx, ses1, "agent-1", "127.0.0.1", 0, 0, "", "", "")
	if err != nil {
		t.Fatalf("failed to issue token pair 1: %v", err)
	}

	// Session 2.
	_, err = clientAuthService.CreateSession(ctx, user.ID, app.ID, "agent-2", "127.0.0.2")
	if err != nil {
		t.Fatalf("failed to create session 2: %v", err)
	}

	// Session 3.
	_, err = clientAuthService.CreateSession(ctx, user.ID, app.ID, "agent-3", "127.0.0.3")
	if err != nil {
		t.Fatalf("failed to create session 3: %v", err)
	}

	// DELETE /me/sessions authenticated as session 1.
	req := httptest.NewRequest(http.MethodDelete, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/me/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+tokenPair1.AccessToken)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var deleteResp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &deleteResp); err != nil {
		t.Fatalf("failed to parse delete response: %v", err)
	}
	revokedRaw, ok := deleteResp["revoked"]
	if !ok {
		t.Fatalf("expected 'revoked' field in response, got: %v", deleteResp)
	}
	// JSON numbers unmarshal as float64.
	revokedCount, ok := revokedRaw.(float64)
	if !ok {
		t.Fatalf("expected 'revoked' to be a number, got %T", revokedRaw)
	}
	if int(revokedCount) != 2 {
		t.Errorf("expected revoked=2, got %v", revokedCount)
	}

	// GET /me/sessions with the SAME token — should still work and return
	// exactly 1 session marked current=true.
	req2 := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/me/sessions", nil)
	req2.Header.Set("Authorization", "Bearer "+tokenPair1.AccessToken)
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200 on GET /me/sessions after bulk revoke, got %d: %s", rr2.Code, rr2.Body.String())
	}

	var getResp map[string]any
	if err := json.Unmarshal(rr2.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("failed to parse get response: %v", err)
	}
	sessions, ok := getResp["sessions"].([]any)
	if !ok {
		t.Fatalf("expected sessions array, got %T", getResp["sessions"])
	}
	if len(sessions) != 1 {
		t.Errorf("expected exactly 1 session remaining, got %d", len(sessions))
	}
	if len(sessions) > 0 {
		entry, _ := sessions[0].(map[string]any)
		if entry["current"] != true {
			t.Error("expected remaining session to have current=true")
		}
	}
}

// TestDeleteMyOtherSessions_NoOthers verifies that when the user has
// only one session the endpoint returns 200 with revoked=0 and the
// token remains valid.
func TestDeleteMyOtherSessions_NoOthers(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "bulk-revoke-single-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_refresh_tokens WHERE session_id IN (SELECT id FROM client_sessions WHERE workspace_id = $1)", ws.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
	}()

	ses, accessToken := createTestClientSessionForApp(t, ws, acc, app)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM users WHERE id = $1", ses.UserID)
	}()

	req := httptest.NewRequest(http.MethodDelete, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/me/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	revokedRaw, ok := resp["revoked"]
	if !ok {
		t.Fatalf("expected 'revoked' field, got: %v", resp)
	}
	revokedCount, ok := revokedRaw.(float64)
	if !ok {
		t.Fatalf("expected 'revoked' to be a number, got %T", revokedRaw)
	}
	if int(revokedCount) != 0 {
		t.Errorf("expected revoked=0, got %v", revokedCount)
	}

	// Token should still work.
	req2 := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/me/sessions", nil)
	req2.Header.Set("Authorization", "Bearer "+accessToken)
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected token still valid after no-op revoke, got %d: %s", rr2.Code, rr2.Body.String())
	}
}

// TestDeleteMyOtherSessions_Unauthenticated verifies that the endpoint
// returns 401 when no bearer token is supplied.
func TestDeleteMyOtherSessions_Unauthenticated(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "bulk-revoke-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodDelete, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/me/sessions", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}
