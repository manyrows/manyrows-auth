package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"manyrows-core/core"
	"manyrows-core/crypto/passwordhash"
	"manyrows-core/utils"
)

func deletePath(ws *core.Workspace, app *core.App) string {
	return "/x/" + ws.Slug + "/apps/" + app.ID.String() + "/a/me/delete"
}

// passwordDeleteSetup makes a user WITH a password and an active session.
func passwordDeleteSetup(t *testing.T) (http.Handler, *core.Workspace, *core.App, *core.Account, string, string) {
	t.Helper()
	r := setupClientAPIRouter(t)
	emailAddr := "del-" + GenerateUniqueSlug("t") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "DEL WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	hash, _ := passwordhash.Hash("correct-password")
	if err := testEnv.Repo.UpdateUserPassword(ctx, user.ID, hash, time.Now().UTC()); err != nil {
		t.Fatalf("set password: %v", err)
	}
	_, token := createTestClientSessionForApp(t, ws, acc, app)
	t.Cleanup(func() { _, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID) })
	return r, ws, app, acc, emailAddr, token
}

func TestDeleteMyAccount_Password_Success(t *testing.T) {
	r, ws, app, _, emailAddr, token := passwordDeleteSetup(t)
	ctx := context.Background()

	body, _ := json.Marshal(map[string]string{"password": "correct-password"})
	req := httptest.NewRequest(http.MethodPost, deletePath(ws, app), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var cnt int
	_ = testEnv.DB.Pool().QueryRow(ctx, "SELECT count(*) FROM users WHERE email = $1", emailAddr).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("user not erased")
	}
	// account.deleted audit row exists and carries no email PII.
	var em, al *string
	err := testEnv.DB.Pool().QueryRow(ctx,
		"SELECT email_attempted, actor_label FROM auth_logs WHERE workspace_id = $1 AND event = 'account.deleted' ORDER BY created_at DESC LIMIT 1",
		ws.ID).Scan(&em, &al)
	if err != nil {
		t.Fatalf("no account.deleted log: %v", err)
	}
	if (em != nil && *em != "") || (al != nil && *al != "") {
		t.Fatalf("account.deleted row leaked email: em=%v al=%v", em, al)
	}
}

func TestDeleteMyAccount_Password_Wrong(t *testing.T) {
	r, ws, app, _, emailAddr, token := passwordDeleteSetup(t)
	ctx := context.Background()
	body, _ := json.Marshal(map[string]string{"password": "WRONG"})
	req := httptest.NewRequest(http.MethodPost, deletePath(ws, app), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	var cnt int
	_ = testEnv.DB.Pool().QueryRow(ctx, "SELECT count(*) FROM users WHERE email = $1", emailAddr).Scan(&cnt)
	if cnt != 1 {
		t.Fatalf("user should still exist")
	}
}

// passwordlessDeleteSetup makes a user WITHOUT a password (social/passkey).
func passwordlessDeleteSetup(t *testing.T) (http.Handler, *core.Workspace, *core.App, *core.Account, *core.User, string) {
	t.Helper()
	r := setupClientAPIRouter(t)
	emailAddr := "delpw-" + GenerateUniqueSlug("t") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "DELPW WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	_, token := createTestClientSessionForApp(t, ws, acc, app)
	t.Cleanup(func() {
		_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM account_delete_requests WHERE user_id = $1", user.ID)
		_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	})
	return r, ws, app, acc, user, token
}

func TestDeleteMyAccount_Code_Required(t *testing.T) {
	r, ws, app, _, _, token := passwordlessDeleteSetup(t)
	body, _ := json.Marshal(map[string]string{}) // no code, no password
	req := httptest.NewRequest(http.MethodPost, deletePath(ws, app), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestDeleteMyAccount_Code_Success(t *testing.T) {
	r, ws, app, _, user, token := passwordlessDeleteSetup(t)
	ctx := context.Background()

	// Seed a delete request with a known code (mirror email-change tests).
	knownCode := "424242"
	otpID := utils.NewUUID()
	codeHash := testHashOTP(otpID, knownCode, testOTPPepper)
	if err := testEnv.Repo.UpsertAccountDeleteRequest(ctx, otpID, user.ID, app.ID, codeHash, time.Now().UTC().Add(15*time.Minute)); err != nil {
		t.Fatalf("seed request: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"code": knownCode})
	req := httptest.NewRequest(http.MethodPost, deletePath(ws, app), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var cnt int
	_ = testEnv.DB.Pool().QueryRow(ctx, "SELECT count(*) FROM users WHERE id = $1", user.ID).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("user not erased")
	}
}