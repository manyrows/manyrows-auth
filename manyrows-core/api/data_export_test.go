package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/core"
	"manyrows-core/utils"
)

func exportPath(ws *core.Workspace, app *core.App) string {
	return "/x/" + ws.Slug + "/apps/" + app.ID.String() + "/a/me/export"
}

func TestGetMyDataExport_Success(t *testing.T) {
	r := setupClientAPIRouter(t)
	ctx := context.Background()
	emailAddr := "exp-" + GenerateUniqueSlug("t") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "EXP WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	_, token := createTestClientSessionForApp(t, ws, acc, app)
	t.Cleanup(func() { _, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID) })

	// Seed one auth-log row so the export's authLogs section is non-empty.
	_, _ = testEnv.DB.Pool().Exec(ctx, `
		INSERT INTO auth_logs (id, workspace_id, app_id, event, outcome, actor_type, subject_user_id, ip, user_agent)
		VALUES ($1,$2,$3,'login.password','success','self',$4,'203.0.113.7'::inet,'export-agent')`,
		utils.NewUUID(), ws.ID, app.ID, user.ID)

	req := httptest.NewRequest(http.MethodGet, exportPath(ws, app), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if cd := rr.Header().Get("Content-Disposition"); cd == "" {
		t.Fatalf("expected Content-Disposition attachment header")
	}

	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, key := range []string{"exportedAt", "schemaVersion", "profile", "customFields", "identities", "sessions", "passkeys", "authLogs"} {
		if _, ok := out[key]; !ok {
			t.Fatalf("export missing section %q; got keys %v", key, out)
		}
	}
	prof, _ := out["profile"].(map[string]any)
	if prof["email"] != emailAddr {
		t.Fatalf("profile email mismatch: %v", prof["email"])
	}
	logs, _ := out["authLogs"].([]any)
	if len(logs) < 1 {
		t.Fatalf("expected >=1 auth log in export, got %d", len(logs))
	}
}

func TestGetMyDataExport_Unauthenticated(t *testing.T) {
	r := setupClientAPIRouter(t)
	emailAddr := "exp2-" + GenerateUniqueSlug("t") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "EXP2 WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	req := httptest.NewRequest(http.MethodGet, exportPath(ws, app), nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}
