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

// TestGetMyDataExport_PrivacyProperties verifies two privacy invariants:
//  1. Cross-user exclusion: auth logs for a different user in the same workspace
//     must not appear in the caller's export.
//  2. Server-visibility inclusion: a custom field with visibility='server' must
//     appear in the export (the subject is entitled to all their own data).
func TestGetMyDataExport_PrivacyProperties(t *testing.T) {
	r := setupClientAPIRouter(t)
	ctx := context.Background()

	// --- primary (caller) user ---
	emailAddr := "exppriv-" + GenerateUniqueSlug("t") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "EXPPRIV WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("primary user: %v", err)
	}
	_, token := createTestClientSessionForApp(t, ws, acc, app)
	t.Cleanup(func() { _, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID) })

	// Seed one auth-log row for the primary user so authLogs is non-empty.
	_, _ = testEnv.DB.Pool().Exec(ctx, `
		INSERT INTO auth_logs (id, workspace_id, app_id, event, outcome, actor_type, subject_user_id, ip, user_agent)
		VALUES ($1,$2,$3,'login.password','success','self',$4,'203.0.113.9'::inet,'CALLER-AGENT')`,
		utils.NewUUID(), ws.ID, app.ID, user.ID)

	// --- second user (different identity, same workspace/app) ---
	otherEmail := "exppriv-other-" + GenerateUniqueSlug("t") + "@example.com"
	otherUser, _, err := testEnv.GetOrCreateUserWithMembership(ctx, otherEmail, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("other user: %v", err)
	}
	t.Cleanup(func() { _, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", otherUser.ID) })

	// Seed an auth-log row for the OTHER user with a distinctive user-agent.
	const otherUserAgent = "OTHER-USER-AGENT"
	_, _ = testEnv.DB.Pool().Exec(ctx, `
		INSERT INTO auth_logs (id, workspace_id, app_id, event, outcome, actor_type, subject_user_id, ip, user_agent)
		VALUES ($1,$2,$3,'login.password','success','self',$4,'203.0.113.10'::inet,$5)`,
		utils.NewUUID(), ws.ID, app.ID, otherUser.ID, otherUserAgent)

	// --- server-visibility custom field via raw SQL ---
	// The API only creates 'client' visibility fields; insert directly to test
	// that the export includes server-visibility fields.
	const serverFieldKey = "internal_tier"
	const serverFieldValue = `"gold"`
	fieldID := utils.NewUUID()
	fieldValueID := utils.NewUUID()
	_, err = testEnv.DB.Pool().Exec(ctx, `
		INSERT INTO user_fields (id, user_pool_id, key, value_type, visibility, user_editable, label, status, created_by_account_id)
		VALUES ($1, $2, $3, 'string', 'server', false, 'Internal Tier', 'active', $4)`,
		fieldID, app.UserPoolID, serverFieldKey, acc.ID)
	if err != nil {
		t.Fatalf("insert user_field: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM user_field_values WHERE id = $1", fieldValueID)
		_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM user_fields WHERE id = $1", fieldID)
	})
	_, err = testEnv.DB.Pool().Exec(ctx, `
		INSERT INTO user_field_values (id, user_id, user_field_id, value_json, updated_by)
		VALUES ($1, $2, $3, $4::jsonb, $2)`,
		fieldValueID, user.ID, fieldID, serverFieldValue)
	if err != nil {
		t.Fatalf("insert user_field_value: %v", err)
	}

	// --- call the export endpoint as the primary user ---
	req := httptest.NewRequest(http.MethodGet, exportPath(ws, app), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("parse export: %v", err)
	}

	// 1. Cross-user exclusion: no log with OTHER-USER-AGENT must appear.
	logs, _ := out["authLogs"].([]any)
	for _, entry := range logs {
		logEntry, _ := entry.(map[string]any)
		if logEntry["userAgent"] == otherUserAgent {
			t.Errorf("export contains auth log belonging to another user (userAgent=%q)", otherUserAgent)
		}
	}
	// Sanity-check that the caller's own log is present.
	found := false
	for _, entry := range logs {
		logEntry, _ := entry.(map[string]any)
		if logEntry["userAgent"] == "CALLER-AGENT" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("export is missing the caller's own auth log (userAgent=CALLER-AGENT)")
	}

	// 2. Server-visibility field must appear in customFields.
	fields, _ := out["customFields"].([]any)
	foundServerField := false
	for _, f := range fields {
		cf, _ := f.(map[string]any)
		if cf["key"] == serverFieldKey {
			foundServerField = true
			if cf["visibility"] != "server" {
				t.Errorf("customField %q has visibility=%q, want server", serverFieldKey, cf["visibility"])
			}
			// value should be the JSON string "gold"
			rawVal, _ := cf["value"]
			valStr := ""
			if rawVal != nil {
				b, _ := json.Marshal(rawVal)
				valStr = string(b)
			}
			if valStr != serverFieldValue {
				t.Errorf("customField %q value = %q, want %q", serverFieldKey, valStr, serverFieldValue)
			}
			break
		}
	}
	if !foundServerField {
		t.Errorf("export customFields missing server-visibility field %q", serverFieldKey)
	}
}

func TestGetMyDataExport_IncludesEmailOnlyRows(t *testing.T) {
	r := setupClientAPIRouter(t)
	ctx := context.Background()
	emailAddr := "eo-" + GenerateUniqueSlug("t") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "EO WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	_, token := createTestClientSessionForApp(t, ws, acc, app)
	t.Cleanup(func() { _, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id=$1", user.ID) })

	// A failed-login row keyed ONLY by email (no subject_user_id) — the caller's email.
	_, _ = testEnv.DB.Pool().Exec(ctx, `
		INSERT INTO auth_logs (id, workspace_id, app_id, event, outcome, actor_type, email_attempted, user_agent)
		VALUES ($1,$2,$3,'login.failed','failed','self',$4,'EMAIL-ONLY-AGENT')`,
		utils.NewUUID(), ws.ID, app.ID, emailAddr)
	// A different user's email-only row — must NOT be exported.
	_, _ = testEnv.DB.Pool().Exec(ctx, `
		INSERT INTO auth_logs (id, workspace_id, app_id, event, outcome, actor_type, email_attempted, user_agent)
		VALUES ($1,$2,$3,'login.failed','failed','self',$4,'OTHER-EMAIL-AGENT')`,
		utils.NewUUID(), ws.ID, app.ID, "someone-else-"+GenerateUniqueSlug("x")+"@example.com")

	req := httptest.NewRequest(http.MethodGet, exportPath(ws, app), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	logs, _ := out["authLogs"].([]any)
	var hasMine, hasOther bool
	for _, e := range logs {
		m, _ := e.(map[string]any)
		if m["userAgent"] == "EMAIL-ONLY-AGENT" {
			hasMine = true
		}
		if m["userAgent"] == "OTHER-EMAIL-AGENT" {
			hasOther = true
		}
	}
	if !hasMine {
		t.Fatalf("export missing the caller's email-only auth log")
	}
	if hasOther {
		t.Fatalf("export leaked another user's email-only auth log")
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
