package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"manyrows-core/core"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

func setupBulkUserImportRouter(t *testing.T, svc *TestServices) *chi.Mux {
	t.Helper()
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)
	wsRouter.Route("/projects/{projectId}/apps/{appId}", func(r chi.Router) {
		r.Post("/users:import", svc.Handler.HandleAdminBulkUserImport)
	})
	return r
}

type importResp struct {
	DryRun  bool `json:"dryRun"`
	Summary struct {
		Total, Created, Updated, Skipped, Failed int
	} `json:"summary"`
	Rows []struct {
		Row     int    `json:"row"`
		Email   string `json:"email"`
		Outcome string `json:"outcome"`
		UserID  string `json:"userId"`
		Errors  []struct {
			Field, Message string
		} `json:"errors"`
		Warnings []string `json:"warnings"`
	} `json:"rows"`
}

func TestBulkUserImport_BatchValidation(t *testing.T) {
	svc := NewTestServices(t)
	router := setupBulkUserImportRouter(t, svc)

	acc := testEnv.CreateTestAccount(t, "imp-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	url := fmt.Sprintf("/admin/workspace/%s/projects/%s/apps/%s/users:import", ws.ID, app.ProjectID, app.ID)

	post := func(t *testing.T, payload map[string]any) (*httptest.ResponseRecorder, importResp) {
		t.Helper()
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		var out importResp
		if rr.Code == http.StatusOK {
			_ = json.Unmarshal(rr.Body.Bytes(), &out)
		}
		return rr, out
	}

	// Empty rows -> 200 with zeroed summary.
	rr, out := post(t, map[string]any{"rows": []any{}})
	if rr.Code != http.StatusOK {
		t.Fatalf("empty: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if out.Summary.Total != 0 || out.Summary.Created != 0 {
		t.Fatalf("empty: expected zero summary, got %+v", out.Summary)
	}

	// Bad onConflict -> 400.
	rr, _ = post(t, map[string]any{"onConflict": "merge", "rows": []any{}})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad onConflict: expected 400, got %d", rr.Code)
	}

	// Over the row cap -> 400.
	tooMany := make([]map[string]any, 1001)
	for i := range tooMany {
		tooMany[i] = map[string]any{"email": fmt.Sprintf("x%d@example.com", i)}
	}
	rr, _ = post(t, map[string]any{"rows": tooMany})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("over cap: expected 400, got %d", rr.Code)
	}

	// Unknown default role -> 400.
	rr, _ = post(t, map[string]any{"defaultRoles": []string{"does-not-exist"}, "rows": []any{}})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown default role: expected 400, got %d", rr.Code)
	}
}

func TestBulkUserImport_AppNotFound(t *testing.T) {
	svc := NewTestServices(t)
	router := setupBulkUserImportRouter(t, svc)

	acc := testEnv.CreateTestAccount(t, "imp2-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	// Real project, random app id -> 404.
	url := fmt.Sprintf("/admin/workspace/%s/projects/%s/apps/%s/users:import", ws.ID, app.ProjectID, uuid.Must(uuid.NewV4()).String())
	body, _ := json.Marshal(map[string]any{"rows": []any{}})
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestBulkUserImport_CrossWorkspaceAppIsolation(t *testing.T) {
	svc := NewTestServices(t)
	router := setupBulkUserImportRouter(t, svc)

	// Workspace A is the caller.
	accA := testEnv.CreateTestAccount(t, "impA-"+GenerateUniqueSlug("u")+"@example.com")
	wsA := testEnv.CreateTestWorkspace(t, accA, "WS-A", GenerateUniqueSlug("ws"))
	sessA, claimsA := testEnv.CreateTestSession(t, accA)

	// Workspace B owns the target app.
	accB := testEnv.CreateTestAccount(t, "impB-"+GenerateUniqueSlug("u")+"@example.com")
	wsB := testEnv.CreateTestWorkspace(t, accB, "WS-B", GenerateUniqueSlug("ws"))
	appB := testEnv.CreateTestApp(t, wsB, accB)
	sessB, _ := testEnv.CreateTestSession(t, accB)

	defer testEnv.CleanupTestData(t, &TestFixtures{Account: accA, Workspace: wsA, Session: sessA})
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: accB, Workspace: wsB, Session: sessB})

	// A's admin targets B's app through A's own workspace path -> 404 (no cross-tenant access).
	url := fmt.Sprintf("/admin/workspace/%s/projects/%s/apps/%s/users:import", wsA.ID, appB.ProjectID, appB.ID)
	body, _ := json.Marshal(map[string]any{"rows": []any{}})
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	testEnv.SetSessionCookie(t, req, claimsA)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for cross-workspace app, got %d: %s", rr.Code, rr.Body.String())
	}
}

func createTestPermission(t *testing.T, projectID uuid.UUID, slug string) core.Permission {
	t.Helper()
	p := core.Permission{ProjectID: projectID, Name: "perm-" + slug, Slug: slug}
	if err := testEnv.Repo.CreatePermission(context.Background(), p); err != nil {
		t.Fatalf("CreatePermission: %v", err)
	}
	got, err := testEnv.Repo.GetPermissionsByProjectID(context.Background(), projectID)
	if err != nil {
		t.Fatalf("GetPermissionsByProjectID: %v", err)
	}
	for _, x := range got {
		if x.Slug == slug {
			return x
		}
	}
	t.Fatalf("permission %s not found after create", slug)
	return core.Permission{}
}

func createTestUserField(t *testing.T, poolID, createdBy uuid.UUID, key string, vt core.UserFieldValueType) core.UserField {
	t.Helper()
	now := time.Now().UTC()
	uf, err := testEnv.Repo.CreateUserField(context.Background(), core.UserField{
		UserPoolID:   poolID,
		Key:          key,
		ValueType:    vt,
		Visibility:   "server",
		UserEditable: false,
		Label:        key,
		Status:       "active",
		CreatedAt:    now,
		UpdatedAt:    now,
		CreatedBy:    createdBy,
	})
	if err != nil {
		t.Fatalf("CreateUserField: %v", err)
	}
	return uf
}

func TestBulkUserImport_DryRunClassifies(t *testing.T) {
	ctx := context.Background()
	svc := NewTestServices(t)
	router := setupBulkUserImportRouter(t, svc)

	acc := testEnv.CreateTestAccount(t, "impdry-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	role := createTestRole(t, app.ProjectID)
	createTestUserField(t, app.UserPoolID, acc.ID, "department", core.UserFieldValueTypeString)

	// An existing user in the pool.
	existingEmail := "existing-" + GenerateUniqueSlug("u") + "@example.com"
	existing, _, err := testEnv.Repo.GetOrCreateUser(ctx, existingEmail, app, core.UserSourceRegistered)
	if err != nil {
		t.Fatalf("seed existing user: %v", err)
	}
	t.Cleanup(func() { _, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", existing.ID) })

	url := fmt.Sprintf("/admin/workspace/%s/projects/%s/apps/%s/users:import", ws.ID, app.ProjectID, app.ID)
	post := func(payload map[string]any) importResp {
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		var out importResp
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	newEmail := "new-" + GenerateUniqueSlug("u") + "@example.com"
	out := post(map[string]any{
		"dryRun":     true,
		"onConflict": "skip",
		"rows": []map[string]any{
			{"email": newEmail, "roles": []string{role.Slug}},
			{"email": existingEmail},
			{"email": "not-an-email"},
			{"email": "bad-role-" + GenerateUniqueSlug("u") + "@e.com", "roles": []string{"nope"}},
			{"email": "bad-field-" + GenerateUniqueSlug("u") + "@e.com", "fields": map[string]any{"department": 123}},
			{"email": "bad-key-" + GenerateUniqueSlug("u") + "@e.com", "fields": map[string]any{"nokey": "x"}},
		},
	})
	// 6 rows: 1 new (created), 1 existing (skipped, onConflict=skip), and 4 that
	// fail validation — invalid email, unknown role, wrong-typed field value, and
	// an unknown field key.
	if out.Summary.Created != 1 || out.Summary.Skipped != 1 || out.Summary.Failed != 4 {
		t.Fatalf("skip mode: expected created=1 skipped=1 failed=4, got %+v", out.Summary)
	}

	// Per-row outcomes + error categories (rows returned in input order).
	type expect struct {
		outcome string
		field   string // first error field, "" when not failed
	}
	wantRows := []expect{
		{"created", ""},
		{"skipped", ""},
		{"failed", "email"},
		{"failed", "roles"},
		{"failed", "fields.department"},
		{"failed", "fields.nokey"},
	}
	if len(out.Rows) != len(wantRows) {
		t.Fatalf("expected %d rows, got %d", len(wantRows), len(out.Rows))
	}
	for i, want := range wantRows {
		got := out.Rows[i]
		if got.Outcome != want.outcome {
			t.Errorf("row %d: outcome = %q, want %q", i+1, got.Outcome, want.outcome)
		}
		if want.field != "" {
			if len(got.Errors) == 0 || got.Errors[0].Field != want.field {
				t.Errorf("row %d: expected first error field %q, got %+v", i+1, want.field, got.Errors)
			}
		}
	}

	out = post(map[string]any{
		"dryRun":     true,
		"onConflict": "update",
		"rows": []map[string]any{
			{"email": newEmail},
			{"email": existingEmail},
		},
	})
	if out.Summary.Created != 1 || out.Summary.Updated != 1 {
		t.Fatalf("update mode: expected created=1 updated=1, got %+v", out.Summary)
	}

	if u, _ := testEnv.Repo.GetUserByEmailInPool(ctx, newEmail, app.UserPoolID); u != nil {
		t.Fatalf("dryRun created a user (%s) — must not write", newEmail)
	}
}

func TestBulkUserImport_AppliesFacets(t *testing.T) {
	ctx := context.Background()
	svc := NewTestServices(t)
	router := setupBulkUserImportRouter(t, svc)

	acc := testEnv.CreateTestAccount(t, "impapply-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	role := createTestRole(t, app.ProjectID)
	url := fmt.Sprintf("/admin/workspace/%s/projects/%s/apps/%s/users:import", ws.ID, app.ProjectID, app.ID)
	post := func(payload map[string]any) importResp {
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		var out importResp
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode response: %v (body=%s)", err, rr.Body.String())
		}
		return out
	}

	email := "applied-" + GenerateUniqueSlug("u") + "@example.com"
	t.Cleanup(func() {
		if u, _ := testEnv.Repo.GetUserByEmailInPool(ctx, email, app.UserPoolID); u != nil {
			_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", u.ID)
		}
	})

	out := post(map[string]any{
		"rows": []map[string]any{
			{"email": email, "enabled": false, "emailVerified": true, "roles": []string{role.Slug}},
		},
	})
	if out.Summary.Created != 1 {
		t.Fatalf("expected created=1, got %+v (rows=%+v)", out.Summary, out.Rows)
	}
	u, err := testEnv.Repo.GetUserByEmailInPool(ctx, email, app.UserPoolID)
	if err != nil || u == nil {
		t.Fatalf("user not created: %v", err)
	}
	if u.Enabled {
		t.Errorf("expected enabled=false")
	}
	if u.EmailVerifiedAt == nil {
		t.Errorf("expected email verified")
	}
	roleRows, err := testEnv.Repo.GetUserRolesByUserAndAppID(ctx, app.ProjectID, u.ID, app.ID)
	if err != nil {
		t.Fatalf("GetUserRolesByUserAndAppID: %v", err)
	}
	if len(roleRows) != 1 || roleRows[0].RoleID != role.ID {
		t.Errorf("expected exactly the imported role on create, got %+v", roleRows)
	}

	// Re-import same email in SKIP mode -> skipped, no change.
	out = post(map[string]any{"onConflict": "skip", "rows": []map[string]any{{"email": email, "enabled": true}}})
	if out.Summary.Skipped != 1 {
		t.Fatalf("expected skipped=1, got %+v", out.Summary)
	}
	u, _ = testEnv.Repo.GetUserByEmailInPool(ctx, email, app.UserPoolID)
	if u.Enabled {
		t.Errorf("skip mode must not have re-enabled the user")
	}

	// Re-import in UPDATE mode with enabled=true -> updated, now enabled.
	out = post(map[string]any{"onConflict": "update", "rows": []map[string]any{{"email": email, "enabled": true}}})
	if out.Summary.Updated != 1 {
		t.Fatalf("expected updated=1, got %+v", out.Summary)
	}
	u, _ = testEnv.Repo.GetUserByEmailInPool(ctx, email, app.UserPoolID)
	if !u.Enabled {
		t.Errorf("update mode should have enabled the user")
	}
}

func TestBulkUserImport_PresentVsAbsentRoles(t *testing.T) {
	ctx := context.Background()
	svc := NewTestServices(t)
	router := setupBulkUserImportRouter(t, svc)

	acc := testEnv.CreateTestAccount(t, "imppva-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	role := createTestRole(t, app.ProjectID)
	url := fmt.Sprintf("/admin/workspace/%s/projects/%s/apps/%s/users:import", ws.ID, app.ProjectID, app.ID)
	post := func(payload map[string]any) {
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
	}

	email := "pva-" + GenerateUniqueSlug("u") + "@example.com"
	t.Cleanup(func() {
		if u, _ := testEnv.Repo.GetUserByEmailInPool(ctx, email, app.UserPoolID); u != nil {
			_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", u.ID)
		}
	})

	// helper: count this user's role rows for the app
	countRoles := func() int {
		urs, err := testEnv.Repo.GetUserRolesByUserAndAppID(ctx, app.ProjectID, mustUserID(t, ctx, app, email), app.ID)
		if err != nil {
			t.Fatalf("GetUserRolesByUserAndAppID: %v", err)
		}
		return len(urs)
	}

	// Create WITH a role.
	post(map[string]any{"rows": []map[string]any{{"email": email, "roles": []string{role.Slug}}}})
	if n := countRoles(); n != 1 {
		t.Fatalf("expected 1 role after create, got %d", n)
	}

	// Update with roles ABSENT -> roles unchanged.
	post(map[string]any{"onConflict": "update", "rows": []map[string]any{{"email": email, "enabled": true}}})
	if n := countRoles(); n != 1 {
		t.Fatalf("absent roles must be preserved, got %d roles", n)
	}

	// Update with roles: [] -> cleared.
	post(map[string]any{"onConflict": "update", "rows": []map[string]any{{"email": email, "roles": []string{}}}})
	if n := countRoles(); n != 0 {
		t.Fatalf("empty roles array must clear roles, got %d", n)
	}
}

func mustUserID(t *testing.T, ctx context.Context, app *core.App, email string) uuid.UUID {
	t.Helper()
	u, err := testEnv.Repo.GetUserByEmailInPool(ctx, email, app.UserPoolID)
	if err != nil || u == nil {
		t.Fatalf("user %s not found: %v", email, err)
	}
	return u.ID
}
