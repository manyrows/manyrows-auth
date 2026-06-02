package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"manyrows-core/api"
	"manyrows-core/auth"
	"manyrows-core/auth/client"
	"manyrows-core/core"
	"manyrows-core/email"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// setupWorkspaceRouter creates a router for workspace-related tests
func setupWorkspaceRouter(t *testing.T) (*chi.Mux, *auth.Service) {
	t.Helper()

	cfg := GetTestConfig()
	adminAuthService, err := auth.NewAuthService(cfg, testEnv.Repo)
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}

	clientAuthService, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("failed to create client auth service: %v", err)
	}

	emailService := email.NewEmailService(true, nil)

	requestHandler := api.NewRequestHandler(
		testEnv.Repo,
		adminAuthService,
		clientAuthService,
		emailService,
		cfg,
		nil,
		nil,
	)

	r := chi.NewRouter()

	// Admin router with auth middleware
	adminRouter := chi.NewRouter()
	adminRouter.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			acc, _, err := adminAuthService.GetLoggedInAccount(r)
			if err != nil || acc == nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			ctx := core.WithAdminAccount(r.Context(), acc)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	// Workspace creation (not scoped to a workspace)
	adminRouter.Post("/workspace", requestHandler.CreateWorkspace)

	// Workspace-scoped router
	adminWorkspaceRouter := chi.NewRouter()
	adminWorkspaceRouter.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			acc, ok := core.AdminAccountFromContext(ctx)
			if !ok || acc == nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			wsIDStr := chi.URLParam(r, "workspaceId")
			wsID, err := uuid.FromString(wsIDStr)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
			// Resolve the workspace-admin role (mirrors the real
			// adminWorkspaceMiddleware) so role-gated handlers — e.g.
			// UpdateWorkspace's owner-only slug change — see the caller's role.
			role, isMember, err := testEnv.Repo.GetWorkspaceAdminRole(ctx, wsID, acc.ID)
			if err != nil || !isMember {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			ws, ok, err := testEnv.Repo.GetWorkspaceByID(ctx, wsID)
			if err != nil || !ok {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}
			ctx = core.WithWorkspace(ctx, ws)
			ctx = core.WithWorkspaceRole(ctx, role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	adminWorkspaceRouter.Post("/", requestHandler.UpdateWorkspace)

	adminRouter.Mount("/workspace/{workspaceId}", adminWorkspaceRouter)
	r.Mount("/admin", adminRouter)

	return r, adminAuthService
}

// TestCreateWorkspace_Forbidden — self-hosted runs a single workspace
// auto-created on first-admin bootstrap (see firstAdminBootstrap.go), so
// CreateWorkspace is intentionally disabled and returns 403 for any
// authenticated POST. The previous _Success / _MissingName cases tested
// a multi-workspace shape that no longer exists.
func TestCreateWorkspace_Forbidden(t *testing.T) {
	router, _ := setupWorkspaceRouter(t)

	email := "create-ws-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"name": "Test Workspace",
		"slug": GenerateUniqueSlug("ws"),
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d: %s", http.StatusForbidden, rr.Code, rr.Body.String())
	}
}

// TestCreateWorkspace_Unauthenticated tests creating workspace without auth
func TestCreateWorkspace_Unauthenticated(t *testing.T) {
	router, _ := setupWorkspaceRouter(t)

	body := map[string]any{
		"name": "Test Workspace",
		"slug": GenerateUniqueSlug("ws"),
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// TestUpdateWorkspace_Success tests updating a workspace
func TestUpdateWorkspace_Success(t *testing.T) {
	router, _ := setupWorkspaceRouter(t)

	emailAddr := "update-ws-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Original Name", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	newSlug := GenerateUniqueSlug("updated")
	body := map[string]any{
		"name": "Updated Name",
		"slug": newSlug,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["name"] != "Updated Name" {
		t.Errorf("expected name %q, got %q", "Updated Name", resp["name"])
	}
	if resp["slug"] != newSlug {
		t.Errorf("expected slug %q, got %q", newSlug, resp["slug"])
	}
}

// TestUpdateWorkspace_SlugChangeRequiresOwner verifies the owner-only gate on
// slug changes: a non-owner workspace admin can still rename the workspace, but
// cannot change its slug (the public API path segment).
func TestUpdateWorkspace_SlugChangeRequiresOwner(t *testing.T) {
	router, _ := setupWorkspaceRouter(t)

	owner := testEnv.CreateTestAccount(t, "ws-owner-"+GenerateUniqueSlug("t")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, owner, "Orig Name", GenerateUniqueSlug("ws"))

	// A second admin holding the non-owner "admin" role.
	member := testEnv.CreateTestAccount(t, "ws-member-"+GenerateUniqueSlug("t")+"@example.com")
	if err := testEnv.Repo.AddWorkspaceAdmin(context.Background(), core.WorkspaceAdmin{
		WorkspaceID: ws.ID, AccountID: member.ID, Role: "admin", AddedBy: &owner.ID,
	}); err != nil {
		t.Fatalf("add member admin: %v", err)
	}
	_, claims := testEnv.CreateTestSession(t, member)

	post := func(name, slug string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"name": name, "slug": slug})
		req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	// Rename only (slug unchanged) → allowed for a non-owner admin.
	if rr := post("Renamed By Member", ws.Slug); rr.Code != http.StatusOK {
		t.Errorf("non-owner rename (same slug): want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	// Change the slug → forbidden for a non-owner.
	if rr := post("Renamed By Member", GenerateUniqueSlug("newslug")); rr.Code != http.StatusForbidden {
		t.Errorf("non-owner slug change: want 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestUpdateWorkspace_MissingName tests updating workspace without name
func TestUpdateWorkspace_MissingName(t *testing.T) {
	router, _ := setupWorkspaceRouter(t)

	emailAddr := "update-ws-noname-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"slug": GenerateUniqueSlug("updated"),
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

// TestUpdateWorkspace_SlugConflict tests updating workspace with conflicting slug
func TestUpdateWorkspace_SlugConflict(t *testing.T) {
	router, _ := setupWorkspaceRouter(t)

	emailAddr := "update-ws-conflict-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws1 := testEnv.CreateTestWorkspace(t, acc, "WS1", GenerateUniqueSlug("ws1"))
	ws2 := testEnv.CreateTestWorkspace(t, acc, "WS2", GenerateUniqueSlug("ws2"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspaces: []*core.Workspace{ws1, ws2}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	// Try to update ws1's slug to ws2's slug
	body := map[string]any{
		"name": "WS1 Updated",
		"slug": ws2.Slug,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws1.ID.String()+"/", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("expected status %d, got %d: %s", http.StatusConflict, rr.Code, rr.Body.String())
	}
}

// TestUpdateWorkspace_Unauthenticated tests updating workspace without auth
func TestUpdateWorkspace_Unauthenticated(t *testing.T) {
	router, _ := setupWorkspaceRouter(t)

	emailAddr := "update-ws-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"name": "Updated Name",
		"slug": GenerateUniqueSlug("updated"),
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}
