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
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// setupRolesRouter creates a router for role tests
func setupRolesRouter(t *testing.T) *chi.Mux {
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
			ok, err = testEnv.Repo.IsWorkspaceOwner(ctx, wsID, acc.ID)
			if err != nil || !ok {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			ws, ok, err := testEnv.Repo.GetWorkspaceByID(ctx, wsID)
			if err != nil || !ok {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}
			ctx = core.WithWorkspace(ctx, ws)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	adminWorkspaceRouter.Get("/projects/{projectId}/roles", requestHandler.HandleGetRoles)
	adminWorkspaceRouter.Post("/projects/{projectId}/roles", requestHandler.HandleCreateRole)
	adminWorkspaceRouter.Put("/projects/{projectId}/roles/{roleId}", requestHandler.HandleUpdateRole)
	adminWorkspaceRouter.Delete("/projects/{projectId}/roles/{roleId}", requestHandler.HandleDeleteRole)
	adminWorkspaceRouter.Put("/projects/{projectId}/roles/{roleId}/permissions", requestHandler.HandleUpdateRolePermissions)

	adminRouter.Mount("/workspace/{workspaceId}", adminWorkspaceRouter)
	r.Mount("/admin", adminRouter)

	return r
}

// TestGetRoles_Success tests listing roles
func TestGetRoles_Success(t *testing.T) {
	router := setupRolesRouter(t)

	email := "role-list-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/roles", nil)
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
}

// TestCreateRole_Success tests creating a role
func TestCreateRole_Success(t *testing.T) {
	router := setupRolesRouter(t)

	email := "role-create-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM roles WHERE project_id = $1 AND slug = 'test-role'", project.ID)
	}()

	body := map[string]any{
		"name": "Test Role",
		"slug": "test-role",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/roles", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
}

// TestCreateRole_MissingName tests creating role without name
func TestCreateRole_MissingName(t *testing.T) {
	router := setupRolesRouter(t)

	email := "role-noname-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"name": "",
		"slug": "test-role",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/roles", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// TestUpdateRole_Success tests updating a role
func TestUpdateRole_Success(t *testing.T) {
	router := setupRolesRouter(t)

	email := "role-update-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM roles WHERE project_id = $1 AND slug = 'update-role'", project.ID)
	}()

	// Create a role first
	createBody := map[string]any{"name": "Original", "slug": "update-role"}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/roles", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create role: %s", createRR.Body.String())
	}

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	// Handler returns role directly, not wrapped in {role: ...}
	roleID := created["id"].(string)

	// Update it
	updateBody := map[string]any{"name": "Updated"}
	updateBytes, _ := json.Marshal(updateBody)
	updateReq := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/roles/"+roleID, bytes.NewReader(updateBytes))
	updateReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, updateReq, claims)

	updateRR := httptest.NewRecorder()
	router.ServeHTTP(updateRR, updateReq)

	if updateRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, updateRR.Code, updateRR.Body.String())
	}
}

// TestDeleteRole_Success tests deleting a role
func TestDeleteRole_Success(t *testing.T) {
	router := setupRolesRouter(t)

	email := "role-delete-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM roles WHERE project_id = $1 AND slug = 'delete-role'", project.ID)
	}()

	// Create a role first
	createBody := map[string]any{"name": "Delete Me", "slug": "delete-role"}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/roles", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	// Handler returns role directly, not wrapped in {role: ...}
	roleID := created["id"].(string)

	// Delete it
	deleteReq := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/roles/"+roleID, nil)
	testEnv.SetSessionCookie(t, deleteReq, claims)

	deleteRR := httptest.NewRecorder()
	router.ServeHTTP(deleteRR, deleteReq)

	if deleteRR.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, deleteRR.Code)
	}
}

// TestUpdateRolePermissions_Success tests updating role permissions
func TestUpdateRolePermissions_Success(t *testing.T) {
	router := setupRolesRouter(t)

	email := "role-perm-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM roles WHERE project_id = $1)", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM roles WHERE project_id = $1 AND slug = 'perm-role'", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM permissions WHERE project_id = $1", project.ID)
	}()

	// Create a permission first
	now := time.Now()
	perm := core.Permission{
		ID:        uuid.Must(uuid.NewV7()),
		ProjectID: project.ID,
		Name:      "Test Permission",
		Slug:      "test-perm",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := testEnv.Repo.CreatePermission(context.Background(), perm); err != nil {
		t.Fatalf("failed to create permission: %v", err)
	}

	// Create a role
	createBody := map[string]any{"name": "Perm Role", "slug": "perm-role"}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/roles", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	// Handler returns role directly, not wrapped in {role: ...}
	roleID := created["id"].(string)

	// Update permissions
	updateBody := map[string]any{"permissionIds": []string{perm.ID.String()}}
	updateBytes, _ := json.Marshal(updateBody)
	updateReq := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/roles/"+roleID+"/permissions", bytes.NewReader(updateBytes))
	updateReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, updateReq, claims)

	updateRR := httptest.NewRecorder()
	router.ServeHTTP(updateRR, updateReq)

	if updateRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, updateRR.Code, updateRR.Body.String())
	}
}

// TestCreateRole_Unauthenticated tests creating role without auth
func TestCreateRole_Unauthenticated(t *testing.T) {
	router := setupRolesRouter(t)

	email := "role-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{"name": "Test Role", "slug": "test-role"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/roles", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// TestCreateRole_NotMember tests creating role when not a member
func TestCreateRole_NotMember(t *testing.T) {
	router := setupRolesRouter(t)

	ownerEmail := "owner-role-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, owner, "Test Project", GenerateUniqueSlug("proj"))

	otherEmail := "other-role-" + GenerateUniqueSlug("test") + "@example.com"
	other := testEnv.CreateTestAccount(t, otherEmail)
	sess, claims := testEnv.CreateTestSession(t, other)

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Projects: []core.Project{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", sess.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", other.ID)
	}()

	body := map[string]any{"name": "Test Role", "slug": "test-role"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/roles", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
}
