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

// setupFeatureFlagsRouter creates a router for feature flag tests
func setupFeatureFlagsRouter(t *testing.T) *chi.Mux {
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

	// NOTE: keep this in sync with manyrows-core/app/router.go. The override
	// list endpoint is project-scoped (no featureFlagId), and update is PATCH.
	adminWorkspaceRouter.Get("/projects/{projectId}/featureFlags", requestHandler.HandleGetFeatureFlags)
	adminWorkspaceRouter.Post("/projects/{projectId}/featureFlags", requestHandler.HandleCreateFeatureFlag)
	adminWorkspaceRouter.Get("/projects/{projectId}/featureFlags/{featureFlagId}", requestHandler.HandleGetFeatureFlag)
	adminWorkspaceRouter.Patch("/projects/{projectId}/featureFlags/{featureFlagId}", requestHandler.HandleUpdateFeatureFlag)
	adminWorkspaceRouter.Delete("/projects/{projectId}/featureFlags/{featureFlagId}", requestHandler.HandleDeleteFeatureFlag)
	adminWorkspaceRouter.Get("/projects/{projectId}/featureFlags/apps", requestHandler.HandleGetFeatureFlagOverrides)
	adminWorkspaceRouter.Put("/projects/{projectId}/featureFlags/{featureFlagId}/apps/{appId}", requestHandler.HandleUpsertFeatureFlagOverride)
	adminWorkspaceRouter.Delete("/projects/{projectId}/featureFlags/{featureFlagId}/apps/{appId}", requestHandler.HandleDeleteFeatureFlagOverride)

	adminRouter.Mount("/workspace/{workspaceId}", adminWorkspaceRouter)
	r.Mount("/admin", adminRouter)

	return r
}

// TestGetFeatureFlags_Success tests listing feature flags
func TestGetFeatureFlags_Success(t *testing.T) {
	router := setupFeatureFlagsRouter(t)

	email := "ff-list-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags", nil)
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

// TestCreateFeatureFlag_Success tests creating a feature flag
func TestCreateFeatureFlag_Success(t *testing.T) {
	router := setupFeatureFlagsRouter(t)

	email := "ff-create-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM feature_flags WHERE project_id = $1", project.ID)
	}()

	body := map[string]any{
		"key":            "test_flag",
		"name":           "Test Feature Flag",
		"defaultEnabled": true,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags", bytes.NewReader(bodyBytes))
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

// TestCreateFeatureFlag_MissingKey tests creating feature flag without key
func TestCreateFeatureFlag_MissingKey(t *testing.T) {
	router := setupFeatureFlagsRouter(t)

	email := "ff-nokey-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"key":  "",
		"name": "Test Flag",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// TestGetFeatureFlag_Success tests getting a single feature flag
func TestGetFeatureFlag_Success(t *testing.T) {
	router := setupFeatureFlagsRouter(t)

	email := "ff-get-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM feature_flags WHERE project_id = $1", project.ID)
	}()

	// Create a flag first
	createBody := map[string]any{"key": "get_flag", "name": "Get Flag", "defaultEnabled": true}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create feature flag: %s", createRR.Body.String())
	}

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	featureFlag := created["featureFlag"].(map[string]any)
	flagID := featureFlag["id"].(string)

	// Get it
	getReq := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags/"+flagID, nil)
	testEnv.SetSessionCookie(t, getReq, claims)

	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, getRR.Code, getRR.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(getRR.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Response is wrapped in {featureFlag: ...}
	gotFlag := resp["featureFlag"].(map[string]any)
	if gotFlag["key"] != "get_flag" {
		t.Errorf("expected key 'get_flag', got %v", gotFlag["key"])
	}
}

// TestGetFeatureFlag_NotFound tests getting non-existent feature flag
func TestGetFeatureFlag_NotFound(t *testing.T) {
	router := setupFeatureFlagsRouter(t)

	email := "ff-get-nf-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	fakeID := uuid.Must(uuid.NewV4())
	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags/"+fakeID.String(), nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

// TestUpdateFeatureFlag_Success tests updating a feature flag
func TestUpdateFeatureFlag_Success(t *testing.T) {
	router := setupFeatureFlagsRouter(t)

	email := "ff-update-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM feature_flags WHERE project_id = $1", project.ID)
	}()

	// Create a flag first
	createBody := map[string]any{"key": "update_flag", "name": "Original Name", "defaultEnabled": false}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create feature flag: %s", createRR.Body.String())
	}

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	featureFlag := created["featureFlag"].(map[string]any)
	flagID := featureFlag["id"].(string)

	// Update it
	updateBody := map[string]any{"description": "Updated description", "defaultEnabled": true}
	updateBytes, _ := json.Marshal(updateBody)
	updateReq := httptest.NewRequest(http.MethodPatch, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags/"+flagID, bytes.NewReader(updateBytes))
	updateReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, updateReq, claims)

	updateRR := httptest.NewRecorder()
	router.ServeHTTP(updateRR, updateReq)

	if updateRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, updateRR.Code, updateRR.Body.String())
	}
}

// TestDeleteFeatureFlag_Success tests deleting a feature flag
func TestDeleteFeatureFlag_Success(t *testing.T) {
	router := setupFeatureFlagsRouter(t)

	email := "ff-delete-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM feature_flags WHERE project_id = $1", project.ID)
	}()

	// Create a flag first
	createBody := map[string]any{"key": "delete_flag", "name": "Delete Me", "defaultEnabled": false}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	featureFlag := created["featureFlag"].(map[string]any)
	flagID := featureFlag["id"].(string)

	// Delete it
	deleteReq := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags/"+flagID, nil)
	testEnv.SetSessionCookie(t, deleteReq, claims)

	deleteRR := httptest.NewRecorder()
	router.ServeHTTP(deleteRR, deleteReq)

	if deleteRR.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, deleteRR.Code)
	}
}

func TestFeatureFlagOverrides_Success(t *testing.T) {
	router := setupFeatureFlagsRouter(t)

	email := "ff-env-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	// Overrides are scoped per-app; the repo validates app belongs to
	// project, so the path must point at a real app (uuid.Nil → ErrNotFound).
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "FF Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM feature_flag_overrides WHERE feature_flag_id IN (SELECT id FROM feature_flags WHERE project_id = $1)", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM feature_flags WHERE project_id = $1", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	// Create a feature flag
	createBody := map[string]any{"key": "env_flag", "name": "Env Flag", "defaultEnabled": false}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	featureFlag := created["featureFlag"].(map[string]any)
	flagID := featureFlag["id"].(string)

	getReq := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags/apps", nil)
	testEnv.SetSessionCookie(t, getReq, claims)

	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, getRR.Code, getRR.Body.String())
	}

	// Upsert environment override
	upsertBody := map[string]any{"enabled": true}
	upsertBytes, _ := json.Marshal(upsertBody)
	upsertReq := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags/"+flagID+"/apps/"+appID.String(), bytes.NewReader(upsertBytes))
	upsertReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, upsertReq, claims)

	upsertRR := httptest.NewRecorder()
	router.ServeHTTP(upsertRR, upsertReq)

	if upsertRR.Code != http.StatusOK && upsertRR.Code != http.StatusCreated {
		t.Errorf("expected status 200 or 201, got %d: %s", upsertRR.Code, upsertRR.Body.String())
	}

	// Delete environment override
	deleteReq := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags/"+flagID+"/apps/"+appID.String(), nil)
	testEnv.SetSessionCookie(t, deleteReq, claims)

	deleteRR := httptest.NewRecorder()
	router.ServeHTTP(deleteRR, deleteReq)

	if deleteRR.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, deleteRR.Code)
	}
}

// TestCreateFeatureFlag_Unauthenticated tests creating feature flag without auth
func TestCreateFeatureFlag_Unauthenticated(t *testing.T) {
	router := setupFeatureFlagsRouter(t)

	email := "ff-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{"key": "test_flag", "name": "Test"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// TestUpsertFeatureFlagEnv_WithRoleIds tests creating an env override with roleIds
func TestUpsertFeatureFlagEnv_WithRoleIds(t *testing.T) {
	router := setupFeatureFlagsRouter(t)

	email := "ff-role-upsert-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "FF Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM feature_flag_overrides WHERE feature_flag_id IN (SELECT id FROM feature_flags WHERE project_id = $1)", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM feature_flags WHERE project_id = $1", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM roles WHERE project_id = $1", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	// Create feature flag
	createBody := map[string]any{"key": "role_flag", "name": "Role Flag", "defaultEnabled": false}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create feature flag: %s", createRR.Body.String())
	}

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	featureFlag := created["featureFlag"].(map[string]any)
	flagID := featureFlag["id"].(string)

	// Create two roles
	role1 := createTestRole(t, project.ID)
	role2 := createTestRole(t, project.ID)

	// Upsert environment override with roleIds
	upsertBody := map[string]any{
		"enabled": true,
		"roleIds": []string{role1.ID.String(), role2.ID.String()},
	}
	upsertBytes, _ := json.Marshal(upsertBody)
	upsertReq := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags/"+flagID+"/apps/"+appID.String(), bytes.NewReader(upsertBytes))
	upsertReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, upsertReq, claims)

	upsertRR := httptest.NewRecorder()
	router.ServeHTTP(upsertRR, upsertReq)

	if upsertRR.Code != http.StatusOK && upsertRR.Code != http.StatusCreated {
		t.Fatalf("expected status 200 or 201, got %d: %s", upsertRR.Code, upsertRR.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(upsertRR.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Regression guard: the upsert response must echo the appId from the
	// URL. The repo previously passed o.ID into the app_id column (and
	// scanned the result back into out.ID), so the response would carry
	// the wrong UUID despite a 200.
	if got, _ := resp["appId"].(string); got != appID.String() {
		t.Errorf("upsert response appId = %q, want %q", got, appID.String())
	}

	// Verify roleIds are present in the response
	roleIDs, ok := resp["roleIds"].([]any)
	if !ok {
		t.Fatalf("expected roleIds in response, got %v", resp["roleIds"])
	}
	if len(roleIDs) != 2 {
		t.Errorf("expected 2 roleIds, got %d", len(roleIDs))
	}

	// Verify the role IDs match
	roleIDSet := map[string]bool{}
	for _, rid := range roleIDs {
		roleIDSet[rid.(string)] = true
	}
	if !roleIDSet[role1.ID.String()] {
		t.Errorf("expected roleIds to contain %s", role1.ID.String())
	}
	if !roleIDSet[role2.ID.String()] {
		t.Errorf("expected roleIds to contain %s", role2.ID.String())
	}
}

// TestUpsertFeatureFlagEnv_ClearRoleIds tests setting roleIds then clearing them
func TestUpsertFeatureFlagEnv_ClearRoleIds(t *testing.T) {
	router := setupFeatureFlagsRouter(t)

	email := "ff-role-clear-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "FF Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM feature_flag_overrides WHERE feature_flag_id IN (SELECT id FROM feature_flags WHERE project_id = $1)", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM feature_flags WHERE project_id = $1", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM roles WHERE project_id = $1", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	// Create feature flag
	createBody := map[string]any{"key": "clear_role_flag", "name": "Clear Role Flag", "defaultEnabled": false}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create feature flag: %s", createRR.Body.String())
	}

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	featureFlag := created["featureFlag"].(map[string]any)
	flagID := featureFlag["id"].(string)

	// Create a role
	role := createTestRole(t, project.ID)

	// Step 1: Upsert with roleIds
	upsertBody := map[string]any{
		"enabled": true,
		"roleIds": []string{role.ID.String()},
	}
	upsertBytes, _ := json.Marshal(upsertBody)
	upsertReq := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags/"+flagID+"/apps/"+appID.String(), bytes.NewReader(upsertBytes))
	upsertReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, upsertReq, claims)

	upsertRR := httptest.NewRecorder()
	router.ServeHTTP(upsertRR, upsertReq)
	if upsertRR.Code != http.StatusOK && upsertRR.Code != http.StatusCreated {
		t.Fatalf("first upsert failed: %d: %s", upsertRR.Code, upsertRR.Body.String())
	}

	// Verify roleIds are set
	var firstResp map[string]any
	json.Unmarshal(upsertRR.Body.Bytes(), &firstResp)
	firstRoleIDs, _ := firstResp["roleIds"].([]any)
	if len(firstRoleIDs) != 1 {
		t.Fatalf("expected 1 roleId after first upsert, got %d", len(firstRoleIDs))
	}

	// Step 2: Upsert with empty roleIds to clear
	clearBody := map[string]any{
		"enabled": true,
		"roleIds": []string{},
	}
	clearBytes, _ := json.Marshal(clearBody)
	clearReq := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags/"+flagID+"/apps/"+appID.String(), bytes.NewReader(clearBytes))
	clearReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, clearReq, claims)

	clearRR := httptest.NewRecorder()
	router.ServeHTTP(clearRR, clearReq)
	if clearRR.Code != http.StatusOK && clearRR.Code != http.StatusCreated {
		t.Fatalf("clear upsert failed: %d: %s", clearRR.Code, clearRR.Body.String())
	}

	var clearResp map[string]any
	json.Unmarshal(clearRR.Body.Bytes(), &clearResp)

	// roleIds should now be empty (either nil or [])
	clearedRoleIDs, _ := clearResp["roleIds"].([]any)
	if len(clearedRoleIDs) != 0 {
		t.Errorf("expected empty roleIds after clear, got %d: %v", len(clearedRoleIDs), clearedRoleIDs)
	}
}

// TestGetFeatureFlagEnvs_IncludesRoleIds tests that listing overrides includes roleIds
func TestGetFeatureFlagEnvs_IncludesRoleIds(t *testing.T) {
	router := setupFeatureFlagsRouter(t)

	email := "ff-role-list-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "FF Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM feature_flag_overrides WHERE feature_flag_id IN (SELECT id FROM feature_flags WHERE project_id = $1)", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM feature_flags WHERE project_id = $1", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM roles WHERE project_id = $1", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	// Create feature flag
	createBody := map[string]any{"key": "list_role_flag", "name": "List Role Flag", "defaultEnabled": false}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create feature flag: %s", createRR.Body.String())
	}

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	featureFlag := created["featureFlag"].(map[string]any)
	flagID := featureFlag["id"].(string)

	// Create a role
	role := createTestRole(t, project.ID)

	// Upsert environment override with roleIds
	upsertBody := map[string]any{
		"enabled": true,
		"roleIds": []string{role.ID.String()},
	}
	upsertBytes, _ := json.Marshal(upsertBody)
	upsertReq := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags/"+flagID+"/apps/"+appID.String(), bytes.NewReader(upsertBytes))
	upsertReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, upsertReq, claims)

	upsertRR := httptest.NewRecorder()
	router.ServeHTTP(upsertRR, upsertReq)
	if upsertRR.Code != http.StatusOK && upsertRR.Code != http.StatusCreated {
		t.Fatalf("upsert failed: %d: %s", upsertRR.Code, upsertRR.Body.String())
	}

	// List all environment overrides for this project
	listReq := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags/apps", nil)
	testEnv.SetSessionCookie(t, listReq, claims)

	listRR := httptest.NewRecorder()
	router.ServeHTTP(listRR, listReq)

	if listRR.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, listRR.Code, listRR.Body.String())
	}

	var listResp map[string]any
	if err := json.Unmarshal(listRR.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to parse list response: %v", err)
	}

	envs, ok := listResp["featureFlagOverrides"].([]any)
	if !ok {
		t.Fatalf("expected featureFlagOverrides array in response")
	}
	if len(envs) == 0 {
		t.Fatal("expected at least one environment override")
	}

	// Find the override for our flag/app pair.
	var envOverride map[string]any
	for _, raw := range envs {
		o := raw.(map[string]any)
		if o["featureFlagId"] == flagID && o["appId"] == appID.String() {
			envOverride = o
			break
		}
	}
	if envOverride == nil {
		// Regression guard: the repo previously scanned the app_id column
		// into o.ID, leaving o.AppID as the zero UUID. That made every
		// override unfindable by (flagId, appId) from the UI's perspective,
		// so toggling a flag would appear to revert after the refetch.
		t.Fatalf("no override found for flagId=%s appId=%s; got %v", flagID, appID.String(), envs)
	}
	if got, _ := envOverride["appId"].(string); got != appID.String() {
		t.Errorf("override appId = %q, want %q", got, appID.String())
	}
	if got, _ := envOverride["featureFlagId"].(string); got != flagID {
		t.Errorf("override featureFlagId = %q, want %q", got, flagID)
	}
	if got, _ := envOverride["enabled"].(bool); !got {
		t.Errorf("override enabled = false, want true")
	}

	roleIDs, ok := envOverride["roleIds"].([]any)
	if !ok {
		t.Fatalf("expected roleIds in override, got %v", envOverride["roleIds"])
	}
	if len(roleIDs) != 1 {
		t.Errorf("expected 1 roleId, got %d", len(roleIDs))
	}
	if len(roleIDs) > 0 && roleIDs[0].(string) != role.ID.String() {
		t.Errorf("expected roleId %s, got %s", role.ID.String(), roleIDs[0].(string))
	}
}

// TestCreateFeatureFlag_NotMember tests creating feature flag when not a member
func TestCreateFeatureFlag_NotMember(t *testing.T) {
	router := setupFeatureFlagsRouter(t)

	ownerEmail := "owner-ff-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, owner, "Test Project", GenerateUniqueSlug("proj"))

	otherEmail := "other-ff-" + GenerateUniqueSlug("test") + "@example.com"
	other := testEnv.CreateTestAccount(t, otherEmail)
	sess, claims := testEnv.CreateTestSession(t, other)

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Projects: []core.Project{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", sess.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", other.ID)
	}()

	body := map[string]any{"key": "test_flag", "name": "Test"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/featureFlags", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
}
