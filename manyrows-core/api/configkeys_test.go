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

// setupConfigKeysRouter creates a router for config key tests
func setupConfigKeysRouter(t *testing.T) *chi.Mux {
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

	adminWorkspaceRouter.Get("/projects/{projectId}/configKeys", requestHandler.HandleGetConfigKeys)
	adminWorkspaceRouter.Post("/projects/{projectId}/configKeys", requestHandler.HandleCreateConfigKey)
	adminWorkspaceRouter.Get("/projects/{projectId}/configKeys/{configKeyId}", requestHandler.HandleGetConfigKey)
	adminWorkspaceRouter.Put("/projects/{projectId}/configKeys/{configKeyId}", requestHandler.HandleUpdateConfigKey)
	adminWorkspaceRouter.Delete("/projects/{projectId}/configKeys/{configKeyId}", requestHandler.HandleDeleteConfigKey)
	adminWorkspaceRouter.Get("/projects/{projectId}/configKeys/{configKeyId}/values", requestHandler.HandleGetConfigValues)
	adminWorkspaceRouter.Put("/projects/{projectId}/configKeys/{configKeyId}/apps/{appId}", requestHandler.HandleUpsertConfigValue)
	adminWorkspaceRouter.Delete("/projects/{projectId}/configKeys/{configKeyId}/apps/{appId}", requestHandler.HandleDeleteConfigValue)

	adminRouter.Mount("/workspace/{workspaceId}", adminWorkspaceRouter)
	r.Mount("/admin", adminRouter)

	return r
}

// TestGetConfigKeys_Success tests listing config keys
func TestGetConfigKeys_Success(t *testing.T) {
	router := setupConfigKeysRouter(t)

	email := "ck-list-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/configKeys", nil)
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

// TestCreateConfigKey_Success tests creating a config key
func TestCreateConfigKey_Success(t *testing.T) {
	router := setupConfigKeysRouter(t)

	email := "ck-create-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM config_keys WHERE project_id = $1", project.ID)
	}()

	body := map[string]any{
		"key":       "API_URL",
		"exposure":  "public",
		"valueType": "string",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/configKeys", bytes.NewReader(bodyBytes))
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

// TestCreateConfigKey_MissingKey tests creating config key without key
func TestCreateConfigKey_MissingKey(t *testing.T) {
	router := setupConfigKeysRouter(t)

	email := "ck-nokey-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"key":      "",
		"exposure": "public",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/configKeys", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// TestGetConfigKey_Success tests getting a single config key
func TestGetConfigKey_Success(t *testing.T) {
	router := setupConfigKeysRouter(t)

	email := "ck-get-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM config_keys WHERE project_id = $1", project.ID)
	}()

	// Create a config key first
	createBody := map[string]any{"key": "GET_KEY", "exposure": "public", "valueType": "string"}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/configKeys", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create config key: %s", createRR.Body.String())
	}

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	configKey := created["configKey"].(map[string]any)
	keyID := configKey["id"].(string)

	// Get it
	getReq := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/configKeys/"+keyID, nil)
	testEnv.SetSessionCookie(t, getReq, claims)

	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, getRR.Code, getRR.Body.String())
	}
}

// TestGetConfigKey_NotFound tests getting non-existent config key
func TestGetConfigKey_NotFound(t *testing.T) {
	router := setupConfigKeysRouter(t)

	email := "ck-notfound-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	fakeID := uuid.Must(uuid.NewV4())
	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/configKeys/"+fakeID.String(), nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

// TestUpdateConfigKey_Success tests updating a config key
func TestUpdateConfigKey_Success(t *testing.T) {
	router := setupConfigKeysRouter(t)

	email := "ck-update-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM config_keys WHERE project_id = $1", project.ID)
	}()

	// Create a config key first
	createBody := map[string]any{"key": "UPDATE_KEY", "exposure": "public", "valueType": "string"}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/configKeys", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	configKey := created["configKey"].(map[string]any)
	keyID := configKey["id"].(string)

	// Update it
	updateBody := map[string]any{"description": "Updated description", "exposure": "private"}
	updateBytes, _ := json.Marshal(updateBody)
	updateReq := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/configKeys/"+keyID, bytes.NewReader(updateBytes))
	updateReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, updateReq, claims)

	updateRR := httptest.NewRecorder()
	router.ServeHTTP(updateRR, updateReq)

	if updateRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, updateRR.Code, updateRR.Body.String())
	}
}

// TestDeleteConfigKey_Success tests deleting a config key
func TestDeleteConfigKey_Success(t *testing.T) {
	router := setupConfigKeysRouter(t)

	email := "ck-delete-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM config_keys WHERE project_id = $1", project.ID)
	}()

	// Create a config key first
	createBody := map[string]any{"key": "DELETE_KEY", "exposure": "public", "valueType": "string"}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/configKeys", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	configKey := created["configKey"].(map[string]any)
	keyID := configKey["id"].(string)

	// Delete it
	deleteReq := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/configKeys/"+keyID, nil)
	testEnv.SetSessionCookie(t, deleteReq, claims)

	deleteRR := httptest.NewRecorder()
	router.ServeHTTP(deleteRR, deleteReq)

	if deleteRR.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, deleteRR.Code)
	}
}

// TestConfigValues_Success tests config value operations
func TestConfigValues_Success(t *testing.T) {
	router := setupConfigKeysRouter(t)

	email := "ck-val-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	// Config values are scoped per-app — the meta query joins apps to
	// validate the (project, app) pair, so the path must point at a
	// real app (uuid.Nil → ErrNotFound).
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "CK Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM config_values WHERE config_key_id IN (SELECT id FROM config_keys WHERE project_id = $1)", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM config_keys WHERE project_id = $1", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	// Create a config key
	createBody := map[string]any{"key": "VAL_KEY", "exposure": "public", "valueType": "string"}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/configKeys", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	configKey := created["configKey"].(map[string]any)
	keyID := configKey["id"].(string)

	// Get values (should be empty)
	getReq := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/configKeys/"+keyID+"/values", nil)
	testEnv.SetSessionCookie(t, getReq, claims)

	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, getRR.Code, getRR.Body.String())
	}

	// Upsert value (route is /configKeys/{id}/apps/{appId}, not /values/{appId}).
	upsertBody := map[string]any{"value": "env-specific-value"}
	upsertBytes, _ := json.Marshal(upsertBody)
	upsertReq := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/configKeys/"+keyID+"/apps/"+appID.String(), bytes.NewReader(upsertBytes))
	upsertReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, upsertReq, claims)

	upsertRR := httptest.NewRecorder()
	router.ServeHTTP(upsertRR, upsertReq)

	if upsertRR.Code != http.StatusOK && upsertRR.Code != http.StatusCreated {
		t.Errorf("expected status 200 or 201, got %d: %s", upsertRR.Code, upsertRR.Body.String())
	}

	// Regression guard: the upsert response must echo back the same
	// appId the caller supplied. The repo previously passed cv.ID into
	// the app_id column (and scanned the result back into out.ID), so
	// the response would carry the wrong UUID despite a 200.
	var upsertResp struct {
		ConfigValue struct {
			AppID       string `json:"appId"`
			ConfigKeyID string `json:"configKeyId"`
		} `json:"configValue"`
	}
	if err := json.Unmarshal(upsertRR.Body.Bytes(), &upsertResp); err != nil {
		t.Fatalf("decode upsert response: %v", err)
	}
	if upsertResp.ConfigValue.AppID != appID.String() {
		t.Errorf("upsert response appId = %q, want %q", upsertResp.ConfigValue.AppID, appID.String())
	}
	if upsertResp.ConfigValue.ConfigKeyID != keyID {
		t.Errorf("upsert response configKeyId = %q, want %q", upsertResp.ConfigValue.ConfigKeyID, keyID)
	}

	// Delete value
	deleteReq := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/configKeys/"+keyID+"/apps/"+appID.String(), nil)
	testEnv.SetSessionCookie(t, deleteReq, claims)

	deleteRR := httptest.NewRecorder()
	router.ServeHTTP(deleteRR, deleteReq)

	if deleteRR.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, deleteRR.Code)
	}
}

// TestCreateConfigKey_Unauthenticated tests creating config key without auth
func TestCreateConfigKey_Unauthenticated(t *testing.T) {
	router := setupConfigKeysRouter(t)

	email := "ck-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{"key": "TEST_KEY", "exposure": "public"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/configKeys", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// TestCreateConfigKey_NotMember tests creating config key when not a member
func TestCreateConfigKey_NotMember(t *testing.T) {
	router := setupConfigKeysRouter(t)

	ownerEmail := "owner-ck-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, owner, "Test Project", GenerateUniqueSlug("proj"))

	otherEmail := "other-ck-" + GenerateUniqueSlug("test") + "@example.com"
	other := testEnv.CreateTestAccount(t, otherEmail)
	sess, claims := testEnv.CreateTestSession(t, other)

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Projects: []core.Project{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", sess.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", other.ID)
	}()

	body := map[string]any{"key": "TEST_KEY", "exposure": "public"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/configKeys", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
}
