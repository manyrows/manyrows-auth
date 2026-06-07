package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"manyrows-core/core"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// generateTestApplePrivateKey produces a valid PKCS8-encoded EC P-256
// private key (the format Apple's .p8 files use) for use in tests.
func generateTestApplePrivateKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// setupAppsRouter creates a router for app tests
func setupAppsRouter(t *testing.T) *chi.Mux {
	t.Helper()
	svc := NewTestServices(t)
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)

	wsRouter.Get("/projects/{projectId}/apps", svc.Handler.HandleGetApps)
	wsRouter.Post("/projects/{projectId}/apps", svc.Handler.HandleCreateApp)
	wsRouter.Get("/projects/{projectId}/apps/{appId}", svc.Handler.HandleGetApp)
	wsRouter.Put("/projects/{projectId}/apps/{appId}", svc.Handler.HandleUpdateApp)
	wsRouter.Delete("/projects/{projectId}/apps/{appId}", svc.Handler.HandleDeleteApp)
	wsRouter.Put("/projects/{projectId}/apps/{appId}/registration", svc.Handler.HandleUpdateAppRegistration)
	wsRouter.Put("/projects/{projectId}/apps/{appId}/auth-method-config", svc.Handler.HandleUpdateAppAuthMethodConfig)
	wsRouter.Put("/projects/{projectId}/apps/{appId}/google-config", svc.Handler.HandleUpdateAppGoogleConfig)
	wsRouter.Put("/projects/{projectId}/apps/{appId}/apple-config", svc.Handler.HandleUpdateAppAppleConfig)
	wsRouter.Put("/projects/{projectId}/apps/{appId}/microsoft-config", svc.Handler.HandleUpdateAppMicrosoftConfig)
	wsRouter.Put("/projects/{projectId}/apps/{appId}/github-config", svc.Handler.HandleUpdateAppGithubConfig)

	return r
}

// TestGetApps_Success tests listing apps. Creates an app first so the
// Scan path actually runs end-to-end — listing an empty project is a
// no-op for rows.Next() and won't catch a column/destination mismatch
// (this once shipped a four-Scan-destination skew that 500'd the list
// page in prod).
func TestGetApps_Success(t *testing.T) {
	router := setupAppsRouter(t)

	email := "apps-list-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps", nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var resp struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(resp.Apps) != 1 {
		t.Errorf("expected 1 app in list, got %d", len(resp.Apps))
	}
}

// TestCreateApp_Success tests creating an app
func TestCreateApp_Success(t *testing.T) {
	router := setupAppsRouter(t)

	email := "apps-create-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE project_id = $1", project.ID)
	}()

	body := map[string]any{
		"name": "Test App",
		"type": "dev",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps", bytes.NewReader(bodyBytes))
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

// TestCreateApp_InheritsProjectOrganizationsEnabled verifies a new app inherits
// the project's org-mode: the first app in a project defaults to false, and a
// later app inherits true once any sibling in the project is enabled.
func TestCreateApp_InheritsProjectOrganizationsEnabled(t *testing.T) {
	router := setupAppsRouter(t)
	ctx := context.Background()

	acc := testEnv.CreateTestAccount(t, "apps-inh-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Inh Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess})
	defer func() {
		_, _ = testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM apps WHERE project_id = $1", project.ID)
	}()

	createApp := func(t *testing.T, typ string) map[string]any {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"type": typ})
		req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("create %s app: expected 201, got %d (%s)", typ, rr.Code, rr.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("parse create response: %v", err)
		}
		return resp
	}

	// First app in a fresh project: nothing to inherit → false.
	first := createApp(t, "dev")
	if first["organizationsEnabled"] == true {
		t.Fatalf("first app should default organizationsEnabled=false, got %v", first["organizationsEnabled"])
	}

	// Enable orgs on the project (via the existing app).
	firstID := uuid.Must(uuid.FromString(first["id"].(string)))
	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, firstID, true); err != nil {
		t.Fatalf("enable existing app: %v", err)
	}

	// A NEW app in the same project inherits true.
	second := createApp(t, "staging")
	if second["organizationsEnabled"] != true {
		t.Fatalf("second app should inherit organizationsEnabled=true, got %v", second["organizationsEnabled"])
	}
	secondID := uuid.Must(uuid.FromString(second["id"].(string)))
	if got, err := testEnv.Repo.GetAppByID(ctx, secondID); err != nil || !got.OrganizationsEnabled {
		t.Fatalf("second app DB flag expected true, err=%v", err)
	}
}

// TestGetApp_Success tests getting a single app
func TestGetApp_Success(t *testing.T) {
	router := setupAppsRouter(t)

	email := "apps-get-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE project_id = $1", project.ID)
	}()

	// Create an app first
	createBody := map[string]any{"name": "Get App", "type": "dev"}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create app: %s", createRR.Body.String())
	}

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	// Handler returns app directly, not wrapped in {app: ...}
	appID := created["id"].(string)

	// Get it
	getReq := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID, nil)
	testEnv.SetSessionCookie(t, getReq, claims)

	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, getRR.Code, getRR.Body.String())
	}
}

// TestGetApp_NotFound tests getting non-existent app
func TestGetApp_NotFound(t *testing.T) {
	router := setupAppsRouter(t)

	email := "apps-notfound-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	fakeID := uuid.Must(uuid.NewV4())
	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+fakeID.String(), nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

// TestUpdateApp_Success tests updating an app
func TestUpdateApp_Success(t *testing.T) {
	router := setupAppsRouter(t)

	email := "apps-update-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE project_id = $1", project.ID)
	}()

	// Create an app first
	createBody := map[string]any{"name": "Original App", "type": "dev"}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	// Handler returns app directly, not wrapped in {app: ...}
	appID := created["id"].(string)

	// Update it
	updateBody := map[string]any{"description": "Updated App"}
	updateBytes, _ := json.Marshal(updateBody)
	updateReq := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID, bytes.NewReader(updateBytes))
	updateReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, updateReq, claims)

	updateRR := httptest.NewRecorder()
	router.ServeHTTP(updateRR, updateReq)

	if updateRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, updateRR.Code, updateRR.Body.String())
	}
}

// TestDeleteApp_Success tests deleting an app
func TestDeleteApp_Success(t *testing.T) {
	router := setupAppsRouter(t)

	email := "apps-delete-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE project_id = $1", project.ID)
	}()

	// Create an app first
	createBody := map[string]any{"name": "Delete App", "type": "dev"}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	// Handler returns app directly, not wrapped in {app: ...}
	appID := created["id"].(string)

	// Delete it
	deleteReq := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID, nil)
	testEnv.SetSessionCookie(t, deleteReq, claims)

	deleteRR := httptest.NewRecorder()
	router.ServeHTTP(deleteRR, deleteReq)

	if deleteRR.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, deleteRR.Code)
	}

	// Verify it's gone
	getReq := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID, nil)
	testEnv.SetSessionCookie(t, getReq, claims)

	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)

	if getRR.Code != http.StatusNotFound {
		t.Errorf("expected app to be deleted, got status %d", getRR.Code)
	}
}

// TestCreateApp_Unauthenticated tests creating app without auth
func TestCreateApp_Unauthenticated(t *testing.T) {
	router := setupAppsRouter(t)

	email := "apps-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{"name": "Test App", "appId": uuid.Must(uuid.NewV4()).String()}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// TestCreateApp_NotMember tests creating app when not a member
func TestCreateApp_NotMember(t *testing.T) {
	router := setupAppsRouter(t)

	ownerEmail := "owner-apps-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, owner, "Test Project", GenerateUniqueSlug("proj"))

	otherEmail := "other-apps-" + GenerateUniqueSlug("test") + "@example.com"
	other := testEnv.CreateTestAccount(t, otherEmail)
	sess, claims := testEnv.CreateTestSession(t, other)

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Projects: []core.Project{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", sess.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", other.ID)
	}()

	body := map[string]any{"name": "Test App", "appId": uuid.Must(uuid.NewV4()).String()}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
}

// TestUpdateAppRegistration_EnableWithRole tests enabling registration with a default role
func TestUpdateAppRegistration_EnableWithRole(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-reg-enable-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	// Create a role for default registration
	role := createTestRole(t, project.ID)

	// Set workspace to a plan that supports registration
	testEnv.SetWorkspacePlan(t, ws.ID, "pro")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"allowRegistration": true,
		"defaultRoleId":     role.ID.String(),
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/registration", bytes.NewReader(bodyBytes))
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

	if resp["allowRegistration"] != true {
		t.Errorf("expected allowRegistration to be true")
	}
}

// TestUpdateAppRegistration_DisableRegistration tests disabling registration
func TestUpdateAppRegistration_DisableRegistration(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-reg-disable-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"allowRegistration": false,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/registration", bytes.NewReader(bodyBytes))
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

	if resp["allowRegistration"] != false {
		t.Errorf("expected allowRegistration to be false")
	}
}

// TestUpdateApp_WithAppUrl tests updating an app with an appUrl
func TestUpdateApp_WithAppUrl(t *testing.T) {
	router := setupAppsRouter(t)

	email := "apps-appurl-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE project_id = $1", project.ID)
	}()

	// Create an app first
	createBody := map[string]any{"name": "AppUrl App", "type": "dev"}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create app: %s", createRR.Body.String())
	}

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	appID := created["id"].(string)

	// Update it with appUrl
	updateBody := map[string]any{"name": "AppUrl App", "appUrl": "https://myapp.com"}
	updateBytes, _ := json.Marshal(updateBody)
	updateReq := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID, bytes.NewReader(updateBytes))
	updateReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, updateReq, claims)

	updateRR := httptest.NewRecorder()
	router.ServeHTTP(updateRR, updateReq)

	if updateRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, updateRR.Code, updateRR.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(updateRR.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	appUrl, ok := resp["appUrl"]
	if !ok {
		t.Errorf("expected appUrl to be present in response")
		return
	}
	if appUrl != "https://myapp.com" {
		t.Errorf("expected appUrl to be %q, got %v", "https://myapp.com", appUrl)
	}
}

// TestUpdateApp_ClearAppUrl tests clearing the appUrl by setting it to empty string
func TestUpdateApp_ClearAppUrl(t *testing.T) {
	router := setupAppsRouter(t)

	email := "apps-clearurl-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE project_id = $1", project.ID)
	}()

	// Create an app
	createBody := map[string]any{"name": "ClearUrl App", "type": "dev"}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create app: %s", createRR.Body.String())
	}

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	appID := created["id"].(string)

	// First set appUrl
	setBody := map[string]any{"name": "ClearUrl App", "appUrl": "https://myapp.com"}
	setBytes, _ := json.Marshal(setBody)
	setReq := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID, bytes.NewReader(setBytes))
	setReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, setReq, claims)

	setRR := httptest.NewRecorder()
	router.ServeHTTP(setRR, setReq)

	if setRR.Code != http.StatusOK {
		t.Fatalf("failed to set appUrl: %s", setRR.Body.String())
	}

	// Now clear appUrl by setting to empty string
	clearBody := map[string]any{"name": "ClearUrl App", "appUrl": ""}
	clearBytes, _ := json.Marshal(clearBody)
	clearReq := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID, bytes.NewReader(clearBytes))
	clearReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, clearReq, claims)

	clearRR := httptest.NewRecorder()
	router.ServeHTTP(clearRR, clearReq)

	if clearRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, clearRR.Code, clearRR.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(clearRR.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// appUrl should be absent (omitempty) or null when cleared
	appUrl, exists := resp["appUrl"]
	if exists && appUrl != nil {
		t.Errorf("expected appUrl to be absent or null after clearing, got %v", appUrl)
	}
}

// TestUpdateApp_WithSessionTtl tests updating an app with a custom session TTL
func TestUpdateApp_WithSessionTtl(t *testing.T) {
	router := setupAppsRouter(t)

	email := "apps-sessttl-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE project_id = $1", project.ID)
	}()

	// Create an app first
	createBody := map[string]any{"name": "SessionTTL App", "type": "dev"}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create app: %s", createRR.Body.String())
	}

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	appID := created["id"].(string)

	// Update it with sessionTtlMinutes
	updateBody := map[string]any{"name": "SessionTTL App", "sessionTtlMinutes": 30}
	updateBytes, _ := json.Marshal(updateBody)
	updateReq := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID, bytes.NewReader(updateBytes))
	updateReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, updateReq, claims)

	updateRR := httptest.NewRecorder()
	router.ServeHTTP(updateRR, updateReq)

	if updateRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, updateRR.Code, updateRR.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(updateRR.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	ttl, ok := resp["sessionTtlMinutes"]
	if !ok {
		t.Errorf("expected sessionTtlMinutes to be present in response")
		return
	}
	// JSON numbers are float64
	if ttl != float64(30) {
		t.Errorf("expected sessionTtlMinutes to be 30, got %v", ttl)
	}
}

// TestUpdateApp_ClearSessionTtl tests setting then clearing the session TTL
func TestUpdateApp_ClearSessionTtl(t *testing.T) {
	router := setupAppsRouter(t)

	email := "apps-clearttl-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE project_id = $1", project.ID)
	}()

	// Create an app
	createBody := map[string]any{"name": "ClearTTL App", "type": "dev"}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create app: %s", createRR.Body.String())
	}

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	appID := created["id"].(string)

	// First set sessionTtlMinutes
	setBody := map[string]any{"name": "ClearTTL App", "sessionTtlMinutes": 60}
	setBytes, _ := json.Marshal(setBody)
	setReq := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID, bytes.NewReader(setBytes))
	setReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, setReq, claims)

	setRR := httptest.NewRecorder()
	router.ServeHTTP(setRR, setReq)

	if setRR.Code != http.StatusOK {
		t.Fatalf("failed to set sessionTtlMinutes: %s", setRR.Body.String())
	}

	// Now clear sessionTtlMinutes by setting to 0
	clearBody := map[string]any{"name": "ClearTTL App", "sessionTtlMinutes": 0}
	clearBytes, _ := json.Marshal(clearBody)
	clearReq := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID, bytes.NewReader(clearBytes))
	clearReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, clearReq, claims)

	clearRR := httptest.NewRecorder()
	router.ServeHTTP(clearRR, clearReq)

	if clearRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, clearRR.Code, clearRR.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(clearRR.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// sessionTtlMinutes should be absent (omitempty) or null when cleared
	ttl, exists := resp["sessionTtlMinutes"]
	if exists && ttl != nil {
		t.Errorf("expected sessionTtlMinutes to be absent or null after clearing, got %v", ttl)
	}
}

// TestUpdateApp_SessionTtl_OmittedPreservesValue tests that omitting sessionTtlMinutes
// from the request body preserves the existing value (doesn't reset it).
func TestUpdateApp_SessionTtl_OmittedPreservesValue(t *testing.T) {
	router := setupAppsRouter(t)

	email := "apps-ttlkeep-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE project_id = $1", project.ID)
	}()

	createBody := map[string]any{"name": "TTL Keep App", "type": "dev"}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)
	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create app: %s", createRR.Body.String())
	}
	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	appID := created["id"].(string)

	// Set TTL to 120
	setBody := map[string]any{"description": "TTL Keep App", "sessionTtlMinutes": 120}
	setBytes, _ := json.Marshal(setBody)
	setReq := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID, bytes.NewReader(setBytes))
	setReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, setReq, claims)
	setRR := httptest.NewRecorder()
	router.ServeHTTP(setRR, setReq)
	if setRR.Code != http.StatusOK {
		t.Fatalf("failed to set TTL: %s", setRR.Body.String())
	}

	// Update description only — sessionTtlMinutes omitted, should be preserved
	nameBody := map[string]any{"description": "TTL Keep App Renamed"}
	nameBytes, _ := json.Marshal(nameBody)
	nameReq := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID, bytes.NewReader(nameBytes))
	nameReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, nameReq, claims)
	nameRR := httptest.NewRecorder()
	router.ServeHTTP(nameRR, nameReq)

	if nameRR.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d: %s", http.StatusOK, nameRR.Code, nameRR.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(nameRR.Body.Bytes(), &resp)

	ttl, ok := resp["sessionTtlMinutes"]
	if !ok || ttl == nil {
		t.Error("expected sessionTtlMinutes to be preserved when omitted from request")
		return
	}
	if ttl != float64(120) {
		t.Errorf("expected sessionTtlMinutes=120, got %v", ttl)
	}
}

// =====================================================================
// /auth-method-config, /google-config, /apple-config
//
// Each provider's toggle lives with its credentials so the UI cannot
// produce the broken state of "enabled with no credentials".
// =====================================================================

// TestUpdateAppAuthMethodConfig_Toggle confirms the email-form mode
// switches independently on /auth-method-config. We flip from
// "password" → "none" (OAuth-only) which is the analogue of the old
// password-off path.
func TestUpdateAppAuthMethodConfig_Toggle(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-pwdcfg-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	// First enable Google so OAuth-only ("none") has a path. The
	// handler now requires googleOAuthClientSecret on enable, so set
	// both creds in one call.
	enableGoogle, _ := json.Marshal(map[string]any{
		"authMethodGoogle":        true,
		"googleOAuthClientId":     "fallback-client.apps.googleusercontent.com",
		"googleOAuthClientSecret": "fallback-secret",
	})
	req := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/google-config", bytes.NewReader(enableGoogle))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("enable google: %d %s", rr.Code, rr.Body.String())
	}

	// Switch primary auth method to "none" — should succeed because Google is on.
	body, _ := json.Marshal(map[string]any{"primaryAuthMethod": "none"})
	req = httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/auth-method-config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["primaryAuthMethod"] != "none" {
		t.Errorf("primaryAuthMethod: expected \"none\", got %v", resp["primaryAuthMethod"])
	}
}

// TestUpdateAppAuthMethodConfig_NoneRequiresOAuth confirms switching
// to "none" (OAuth-only) when no OAuth provider is configured returns
// 400 — there'd be no usable sign-in path.
//
// The schema defaults Google to ON, so we have to disable Google first
// before the "none" attempt can land in the no-method state we want
// to test.
func TestUpdateAppAuthMethodConfig_NoneRequiresOAuth(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-pwdcfg-otponly-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	// Disable Google first.
	disableGoogle, _ := json.Marshal(map[string]any{"authMethodGoogle": false})
	req := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/google-config", bytes.NewReader(disableGoogle))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("disable google: %d %s", rr.Code, rr.Body.String())
	}

	// Now attempt to switch to "none" — would leave no sign-in path.
	body, _ := json.Marshal(map[string]any{"primaryAuthMethod": "none"})
	req = httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/auth-method-config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestUpdateAppGoogleConfig_EnableSetClear walks the lifecycle:
// enable+set credentials, clear secret, fully disable.
func TestUpdateAppGoogleConfig_EnableSetClear(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-googlecfg-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	url := "/admin/workspace/" + ws.ID.String() + "/projects/" + project.ID.String() + "/apps/" + appID.String() + "/google-config"

	// Enable + set client ID + secret
	body, _ := json.Marshal(map[string]any{
		"authMethodGoogle":        true,
		"googleOAuthClientId":     "test-client.apps.googleusercontent.com",
		"googleOAuthClientSecret": "test-secret-value",
	})
	req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("enable+set: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["authMethodGoogle"] != true {
		t.Errorf("authMethodGoogle: got %v", resp["authMethodGoogle"])
	}
	if resp["googleOAuthClientId"] != "test-client.apps.googleusercontent.com" {
		t.Errorf("googleOAuthClientId: got %v", resp["googleOAuthClientId"])
	}
	if resp["hasGoogleClientSecret"] != true {
		t.Errorf("hasGoogleClientSecret after set: got %v", resp["hasGoogleClientSecret"])
	}

	// Disable Google first — the handler now rejects clearing the
	// secret while Google is still enabled (would leave it in an
	// enabled-without-secret state).
	body, _ = json.Marshal(map[string]any{"authMethodGoogle": false})
	req = httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["authMethodGoogle"] != false {
		t.Errorf("authMethodGoogle after disable: got %v", resp["authMethodGoogle"])
	}

	// Now clear secret explicitly.
	body, _ = json.Marshal(map[string]any{"googleOAuthClientSecret": ""})
	req = httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("clear secret: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["hasGoogleClientSecret"] != false {
		t.Errorf("hasGoogleClientSecret after clear: got %v", resp["hasGoogleClientSecret"])
	}
}

// TestUpdateAppGoogleConfig_RejectsEnableWithoutClientID guards the
// invariant that the broken split-UI used to allow.
func TestUpdateAppGoogleConfig_RejectsEnableWithoutClientID(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-googlecfg-noclient-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body, _ := json.Marshal(map[string]any{"authMethodGoogle": true})
	req := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/google-config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestUpdateAppAppleConfig_EnableSetDisable walks the Apple lifecycle.
func TestUpdateAppAppleConfig_EnableSetDisable(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-applecfg-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	url := "/admin/workspace/" + ws.ID.String() + "/projects/" + project.ID.String() + "/apps/" + appID.String() + "/apple-config"

	pem := generateTestApplePrivateKey(t)
	body, _ := json.Marshal(map[string]any{
		"authMethodApple": true,
		"appleServicesId": "com.example.signin",
		"appleTeamId":     "ABCDE12345",
		"appleKeyId":      "KEY1234567",
		"applePrivateKey": pem,
	})
	req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("enable+set: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["authMethodApple"] != true {
		t.Errorf("authMethodApple: got %v", resp["authMethodApple"])
	}
	if resp["hasApplePrivateKey"] != true {
		t.Errorf("hasApplePrivateKey: got %v", resp["hasApplePrivateKey"])
	}

	// Disable (password still on as fallback).
	body, _ = json.Marshal(map[string]any{"authMethodApple": false})
	req = httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["authMethodApple"] != false {
		t.Errorf("authMethodApple after disable: got %v", resp["authMethodApple"])
	}
}

// TestUpdateAppAppleConfig_RejectsEnableWithoutFullCreds confirms the
// toggle requires every Apple field — Services ID, Team ID, Key ID,
// AND a stored .p8.
func TestUpdateAppAppleConfig_RejectsEnableWithoutFullCreds(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-applecfg-incomplete-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	// Try enabling with only services ID — missing the other three.
	body, _ := json.Marshal(map[string]any{
		"authMethodApple": true,
		"appleServicesId": "com.example.signin",
	})
	req := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/apple-config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestUpdateAppMicrosoftConfig_EnableSetDisable walks the Microsoft
// lifecycle: enable + set creds + tenant=organizations, then disable.
func TestUpdateAppMicrosoftConfig_EnableSetDisable(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-mscfg-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	url := "/admin/workspace/" + ws.ID.String() + "/projects/" + project.ID.String() + "/apps/" + appID.String() + "/microsoft-config"

	body, _ := json.Marshal(map[string]any{
		"authMethodMicrosoft":   true,
		"microsoftClientId":     "00000000-0000-0000-0000-deadbeefcafe",
		"microsoftClientSecret": "ms-secret-value",
		"microsoftTenant":       "organizations",
	})
	req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("enable+set: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["authMethodMicrosoft"] != true {
		t.Errorf("authMethodMicrosoft: got %v", resp["authMethodMicrosoft"])
	}
	if resp["microsoftTenant"] != "organizations" {
		t.Errorf("microsoftTenant: got %v", resp["microsoftTenant"])
	}
	if resp["hasMicrosoftClientSecret"] != true {
		t.Errorf("hasMicrosoftClientSecret: got %v", resp["hasMicrosoftClientSecret"])
	}

	// Disable (password still on as fallback).
	body, _ = json.Marshal(map[string]any{"authMethodMicrosoft": false})
	req = httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["authMethodMicrosoft"] != false {
		t.Errorf("authMethodMicrosoft after disable: got %v", resp["authMethodMicrosoft"])
	}
}

// TestUpdateAppMicrosoftConfig_RejectsEnableWithoutCreds verifies the
// invariant: can't enable Microsoft without both client ID and secret.
func TestUpdateAppMicrosoftConfig_RejectsEnableWithoutCreds(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-mscfg-incomplete-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	// Toggle on with only client ID (no secret) — should reject.
	body, _ := json.Marshal(map[string]any{
		"authMethodMicrosoft": true,
		"microsoftClientId":   "00000000-0000-0000-0000-deadbeefcafe",
	})
	req := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/microsoft-config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestUpdateAppMicrosoftConfig_RejectsBadTenant guards the tenant
// validation — must be one of the four allowed shapes.
func TestUpdateAppMicrosoftConfig_RejectsBadTenant(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-mscfg-bad-tenant-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body, _ := json.Marshal(map[string]any{
		"microsoftClientId":     "00000000-0000-0000-0000-deadbeefcafe",
		"microsoftClientSecret": "ms-secret-value",
		"microsoftTenant":       "not-a-real-tenant-value",
	})
	req := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/microsoft-config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestUpdateAppMicrosoftConfig_ClearSecret sets a secret then clears
// it with explicit "", verifying hasMicrosoftClientSecret toggles.
func TestUpdateAppMicrosoftConfig_ClearSecret(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-mscfg-clear-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	url := "/admin/workspace/" + ws.ID.String() + "/projects/" + project.ID.String() + "/apps/" + appID.String() + "/microsoft-config"

	body, _ := json.Marshal(map[string]any{
		"microsoftClientId":     "00000000-0000-0000-0000-deadbeefcafe",
		"microsoftClientSecret": "ms-secret-value",
	})
	req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("set: %d %s", rr.Code, rr.Body.String())
	}

	body, _ = json.Marshal(map[string]any{"microsoftClientSecret": ""})
	req = httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["hasMicrosoftClientSecret"] != false {
		t.Errorf("hasMicrosoftClientSecret after clear: got %v", resp["hasMicrosoftClientSecret"])
	}
}

// TestUpdateAppMicrosoftConfig_RejectsLastMethodOff confirms turning
// off Microsoft when it's the last enabled sign-in method (primary
// mode is "none") returns 400 — the cross-method check correctly
// considers Microsoft.
func TestUpdateAppMicrosoftConfig_RejectsLastMethodOff(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-mscfg-otponly-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	// Default app: primaryAuthMethod=password, google=true, apple=false, microsoft=false.
	// Switch primary mode to "none" — Google is on, so it satisfies the "needs OAuth" rule.
	body, _ := json.Marshal(map[string]any{"primaryAuthMethod": "none"})
	req := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/auth-method-config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("switch to none: %d %s", rr.Code, rr.Body.String())
	}

	// Enable Microsoft so we can turn off Google.
	body, _ = json.Marshal(map[string]any{
		"authMethodMicrosoft":   true,
		"microsoftClientId":     "00000000-0000-0000-0000-deadbeefcafe",
		"microsoftClientSecret": "ms-secret",
	})
	req = httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/microsoft-config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("enable microsoft: %d %s", rr.Code, rr.Body.String())
	}

	// Disable Google. Microsoft is the only one left, but that's fine.
	body, _ = json.Marshal(map[string]any{"authMethodGoogle": false})
	req = httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/google-config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("disable google: %d %s", rr.Code, rr.Body.String())
	}

	// Now Microsoft is the *only* method on. Disabling it should 400
	// because primary mode is "none" with no OAuth provider left —
	// the app would have no working sign-in path. This proves the
	// cross-method helper actually counts Microsoft.
	body, _ = json.Marshal(map[string]any{"authMethodMicrosoft": false})
	req = httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/microsoft-config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 (Microsoft is last method), got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestUpdateAppMicrosoftConfig_AcceptsSpecificTenantUUID confirms
// single-tenant mode works with an arbitrary tenant UUID.
func TestUpdateAppMicrosoftConfig_AcceptsSpecificTenantUUID(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-mscfg-uuid-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	const tenantUUID = "11111111-2222-3333-4444-555555555555"
	body, _ := json.Marshal(map[string]any{
		"microsoftClientId":     "00000000-0000-0000-0000-deadbeefcafe",
		"microsoftClientSecret": "ms-secret-value",
		"microsoftTenant":       tenantUUID,
	})
	req := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/microsoft-config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["microsoftTenant"] != tenantUUID {
		t.Errorf("microsoftTenant: got %v, want %s", resp["microsoftTenant"], tenantUUID)
	}
}

// TestUpdateAppGithubConfig_EnableSetDisable walks the GitHub
// lifecycle: enable + set creds, then disable.
func TestUpdateAppGithubConfig_EnableSetDisable(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-ghcfg-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	url := "/admin/workspace/" + ws.ID.String() + "/projects/" + project.ID.String() + "/apps/" + appID.String() + "/github-config"

	body, _ := json.Marshal(map[string]any{
		"authMethodGithub":   true,
		"githubClientId":     "Iv1.test123",
		"githubClientSecret": "gh-secret-value",
	})
	req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("enable+set: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["authMethodGithub"] != true {
		t.Errorf("authMethodGithub: got %v", resp["authMethodGithub"])
	}
	if resp["githubClientId"] != "Iv1.test123" {
		t.Errorf("githubClientId: got %v", resp["githubClientId"])
	}
	if resp["hasGithubClientSecret"] != true {
		t.Errorf("hasGithubClientSecret: got %v", resp["hasGithubClientSecret"])
	}

	// Disable (password still on as fallback).
	body, _ = json.Marshal(map[string]any{"authMethodGithub": false})
	req = httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["authMethodGithub"] != false {
		t.Errorf("authMethodGithub after disable: got %v", resp["authMethodGithub"])
	}
}

// TestUpdateAppGithubConfig_RejectsEnableWithoutCreds verifies the
// invariant: can't enable GitHub without both client ID and secret.
func TestUpdateAppGithubConfig_RejectsEnableWithoutCreds(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-ghcfg-incomplete-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body, _ := json.Marshal(map[string]any{
		"authMethodGithub": true,
		"githubClientId":   "Iv1.test123",
		// secret missing
	})
	req := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/github-config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestUpdateAppGithubConfig_RejectsLastMethodOff confirms turning off
// GitHub when it's the last enabled sign-in method (primary mode is
// "none") returns 400 — the 5-arg requireAtLeastOneSignInMethod helper
// correctly counts GitHub.
func TestUpdateAppGithubConfig_RejectsLastMethodOff(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-ghcfg-otponly-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	// Default: primaryAuthMethod=password, google=true (schema), apple/microsoft/github=false.
	// Switch primary mode to "none" — Google is on, so OAuth-only is valid.
	body, _ := json.Marshal(map[string]any{"primaryAuthMethod": "none"})
	req := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/auth-method-config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("switch to none: %d %s", rr.Code, rr.Body.String())
	}

	// Enable GitHub so we can disable Google.
	body, _ = json.Marshal(map[string]any{
		"authMethodGithub":   true,
		"githubClientId":     "Iv1.test123",
		"githubClientSecret": "gh-secret",
	})
	req = httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/github-config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("enable github: %d %s", rr.Code, rr.Body.String())
	}

	// Disable Google. GitHub is the only one left, but that's fine.
	body, _ = json.Marshal(map[string]any{"authMethodGoogle": false})
	req = httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/google-config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("disable google: %d %s", rr.Code, rr.Body.String())
	}

	// Now GitHub is the *only* method on. Disabling it should 400
	// because primary mode is "none" with no OAuth provider left —
	// the app would have no working sign-in path. This proves the
	// helper actually counts GitHub as a sign-in method (the 5-arg
	// ripple invariant).
	body, _ = json.Marshal(map[string]any{"authMethodGithub": false})
	req = httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/github-config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 (GitHub is last method), got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestUpdateAppGithubConfig_ClearSecret sets a secret then clears it.
func TestUpdateAppGithubConfig_ClearSecret(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-ghcfg-clear-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	url := "/admin/workspace/" + ws.ID.String() + "/projects/" + project.ID.String() + "/apps/" + appID.String() + "/github-config"

	body, _ := json.Marshal(map[string]any{
		"githubClientId":     "Iv1.test123",
		"githubClientSecret": "gh-secret-value",
	})
	req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("set: %d %s", rr.Code, rr.Body.String())
	}

	body, _ = json.Marshal(map[string]any{"githubClientSecret": ""})
	req = httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["hasGithubClientSecret"] != false {
		t.Errorf("hasGithubClientSecret after clear: got %v", resp["hasGithubClientSecret"])
	}
}

// TestUpdateAppAppleConfig_RejectsInvalidKey ensures a payload that
// isn't a parseable PKCS8 EC key is rejected up-front.
func TestUpdateAppAppleConfig_RejectsInvalidKey(t *testing.T) {
	router := setupAppsRouter(t)

	email := "app-applecfg-bad-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body, _ := json.Marshal(map[string]any{"applePrivateKey": "this is not a real PEM block"})

	req := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/apple-config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}
