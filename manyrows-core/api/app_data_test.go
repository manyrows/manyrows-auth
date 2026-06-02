package api_test

import (
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
)

// setupAppDataRouter creates a router for app data tests
func setupAppDataRouter(t *testing.T) *chi.Mux {
	t.Helper()

	cfg := GetTestConfig() // calls InitPlans internally

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

	adminRouter.Get("/app-data", requestHandler.GetAdminAppData)

	r.Mount("/admin", adminRouter)

	return r
}

// TestGetAdminAppData_Success tests getting admin app data
func TestGetAdminAppData_Success(t *testing.T) {
	router := setupAppDataRouter(t)

	email := "appdata-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, "/admin/app-data", nil)
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

	// Verify account data
	if resp["account"] == nil {
		t.Error("expected account in response")
	}

	// Verify workspaces
	workspaces, ok := resp["workspaces"].([]any)
	if !ok {
		t.Error("expected workspaces array in response")
	} else if len(workspaces) == 0 {
		t.Error("expected at least one workspace")
	}
}

// TestGetAdminAppData_MultipleWorkspaces tests with multiple workspace memberships
func TestGetAdminAppData_MultipleWorkspaces(t *testing.T) {
	router := setupAppDataRouter(t)

	email := "appdata-multi-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws1 := testEnv.CreateTestWorkspace(t, acc, "Test WS 1", GenerateUniqueSlug("ws1"))
	ws2 := testEnv.CreateTestWorkspace(t, acc, "Test WS 2", GenerateUniqueSlug("ws2"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws1, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM workspace_members WHERE workspace_id = $1", ws2.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM workspaces WHERE id = $1", ws2.ID)
	}()

	req := httptest.NewRequest(http.MethodGet, "/admin/app-data", nil)
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

	workspaces, ok := resp["workspaces"].([]any)
	if !ok {
		t.Error("expected workspaces array in response")
	} else if len(workspaces) < 2 {
		t.Errorf("expected at least 2 workspaces, got %d", len(workspaces))
	}
}

// TestGetAdminAppData_WithProject tests that projects are included
func TestGetAdminAppData_WithProject(t *testing.T) {
	router := setupAppDataRouter(t)

	email := "appdata-proj-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, "/admin/app-data", nil)
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

	workspaces, ok := resp["workspaces"].([]any)
	if !ok || len(workspaces) == 0 {
		t.Fatal("expected workspaces array with at least one workspace")
	}

	// Check that projects exist in the workspace
	wsData := workspaces[0].(map[string]any)
	projects, ok := wsData["projects"].([]any)
	if !ok {
		t.Error("expected projects array in workspace")
	} else if len(projects) == 0 {
		t.Error("expected at least one project")
	}
}

// TestGetAdminAppData_Unauthenticated tests app data without auth
func TestGetAdminAppData_Unauthenticated(t *testing.T) {
	router := setupAppDataRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/app-data", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// TestGetAdminAppData_CacheControl tests that Cache-Control header is set
func TestGetAdminAppData_CacheControl(t *testing.T) {
	router := setupAppDataRouter(t)

	email := "appdata-cache-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, "/admin/app-data", nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	cacheControl := rr.Header().Get("Cache-Control")
	if cacheControl != "no-store" {
		t.Errorf("expected Cache-Control 'no-store', got '%s'", cacheControl)
	}
}
