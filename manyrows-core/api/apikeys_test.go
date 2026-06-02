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

// setupAPIKeysRouter creates a router for API key tests
func setupAPIKeysRouter(t *testing.T) *chi.Mux {
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
			ctx = core.WithWorkspaceRole(ctx, "owner")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	adminWorkspaceRouter.Get("/apiKeys", requestHandler.HandleGetApiKeys)
	adminWorkspaceRouter.Post("/apiKeys", requestHandler.HandleCreateApiKey)
	adminWorkspaceRouter.Get("/apiKeys/{id}", requestHandler.HandleGetApiKey)
	adminWorkspaceRouter.Delete("/apiKeys/{id}", requestHandler.HandleDeleteApiKey)

	adminRouter.Mount("/workspace/{workspaceId}", adminWorkspaceRouter)
	r.Mount("/admin", adminRouter)

	return r
}

// TestGetApiKeys_Success tests listing API keys
func TestGetApiKeys_Success(t *testing.T) {
	router := setupAPIKeysRouter(t)

	email := "apikeys-list-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/apiKeys", nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var keys []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &keys); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Initially should be empty
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

// TestCreateApiKey_Success tests creating an API key
func TestCreateApiKey_Success(t *testing.T) {
	router := setupAPIKeysRouter(t)

	email := "apikeys-create-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		// Cleanup API keys
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM api_keys WHERE workspace_id = $1", ws.ID)
	}()

	body := map[string]any{
		"name": "Test API Key",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/apiKeys", bytes.NewReader(bodyBytes))
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

	if resp["name"] != "Test API Key" {
		t.Errorf("expected name 'Test API Key', got %v", resp["name"])
	}

	// Should have a key in the response
	key, ok := resp["key"].(string)
	if !ok || key == "" {
		t.Error("expected key in response")
	}

	// Key should start with "mr_"
	if len(key) < 3 || key[:3] != "mr_" {
		t.Errorf("expected key to start with 'mr_', got %s", key)
	}
}

// TestCreateApiKey_MissingName tests creating API key without name
func TestCreateApiKey_MissingName(t *testing.T) {
	router := setupAPIKeysRouter(t)

	email := "apikeys-noname-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"name": "",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/apiKeys", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// TestGetApiKey_Success tests getting a single API key
func TestGetApiKey_Success(t *testing.T) {
	router := setupAPIKeysRouter(t)

	email := "apikeys-get-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM api_keys WHERE workspace_id = $1", ws.ID)
	}()

	// First create an API key
	body := map[string]any{"name": "Test Key"}
	bodyBytes, _ := json.Marshal(body)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/apiKeys", bytes.NewReader(bodyBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create API key: %s", createRR.Body.String())
	}

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	keyID := created["id"].(string)

	// Now get it
	getReq := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/apiKeys/"+keyID, nil)
	testEnv.SetSessionCookie(t, getReq, claims)

	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, getRR.Code, getRR.Body.String())
	}
}

// TestGetApiKey_NotFound tests getting non-existent API key
func TestGetApiKey_NotFound(t *testing.T) {
	router := setupAPIKeysRouter(t)

	email := "apikeys-notfound-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	fakeID := uuid.Must(uuid.NewV4())
	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/apiKeys/"+fakeID.String(), nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

// TestDeleteApiKey_Success tests deleting an API key
func TestDeleteApiKey_Success(t *testing.T) {
	router := setupAPIKeysRouter(t)

	email := "apikeys-delete-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM api_keys WHERE workspace_id = $1", ws.ID)
	}()

	// Create an API key
	body := map[string]any{"name": "Delete Me"}
	bodyBytes, _ := json.Marshal(body)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/apiKeys", bytes.NewReader(bodyBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	keyID := created["id"].(string)

	// Delete it
	deleteReq := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/apiKeys/"+keyID, nil)
	testEnv.SetSessionCookie(t, deleteReq, claims)

	deleteRR := httptest.NewRecorder()
	router.ServeHTTP(deleteRR, deleteReq)

	if deleteRR.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, deleteRR.Code)
	}

	// Verify it's gone
	getReq := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/apiKeys/"+keyID, nil)
	testEnv.SetSessionCookie(t, getReq, claims)

	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)

	if getRR.Code != http.StatusNotFound {
		t.Errorf("expected key to be deleted, got status %d", getRR.Code)
	}
}

// TestCreateApiKey_Unauthenticated tests creating API key without auth
func TestCreateApiKey_Unauthenticated(t *testing.T) {
	router := setupAPIKeysRouter(t)

	email := "apikeys-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{"name": "Test Key"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/apiKeys", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// TestCreateApiKey_NotMember tests creating API key when not workspace member
func TestCreateApiKey_NotMember(t *testing.T) {
	router := setupAPIKeysRouter(t)

	// Create owner and workspace
	ownerEmail := "owner-apikey-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))

	// Create other user
	otherEmail := "other-apikey-" + GenerateUniqueSlug("test") + "@example.com"
	other := testEnv.CreateTestAccount(t, otherEmail)
	sess, claims := testEnv.CreateTestSession(t, other)

	fixtures := &TestFixtures{Account: owner, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", sess.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", other.ID)
	}()

	body := map[string]any{"name": "Test Key"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/apiKeys", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
}
