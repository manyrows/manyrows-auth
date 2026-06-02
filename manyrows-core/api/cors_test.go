package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// setupCORSRouter creates a router for CORS origin tests (app-scoped)
func setupCORSRouter(t *testing.T) *chi.Mux {
	t.Helper()
	svc := NewTestServices(t)
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)

	wsRouter.Get("/projects/{projectId}/apps/{appId}/corsOrigins", svc.Handler.HandleGetCorsOrigins)
	wsRouter.Post("/projects/{projectId}/apps/{appId}/corsOrigins", svc.Handler.HandleCreateCorsOrigin)
	wsRouter.Delete("/projects/{projectId}/apps/{appId}/corsOrigins/{id}", svc.Handler.HandleDeleteCorsOrigin)

	return r
}

func corsBasePath(wsID, projectID, appID string) string {
	return "/admin/workspace/" + wsID + "/projects/" + projectID + "/apps/" + appID + "/corsOrigins"
}

// TestGetCorsOrigins_Success tests listing CORS origins
func TestGetCorsOrigins_Success(t *testing.T) {
	router := setupCORSRouter(t)

	email := "cors-list-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, corsBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String()), nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var origins []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &origins); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
}

// TestCreateCorsOrigin_Success tests creating a CORS origin
func TestCreateCorsOrigin_Success(t *testing.T) {
	router := setupCORSRouter(t)

	email := "cors-create-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM app_cors_origins WHERE app_id = $1", app.ID)
	}()

	body := map[string]any{
		"origin": "https://example.com",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, corsBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String()), bytes.NewReader(bodyBytes))
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

	if resp["origin"] != "https://example.com" {
		t.Errorf("expected origin 'https://example.com', got %v", resp["origin"])
	}
}

// TestCreateCorsOrigin_InvalidURL tests creating CORS origin with invalid URL
func TestCreateCorsOrigin_InvalidURL(t *testing.T) {
	router := setupCORSRouter(t)

	email := "cors-invalid-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"origin": "not-a-url",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, corsBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String()), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// TestCreateCorsOrigin_MissingOrigin tests creating CORS origin without origin
func TestCreateCorsOrigin_MissingOrigin(t *testing.T) {
	router := setupCORSRouter(t)

	email := "cors-missing-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"origin": "",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, corsBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String()), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// TestCreateCorsOrigin_WithPath tests creating CORS origin with path (should fail)
func TestCreateCorsOrigin_WithPath(t *testing.T) {
	router := setupCORSRouter(t)

	email := "cors-path-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"origin": "https://example.com/path",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, corsBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String()), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// TestDeleteCorsOrigin_Success tests deleting a CORS origin
func TestDeleteCorsOrigin_Success(t *testing.T) {
	router := setupCORSRouter(t)

	email := "cors-delete-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM app_cors_origins WHERE app_id = $1", app.ID)
	}()

	base := corsBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String())

	// Create a CORS origin first
	body := map[string]any{"origin": "https://delete-me.com"}
	bodyBytes, _ := json.Marshal(body)
	createReq := httptest.NewRequest(http.MethodPost, base, bytes.NewReader(bodyBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create CORS origin: %s", createRR.Body.String())
	}

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	originID := created["id"].(string)

	// Delete it
	deleteReq := httptest.NewRequest(http.MethodDelete, base+"/"+originID, nil)
	testEnv.SetSessionCookie(t, deleteReq, claims)

	deleteRR := httptest.NewRecorder()
	router.ServeHTTP(deleteRR, deleteReq)

	if deleteRR.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, deleteRR.Code)
	}
}

// TestCreateCorsOrigin_Unauthenticated tests creating CORS origin without auth
func TestCreateCorsOrigin_Unauthenticated(t *testing.T) {
	router := setupCORSRouter(t)

	email := "cors-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{"origin": "https://example.com"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, corsBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String()), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// TestCreateCorsOrigin_NotMember tests creating CORS origin when not a member
func TestCreateCorsOrigin_NotMember(t *testing.T) {
	router := setupCORSRouter(t)

	ownerEmail := "owner-cors-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, owner)

	otherEmail := "other-cors-" + GenerateUniqueSlug("test") + "@example.com"
	other := testEnv.CreateTestAccount(t, otherEmail)
	sess, claims := testEnv.CreateTestSession(t, other)

	fixtures := &TestFixtures{Account: owner, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", sess.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", other.ID)
	}()

	body := map[string]any{"origin": "https://example.com"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, corsBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String()), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
}
