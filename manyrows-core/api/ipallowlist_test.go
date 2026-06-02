package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// setupIPAllowlistRouter creates a router for IP allowlist tests (app-scoped)
func setupIPAllowlistRouter(t *testing.T) *chi.Mux {
	t.Helper()
	svc := NewTestServices(t)
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)

	wsRouter.Get("/projects/{projectId}/apps/{appId}/ipAllowlist", svc.Handler.HandleGetIPAllowlist)
	wsRouter.Post("/projects/{projectId}/apps/{appId}/ipAllowlist", svc.Handler.HandleCreateIPAllowlistEntry)
	wsRouter.Put("/projects/{projectId}/apps/{appId}/ipAllowlist/{id}", svc.Handler.HandleUpdateIPAllowlistEntry)
	wsRouter.Delete("/projects/{projectId}/apps/{appId}/ipAllowlist/{id}", svc.Handler.HandleDeleteIPAllowlistEntry)

	return r
}

func ipBasePath(wsID, projectID, appID string) string {
	return "/admin/workspace/" + wsID + "/projects/" + projectID + "/apps/" + appID + "/ipAllowlist"
}

// TestGetIPAllowlist_Success tests listing IP allowlist entries
func TestGetIPAllowlist_Success(t *testing.T) {
	router := setupIPAllowlistRouter(t)

	email := "ip-list-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, ipBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String()), nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var entries []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &entries); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
}

// TestCreateIPAllowlistEntry_SingleIP tests creating an entry with a single IP
func TestCreateIPAllowlistEntry_SingleIP(t *testing.T) {
	router := setupIPAllowlistRouter(t)

	email := "ip-create-single-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM app_ip_allowlist WHERE app_id = $1", app.ID)
	}()

	body := map[string]any{
		"ipRange":     "192.168.1.1",
		"description": "Test IP",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, ipBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String()), bytes.NewReader(bodyBytes))
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

	if resp["ipRange"] != "192.168.1.1" {
		t.Errorf("expected ipRange '192.168.1.1', got %v", resp["ipRange"])
	}
	if resp["description"] != "Test IP" {
		t.Errorf("expected description 'Test IP', got %v", resp["description"])
	}
}

// TestCreateIPAllowlistEntry_CIDR tests creating an entry with a CIDR range
func TestCreateIPAllowlistEntry_CIDR(t *testing.T) {
	router := setupIPAllowlistRouter(t)

	email := "ip-create-cidr-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM app_ip_allowlist WHERE app_id = $1", app.ID)
	}()

	body := map[string]any{
		"ipRange":     "10.0.0.0/8",
		"description": "Private network",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, ipBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String()), bytes.NewReader(bodyBytes))
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

	if resp["ipRange"] != "10.0.0.0/8" {
		t.Errorf("expected ipRange '10.0.0.0/8', got %v", resp["ipRange"])
	}
}

// TestCreateIPAllowlistEntry_InvalidIP tests creating with invalid IP
func TestCreateIPAllowlistEntry_InvalidIP(t *testing.T) {
	router := setupIPAllowlistRouter(t)

	email := "ip-invalid-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"ipRange":     "not-an-ip",
		"description": "Invalid",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, ipBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String()), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// TestCreateIPAllowlistEntry_MissingIPRange tests creating without ipRange
func TestCreateIPAllowlistEntry_MissingIPRange(t *testing.T) {
	router := setupIPAllowlistRouter(t)

	email := "ip-missing-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"ipRange":     "",
		"description": "No IP",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, ipBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String()), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// TestCreateIPAllowlistEntry_IPv6 tests creating with IPv6 address
func TestCreateIPAllowlistEntry_IPv6(t *testing.T) {
	router := setupIPAllowlistRouter(t)

	email := "ip-ipv6-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM app_ip_allowlist WHERE app_id = $1", app.ID)
	}()

	body := map[string]any{
		"ipRange":     "2001:db8::1",
		"description": "IPv6 address",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, ipBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String()), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}
}

// TestDeleteIPAllowlistEntry_Success tests deleting an IP allowlist entry
func TestDeleteIPAllowlistEntry_Success(t *testing.T) {
	router := setupIPAllowlistRouter(t)

	email := "ip-delete-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM app_ip_allowlist WHERE app_id = $1", app.ID)
	}()

	base := ipBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String())

	// Create an entry first
	body := map[string]any{"ipRange": "192.168.1.100", "description": "Delete me"}
	bodyBytes, _ := json.Marshal(body)
	createReq := httptest.NewRequest(http.MethodPost, base, bytes.NewReader(bodyBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create IP allowlist entry: %s", createRR.Body.String())
	}

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	entryID := created["id"].(string)

	// Delete it
	deleteReq := httptest.NewRequest(http.MethodDelete, base+"/"+entryID, nil)
	testEnv.SetSessionCookie(t, deleteReq, claims)

	deleteRR := httptest.NewRecorder()
	router.ServeHTTP(deleteRR, deleteReq)

	if deleteRR.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, deleteRR.Code)
	}
}

// TestCreateIPAllowlistEntry_Unauthenticated tests creating without auth
func TestCreateIPAllowlistEntry_Unauthenticated(t *testing.T) {
	router := setupIPAllowlistRouter(t)

	email := "ip-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{"ipRange": "192.168.1.1"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, ipBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String()), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// TestCreateIPAllowlistEntry_NotMember tests creating when not a member
func TestCreateIPAllowlistEntry_NotMember(t *testing.T) {
	router := setupIPAllowlistRouter(t)

	ownerEmail := "owner-ip-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, owner)

	otherEmail := "other-ip-" + GenerateUniqueSlug("test") + "@example.com"
	other := testEnv.CreateTestAccount(t, otherEmail)
	sess, claims := testEnv.CreateTestSession(t, other)

	fixtures := &TestFixtures{Account: owner, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", sess.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", other.ID)
	}()

	body := map[string]any{"ipRange": "192.168.1.1"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, ipBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String()), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
}

// TestUpdateIPAllowlistEntry_Success tests updating an IP allowlist entry
func TestUpdateIPAllowlistEntry_Success(t *testing.T) {
	router := setupIPAllowlistRouter(t)

	email := "ip-update-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM app_ip_allowlist WHERE app_id = $1", app.ID)
	}()

	base := ipBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String())

	// Create an entry first
	createBody := map[string]any{"ipRange": "192.168.1.50", "description": "Original"}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, base, bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create entry: %s", createRR.Body.String())
	}

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	entryID := created["id"].(string)

	// Update it
	updateBody := map[string]any{"ipRange": "10.0.0.1", "description": "Updated"}
	updateBytes, _ := json.Marshal(updateBody)
	updateReq := httptest.NewRequest(http.MethodPut, base+"/"+entryID, bytes.NewReader(updateBytes))
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

	if resp["ipRange"] != "10.0.0.1" {
		t.Errorf("expected ipRange '10.0.0.1', got %v", resp["ipRange"])
	}
	if resp["description"] != "Updated" {
		t.Errorf("expected description 'Updated', got %v", resp["description"])
	}
}

// TestUpdateIPAllowlistEntry_NotFound tests updating a non-existent entry
func TestUpdateIPAllowlistEntry_NotFound(t *testing.T) {
	router := setupIPAllowlistRouter(t)

	email := "ip-upd-nf-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	fakeID := uuid.Must(uuid.NewV4())
	body := map[string]any{"ipRange": "10.0.0.1", "description": "Nope"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, ipBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String())+"/"+fakeID.String(), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d: %s", http.StatusNotFound, rr.Code, rr.Body.String())
	}
}

// TestUpdateIPAllowlistEntry_InvalidIP tests updating with an invalid IP
func TestUpdateIPAllowlistEntry_InvalidIP(t *testing.T) {
	router := setupIPAllowlistRouter(t)

	email := "ip-upd-inv-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM app_ip_allowlist WHERE app_id = $1", app.ID)
	}()

	base := ipBasePath(ws.ID.String(), app.ProjectID.String(), app.ID.String())

	// Create an entry first
	createBody := map[string]any{"ipRange": "192.168.1.99", "description": "Test"}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, base, bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create entry: %s", createRR.Body.String())
	}

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	entryID := created["id"].(string)

	// Try to update with invalid IP
	updateBody := map[string]any{"ipRange": "not-valid-ip"}
	updateBytes, _ := json.Marshal(updateBody)
	updateReq := httptest.NewRequest(http.MethodPut, base+"/"+entryID, bytes.NewReader(updateBytes))
	updateReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, updateReq, claims)

	updateRR := httptest.NewRecorder()
	router.ServeHTTP(updateRR, updateReq)

	if updateRR.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, updateRR.Code, updateRR.Body.String())
	}
}
