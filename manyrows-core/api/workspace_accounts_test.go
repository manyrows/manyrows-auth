package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"manyrows-core/core"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// setupWorkspaceAccountsRouter creates a router for workspace accounts tests
func setupWorkspaceAccountsRouter(t *testing.T) *chi.Mux {
	t.Helper()
	svc := NewTestServices(t)
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)

	wsRouter.Get("/accounts", svc.Handler.HandleGetWorkspaceAccounts)
	wsRouter.Post("/accounts", svc.Handler.HandleCreateWorkspaceAccount)
	wsRouter.Post("/accounts/bulk-import", svc.Handler.HandleBulkImportWorkspaceAccounts)
	wsRouter.Get("/accounts/{accountId}", svc.Handler.HandleGetWorkspaceAccount)
	wsRouter.Patch("/accounts/{accountId}", svc.Handler.HandleUpdateWorkspaceAccount)
	wsRouter.Delete("/accounts/{accountId}", svc.Handler.HandleDeleteWorkspaceAccount)

	return r
}

// TestGetWorkspaceAccounts_Success tests listing workspace accounts
func TestGetWorkspaceAccounts_Success(t *testing.T) {
	router := setupWorkspaceAccountsRouter(t)

	email := "ws-accounts-list-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/accounts", nil)
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

	if resp["accounts"] == nil {
		t.Error("expected accounts in response")
	}
	if resp["total"] == nil {
		t.Error("expected total in response")
	}
}

// TestGetWorkspaceAccounts_Unauthenticated tests without auth
func TestGetWorkspaceAccounts_Unauthenticated(t *testing.T) {
	router := setupWorkspaceAccountsRouter(t)

	email := "ws-accounts-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/accounts", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// TestCreateWorkspaceAccount_Success tests creating a workspace account
func TestCreateWorkspaceAccount_Success(t *testing.T) {
	router := setupWorkspaceAccountsRouter(t)

	email := "ws-accounts-create-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	// Handler requires appId + (roleIds OR app.DefaultRoleID); create both.
	app := testEnv.CreateTestApp(t, ws, acc)
	role := createTestRole(t, app.ProjectID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	newEmail := "new-user-" + GenerateUniqueSlug("test") + "@example.com"
	body := map[string]any{
		"email":   newEmail,
		"appId":   app.ID.String(),
		"roleIds": []string{role.ID.String()},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/accounts", bytes.NewReader(bodyBytes))
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

	if resp["id"] == nil {
		t.Error("expected id in response")
	}
	if resp["email"] != newEmail {
		t.Errorf("expected email %q, got %v", newEmail, resp["email"])
	}

	// Cleanup the created user
	if waID, ok := resp["id"].(string); ok {
		waUUID, _ := uuid.FromString(waID)
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM users WHERE id = $1", waUUID)
	}
}

// TestCreateWorkspaceAccount_InvalidEmail tests creating with invalid email
func TestCreateWorkspaceAccount_InvalidEmail(t *testing.T) {
	router := setupWorkspaceAccountsRouter(t)

	email := "ws-accounts-inv-email-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"email":       "not-an-email",
		"displayName": "Test User",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/accounts", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

// TestCreateWorkspaceAccount_Duplicate tests creating duplicate account.
// With the new user model, duplicates return 201 with created=false (idempotent).
func TestCreateWorkspaceAccount_Duplicate(t *testing.T) {
	router := setupWorkspaceAccountsRouter(t)

	email := "ws-accounts-dup-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	// Create an app for scope-aware user creation
	app := testEnv.CreateTestApp(t, ws, acc)
	role := createTestRole(t, app.ProjectID)
	testEnv.SetWorkspacePlan(t, ws.ID, "starter")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	// Create first user via repo
	newEmail := "dup-user-" + GenerateUniqueSlug("test") + "@example.com"
	user, _, err := testEnv.GetOrCreateUserWithMembership(context.Background(), newEmail, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create first user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM users WHERE id = $1", user.ID)
	}()

	// Try to create duplicate via the API
	body := map[string]any{
		"email":   newEmail,
		"appId":   app.ID.String(),
		"roleIds": []string{role.ID.String()},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/accounts", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// The new handler returns 201 for both new and existing users
	if rr.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// The duplicate should return created=false
	if resp["created"] != false {
		t.Errorf("expected created=false for duplicate, got %v", resp["created"])
	}
}

// TestDeleteWorkspaceAccount_Success tests deleting a workspace account
func TestDeleteWorkspaceAccount_Success(t *testing.T) {
	router := setupWorkspaceAccountsRouter(t)

	email := "ws-accounts-del-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	// Create user to delete
	newEmail := "del-user-" + GenerateUniqueSlug("test") + "@example.com"
	user, _, err := testEnv.GetOrCreateUserWithMembership(context.Background(), newEmail, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/accounts/"+user.ID.String(), nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d: %s", http.StatusNoContent, rr.Code, rr.Body.String())
	}
}

// TestDeleteWorkspaceAccount_NotFound tests deleting non-existent account
func TestDeleteWorkspaceAccount_NotFound(t *testing.T) {
	router := setupWorkspaceAccountsRouter(t)

	email := "ws-accounts-del-nf-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	fakeID := uuid.Must(uuid.NewV4())
	req := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/accounts/"+fakeID.String(), nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d: %s", http.StatusNotFound, rr.Code, rr.Body.String())
	}
}

// TestGetWorkspaceAccount_Success tests getting a single workspace account
func TestGetWorkspaceAccount_Success(t *testing.T) {
	router := setupWorkspaceAccountsRouter(t)

	email := "ws-accounts-get-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	// Create user to get
	newEmail := "get-user-" + GenerateUniqueSlug("test") + "@example.com"
	user, _, err := testEnv.GetOrCreateUserWithMembership(context.Background(), newEmail, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM users WHERE id = $1", user.ID)
	}()

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/accounts/"+user.ID.String(), nil)
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

	if resp["email"] != newEmail {
		t.Errorf("expected email %q, got %v", newEmail, resp["email"])
	}
}

// TestUpdateWorkspaceAccount_Success tests updating a workspace account (user)
func TestUpdateWorkspaceAccount_Success(t *testing.T) {
	router := setupWorkspaceAccountsRouter(t)

	email := "ws-accounts-upd-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	// Create user to update
	newEmail := "upd-user-" + GenerateUniqueSlug("test") + "@example.com"
	user, _, err := testEnv.GetOrCreateUserWithMembership(context.Background(), newEmail, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM users WHERE id = $1", user.ID)
	}()

	body := map[string]any{}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPatch, "/admin/workspace/"+ws.ID.String()+"/accounts/"+user.ID.String(), bytes.NewReader(bodyBytes))
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

	if resp["email"] != newEmail {
		t.Errorf("expected email %q, got %v", newEmail, resp["email"])
	}
}

// TestBulkImportWorkspaceAccounts_Success tests importing multiple accounts
func TestBulkImportWorkspaceAccounts_Success(t *testing.T) {
	router := setupWorkspaceAccountsRouter(t)

	email := "ws-bulk-import-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	testEnv.SetWorkspacePlan(t, ws.ID, "starter")

	app := testEnv.CreateTestApp(t, ws, acc)
	role := createTestRole(t, app.ProjectID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"appId":   app.ID.String(),
		"roleIds": []string{role.ID.String()},
		"accounts": []map[string]any{
			{"email": "bulk1-" + GenerateUniqueSlug("test") + "@example.com"},
			{"email": "bulk2-" + GenerateUniqueSlug("test") + "@example.com"},
			{"email": "bulk3-" + GenerateUniqueSlug("test") + "@example.com"},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/accounts/bulk-import", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["imported"] != float64(3) {
		t.Errorf("expected 3 imported, got %v", resp["imported"])
	}
	if resp["total"] != float64(3) {
		t.Errorf("expected total 3, got %v", resp["total"])
	}
	if resp["failed"] != float64(0) {
		t.Errorf("expected 0 failed, got %v", resp["failed"])
	}
}

// TestBulkImportWorkspaceAccounts_InvalidEmails tests bulk import with invalid emails
func TestBulkImportWorkspaceAccounts_InvalidEmails(t *testing.T) {
	router := setupWorkspaceAccountsRouter(t)

	email := "ws-bulk-inv-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	testEnv.SetWorkspacePlan(t, ws.ID, "starter")

	app := testEnv.CreateTestApp(t, ws, acc)
	role := createTestRole(t, app.ProjectID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"appId":   app.ID.String(),
		"roleIds": []string{role.ID.String()},
		"accounts": []map[string]any{
			{"email": "valid-" + GenerateUniqueSlug("test") + "@example.com"},
			{"email": "not-an-email"},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/accounts/bulk-import", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp["imported"] != float64(1) {
		t.Errorf("expected 1 imported, got %v", resp["imported"])
	}
	if resp["failed"] != float64(1) {
		t.Errorf("expected 1 failed, got %v", resp["failed"])
	}

	failures, ok := resp["failures"].([]any)
	if !ok || len(failures) != 1 {
		t.Fatalf("expected 1 failure entry, got %v", resp["failures"])
	}
	entry := failures[0].(map[string]any)
	if entry["reason"] != "invalid email format" {
		t.Errorf("expected reason 'invalid email format', got %v", entry["reason"])
	}
}

// TestBulkImportWorkspaceAccounts_TooMany tests exceeding 1000 account limit
func TestBulkImportWorkspaceAccounts_TooMany(t *testing.T) {
	router := setupWorkspaceAccountsRouter(t)

	email := "ws-bulk-too-many-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	accounts := make([]map[string]any, 1001)
	for i := range accounts {
		accounts[i] = map[string]any{"email": "x@example.com", "displayName": "X"}
	}
	body := map[string]any{"accounts": accounts}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/accounts/bulk-import", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

// TestGetWorkspaceAccounts_EnrichedFields tests that the accounts response includes
// the enriched fields: enabled, source, and createdAt.
func TestGetWorkspaceAccounts_EnrichedFields(t *testing.T) {
	router := setupWorkspaceAccountsRouter(t)

	email := "ws-acct-enriched-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	// Create a user
	userEmail := "enriched-user-" + GenerateUniqueSlug("test") + "@example.com"
	user, _, err := testEnv.GetOrCreateUserWithMembership(context.Background(), userEmail, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer cleanupUser(t, user.ID)

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/accounts", nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	accounts, ok := resp["accounts"].([]any)
	if !ok {
		t.Fatalf("expected accounts array, got %T", resp["accounts"])
	}

	// Find the user we created
	var found map[string]any
	for _, a := range accounts {
		entry, ok := a.(map[string]any)
		if !ok {
			continue
		}
		if entry["email"] == userEmail {
			found = entry
			break
		}
	}

	if found == nil {
		t.Fatalf("user %q not found in accounts response", userEmail)
	}

	// Verify enriched fields

	// enabled should be true (default for newly created users)
	if enabled, ok := found["enabled"].(bool); !ok || !enabled {
		t.Errorf("expected enabled=true, got %v", found["enabled"])
	}

	// source should be "invited"
	if source, ok := found["source"].(string); !ok || source != "invited" {
		t.Errorf("expected source=%q, got %v", "invited", found["source"])
	}

	// createdAt should be present and non-empty
	if createdAt, ok := found["createdAt"].(string); !ok || createdAt == "" {
		t.Errorf("expected non-empty createdAt, got %v", found["createdAt"])
	}
}

// TestGetWorkspaceAccounts_PoolFilter exercises the pool-scoped autocomplete
// path: poolId + email substring + limit. Verifies (a) only users in the
// queried pool come back, (b) ILIKE matches case-insensitive substrings,
// (c) the limit caps results.
func TestGetWorkspaceAccounts_PoolFilter(t *testing.T) {
	router := setupWorkspaceAccountsRouter(t)
	ctx := context.Background()

	adminEmail := "ws-acc-poolfilter-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, adminEmail)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	// Two apps in two different pools.
	app1 := testEnv.CreateTestApp(t, ws, acc)
	app2 := testEnv.CreateTestApp(t, ws, acc)

	u1, _, err := testEnv.GetOrCreateUserWithMembership(ctx, "alice-"+GenerateUniqueSlug("test")+"@example.com", app1, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	defer cleanupUser(t, u1.ID)

	u2, _, err := testEnv.GetOrCreateUserWithMembership(ctx, "alistair-"+GenerateUniqueSlug("test")+"@example.com", app1, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("seed alistair: %v", err)
	}
	defer cleanupUser(t, u2.ID)

	u3, _, err := testEnv.GetOrCreateUserWithMembership(ctx, "bob-"+GenerateUniqueSlug("test")+"@example.com", app2, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("seed bob: %v", err)
	}
	defer cleanupUser(t, u3.ID)

	get := func(t *testing.T, query string) []map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/accounts?"+query, nil)
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		raw, _ := resp["accounts"].([]any)
		out := make([]map[string]any, 0, len(raw))
		for _, a := range raw {
			if m, ok := a.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}

	// 1) Pool filter limits to that pool only.
	pool1 := app1.UserPoolID.String()
	accounts := get(t, "poolId="+pool1)
	emails := map[string]bool{}
	for _, a := range accounts {
		if s, ok := a["email"].(string); ok {
			emails[s] = true
		}
	}
	if !emails[u1.Email] || !emails[u2.Email] {
		t.Errorf("expected pool1 users present, got %v", emails)
	}
	if emails[u3.Email] {
		t.Errorf("pool2 user leaked into pool1 results: %v", emails)
	}

	// 2) Email substring narrows to the matching prefix (case-insensitive).
	accounts = get(t, "poolId="+pool1+"&email=ALIS")
	if len(accounts) != 1 || accounts[0]["email"].(string) != u2.Email {
		t.Errorf("expected exactly alistair, got %v", accounts)
	}

	// 3) limit caps results.
	accounts = get(t, "poolId="+pool1+"&limit=1")
	if len(accounts) != 1 {
		t.Errorf("limit=1 returned %d rows", len(accounts))
	}
}

// TestGetWorkspaceAccounts_PoolWrongWorkspace ensures an admin in
// workspace A cannot enumerate users in workspace B's pool by passing
// a foreign poolId in the URL.
func TestGetWorkspaceAccounts_PoolWrongWorkspace(t *testing.T) {
	router := setupWorkspaceAccountsRouter(t)
	ctx := context.Background()
	_ = ctx

	// Workspace A — the attacker.
	attackerEmail := "ws-acc-poolwrong-a-" + GenerateUniqueSlug("test") + "@example.com"
	attacker := testEnv.CreateTestAccount(t, attackerEmail)
	wsA := testEnv.CreateTestWorkspace(t, attacker, "WS A", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, attacker)
	fixturesA := &TestFixtures{Account: attacker, Workspace: wsA, Session: sess}
	defer testEnv.CleanupTestData(t, fixturesA)

	// Workspace B — the victim with a pool the attacker shouldn't see.
	victimEmail := "ws-acc-poolwrong-b-" + GenerateUniqueSlug("test") + "@example.com"
	victim := testEnv.CreateTestAccount(t, victimEmail)
	wsB := testEnv.CreateTestWorkspace(t, victim, "WS B", GenerateUniqueSlug("ws"))
	fixturesB := &TestFixtures{Account: victim, Workspace: wsB}
	defer testEnv.CleanupTestData(t, fixturesB)

	victimApp := testEnv.CreateTestApp(t, wsB, victim)
	foreignPoolID := victimApp.UserPoolID.String()

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+wsA.ID.String()+"/accounts?poolId="+foreignPoolID, nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("foreign poolId should 404, got %d: %s", rr.Code, rr.Body.String())
	}
}
