package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"manyrows-core/api"
	"manyrows-core/auth"
	"manyrows-core/auth/client"
	"manyrows-core/core"
	"manyrows-core/crypto"
	"manyrows-core/email"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// setupSMTPRouter creates a router for SMTP config tests
func setupSMTPRouter(t *testing.T) *chi.Mux {
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

	encryptor := crypto.NewMySecretEncryptor(cfg)

	requestHandler := api.NewRequestHandler(
		testEnv.Repo,
		adminAuthService,
		clientAuthService,
		emailService,
		cfg,
		encryptor,
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

			// Check role
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

	adminWorkspaceRouter.Get("/smtp", requestHandler.HandleGetSMTPConfig)
	adminWorkspaceRouter.Post("/smtp", requestHandler.HandleUpsertSMTPConfig)
	adminWorkspaceRouter.Delete("/smtp", requestHandler.HandleDeleteSMTPConfig)
	adminWorkspaceRouter.Post("/smtp/test", requestHandler.HandleTestSMTPConfig)

	adminRouter.Mount("/workspace/{workspaceId}", adminWorkspaceRouter)
	r.Mount("/admin", adminRouter)

	return r
}

func smtpCleanup(t *testing.T, wsID uuid.UUID) {
	t.Helper()
	pool := testEnv.DB.Pool()
	ctx := context.Background()
	_, _ = pool.Exec(ctx, "DELETE FROM workspace_smtp_configs WHERE workspace_id = $1", wsID)
}

func smtpBasePath(wsID uuid.UUID) string {
	return "/admin/workspace/" + wsID.String() + "/smtp"
}

// TestGetSMTPConfig_NotConfigured tests getting SMTP config when none exists
func TestGetSMTPConfig_NotConfigured(t *testing.T) {
	router := setupSMTPRouter(t)

	em := "smtp-get-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, smtpBasePath(ws.ID), nil)
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

	if resp["configured"] != false {
		t.Errorf("expected configured=false, got %v", resp["configured"])
	}
}

// TestUpsertSMTPConfig_Success tests creating an SMTP config
func TestUpsertSMTPConfig_Success(t *testing.T) {
	router := setupSMTPRouter(t)

	em := "smtp-upsert-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer smtpCleanup(t, ws.ID)

	body := map[string]any{
		"enabled":   true,
		"host":      "smtp.example.com",
		"port":      587,
		"username":  "user@example.com",
		"password":  "secret123",
		"fromEmail": "noreply@example.com",
		"fromName":  "Test App",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, smtpBasePath(ws.ID), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	// Verify it's stored by reading it back
	getReq := httptest.NewRequest(http.MethodGet, smtpBasePath(ws.ID), nil)
	testEnv.SetSessionCookie(t, getReq, claims)

	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Fatalf("failed to get SMTP config: %s", getRR.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(getRR.Body.Bytes(), &resp)

	if resp["configured"] != true {
		t.Errorf("expected configured=true, got %v", resp["configured"])
	}
	if resp["host"] != "smtp.example.com" {
		t.Errorf("expected host 'smtp.example.com', got %v", resp["host"])
	}
	if resp["hasPassword"] != true {
		t.Errorf("expected hasPassword=true, got %v", resp["hasPassword"])
	}
	// Password should NOT be returned
	if _, exists := resp["password"]; exists {
		t.Error("password should not be in response")
	}
}

// TestUpsertSMTPConfig_MissingHost tests creating SMTP config without host
func TestUpsertSMTPConfig_MissingHost(t *testing.T) {
	router := setupSMTPRouter(t)

	em := "smtp-nohost-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"enabled":   true,
		"host":      "",
		"port":      587,
		"fromEmail": "noreply@example.com",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, smtpBasePath(ws.ID), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// TestUpsertSMTPConfig_MissingFromEmail tests creating SMTP config without fromEmail
func TestUpsertSMTPConfig_MissingFromEmail(t *testing.T) {
	router := setupSMTPRouter(t)

	em := "smtp-nofrom-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"enabled":   true,
		"host":      "smtp.example.com",
		"port":      587,
		"fromEmail": "",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, smtpBasePath(ws.ID), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// TestDeleteSMTPConfig_Success tests deleting an SMTP config
func TestDeleteSMTPConfig_Success(t *testing.T) {
	router := setupSMTPRouter(t)

	em := "smtp-delete-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer smtpCleanup(t, ws.ID)

	// Create an SMTP config first
	body := map[string]any{
		"enabled":   true,
		"host":      "smtp.example.com",
		"port":      587,
		"fromEmail": "noreply@example.com",
	}
	bodyBytes, _ := json.Marshal(body)

	createReq := httptest.NewRequest(http.MethodPost, smtpBasePath(ws.ID), bytes.NewReader(bodyBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusOK {
		t.Fatalf("failed to create SMTP config: %s", createRR.Body.String())
	}

	// Delete it
	deleteReq := httptest.NewRequest(http.MethodDelete, smtpBasePath(ws.ID), nil)
	testEnv.SetSessionCookie(t, deleteReq, claims)

	deleteRR := httptest.NewRecorder()
	router.ServeHTTP(deleteRR, deleteReq)

	if deleteRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, deleteRR.Code, deleteRR.Body.String())
		return
	}

	// Verify it's gone
	getReq := httptest.NewRequest(http.MethodGet, smtpBasePath(ws.ID), nil)
	testEnv.SetSessionCookie(t, getReq, claims)

	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)

	var resp map[string]any
	json.Unmarshal(getRR.Body.Bytes(), &resp)

	if resp["configured"] != false {
		t.Errorf("expected configured=false after delete, got %v", resp["configured"])
	}
}

// TestUpsertSMTPConfig_ForbiddenForAdmin tests that non-owner admins cannot upsert
func TestUpsertSMTPConfig_ForbiddenForAdmin(t *testing.T) {
	router := setupSMTPRouter(t)

	ownerEmail := "smtp-owner-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))

	// AddFieldIssue a non-owner admin
	adminEmail := "smtp-admin-" + GenerateUniqueSlug("test") + "@example.com"
	adminAcc := testEnv.CreateTestAccount(t, adminEmail)
	adminMember := core.WorkspaceAdmin{
		WorkspaceID: ws.ID,
		AccountID:   adminAcc.ID,
		Role:        "admin",
		AddedBy:     &owner.ID,
	}
	if err := testEnv.Repo.AddWorkspaceAdmin(context.Background(), adminMember); err != nil {
		t.Fatalf("failed to add admin: %v", err)
	}

	sess, claims := testEnv.CreateTestSession(t, adminAcc)

	fixtures := &TestFixtures{Account: owner, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		ctx := context.Background()
		_, _ = pool.Exec(ctx, "DELETE FROM workspace_admins WHERE account_id = $1", adminAcc.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM sessions WHERE id = $1", sess.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM accounts WHERE id = $1", adminAcc.ID)
	}()

	body := map[string]any{
		"enabled":   true,
		"host":      "smtp.example.com",
		"port":      587,
		"fromEmail": "noreply@example.com",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, smtpBasePath(ws.ID), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
}

// TestDeleteSMTPConfig_ForbiddenForAdmin tests that non-owner admins cannot delete
func TestDeleteSMTPConfig_ForbiddenForAdmin(t *testing.T) {
	router := setupSMTPRouter(t)

	ownerEmail := "smtp-delown-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))

	// AddFieldIssue a non-owner admin
	adminEmail := "smtp-deladm-" + GenerateUniqueSlug("test") + "@example.com"
	adminAcc := testEnv.CreateTestAccount(t, adminEmail)
	adminMember := core.WorkspaceAdmin{
		WorkspaceID: ws.ID,
		AccountID:   adminAcc.ID,
		Role:        "admin",
		AddedBy:     &owner.ID,
	}
	if err := testEnv.Repo.AddWorkspaceAdmin(context.Background(), adminMember); err != nil {
		t.Fatalf("failed to add admin: %v", err)
	}

	sess, claims := testEnv.CreateTestSession(t, adminAcc)

	fixtures := &TestFixtures{Account: owner, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		ctx := context.Background()
		_, _ = pool.Exec(ctx, "DELETE FROM workspace_admins WHERE account_id = $1", adminAcc.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM sessions WHERE id = $1", sess.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM accounts WHERE id = $1", adminAcc.ID)
	}()

	req := httptest.NewRequest(http.MethodDelete, smtpBasePath(ws.ID), nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
}

// TestTestSMTPConfig_NotConfigured tests testing SMTP when no SMTP
// config row exists. The endpoint falls back to the console provider
// (mail to stdout) and reports success — the test endpoint exercises
// outbound delivery, which still works via the fallback even without
// stored SMTP credentials.
func TestTestSMTPConfig_NotConfigured(t *testing.T) {
	router := setupSMTPRouter(t)

	em := "smtp-testnocfg-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodPost, smtpBasePath(ws.ID)+"/test", nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

// TestGetSMTPConfig_Unauthenticated tests getting SMTP config without auth
func TestGetSMTPConfig_Unauthenticated(t *testing.T) {
	router := setupSMTPRouter(t)

	em := "smtp-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, smtpBasePath(ws.ID), nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// TestUpsertSMTPConfig_UpdateExisting tests updating an existing SMTP config
func TestUpsertSMTPConfig_UpdateExisting(t *testing.T) {
	router := setupSMTPRouter(t)

	em := "smtp-update-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer smtpCleanup(t, ws.ID)

	// Create initial config
	body1 := map[string]any{
		"enabled":   true,
		"host":      "smtp1.example.com",
		"port":      587,
		"fromEmail": "noreply@example.com",
	}
	bodyBytes1, _ := json.Marshal(body1)
	req1 := httptest.NewRequest(http.MethodPost, smtpBasePath(ws.ID), bytes.NewReader(bodyBytes1))
	req1.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req1, claims)

	rr1 := httptest.NewRecorder()
	router.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("failed to create initial SMTP config: %s", rr1.Body.String())
	}

	// Update with new host
	body2 := map[string]any{
		"enabled":   false,
		"host":      "smtp2.example.com",
		"port":      465,
		"fromEmail": "updated@example.com",
	}
	bodyBytes2, _ := json.Marshal(body2)
	req2 := httptest.NewRequest(http.MethodPost, smtpBasePath(ws.ID), bytes.NewReader(bodyBytes2))
	req2.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req2, claims)

	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr2.Code, rr2.Body.String())
		return
	}

	// Verify the update
	getReq := httptest.NewRequest(http.MethodGet, smtpBasePath(ws.ID), nil)
	testEnv.SetSessionCookie(t, getReq, claims)

	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)

	var resp map[string]any
	json.Unmarshal(getRR.Body.Bytes(), &resp)

	if resp["host"] != "smtp2.example.com" {
		t.Errorf("expected host 'smtp2.example.com', got %v", resp["host"])
	}
	if resp["enabled"] != false {
		t.Errorf("expected enabled=false, got %v", resp["enabled"])
	}
}
