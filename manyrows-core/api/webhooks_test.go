package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

// setupWebhooksRouter creates a router for webhook tests
func setupWebhooksRouter(t *testing.T) *chi.Mux {
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

	adminWorkspaceRouter.Get("/projects/{projectId}/apps/{appId}/webhooks", requestHandler.HandleListWebhooks)
	adminWorkspaceRouter.Post("/projects/{projectId}/apps/{appId}/webhooks", requestHandler.HandleCreateWebhook)
	adminWorkspaceRouter.Get("/projects/{projectId}/apps/{appId}/webhooks/{webhookId}", requestHandler.HandleGetWebhook)
	adminWorkspaceRouter.Patch("/projects/{projectId}/apps/{appId}/webhooks/{webhookId}", requestHandler.HandleUpdateWebhook)
	adminWorkspaceRouter.Delete("/projects/{projectId}/apps/{appId}/webhooks/{webhookId}", requestHandler.HandleDeleteWebhook)
	adminWorkspaceRouter.Get("/projects/{projectId}/apps/{appId}/webhooks/{webhookId}/deliveries", requestHandler.HandleListWebhookDeliveries)
	adminWorkspaceRouter.Post("/projects/{projectId}/apps/{appId}/webhooks/{webhookId}/deliveries/{deliveryId}/retry", requestHandler.HandleRetryWebhookDelivery)

	adminRouter.Mount("/workspace/{workspaceId}", adminWorkspaceRouter)
	r.Mount("/admin", adminRouter)

	return r
}

func webhooksCleanup(t *testing.T, appID uuid.UUID) {
	t.Helper()
	pool := testEnv.DB.Pool()
	ctx := context.Background()
	_, _ = pool.Exec(ctx, "DELETE FROM webhook_deliveries WHERE webhook_id IN (SELECT id FROM webhooks WHERE app_id = $1)", appID)
	_, _ = pool.Exec(ctx, "DELETE FROM webhooks WHERE app_id = $1", appID)
}

func webhooksBasePath(wsID, projectID, appID uuid.UUID) string {
	return "/admin/workspace/" + wsID.String() + "/projects/" + projectID.String() + "/apps/" + appID.String() + "/webhooks"
}

// webhooksCreateApp creates an app for webhook tests.
func webhooksCreateApp(t *testing.T, wsID, projectID uuid.UUID) uuid.UUID {
	t.Helper()
	return createTestApp(t, wsID, projectID, uuid.Nil, "Webhook App")
}

// TestListWebhooks_Empty tests listing webhooks when none exist
func TestListWebhooks_Empty(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-list-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	req := httptest.NewRequest(http.MethodGet, webhooksBasePath(ws.ID, project.ID, appID), nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var webhooks []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &webhooks); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(webhooks) != 0 {
		t.Errorf("expected 0 webhooks, got %d", len(webhooks))
	}
}

// TestCreateWebhook_Success tests creating a webhook
func TestCreateWebhook_Success(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-create-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()
	defer webhooksCleanup(t, appID)

	body := map[string]any{
		"url":         "https://example.com/webhook",
		"events":      []string{"user.login", "user.register"},
		"description": "Test webhook",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID), bytes.NewReader(bodyBytes))
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

	// Secret should be returned on create
	if resp["secret"] == nil || resp["secret"] == "" {
		t.Error("expected secret to be returned on create")
	}
	if resp["url"] != "https://example.com/webhook" {
		t.Errorf("expected url 'https://example.com/webhook', got %v", resp["url"])
	}
	if resp["status"] != "active" {
		t.Errorf("expected status 'active', got %v", resp["status"])
	}
}

// TestCreateWebhook_SecretEncryptedAtRest proves the signing secret is never
// persisted in plaintext: after a create, the secret column is empty and the
// at-rest secret_encrypted ciphertext decrypts (under the right AAD) back to
// exactly the plaintext returned once in the create response.
func TestCreateWebhook_SecretEncryptedAtRest(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-enc-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()
	defer webhooksCleanup(t, appID)

	body := map[string]any{
		"url":    "https://example.com/webhook",
		"events": []string{"user.login"},
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID), bytes.NewReader(bodyBytes))
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
	plaintext, _ := resp["secret"].(string)
	if plaintext == "" {
		t.Fatal("expected plaintext secret in create response")
	}
	webhookID, err := uuid.FromString(resp["id"].(string))
	if err != nil {
		t.Fatalf("bad webhook id in response: %v", err)
	}

	// Read the raw row. secret must be empty; secret_encrypted must be set.
	var secretCol string
	var secretEnc []byte
	if err := testEnv.DB.Pool().QueryRow(context.Background(),
		"SELECT secret, secret_encrypted FROM webhooks WHERE id = $1", webhookID,
	).Scan(&secretCol, &secretEnc); err != nil {
		t.Fatalf("failed to read webhook row: %v", err)
	}
	if secretCol != "" {
		t.Errorf("plaintext secret column should be empty at rest, got %q", secretCol)
	}
	if len(secretEnc) == 0 {
		t.Fatal("secret_encrypted should be populated at rest")
	}
	if string(secretEnc) == plaintext {
		t.Fatal("secret_encrypted is storing the plaintext, not ciphertext")
	}

	// Ciphertext decrypts back to the plaintext under the row-bound AAD.
	enc := crypto.NewMySecretEncryptor(GetTestConfig())
	got, err := enc.DecryptFromBytesWithAAD(secretEnc, crypto.AAD("webhooks", "secret_encrypted", webhookID))
	if err != nil {
		t.Fatalf("failed to decrypt secret_encrypted: %v", err)
	}
	if string(got) != plaintext {
		t.Errorf("decrypted secret %q != create-response secret %q", string(got), plaintext)
	}

	// AAD binding: decrypting with a different row id must fail (no shuffling).
	if _, err := enc.DecryptFromBytesWithAAD(secretEnc, crypto.AAD("webhooks", "secret_encrypted", uuid.Must(uuid.NewV4()))); err == nil {
		t.Error("expected decrypt to fail under a mismatched AAD (row id)")
	}
}

// TestValidateWebhookURL_ProdMode tests URL validation in production mode
func TestValidateWebhookURL_ProdMode(t *testing.T) {
	// HTTP blocked in prod
	if api.ValidateWebhookURL("http://example.com/webhook", false) {
		t.Error("expected HTTP to be blocked in prod mode")
	}
	// HTTPS allowed in prod
	if !api.ValidateWebhookURL("https://example.com/webhook", false) {
		t.Error("expected HTTPS to be allowed in prod mode")
	}
	// Localhost blocked in prod
	if api.ValidateWebhookURL("https://localhost/webhook", false) {
		t.Error("expected localhost to be blocked in prod mode")
	}
	if api.ValidateWebhookURL("https://127.0.0.1/webhook", false) {
		t.Error("expected 127.0.0.1 to be blocked in prod mode")
	}
}

// TestValidateWebhookURL_DevMode tests URL validation in dev mode
func TestValidateWebhookURL_DevMode(t *testing.T) {
	// HTTP allowed in dev
	if !api.ValidateWebhookURL("http://localhost:8080/webhook", true) {
		t.Error("expected HTTP localhost to be allowed in dev mode")
	}
	// HTTPS allowed in dev
	if !api.ValidateWebhookURL("https://example.com/webhook", true) {
		t.Error("expected HTTPS to be allowed in dev mode")
	}
	// No scheme still blocked
	if api.ValidateWebhookURL("ftp://example.com/webhook", true) {
		t.Error("expected FTP to be blocked even in dev mode")
	}
}

// TestCreateWebhook_LocalhostAllowedInDev tests that localhost works in dev mode (tests run in dev)
func TestCreateWebhook_LocalhostAllowedInDev(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-localhost-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer webhooksCleanup(t, appID)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	body := map[string]any{
		"url":    "http://localhost:8080/webhook",
		"events": []string{"user.login"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected status %d (localhost allowed in dev), got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}
}

// TestCreateWebhook_InvalidEvent tests that invalid event names are rejected
func TestCreateWebhook_InvalidEvent(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-event-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	body := map[string]any{
		"url":    "https://example.com/webhook",
		"events": []string{"user.login", "invalid.event"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// TestCreateWebhook_EmptyURL tests that empty URL is rejected
func TestCreateWebhook_EmptyURL(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-empty-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	body := map[string]any{
		"url":    "",
		"events": []string{"user.login"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// TestGetWebhook_Success tests getting a single webhook
func TestGetWebhook_Success(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-get-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()
	defer webhooksCleanup(t, appID)

	// Create a webhook first
	createBody := map[string]any{
		"url":    "https://example.com/webhook",
		"events": []string{"user.login"},
	}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID), bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create webhook: %s", createRR.Body.String())
	}

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	webhookID := created["id"].(string)

	// Get the webhook
	getReq := httptest.NewRequest(http.MethodGet, webhooksBasePath(ws.ID, project.ID, appID)+"/"+webhookID, nil)
	testEnv.SetSessionCookie(t, getReq, claims)

	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, getRR.Code, getRR.Body.String())
		return
	}

	var resp map[string]any
	json.Unmarshal(getRR.Body.Bytes(), &resp)

	// Secret should NOT be returned on GET (omitempty removes the key entirely)
	if secret, ok := resp["secret"]; ok && secret != "" {
		t.Error("expected secret to be empty on GET")
	}
}

// TestGetWebhook_NotFound tests getting a non-existent webhook
func TestGetWebhook_NotFound(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-notfound-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	fakeID := uuid.Must(uuid.NewV4())
	req := httptest.NewRequest(http.MethodGet, webhooksBasePath(ws.ID, project.ID, appID)+"/"+fakeID.String(), nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

// TestUpdateWebhook_Success tests updating a webhook
func TestUpdateWebhook_Success(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-update-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()
	defer webhooksCleanup(t, appID)

	// Create a webhook first
	createBody := map[string]any{
		"url":         "https://example.com/webhook",
		"events":      []string{"user.login"},
		"description": "Original",
	}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID), bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	webhookID := created["id"].(string)

	// Update description and status
	desc := "Updated description"
	status := "disabled"
	updateBody := map[string]any{
		"description": &desc,
		"status":      &status,
	}
	updateBytes, _ := json.Marshal(updateBody)
	updateReq := httptest.NewRequest(http.MethodPatch, webhooksBasePath(ws.ID, project.ID, appID)+"/"+webhookID, bytes.NewReader(updateBytes))
	updateReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, updateReq, claims)

	updateRR := httptest.NewRecorder()
	router.ServeHTTP(updateRR, updateReq)

	if updateRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, updateRR.Code, updateRR.Body.String())
		return
	}

	var resp map[string]any
	json.Unmarshal(updateRR.Body.Bytes(), &resp)

	if resp["description"] != "Updated description" {
		t.Errorf("expected description 'Updated description', got %v", resp["description"])
	}
	if resp["status"] != "disabled" {
		t.Errorf("expected status 'disabled', got %v", resp["status"])
	}
}

// TestUpdateWebhook_InvalidStatus tests updating a webhook with invalid status
func TestUpdateWebhook_InvalidStatus(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-badstatus-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()
	defer webhooksCleanup(t, appID)

	// Create a webhook first
	createBody := map[string]any{
		"url":    "https://example.com/webhook",
		"events": []string{"user.login"},
	}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID), bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	webhookID := created["id"].(string)

	// Update with invalid status
	status := "bogus"
	updateBody := map[string]any{"status": &status}
	updateBytes, _ := json.Marshal(updateBody)
	updateReq := httptest.NewRequest(http.MethodPatch, webhooksBasePath(ws.ID, project.ID, appID)+"/"+webhookID, bytes.NewReader(updateBytes))
	updateReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, updateReq, claims)

	updateRR := httptest.NewRecorder()
	router.ServeHTTP(updateRR, updateReq)

	if updateRR.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, updateRR.Code)
	}
}

// TestDeleteWebhook_Success tests deleting a webhook
func TestDeleteWebhook_Success(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-delete-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()
	defer webhooksCleanup(t, appID)

	// Create a webhook first
	createBody := map[string]any{
		"url":    "https://example.com/webhook",
		"events": []string{"user.login"},
	}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID), bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	webhookID := created["id"].(string)

	// Delete the webhook
	deleteReq := httptest.NewRequest(http.MethodDelete, webhooksBasePath(ws.ID, project.ID, appID)+"/"+webhookID, nil)
	testEnv.SetSessionCookie(t, deleteReq, claims)

	deleteRR := httptest.NewRecorder()
	router.ServeHTTP(deleteRR, deleteReq)

	if deleteRR.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, deleteRR.Code)
		return
	}

	// Verify it's gone
	getReq := httptest.NewRequest(http.MethodGet, webhooksBasePath(ws.ID, project.ID, appID)+"/"+webhookID, nil)
	testEnv.SetSessionCookie(t, getReq, claims)

	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)

	if getRR.Code != http.StatusNotFound {
		t.Errorf("expected status %d after delete, got %d", http.StatusNotFound, getRR.Code)
	}
}

// TestDeleteWebhook_NotFound tests deleting a non-existent webhook
func TestDeleteWebhook_NotFound(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-delnf-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	fakeID := uuid.Must(uuid.NewV4())
	req := httptest.NewRequest(http.MethodDelete, webhooksBasePath(ws.ID, project.ID, appID)+"/"+fakeID.String(), nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

// TestListWebhookDeliveries_Success tests listing deliveries for a webhook
func TestListWebhookDeliveries_Success(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-deliv-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()
	defer webhooksCleanup(t, appID)

	// Create a webhook
	createBody := map[string]any{
		"url":    "https://example.com/webhook",
		"events": []string{"user.login"},
	}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID), bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	webhookID := created["id"].(string)

	// List deliveries (should be empty)
	delivReq := httptest.NewRequest(http.MethodGet, webhooksBasePath(ws.ID, project.ID, appID)+"/"+webhookID+"/deliveries", nil)
	testEnv.SetSessionCookie(t, delivReq, claims)

	delivRR := httptest.NewRecorder()
	router.ServeHTTP(delivRR, delivReq)

	if delivRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, delivRR.Code, delivRR.Body.String())
		return
	}

	var deliveries []map[string]any
	if err := json.Unmarshal(delivRR.Body.Bytes(), &deliveries); err != nil {
		t.Fatalf("failed to parse deliveries: %v", err)
	}
	if len(deliveries) != 0 {
		t.Errorf("expected 0 deliveries, got %d", len(deliveries))
	}
}

// TestListWebhookDeliveries_WebhookNotFound tests listing deliveries for non-existent webhook
func TestListWebhookDeliveries_WebhookNotFound(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-delivnf-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	fakeID := uuid.Must(uuid.NewV4())
	req := httptest.NewRequest(http.MethodGet, webhooksBasePath(ws.ID, project.ID, appID)+"/"+fakeID.String()+"/deliveries", nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

// TestRetryWebhookDelivery_NotFound tests retrying a non-existent delivery
func TestRetryWebhookDelivery_NotFound(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-retrynf-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()
	defer webhooksCleanup(t, appID)

	// Create a real webhook
	createBody := map[string]any{
		"url":    "https://example.com/webhook",
		"events": []string{"user.login"},
	}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID), bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	webhookID := created["id"].(string)
	fakeDeliveryID := uuid.Must(uuid.NewV4())

	retryReq := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID)+"/"+webhookID+"/deliveries/"+fakeDeliveryID.String()+"/retry", nil)
	testEnv.SetSessionCookie(t, retryReq, claims)

	retryRR := httptest.NewRecorder()
	router.ServeHTTP(retryRR, retryReq)

	if retryRR.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, retryRR.Code)
	}
}

// TestCreateWebhook_Unauthenticated tests creating webhook without auth
func TestCreateWebhook_Unauthenticated(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	body := map[string]any{
		"url":    "https://example.com/webhook",
		"events": []string{"user.login"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// TestListWebhooks_AfterCreate tests listing after creating webhooks
func TestListWebhooks_AfterCreate(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-listcr-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()
	defer webhooksCleanup(t, appID)

	// Create a webhook
	createBody := map[string]any{
		"url":    "https://example.com/webhook",
		"events": []string{"user.login"},
	}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID), bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)

	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create webhook: %s", createRR.Body.String())
	}

	// List webhooks
	listReq := httptest.NewRequest(http.MethodGet, webhooksBasePath(ws.ID, project.ID, appID), nil)
	testEnv.SetSessionCookie(t, listReq, claims)

	listRR := httptest.NewRecorder()
	router.ServeHTTP(listRR, listReq)

	if listRR.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, listRR.Code)
		return
	}

	var webhooks []map[string]any
	json.Unmarshal(listRR.Body.Bytes(), &webhooks)

	if len(webhooks) != 1 {
		t.Errorf("expected 1 webhook, got %d", len(webhooks))
		return
	}

	// Secret should NOT be in list response (omitempty removes the key entirely)
	if secret, ok := webhooks[0]["secret"]; ok && secret != "" {
		t.Error("expected secret to be empty in list response")
	}
}

// TestCreateWebhook_EmptyEventsRejected tests that an empty events array is rejected
func TestCreateWebhook_EmptyEventsRejected(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-emptyev-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	body := map[string]any{
		"url":    "https://example.com/webhook",
		"events": []string{},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

// TestCreateWebhook_NilEventsRejected tests that omitting events is rejected
func TestCreateWebhook_NilEventsRejected(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-nilev-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	body := map[string]any{
		"url": "https://example.com/webhook",
		// events omitted
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

// TestUpdateWebhook_EmptyEventsRejected tests that updating events to empty is rejected
func TestUpdateWebhook_EmptyEventsRejected(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-updempty-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer webhooksCleanup(t, appID)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	// Create a webhook first
	createBody := map[string]any{
		"url":    "https://example.com/webhook",
		"events": []string{"user.login"},
	}
	createBytes, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID), bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)
	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create webhook: %s", createRR.Body.String())
	}
	var created map[string]any
	json.Unmarshal(createRR.Body.Bytes(), &created)
	webhookID := created["id"].(string)

	// Try to update events to empty
	updateBody := map[string]any{"events": []string{}}
	updateBytes, _ := json.Marshal(updateBody)
	updateReq := httptest.NewRequest(http.MethodPatch, webhooksBasePath(ws.ID, project.ID, appID)+"/"+webhookID, bytes.NewReader(updateBytes))
	updateReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, updateReq, claims)
	updateRR := httptest.NewRecorder()
	router.ServeHTTP(updateRR, updateReq)

	if updateRR.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, updateRR.Code, updateRR.Body.String())
	}
}

// TestWebhook_CrossAppIsolation tests that webhooks from one app are not visible to another
func TestWebhook_CrossAppIsolation(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-isolation-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	// Second project so app2 can share env type with app1 — apps are
	// now unique on (project_id, type) per migration 00005.
	project2 := testEnv.CreateTestProject(t, ws, acc, "Test Project 2", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	app1ID := webhooksCreateApp(t, ws.ID, project.ID)
	app2ID := createTestApp(t, ws.ID, project2.ID, uuid.Nil, "App2")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer webhooksCleanup(t, app1ID)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", app1ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", app2ID)
	}()

	// Create webhook on app1
	body := map[string]any{
		"url":    "https://example.com/webhook",
		"events": []string{"user.login"},
	}
	bodyBytes, _ := json.Marshal(body)
	createReq := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, app1ID), bytes.NewReader(bodyBytes))
	createReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, createReq, claims)
	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("failed to create webhook: %s", createRR.Body.String())
	}

	// List webhooks on app2 — should be empty
	listReq := httptest.NewRequest(http.MethodGet, webhooksBasePath(ws.ID, project2.ID, app2ID), nil)
	testEnv.SetSessionCookie(t, listReq, claims)
	listRR := httptest.NewRecorder()
	router.ServeHTTP(listRR, listReq)

	if listRR.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d: %s", http.StatusOK, listRR.Code, listRR.Body.String())
	}
	var webhooks []map[string]any
	json.Unmarshal(listRR.Body.Bytes(), &webhooks)
	if len(webhooks) != 0 {
		t.Errorf("expected 0 webhooks on app2, got %d", len(webhooks))
	}
}

// TestCreateWebhook_LimitReached tests that creating more than maxWebhooksPerApp is rejected
func TestCreateWebhook_LimitReached(t *testing.T) {
	router := setupWebhooksRouter(t)

	em := "wh-limit-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, em)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	appID := webhooksCreateApp(t, ws.ID, project.ID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer webhooksCleanup(t, appID)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	// Create webhooks up to the per-app limit (maxWebhooksPerApp = 10).
	for i := 0; i < 10; i++ {
		body := map[string]any{
			"url":    fmt.Sprintf("https://example.com/webhook-%d", i),
			"events": []string{"user.login"},
		}
		bodyBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID), bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("webhook %d: expected %d, got %d: %s", i, http.StatusCreated, rr.Code, rr.Body.String())
		}
	}

	// 2nd should fail
	body := map[string]any{
		"url":    "https://example.com/webhook-overflow",
		"events": []string{"user.login"},
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, webhooksBasePath(ws.ID, project.ID, appID), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("expected status %d for limit reached, got %d: %s", http.StatusConflict, rr.Code, rr.Body.String())
	}
}
