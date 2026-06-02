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
	"manyrows-core/crypto/passwordhash"
	"manyrows-core/email"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
)

// setupTOTPTestRouter creates a router with TOTP endpoints for testing.
// Unlike the shared NewTestServices, this passes a real encryptor since TOTP requires encryption.
func setupTOTPTestRouter(t *testing.T) (*chi.Mux, *auth.Service) {
	t.Helper()

	cfg := GetTestConfig()

	adminAuth, err := auth.NewAuthService(cfg, testEnv.Repo)
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}
	clientAuth, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("failed to create client auth service: %v", err)
	}

	emailSvc := email.NewEmailService(true, nil)
	encryptor := crypto.NewMySecretEncryptor(cfg)

	handler := api.NewRequestHandler(
		testEnv.Repo,
		adminAuth,
		clientAuth,
		emailSvc,
		cfg,
		encryptor,
		nil,
	)

	r := chi.NewRouter()

	// Unauthenticated TOTP verify (like login flow)
	r.Post("/admin/auth/totp/verify", handler.AdminTOTPVerify)

	// Authenticated TOTP management endpoints
	r.Group(func(r chi.Router) {
		r.Use(AdminAuthMiddleware(adminAuth))
		r.Post("/admin/totp/setup", handler.AdminTOTPSetup)
		r.Post("/admin/totp/enable", handler.AdminTOTPEnable)
		r.Post("/admin/totp/disable", handler.AdminTOTPDisable)
		r.Post("/admin/totp/backup-codes", handler.AdminTOTPRegenerateBackupCodes)
	})

	return r, adminAuth
}

// createAccountWithPassword creates a test account and sets a password hash.
func createAccountWithPassword(t *testing.T, pw string) *core.Account {
	t.Helper()
	em := "totp-" + GenerateUniqueSlug("user") + "@test.com"
	acc := testEnv.CreateTestAccount(t, em)

	hash, err := passwordhash.Hash(pw)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	_, err = testEnv.DB.Pool().Exec(context.Background(),
		"UPDATE accounts SET password_hash = $1, password_set_at = now() WHERE id = $2",
		hash, acc.ID)
	if err != nil {
		t.Fatalf("failed to set password: %v", err)
	}
	return acc
}

// enableTOTPForAccount runs the full setup+enable flow directly in the DB for a given account.
// Returns the plaintext TOTP secret and backup codes.
func enableTOTPForAccount(t *testing.T, acc *core.Account) (secret string, backupCodes []string) {
	t.Helper()
	cfg := GetTestConfig()
	encryptor := crypto.NewMySecretEncryptor(cfg)

	// Generate a TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Manyrows",
		AccountName: acc.Email,
	})
	if err != nil {
		t.Fatalf("failed to generate TOTP key: %v", err)
	}
	secret = key.Secret()

	// Encrypt and store secret with AAD-bound v0x03 (matches what
	// the production handler now writes via EncryptToBytesWithAAD).
	encrypted, err := encryptor.EncryptToBytesWithAAD(
		[]byte(secret),
		crypto.AAD("accounts", "totp_secret_encrypted", acc.ID),
	)
	if err != nil {
		t.Fatalf("failed to encrypt TOTP secret: %v", err)
	}
	if err := testEnv.Repo.SetTOTPSecret(context.Background(), acc.ID, encrypted); err != nil {
		t.Fatalf("failed to store TOTP secret: %v", err)
	}

	// Generate backup codes
	backupCodes = []string{"aabbccdd", "11223344", "55667788", "99aabbcc", "ddeeff00", "11335577", "22446688", "33557799"}
	codesJSON, _ := json.Marshal(backupCodes)
	encryptedCodes, err := encryptor.EncryptToBytesWithAAD(
		codesJSON,
		crypto.AAD("accounts", "totp_backup_codes_encrypted", acc.ID),
	)
	if err != nil {
		t.Fatalf("failed to encrypt backup codes: %v", err)
	}

	// Enable TOTP
	now := time.Now().UTC()
	if err := testEnv.Repo.EnableTOTP(context.Background(), acc.ID, now, encryptedCodes); err != nil {
		t.Fatalf("failed to enable TOTP: %v", err)
	}

	return secret, backupCodes
}

// jsonBody marshals a value to a *bytes.Reader for use with httptest.NewRequest.
func jsonBody(t *testing.T, v any) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("failed to marshal JSON: %v", err)
	}
	return bytes.NewReader(b)
}

// ============================================================================
// POST /admin/totp/setup
// ============================================================================

func TestAdminTOTPSetup_Success(t *testing.T) {
	router, _ := setupTOTPTestRouter(t)

	acc := testEnv.CreateTestAccount(t, "totp-setup-"+GenerateUniqueSlug("u")+"@test.com")
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Session: sess})

	req := httptest.NewRequest(http.MethodPost, "/admin/totp/setup", nil)
	testEnv.SetSessionCookie(t, req, claims)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["secret"] == nil || resp["secret"] == "" {
		t.Error("expected secret in response")
	}
	if resp["uri"] == nil || resp["uri"] == "" {
		t.Error("expected uri in response")
	}

	// Verify secret was stored in DB
	freshAcc, err := testEnv.Repo.GetAccountByID(context.Background(), acc.ID)
	if err != nil {
		t.Fatalf("failed to fetch account: %v", err)
	}
	if len(freshAcc.TOTPSecretEncrypted) == 0 {
		t.Error("expected TOTP secret to be stored")
	}
}

func TestAdminTOTPSetup_AlreadyEnabled(t *testing.T) {
	router, _ := setupTOTPTestRouter(t)

	acc := testEnv.CreateTestAccount(t, "totp-setup-dup-"+GenerateUniqueSlug("u")+"@test.com")
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Session: sess})

	// Enable TOTP directly
	enableTOTPForAccount(t, acc)

	req := httptest.NewRequest(http.MethodPost, "/admin/totp/setup", nil)
	testEnv.SetSessionCookie(t, req, claims)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminTOTPSetup_Unauthenticated(t *testing.T) {
	router, _ := setupTOTPTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/totp/setup", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================================
// POST /admin/totp/enable
// ============================================================================

func TestAdminTOTPEnable_Success(t *testing.T) {
	router, _ := setupTOTPTestRouter(t)

	acc := testEnv.CreateTestAccount(t, "totp-enable-"+GenerateUniqueSlug("u")+"@test.com")
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Session: sess})

	// First do setup to store a secret
	setupReq := httptest.NewRequest(http.MethodPost, "/admin/totp/setup", nil)
	testEnv.SetSessionCookie(t, setupReq, claims)
	setupRec := httptest.NewRecorder()
	router.ServeHTTP(setupRec, setupReq)

	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup failed: %d: %s", setupRec.Code, setupRec.Body.String())
	}

	var setupResp map[string]any
	json.NewDecoder(setupRec.Body).Decode(&setupResp)
	secret := setupResp["secret"].(string)

	// Generate a valid TOTP code
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate TOTP code: %v", err)
	}

	// Enable with valid code
	enableReq := httptest.NewRequest(http.MethodPost, "/admin/totp/enable",
		jsonBody(t, map[string]string{"code": code}))
	enableReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, enableReq, claims)
	enableRec := httptest.NewRecorder()
	router.ServeHTTP(enableRec, enableReq)

	if enableRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", enableRec.Code, enableRec.Body.String())
	}

	var enableResp map[string]any
	json.NewDecoder(enableRec.Body).Decode(&enableResp)

	codes, ok := enableResp["backupCodes"].([]any)
	if !ok || len(codes) != 8 {
		t.Errorf("expected 8 backup codes, got %v", enableResp["backupCodes"])
	}

	// Verify TOTP is now enabled in DB
	freshAcc, err := testEnv.Repo.GetAccountByID(context.Background(), acc.ID)
	if err != nil {
		t.Fatalf("failed to fetch account: %v", err)
	}
	if !freshAcc.HasTOTP() {
		t.Error("expected TOTP to be enabled")
	}
}

func TestAdminTOTPEnable_InvalidCode(t *testing.T) {
	router, _ := setupTOTPTestRouter(t)

	acc := testEnv.CreateTestAccount(t, "totp-enable-bad-"+GenerateUniqueSlug("u")+"@test.com")
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Session: sess})

	// Setup first
	setupReq := httptest.NewRequest(http.MethodPost, "/admin/totp/setup", nil)
	testEnv.SetSessionCookie(t, setupReq, claims)
	setupRec := httptest.NewRecorder()
	router.ServeHTTP(setupRec, setupReq)

	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup failed: %d: %s", setupRec.Code, setupRec.Body.String())
	}

	// Try to enable with wrong code
	enableReq := httptest.NewRequest(http.MethodPost, "/admin/totp/enable",
		jsonBody(t, map[string]string{"code": "000000"}))
	enableReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, enableReq, claims)
	enableRec := httptest.NewRecorder()
	router.ServeHTTP(enableRec, enableReq)

	if enableRec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", enableRec.Code, enableRec.Body.String())
	}

	// Verify TOTP is still not enabled
	freshAcc, err := testEnv.Repo.GetAccountByID(context.Background(), acc.ID)
	if err != nil {
		t.Fatalf("failed to fetch account: %v", err)
	}
	if freshAcc.HasTOTP() {
		t.Error("expected TOTP to NOT be enabled after invalid code")
	}
}

func TestAdminTOTPEnable_NoSetup(t *testing.T) {
	router, _ := setupTOTPTestRouter(t)

	acc := testEnv.CreateTestAccount(t, "totp-enable-nosetup-"+GenerateUniqueSlug("u")+"@test.com")
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Session: sess})

	// Try to enable without setup
	req := httptest.NewRequest(http.MethodPost, "/admin/totp/enable",
		jsonBody(t, map[string]string{"code": "123456"}))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminTOTPEnable_EmptyCode(t *testing.T) {
	router, _ := setupTOTPTestRouter(t)

	acc := testEnv.CreateTestAccount(t, "totp-enable-empty-"+GenerateUniqueSlug("u")+"@test.com")
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Session: sess})

	req := httptest.NewRequest(http.MethodPost, "/admin/totp/enable",
		jsonBody(t, map[string]string{"code": ""}))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================================
// POST /admin/totp/disable
// ============================================================================

func TestAdminTOTPDisable_Success(t *testing.T) {
	router, _ := setupTOTPTestRouter(t)
	password := "securepassword123"

	acc := createAccountWithPassword(t, password)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Session: sess})

	enableTOTPForAccount(t, acc)

	req := httptest.NewRequest(http.MethodPost, "/admin/totp/disable",
		jsonBody(t, map[string]string{"password": password}))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["ok"] != true {
		t.Errorf("expected ok=true, got %v", resp["ok"])
	}

	// Verify TOTP is disabled in DB
	freshAcc, err := testEnv.Repo.GetAccountByID(context.Background(), acc.ID)
	if err != nil {
		t.Fatalf("failed to fetch account: %v", err)
	}
	if freshAcc.HasTOTP() {
		t.Error("expected TOTP to be disabled")
	}
}

func TestAdminTOTPDisable_WrongPassword(t *testing.T) {
	router, _ := setupTOTPTestRouter(t)

	acc := createAccountWithPassword(t, "securepassword123")
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Session: sess})

	enableTOTPForAccount(t, acc)

	req := httptest.NewRequest(http.MethodPost, "/admin/totp/disable",
		jsonBody(t, map[string]string{"password": "wrongpassword123"}))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify TOTP is still enabled
	freshAcc, err := testEnv.Repo.GetAccountByID(context.Background(), acc.ID)
	if err != nil {
		t.Fatalf("failed to fetch account: %v", err)
	}
	if !freshAcc.HasTOTP() {
		t.Error("expected TOTP to still be enabled")
	}
}

func TestAdminTOTPDisable_NotEnabled(t *testing.T) {
	router, _ := setupTOTPTestRouter(t)

	acc := createAccountWithPassword(t, "securepassword123")
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Session: sess})

	req := httptest.NewRequest(http.MethodPost, "/admin/totp/disable",
		jsonBody(t, map[string]string{"password": "securepassword123"}))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================================
// POST /admin/totp/backup-codes (regenerate)
// ============================================================================

func TestAdminTOTPRegenerateBackupCodes_Success(t *testing.T) {
	router, _ := setupTOTPTestRouter(t)
	password := "securepassword123"

	acc := createAccountWithPassword(t, password)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Session: sess})

	_, oldCodes := enableTOTPForAccount(t, acc)

	req := httptest.NewRequest(http.MethodPost, "/admin/totp/backup-codes",
		jsonBody(t, map[string]string{"password": password}))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	newCodes, ok := resp["backupCodes"].([]any)
	if !ok || len(newCodes) != 8 {
		t.Fatalf("expected 8 new backup codes, got %v", resp["backupCodes"])
	}

	// Verify new codes are different from old ones
	newFirst := newCodes[0].(string)
	if newFirst == oldCodes[0] {
		t.Error("expected new backup codes to be different from old ones")
	}
}

func TestAdminTOTPRegenerateBackupCodes_WrongPassword(t *testing.T) {
	router, _ := setupTOTPTestRouter(t)

	acc := createAccountWithPassword(t, "securepassword123")
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Session: sess})

	enableTOTPForAccount(t, acc)

	req := httptest.NewRequest(http.MethodPost, "/admin/totp/backup-codes",
		jsonBody(t, map[string]string{"password": "wrongpassword123"}))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminTOTPRegenerateBackupCodes_NotEnabled(t *testing.T) {
	router, _ := setupTOTPTestRouter(t)

	acc := createAccountWithPassword(t, "securepassword123")
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Session: sess})

	req := httptest.NewRequest(http.MethodPost, "/admin/totp/backup-codes",
		jsonBody(t, map[string]string{"password": "securepassword123"}))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================================
// POST /admin/auth/totp/verify (unauthenticated, login flow)
// ============================================================================

func TestAdminTOTPVerify_ValidTOTPCode(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	router, _ := setupTOTPTestRouter(t)

	acc := createAccountWithPassword(t, "securepassword123")
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM sessions WHERE account_id = $1", acc.ID)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	secret, _ := enableTOTPForAccount(t, acc)

	// Generate valid TOTP code
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate TOTP code: %v", err)
	}

	// Sign a challenge token
	cfg := GetTestConfig()
	totpKey, _ := cfg.GetSessionAuthKey()
	challengeToken := auth.SignTOTPChallenge([]byte(totpKey), acc.ID, 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/totp/verify",
		jsonBody(t, map[string]string{
			"challengeToken": challengeToken,
			"code":           code,
		}))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["ok"] != true {
		t.Errorf("expected ok=true, got %v", resp["ok"])
	}

	// Verify session cookie was set
	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "MRSESSION" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Error("expected session cookie to be set after TOTP verify")
	}
}

func TestAdminTOTPVerify_ValidBackupCode(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	router, _ := setupTOTPTestRouter(t)

	acc := createAccountWithPassword(t, "securepassword123")
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM sessions WHERE account_id = $1", acc.ID)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	_, backupCodes := enableTOTPForAccount(t, acc)

	cfg := GetTestConfig()
	totpKey, _ := cfg.GetSessionAuthKey()
	challengeToken := auth.SignTOTPChallenge([]byte(totpKey), acc.ID, 5*time.Minute)

	// Use the first backup code
	req := httptest.NewRequest(http.MethodPost, "/admin/auth/totp/verify",
		jsonBody(t, map[string]string{
			"challengeToken": challengeToken,
			"code":           backupCodes[0],
		}))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify backup code was consumed (only 7 remaining)
	freshAcc, err := testEnv.Repo.GetAccountByID(context.Background(), acc.ID)
	if err != nil {
		t.Fatalf("failed to fetch account: %v", err)
	}

	encryptor := crypto.NewMySecretEncryptor(cfg)
	decrypted, err := encryptor.DecryptFromBytesWithAAD(
		freshAcc.TOTPBackupCodesEncrypted,
		crypto.AAD("accounts", "totp_backup_codes_encrypted", acc.ID),
	)
	if err != nil {
		t.Fatalf("failed to decrypt backup codes: %v", err)
	}
	var remainingCodes []string
	json.Unmarshal(decrypted, &remainingCodes)

	if len(remainingCodes) != 7 {
		t.Errorf("expected 7 remaining backup codes after consumption, got %d", len(remainingCodes))
	}
}

func TestAdminTOTPVerify_BackupCodeConsumedOnlyOnce(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	router, _ := setupTOTPTestRouter(t)

	acc := createAccountWithPassword(t, "securepassword123")
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM sessions WHERE account_id = $1", acc.ID)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	_, backupCodes := enableTOTPForAccount(t, acc)
	usedCode := backupCodes[0]

	cfg := GetTestConfig()
	totpKey, _ := cfg.GetSessionAuthKey()

	// First use — should succeed
	token1 := auth.SignTOTPChallenge([]byte(totpKey), acc.ID, 5*time.Minute)
	req1 := httptest.NewRequest(http.MethodPost, "/admin/auth/totp/verify",
		jsonBody(t, map[string]string{"challengeToken": token1, "code": usedCode}))
	req1.Header.Set("Content-Type", "application/json")
	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first backup code use: expected 200, got %d: %s", rec1.Code, rec1.Body.String())
	}

	// Second use of same code — should fail
	token2 := auth.SignTOTPChallenge([]byte(totpKey), acc.ID, 5*time.Minute)
	req2 := httptest.NewRequest(http.MethodPost, "/admin/auth/totp/verify",
		jsonBody(t, map[string]string{"challengeToken": token2, "code": usedCode}))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("second backup code use: expected 401, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

func TestAdminTOTPVerify_InvalidCode(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	router, _ := setupTOTPTestRouter(t)

	acc := createAccountWithPassword(t, "securepassword123")
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM sessions WHERE account_id = $1", acc.ID)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	enableTOTPForAccount(t, acc)

	cfg := GetTestConfig()
	totpKey, _ := cfg.GetSessionAuthKey()
	challengeToken := auth.SignTOTPChallenge([]byte(totpKey), acc.ID, 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/totp/verify",
		jsonBody(t, map[string]string{
			"challengeToken": challengeToken,
			"code":           "000000",
		}))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminTOTPVerify_ExpiredChallenge(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	router, _ := setupTOTPTestRouter(t)

	acc := createAccountWithPassword(t, "securepassword123")
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM sessions WHERE account_id = $1", acc.ID)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	secret, _ := enableTOTPForAccount(t, acc)

	code, _ := totp.GenerateCode(secret, time.Now())

	cfg := GetTestConfig()
	totpKey, _ := cfg.GetSessionAuthKey()
	// Sign with already-expired TTL
	challengeToken := auth.SignTOTPChallenge([]byte(totpKey), acc.ID, -1*time.Second)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/totp/verify",
		jsonBody(t, map[string]string{
			"challengeToken": challengeToken,
			"code":           code,
		}))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminTOTPVerify_InvalidChallengeToken(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	router, _ := setupTOTPTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/totp/verify",
		jsonBody(t, map[string]string{
			"challengeToken": "not-a-valid-token",
			"code":           "123456",
		}))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminTOTPVerify_MissingFields(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	router, _ := setupTOTPTestRouter(t)

	// Missing code
	req1 := httptest.NewRequest(http.MethodPost, "/admin/auth/totp/verify",
		jsonBody(t, map[string]string{"challengeToken": "some-token"}))
	req1.Header.Set("Content-Type", "application/json")
	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusBadRequest {
		t.Errorf("missing code: expected 400, got %d", rec1.Code)
	}

	// Missing challenge token
	req2 := httptest.NewRequest(http.MethodPost, "/admin/auth/totp/verify",
		jsonBody(t, map[string]string{"code": "123456"}))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("missing challengeToken: expected 400, got %d", rec2.Code)
	}
}

// ============================================================================
// Integration: Login → TOTP flow
// ============================================================================

func TestLoginTOTPFlow_ReturnsChallenge(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)

	// This test verifies that login returns totpRequired when TOTP is enabled.
	// We need the login route too.
	cfg := GetTestConfig()
	adminAuth, _ := auth.NewAuthService(cfg, testEnv.Repo)
	clientAuth, _ := client.NewAuthService(cfg, testEnv.Repo, nil)
	emailSvc := email.NewEmailService(true, nil)
	encryptor := crypto.NewMySecretEncryptor(cfg)
	handler := api.NewRequestHandler(testEnv.Repo, adminAuth, clientAuth, emailSvc, cfg, encryptor, nil)

	r := chi.NewRouter()
	r.Post("/admin/auth/login", handler.AdminLogin)
	r.Post("/admin/auth/totp/verify", handler.AdminTOTPVerify)

	password := "securepassword123"
	acc := createAccountWithPassword(t, password)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM sessions WHERE account_id = $1", acc.ID)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	secret, _ := enableTOTPForAccount(t, acc)

	// Step 1: Login with password → should get totpRequired
	loginReq := httptest.NewRequest(http.MethodPost, "/admin/auth/login",
		jsonBody(t, map[string]string{"email": acc.Email, "password": password}))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	r.ServeHTTP(loginRec, loginReq)

	if loginRec.Code != http.StatusOK {
		t.Fatalf("login: expected 200, got %d: %s", loginRec.Code, loginRec.Body.String())
	}

	var loginResp map[string]any
	json.NewDecoder(loginRec.Body).Decode(&loginResp)

	if loginResp["totpRequired"] != true {
		t.Fatalf("expected totpRequired=true, got %v", loginResp["totpRequired"])
	}
	challengeToken, ok := loginResp["challengeToken"].(string)
	if !ok || challengeToken == "" {
		t.Fatal("expected non-empty challengeToken")
	}

	// Should NOT have a session cookie yet
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == "MRSESSION" {
			t.Error("should not have session cookie before TOTP verify")
		}
	}

	// Step 2: Verify TOTP code → should complete login
	code, _ := totp.GenerateCode(secret, time.Now())
	verifyReq := httptest.NewRequest(http.MethodPost, "/admin/auth/totp/verify",
		jsonBody(t, map[string]string{
			"challengeToken": challengeToken,
			"code":           code,
		}))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyRec := httptest.NewRecorder()
	r.ServeHTTP(verifyRec, verifyReq)

	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify: expected 200, got %d: %s", verifyRec.Code, verifyRec.Body.String())
	}

	// Should have session cookie now
	var sessionCookie *http.Cookie
	for _, c := range verifyRec.Result().Cookies() {
		if c.Name == "MRSESSION" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Error("expected session cookie after TOTP verify")
	}
}
