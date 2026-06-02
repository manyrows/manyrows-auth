package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"manyrows-core/api"
	"manyrows-core/auth"
	"manyrows-core/auth/client"
	"manyrows-core/core"
	"manyrows-core/crypto/passwordhash"
	"manyrows-core/email"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// setupAuthTestRouter creates a minimal router for testing auth endpoints.
// Resets the pinned super_admin_email before each test so the admin-register
// gate doesn't leak across tests: once any test successfully registers (which
// pins the email), subsequent tests with different emails would otherwise
// get error.registrationDisabled.
func setupAuthTestRouter(t *testing.T) *chi.Mux {
	t.Helper()

	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		"DELETE FROM system_secrets WHERE name = 'super_admin_email'",
	); err != nil {
		t.Fatalf("reset super_admin_email: %v", err)
	}
	core.SetSuperAdminEmail("")

	conf := GetTestConfig()

	adminAuthService, err := auth.NewAuthService(conf, testEnv.Repo)
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}

	clientAuthService, err := client.NewAuthService(conf, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("failed to create client auth service: %v", err)
	}

	emailService := email.NewEmailService(true, nil) // dev mode - doesn't send real emails

	requestHandler := api.NewRequestHandler(
		testEnv.Repo,
		adminAuthService,
		clientAuthService,
		emailService,
		conf,
		nil,
		nil,
	)

	r := chi.NewRouter()

	// Public auth endpoints (no auth required)
	r.Post("/admin/auth/register", requestHandler.AdminRegister)
	r.Post("/admin/auth/login", requestHandler.AdminLogin)
	r.Post("/admin/auth/forgot", requestHandler.AdminForgotPassword)
	r.Post("/admin/auth/reset", requestHandler.AdminResetPassword)

	// Authenticated auth endpoints
	r.Group(func(r chi.Router) {
		// Auth middleware
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				acc, _, err := adminAuthService.GetLoggedInAccount(r)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				if acc == nil {
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}
				ctx := core.WithAdminAccount(r.Context(), acc)
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		})

		r.Post("/admin/auth/validate", requestHandler.SendValidateEmail)
		r.Post("/admin/auth/verify", requestHandler.VerifyValidationCode)
		r.Post("/admin/logout", requestHandler.AdminLogout)
	})

	return r
}

// ============================================================================
// POST /admin/auth/register - Register
// ============================================================================

func TestAdminRegister_Success(t *testing.T) {
	router := setupAuthTestRouter(t)

	email := "test-register-" + GenerateUniqueSlug("user") + "@test.com"
	body := map[string]string{
		"email":    email,
		"password": "securepassword123",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["ok"] != true {
		t.Errorf("expected ok=true, got %v", resp["ok"])
	}

	// Verify account was created
	acc, vr, err := testEnv.Repo.GetAccountByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("failed to get account: %v", err)
	}
	if !vr.Ok() || acc == nil {
		t.Fatal("expected account to be created")
	}

	// Cleanup
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM sessions WHERE account_id = $1", acc.ID)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	// Verify session cookie was set (user is logged in)
	cookies := rec.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "MRSESSION" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Error("expected session cookie to be set")
	}
}

func TestAdminRegister_MissingEmail(t *testing.T) {
	router := setupAuthTestRouter(t)

	body := map[string]string{
		"password": "securepassword123",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

func TestAdminRegister_MissingPassword(t *testing.T) {
	router := setupAuthTestRouter(t)

	body := map[string]string{
		"email": "test@test.com",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

func TestAdminRegister_PasswordTooShort(t *testing.T) {
	router := setupAuthTestRouter(t)

	body := map[string]string{
		"email":    "test@test.com",
		"password": "short", // Less than 10 characters
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

func TestAdminRegister_InvalidEmail(t *testing.T) {
	router := setupAuthTestRouter(t)

	body := map[string]string{
		"email":    "not-an-email",
		"password": "securepassword123",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

func TestAdminRegister_DuplicateEmail(t *testing.T) {
	// First create an account
	email := "test-duplicate-" + GenerateUniqueSlug("user") + "@test.com"
	acc := testEnv.CreateTestAccount(t, email)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	router := setupAuthTestRouter(t)

	body := map[string]string{
		"email":    email,
		"password": "securepassword123",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Returns 200 OK with {"ok": true} to avoid leaking account existence.
	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
}

func TestAdminRegister_InvalidJSON(t *testing.T) {
	router := setupAuthTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/register", strings.NewReader("not valid json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

// ============================================================================
// POST /admin/auth/login - Login
// ============================================================================

func TestAdminLogin_Success(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)

	// Create account with password
	email := "test-login-" + GenerateUniqueSlug("user") + "@test.com"
	password := "securepassword123"

	// Hash password
	hash, _ := passwordhash.Hash(password)

	// Create account with password directly in DB
	acc := testEnv.CreateTestAccount(t, email)
	testEnv.DB.Pool().Exec(context.Background(),
		"UPDATE accounts SET password_hash = $1, password_set_at = now() WHERE id = $2",
		hash, acc.ID)

	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM sessions WHERE account_id = $1", acc.ID)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	router := setupAuthTestRouter(t)

	body := map[string]string{
		"email":    email,
		"password": password,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["ok"] != true {
		t.Errorf("expected ok=true, got %v", resp["ok"])
	}

	// Verify session cookie was set
	cookies := rec.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "MRSESSION" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Error("expected session cookie to be set")
	}
}

func TestAdminLogin_WrongPassword(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)

	// Create account with password
	email := "test-login-wrong-" + GenerateUniqueSlug("user") + "@test.com"
	password := "securepassword123"

	hash, _ := passwordhash.Hash(password)

	acc := testEnv.CreateTestAccount(t, email)
	testEnv.DB.Pool().Exec(context.Background(),
		"UPDATE accounts SET password_hash = $1, password_set_at = now() WHERE id = $2",
		hash, acc.ID)

	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	router := setupAuthTestRouter(t)

	body := map[string]string{
		"email":    email,
		"password": "wrongpassword123",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
}

func TestAdminLogin_NonExistentAccount(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)

	router := setupAuthTestRouter(t)

	body := map[string]string{
		"email":    "nonexistent-" + GenerateUniqueSlug("user") + "@test.com",
		"password": "securepassword123",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
}

func TestAdminLogin_MissingEmail(t *testing.T) {
	router := setupAuthTestRouter(t)

	body := map[string]string{
		"password": "securepassword123",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

func TestAdminLogin_MissingPassword(t *testing.T) {
	router := setupAuthTestRouter(t)

	body := map[string]string{
		"email": "test@test.com",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

func TestAdminLogin_AccountWithoutPassword(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)

	// Create account without password (e.g., created via magic link)
	email := "test-login-nopw-" + GenerateUniqueSlug("user") + "@test.com"
	acc := testEnv.CreateTestAccount(t, email)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	router := setupAuthTestRouter(t)

	body := map[string]string{
		"email":    email,
		"password": "securepassword123",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Should fail because account has no password set
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
}

// ============================================================================
// POST /admin/auth/forgot - Forgot Password
// ============================================================================

func TestAdminForgotPassword_Success(t *testing.T) {
	// Create account
	email := "test-forgot-" + GenerateUniqueSlug("user") + "@test.com"
	acc := testEnv.CreateTestAccount(t, email)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM account_password_reset_otps WHERE account_id = $1", acc.ID)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	router := setupAuthTestRouter(t)

	body := map[string]string{
		"email": email,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/forgot", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["ok"] != true {
		t.Errorf("expected ok=true, got %v", resp["ok"])
	}
}

func TestAdminForgotPassword_NonExistentEmail(t *testing.T) {
	router := setupAuthTestRouter(t)

	// Should still return OK to not leak whether email exists
	body := map[string]string{
		"email": "nonexistent-" + GenerateUniqueSlug("user") + "@test.com",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/forgot", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Should return OK to not leak email existence
	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
}

func TestAdminForgotPassword_InvalidEmail(t *testing.T) {
	router := setupAuthTestRouter(t)

	body := map[string]string{
		"email": "not-an-email",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/forgot", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

func TestAdminForgotPassword_MissingEmail(t *testing.T) {
	router := setupAuthTestRouter(t)

	body := map[string]string{}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/forgot", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

// ============================================================================
// POST /admin/auth/reset - Reset Password
// ============================================================================

func TestAdminResetPassword_InvalidCode(t *testing.T) {
	// Create account
	email := "test-reset-" + GenerateUniqueSlug("user") + "@test.com"
	acc := testEnv.CreateTestAccount(t, email)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	router := setupAuthTestRouter(t)

	body := map[string]string{
		"email":    email,
		"code":     "123456", // Invalid code
		"password": "newpassword123",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/reset", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
}

func TestAdminResetPassword_InvalidCodeFormat(t *testing.T) {
	router := setupAuthTestRouter(t)

	body := map[string]string{
		"email":    "test@test.com",
		"code":     "abc", // Not 6 digits
		"password": "newpassword123",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/reset", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

func TestAdminResetPassword_PasswordTooShort(t *testing.T) {
	router := setupAuthTestRouter(t)

	body := map[string]string{
		"email":    "test@test.com",
		"code":     "123456",
		"password": "short", // Less than 10 characters
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/reset", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

// TestAdminResetPassword_BurnsAfterMaxAttempts mirrors the M8 test for
// the admin email-change OTP, applied to the password-reset flow:
// after otpMaxAttempts wrong codes the OTP row should have attempts==cap
// and used_at!=NULL, so a fresh attempt finds no active OTP. Belt-and-
// braces against the IP/subject windows on this much higher-stakes flow.
func TestAdminResetPassword_BurnsAfterMaxAttempts(t *testing.T) {
	const maxAttempts = 5

	emailAddr := "test-reset-burn-" + GenerateUniqueSlug("user") + "@test.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM account_password_reset_otps WHERE account_id = $1", acc.ID)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	router := setupAuthTestRouter(t)

	// Issue a fresh OTP via the forgot endpoint.
	forgotBody, _ := json.Marshal(map[string]string{"email": emailAddr})
	freq := httptest.NewRequest(http.MethodPost, "/admin/auth/forgot", bytes.NewReader(forgotBody))
	freq.Header.Set("Content-Type", "application/json")
	frec := httptest.NewRecorder()
	router.ServeHTTP(frec, freq)
	if frec.Code != http.StatusOK {
		t.Fatalf("could not seed reset OTP: status %d body %s", frec.Code, frec.Body.String())
	}

	tryReset := func(code string) int {
		body, _ := json.Marshal(map[string]string{
			"email":    emailAddr,
			"code":     code,
			"password": "newpassword123",
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/auth/reset", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}

	for i := 0; i < maxAttempts; i++ {
		if got := tryReset("000000"); got != http.StatusUnauthorized {
			t.Fatalf("wrong-code attempt %d: expected %d, got %d", i+1, http.StatusUnauthorized, got)
		}
	}

	var attempts int
	var usedAt *time.Time
	err := testEnv.DB.Pool().QueryRow(
		context.Background(),
		`SELECT attempts, used_at FROM account_password_reset_otps WHERE account_id = $1 ORDER BY created_at DESC LIMIT 1`,
		acc.ID,
	).Scan(&attempts, &usedAt)
	if err != nil {
		t.Fatalf("could not read OTP row: %v", err)
	}
	if attempts != maxAttempts {
		t.Errorf("expected attempts=%d, got %d", maxAttempts, attempts)
	}
	if usedAt == nil {
		t.Errorf("expected used_at to be set after max attempts (OTP burned)")
	}
}

func TestAdminResetPassword_NonExistentAccount(t *testing.T) {
	router := setupAuthTestRouter(t)

	body := map[string]string{
		"email":    "nonexistent-" + GenerateUniqueSlug("user") + "@test.com",
		"code":     "123456",
		"password": "newpassword123",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/reset", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
}

// ============================================================================
// POST /admin/auth/validate - Send Validation Email (requires auth)
// ============================================================================

func TestSendValidateEmail_Unauthenticated(t *testing.T) {
	router := setupAuthTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/validate", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
}

func TestSendValidateEmail_Success(t *testing.T) {
	email := "test-validate-" + GenerateUniqueSlug("user") + "@test.com"
	acc := testEnv.CreateTestAccount(t, email)
	sess, claims := testEnv.CreateTestSession(t, acc)

	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM account_email_otps WHERE account_id = $1", acc.ID)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", sess.ID)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	router := setupAuthTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/validate", nil)
	testEnv.SetSessionCookie(t, req, claims)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["ok"] != true {
		t.Errorf("expected ok=true, got %v", resp["ok"])
	}
}

func TestSendValidateEmail_AlreadyValidated(t *testing.T) {
	email := "test-validate-done-" + GenerateUniqueSlug("user") + "@test.com"
	acc := testEnv.CreateTestAccount(t, email)
	sess, claims := testEnv.CreateTestSession(t, acc)

	// Mark account as validated
	testEnv.DB.Pool().Exec(context.Background(), "UPDATE accounts SET validated_at = now() WHERE id = $1", acc.ID)

	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", sess.ID)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	router := setupAuthTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/validate", nil)
	testEnv.SetSessionCookie(t, req, claims)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["ok"] != true {
		t.Errorf("expected ok=true, got %v", resp["ok"])
	}
	if resp["validated"] != true {
		t.Errorf("expected validated=true, got %v", resp["validated"])
	}
}

// ============================================================================
// POST /admin/auth/verify - Verify Validation Code (requires auth)
// ============================================================================

func TestVerifyValidationCode_Unauthenticated(t *testing.T) {
	router := setupAuthTestRouter(t)

	body := map[string]string{
		"code": "123456",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/verify", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
}

func TestVerifyValidationCode_InvalidCode(t *testing.T) {
	email := "test-verify-" + GenerateUniqueSlug("user") + "@test.com"
	acc := testEnv.CreateTestAccount(t, email)
	sess, claims := testEnv.CreateTestSession(t, acc)

	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", sess.ID)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	router := setupAuthTestRouter(t)

	body := map[string]string{
		"code": "123456", // Invalid code - no OTP exists
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/verify", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
}

func TestVerifyValidationCode_InvalidCodeFormat(t *testing.T) {
	email := "test-verify-fmt-" + GenerateUniqueSlug("user") + "@test.com"
	acc := testEnv.CreateTestAccount(t, email)
	sess, claims := testEnv.CreateTestSession(t, acc)

	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", sess.ID)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	router := setupAuthTestRouter(t)

	body := map[string]string{
		"code": "abc", // Not 6 digits
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/verify", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

func TestVerifyValidationCode_AlreadyValidated(t *testing.T) {
	email := "test-verify-done-" + GenerateUniqueSlug("user") + "@test.com"
	acc := testEnv.CreateTestAccount(t, email)
	sess, claims := testEnv.CreateTestSession(t, acc)

	// Mark account as validated
	testEnv.DB.Pool().Exec(context.Background(), "UPDATE accounts SET validated_at = now() WHERE id = $1", acc.ID)

	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", sess.ID)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	router := setupAuthTestRouter(t)

	body := map[string]string{
		"code": "123456",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/verify", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Should return OK with validated=true (idempotent)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["validated"] != true {
		t.Errorf("expected validated=true, got %v", resp["validated"])
	}
}

// ============================================================================
// POST /admin/logout - Logout (requires auth)
// ============================================================================

func TestAdminLogout_Success(t *testing.T) {
	email := "test-logout-" + GenerateUniqueSlug("user") + "@test.com"
	acc := testEnv.CreateTestAccount(t, email)
	sess, claims := testEnv.CreateTestSession(t, acc)

	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	router := setupAuthTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/logout", nil)
	testEnv.SetSessionCookie(t, req, claims)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	// Verify session was deleted
	var count int
	testEnv.DB.Pool().QueryRow(context.Background(),
		"SELECT COUNT(*) FROM sessions WHERE id = $1", sess.ID).Scan(&count)
	if count != 0 {
		t.Error("expected session to be deleted")
	}
}

func TestAdminLogout_Unauthenticated(t *testing.T) {
	router := setupAuthTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/logout", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
}
