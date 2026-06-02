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
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// setupProfileRouter creates a router for profile tests
func setupProfileRouter(t *testing.T) *chi.Mux {
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

	adminRouter.Post("/profile/name", requestHandler.UpdateAccountName)
	adminRouter.Post("/profile/email/change", requestHandler.RequestEmailChange)
	adminRouter.Post("/profile/email/verify", requestHandler.VerifyEmailChange)

	r.Mount("/admin", adminRouter)

	return r
}

// TestUpdateAccountName_Success tests updating account name
func TestUpdateAccountName_Success(t *testing.T) {
	router := setupProfileRouter(t)

	email := "profile-name-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"name": "Updated Name",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/profile/name", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	// Verify the name was updated
	updated, err := testEnv.Repo.GetAccountByID(context.Background(), acc.ID)
	if err != nil {
		t.Fatalf("failed to get account: %v", err)
	}
	if updated.Name != "Updated Name" {
		t.Errorf("expected name 'Updated Name', got '%s'", updated.Name)
	}
}

// TestUpdateAccountName_EmptyName tests updating with empty name
func TestUpdateAccountName_EmptyName(t *testing.T) {
	router := setupProfileRouter(t)

	email := "profile-empty-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"name": "",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/profile/name", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

// TestUpdateAccountName_Unauthenticated tests updating name without auth
func TestUpdateAccountName_Unauthenticated(t *testing.T) {
	router := setupProfileRouter(t)

	body := map[string]any{
		"name": "New Name",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/profile/name", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// TestRequestEmailChange_Success tests requesting email change
func TestRequestEmailChange_Success(t *testing.T) {
	router := setupProfileRouter(t)

	email := "profile-email-" + GenerateUniqueSlug("test") + "@example.com"
	password := "validPassword123"
	acc := createTestAccountWithPasswordForProfile(t, email, password)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM email_change_requests WHERE account_id = $1", acc.ID)
	}()

	newEmail := "new-email-" + GenerateUniqueSlug("test") + "@example.com"
	body := map[string]any{
		"newEmail": newEmail,
		"password": password,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/profile/email/change", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
}

// createTestAccountWithPasswordForProfile creates a test account with a password
func createTestAccountWithPasswordForProfile(t *testing.T, emailAddr, password string) *core.Account {
	t.Helper()
	ctx := context.Background()

	acc := testEnv.CreateTestAccount(t, emailAddr)

	// Hash the password and update the account
	hash, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	pool := testEnv.DB.Pool()
	_, err = pool.Exec(ctx, "UPDATE accounts SET password_hash = $1, password_set_at = $2 WHERE id = $3",
		hash, time.Now().UTC(), acc.ID)
	if err != nil {
		t.Fatalf("failed to update account password: %v", err)
	}

	return acc
}

// TestRequestEmailChange_InvalidEmail tests requesting with invalid email
func TestRequestEmailChange_InvalidEmail(t *testing.T) {
	router := setupProfileRouter(t)

	email := "profile-inv-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"newEmail": "not-an-email",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/profile/email/change", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

// TestRequestEmailChange_SameEmail tests requesting change to same email
func TestRequestEmailChange_SameEmail(t *testing.T) {
	router := setupProfileRouter(t)

	email := "profile-same-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"newEmail": email, // same as current
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/profile/email/change", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Should reject changing to the same email
	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusConflict {
		t.Errorf("expected status %d or %d, got %d: %s", http.StatusBadRequest, http.StatusConflict, rr.Code, rr.Body.String())
	}
}

// TestRequestEmailChange_Unauthenticated tests requesting without auth
func TestRequestEmailChange_Unauthenticated(t *testing.T) {
	router := setupProfileRouter(t)

	body := map[string]any{
		"newEmail": "new@example.com",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/profile/email/change", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// TestVerifyEmailChange_InvalidCode tests verifying with invalid code
func TestVerifyEmailChange_InvalidCode(t *testing.T) {
	router := setupProfileRouter(t)

	email := "profile-verify-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"code": "000000",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/profile/email/verify", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d or %d, got %d: %s", http.StatusUnauthorized, http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

// TestVerifyEmailChange_BurnsAfterMaxAttempts confirms the per-OTP cap
// (M8): after maxEmailChangeOTPAttempts wrong guesses the OTP row is
// burned (used_at set, attempts == cap), and a subsequent guess hits
// the saturated-row early-reject path with badRequest instead of
// invalidCode. Belt-and-braces against the IP/subject windows.
func TestVerifyEmailChange_BurnsAfterMaxAttempts(t *testing.T) {
	router := setupProfileRouter(t)

	const maxAttempts = 5

	emailAddr := "profile-burn-" + GenerateUniqueSlug("test") + "@example.com"
	password := "validPassword123"
	acc := createTestAccountWithPasswordForProfile(t, emailAddr, password)
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM account_email_change_otps WHERE account_id = $1", acc.ID)
	}()

	// Issue a fresh OTP.
	newEmail := "burn-target-" + GenerateUniqueSlug("test") + "@example.com"
	reqBody, _ := json.Marshal(map[string]any{"newEmail": newEmail, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/admin/profile/email/change", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("could not seed OTP: status %d body %s", rr.Code, rr.Body.String())
	}

	verify := func(code string) int {
		body, _ := json.Marshal(map[string]any{"code": code})
		r := httptest.NewRequest(http.MethodPost, "/admin/profile/email/verify", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		testEnv.SetSessionCookie(t, r, claims)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w.Code
	}

	// First (maxAttempts - 1) wrong codes return 401 invalidCode but
	// leave the OTP usable.
	for i := 0; i < maxAttempts-1; i++ {
		if got := verify("000000"); got != http.StatusUnauthorized {
			t.Fatalf("wrong-code attempt %d: expected %d, got %d", i+1, http.StatusUnauthorized, got)
		}
	}

	// The Nth wrong code should also return 401 (still wrong) but
	// burn the OTP under the hood.
	if got := verify("000000"); got != http.StatusUnauthorized {
		t.Fatalf("max-th attempt: expected %d, got %d", http.StatusUnauthorized, got)
	}

	// Confirm the row state in the DB: attempts hit the cap and used_at
	// is set.
	var attempts int
	var usedAt *time.Time
	err := testEnv.DB.Pool().QueryRow(
		context.Background(),
		`SELECT attempts, used_at FROM account_email_change_otps WHERE account_id = $1 ORDER BY created_at DESC LIMIT 1`,
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

	// A further attempt now finds no active OTP and falls into the
	// "no active OTP" branch (badRequest), not invalidCode.
	if got := verify("000000"); got != http.StatusBadRequest {
		t.Errorf("post-burn attempt: expected %d, got %d", http.StatusBadRequest, got)
	}
}

// TestVerifyEmailChange_Unauthenticated tests verifying without auth
func TestVerifyEmailChange_Unauthenticated(t *testing.T) {
	router := setupProfileRouter(t)

	body := map[string]any{
		"code": "123456",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/profile/email/verify", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}
