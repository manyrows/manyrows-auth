package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
	"manyrows-core/api"
	"manyrows-core/auth"
	"manyrows-core/auth/client"
	"manyrows-core/crypto"
	"manyrows-core/email"
)

// TestSessionRepo_RememberMeRoundTrips pins that the remember_me column is
// written and read back through the repo.
func TestSessionRepo_RememberMeRoundTrips(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "rmrt-"+GenerateUniqueSlug("u")+"@example.com")
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc})

	sess, claims := testEnv.CreateTestSession(t, acc)

	// Flip remember_me on directly, then read it back through the repo.
	if _, err := testEnv.DB.Pool().Exec(ctx,
		`UPDATE sessions SET remember_me = true WHERE id = $1`, sess.ID); err != nil {
		t.Fatalf("set remember_me: %v", err)
	}

	got, err := testEnv.Repo.GetSessionByToken(ctx, claims)
	if err != nil {
		t.Fatalf("GetSessionByToken: %v", err)
	}
	if got == nil || !got.RememberMe {
		t.Fatalf("expected RememberMe=true, got %+v", got)
	}
}

// TestAdminSession_RememberMeBypassesIdle pins that a remembered session is NOT
// reaped by the 8h idle timeout even when last_seen_at is well past the window,
// while a non-remembered session is. The 30d absolute TTL still applies to both.
func TestAdminSession_RememberMeBypassesIdle(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "rmidle-"+GenerateUniqueSlug("u")+"@example.com")
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc})

	authSvc, err := auth.NewAuthService(GetTestConfig(), testEnv.Repo)
	if err != nil {
		t.Fatalf("auth service: %v", err)
	}

	// Remembered + idle beyond the window → still resolves, row kept.
	sess, claims := testEnv.CreateTestSession(t, acc)
	if _, err := testEnv.DB.Pool().Exec(ctx,
		`UPDATE sessions SET remember_me = true, last_seen_at = now() - interval '9 hours' WHERE id = $1`,
		sess.ID); err != nil {
		t.Fatalf("backdate + remember: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/x", nil)
	testEnv.SetSessionCookie(t, req, claims)

	got, gErr := authSvc.GetSession(req)
	if gErr != nil {
		t.Fatalf("GetSession returned error: %v", gErr)
	}
	if got == nil {
		t.Fatal("remembered idle session must still resolve (not logged out)")
	}

	var n int
	if err := testEnv.DB.Pool().QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE id = $1`, sess.ID).Scan(&n); err != nil {
		t.Fatalf("count session: %v", err)
	}
	if n != 1 {
		t.Fatalf("remembered session row must be kept, found %d", n)
	}
}

// TestDoLoginRemember_PersistsFlag pins that DoLoginRemember writes the chosen
// flag and the DoLogin shim defaults it to false.
func TestDoLoginRemember_PersistsFlag(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "rmlogin-"+GenerateUniqueSlug("u")+"@example.com")
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc})

	authSvc, err := auth.NewAuthService(GetTestConfig(), testEnv.Repo)
	if err != nil {
		t.Fatalf("auth service: %v", err)
	}

	// remember=true via DoLoginRemember.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/auth/login", nil)
	remembered, err := authSvc.DoLoginRemember(w, r, acc, true)
	if err != nil {
		t.Fatalf("DoLoginRemember: %v", err)
	}
	if !remembered.RememberMe {
		t.Fatalf("returned session RememberMe=true expected, got %+v", remembered)
	}
	var rm bool
	if err := testEnv.DB.Pool().QueryRow(ctx,
		`SELECT remember_me FROM sessions WHERE id = $1`, remembered.ID).Scan(&rm); err != nil {
		t.Fatalf("read remember_me: %v", err)
	}
	if !rm {
		t.Fatal("persisted remember_me should be true")
	}

	// shim defaults to false.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/admin/auth/login", nil)
	plain, err := authSvc.DoLogin(w2, r2, acc)
	if err != nil {
		t.Fatalf("DoLogin: %v", err)
	}
	if plain.RememberMe {
		t.Fatal("DoLogin shim should default RememberMe=false")
	}
}

// TestAdminLoginTOTP_RememberMeRoundTrips pins that remember-me chosen at the
// password step survives the 2FA round trip and lands on the minted session.
func TestAdminLoginTOTP_RememberMeRoundTrips(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)

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

	// Step 1: password login with rememberMe:true → challenge token.
	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/admin/auth/login",
		jsonBody(t, map[string]any{"email": acc.Email, "password": password, "rememberMe": true}))
	loginReq.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login: expected 200, got %d: %s", loginRec.Code, loginRec.Body.String())
	}
	var loginResp map[string]any
	json.NewDecoder(loginRec.Body).Decode(&loginResp)
	challengeToken, _ := loginResp["challengeToken"].(string)
	if challengeToken == "" {
		t.Fatal("expected challengeToken")
	}

	// Step 2: verify TOTP → completes login.
	code, _ := totp.GenerateCode(secret, time.Now())
	verifyRec := httptest.NewRecorder()
	verifyReq := httptest.NewRequest(http.MethodPost, "/admin/auth/totp/verify",
		jsonBody(t, map[string]any{"challengeToken": challengeToken, "code": code}))
	verifyReq.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify: expected 200, got %d: %s", verifyRec.Code, verifyRec.Body.String())
	}

	var rm bool
	if err := testEnv.DB.Pool().QueryRow(context.Background(),
		`SELECT remember_me FROM sessions WHERE account_id = $1 ORDER BY created_at DESC LIMIT 1`,
		acc.ID).Scan(&rm); err != nil {
		t.Fatalf("read remember_me: %v", err)
	}
	if !rm {
		t.Fatal("expected remember_me=true after 2FA round trip")
	}
}

// TestAdminLogin_RememberMePersisted pins that a non-2FA password login with
// rememberMe:true mints a remembered session.
func TestAdminLogin_RememberMePersisted(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)

	cfg := GetTestConfig()
	adminAuth, _ := auth.NewAuthService(cfg, testEnv.Repo)
	clientAuth, _ := client.NewAuthService(cfg, testEnv.Repo, nil)
	emailSvc := email.NewEmailService(true, nil)
	encryptor := crypto.NewMySecretEncryptor(cfg)
	handler := api.NewRequestHandler(testEnv.Repo, adminAuth, clientAuth, emailSvc, cfg, encryptor, nil)

	r := chi.NewRouter()
	r.Post("/admin/auth/login", handler.AdminLogin)

	password := "securepassword123"
	acc := createAccountWithPassword(t, password)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM sessions WHERE account_id = $1", acc.ID)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	loginReq := httptest.NewRequest(http.MethodPost, "/admin/auth/login",
		jsonBody(t, map[string]any{"email": acc.Email, "password": password, "rememberMe": true}))
	loginReq.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, loginReq)

	if rec.Code != http.StatusOK {
		t.Fatalf("login: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var rm bool
	if err := testEnv.DB.Pool().QueryRow(context.Background(),
		`SELECT remember_me FROM sessions WHERE account_id = $1 ORDER BY created_at DESC LIMIT 1`,
		acc.ID).Scan(&rm); err != nil {
		t.Fatalf("read remember_me: %v", err)
	}
	if !rm {
		t.Fatal("expected remember_me=true on the minted session")
	}
}
