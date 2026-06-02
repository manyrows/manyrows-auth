package api_test

// Integration tests for the install-wide signing-key endpoints. Use
// the live test DB so the system_secrets persistence and the
// requireSuperAdmin guard are both exercised end-to-end.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"manyrows-core/api"
	"manyrows-core/auth"
	"manyrows-core/auth/client"
	"manyrows-core/core"
	"manyrows-core/email"
)

func setupSecurityRouter(t *testing.T) (*chi.Mux, *auth.Service, *client.AuthService) {
	t.Helper()

	cfg := GetTestConfig()
	adminAuthService, err := auth.NewAuthService(cfg, testEnv.Repo)
	if err != nil {
		t.Fatalf("admin auth service: %v", err)
	}
	clientAuthService, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("client auth service: %v", err)
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
	r.Mount("/admin", adminRouter)
	adminRouter.Get("/security/signing-keys", requestHandler.GetSigningKeys)
	adminRouter.Post("/security/signing-keys/rotate", requestHandler.PostRotateSigningKey)
	adminRouter.Post("/security/signing-keys/retire-previous", requestHandler.PostRetirePreviousSigningKey)

	return r, adminAuthService, clientAuthService
}

// withSuperAdmin sets the in-memory super-admin email to acc's email
// for the duration of the test. system_secrets is left alone — the
// rotation handlers only care about the in-memory check.
func withSuperAdmin(t *testing.T, email string) {
	t.Helper()
	prev := core.GetSuperAdminEmail()
	core.SetSuperAdminEmail(email)
	t.Cleanup(func() { core.SetSuperAdminEmail(prev) })
}

type signingKeyResp struct {
	Current struct {
		KID string `json:"kid"`
	} `json:"current"`
	Previous *struct {
		KID string `json:"kid"`
	} `json:"previous,omitempty"`
}

func TestSigningKeys_NotLoggedIn_Returns401(t *testing.T) {
	router, _, _ := setupSecurityRouter(t)

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/admin/security/signing-keys"},
		{http.MethodPost, "/admin/security/signing-keys/rotate"},
		{http.MethodPost, "/admin/security/signing-keys/retire-previous"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: want 401, got %d (%s)", tc.method, tc.path, rr.Code, rr.Body.String())
		}
	}
}

func TestSigningKeys_NonSuperAdmin_Returns403(t *testing.T) {
	router, _, _ := setupSecurityRouter(t)

	// Logged-in admin who is NOT the super admin.
	acc := testEnv.CreateTestAccount(t, "non-super-"+GenerateUniqueSlug("t")+"@example.com")
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Session: sess})

	withSuperAdmin(t, "someone-else@example.com")

	req := httptest.NewRequest(http.MethodGet, "/admin/security/signing-keys", nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("non-super GET: want 403, got %d (%s)", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/security/signing-keys/rotate", nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("non-super rotate: want 403, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestSigningKeys_StatusReturnsCurrentKID(t *testing.T) {
	router, _, _ := setupSecurityRouter(t)

	acc := testEnv.CreateTestAccount(t, "super-status-"+GenerateUniqueSlug("t")+"@example.com")
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Session: sess})
	withSuperAdmin(t, acc.Email)

	req := httptest.NewRequest(http.MethodGet, "/admin/security/signing-keys", nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var got signingKeyResp
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, rr.Body.String())
	}
	if got.Current.KID == "" {
		t.Error("expected non-empty current.kid")
	}
}

func TestSigningKeys_RotateProducesNewKID_AndExposesPrevious(t *testing.T) {
	router, _, _ := setupSecurityRouter(t)

	acc := testEnv.CreateTestAccount(t, "super-rotate-"+GenerateUniqueSlug("t")+"@example.com")
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Session: sess})
	withSuperAdmin(t, acc.Email)

	// Capture pre-rotation kid.
	preReq := httptest.NewRequest(http.MethodGet, "/admin/security/signing-keys", nil)
	testEnv.SetSessionCookie(t, preReq, claims)
	preRR := httptest.NewRecorder()
	router.ServeHTTP(preRR, preReq)
	var pre signingKeyResp
	if err := json.Unmarshal(preRR.Body.Bytes(), &pre); err != nil {
		t.Fatalf("pre unmarshal: %v", err)
	}

	// Rotate.
	rotReq := httptest.NewRequest(http.MethodPost, "/admin/security/signing-keys/rotate", nil)
	testEnv.SetSessionCookie(t, rotReq, claims)
	rotRR := httptest.NewRecorder()
	router.ServeHTTP(rotRR, rotReq)
	if rotRR.Code != http.StatusOK {
		t.Fatalf("rotate: want 200, got %d (%s)", rotRR.Code, rotRR.Body.String())
	}
	var post signingKeyResp
	if err := json.Unmarshal(rotRR.Body.Bytes(), &post); err != nil {
		t.Fatalf("post unmarshal: %v", err)
	}

	if post.Current.KID == "" {
		t.Fatal("post-rotate current.kid empty")
	}
	if post.Current.KID == pre.Current.KID {
		t.Error("post-rotate current.kid should differ from pre-rotate")
	}
	if post.Previous == nil {
		t.Fatal("post-rotate previous should be set")
	}
	if post.Previous.KID != pre.Current.KID {
		t.Errorf("post-rotate previous.kid (%s) should match pre-rotate current (%s)",
			post.Previous.KID, pre.Current.KID)
	}

	// Reset for any subsequent test in this file: rotate state lives
	// in system_secrets and the AuthService caches the keyset
	// in-process. Retire the previous so the row is gone; the next
	// test's NewAuthService will boot with just a current.
	retireReq := httptest.NewRequest(http.MethodPost, "/admin/security/signing-keys/retire-previous", nil)
	testEnv.SetSessionCookie(t, retireReq, claims)
	retireRR := httptest.NewRecorder()
	router.ServeHTTP(retireRR, retireReq)
	if retireRR.Code != http.StatusOK {
		t.Fatalf("cleanup retire: %d (%s)", retireRR.Code, retireRR.Body.String())
	}
}

func TestSigningKeys_RetirePrevious_DropsItFromStatus(t *testing.T) {
	router, _, _ := setupSecurityRouter(t)

	acc := testEnv.CreateTestAccount(t, "super-retire-"+GenerateUniqueSlug("t")+"@example.com")
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Session: sess})
	withSuperAdmin(t, acc.Email)

	// Rotate to create a previous slot.
	rotReq := httptest.NewRequest(http.MethodPost, "/admin/security/signing-keys/rotate", nil)
	testEnv.SetSessionCookie(t, rotReq, claims)
	rotRR := httptest.NewRecorder()
	router.ServeHTTP(rotRR, rotReq)
	if rotRR.Code != http.StatusOK {
		t.Fatalf("rotate: %d", rotRR.Code)
	}

	// Retire it.
	retireReq := httptest.NewRequest(http.MethodPost, "/admin/security/signing-keys/retire-previous", nil)
	testEnv.SetSessionCookie(t, retireReq, claims)
	retireRR := httptest.NewRecorder()
	router.ServeHTTP(retireRR, retireReq)
	if retireRR.Code != http.StatusOK {
		t.Fatalf("retire: want 200, got %d (%s)", retireRR.Code, retireRR.Body.String())
	}
	var got signingKeyResp
	if err := json.Unmarshal(retireRR.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Previous != nil {
		t.Errorf("post-retire previous should be nil, got %+v", got.Previous)
	}
	if got.Current.KID == "" {
		t.Error("post-retire current.kid should still be set")
	}
}

func TestSigningKeys_RetirePrevious_NoOpWhenNoPrevious(t *testing.T) {
	router, _, _ := setupSecurityRouter(t)

	acc := testEnv.CreateTestAccount(t, "super-retire-noop-"+GenerateUniqueSlug("t")+"@example.com")
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Session: sess})
	withSuperAdmin(t, acc.Email)

	// No prior rotate — retire should still succeed (idempotent).
	retireReq := httptest.NewRequest(http.MethodPost, "/admin/security/signing-keys/retire-previous", nil)
	testEnv.SetSessionCookie(t, retireReq, claims)
	retireRR := httptest.NewRecorder()
	router.ServeHTTP(retireRR, retireReq)
	if retireRR.Code != http.StatusOK {
		t.Fatalf("retire-noop: want 200, got %d (%s)", retireRR.Code, retireRR.Body.String())
	}
	var got signingKeyResp
	if err := json.Unmarshal(retireRR.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Previous != nil {
		t.Errorf("expected previous=nil on no-op retire, got %+v", got.Previous)
	}
}
