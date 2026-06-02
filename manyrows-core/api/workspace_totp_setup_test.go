package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/core/repo"

	"github.com/gofrs/uuid/v5"
	"github.com/pquerna/otp/totp"
)

// =====================
// Setup challenge plumbing
// =====================

func signTestSetupChallenge(t *testing.T, userID, appID uuid.UUID, ttl time.Duration, rememberMe bool) string {
	t.Helper()
	cfg := GetTestConfig()
	totpKey, _ := cfg.GetSessionAuthKey()
	return auth.SignTOTPSetupChallenge([]byte(totpKey), userID, appID, ttl, rememberMe)
}

// configureAppRequire2FA flips Require2FA on a test app via the
// repo's update path. The plain CreateTestApp helper leaves it
// false, so the magic-link / OTP "needs 2FA setup" tests require
// this preparation.
func configureAppRequire2FA(t *testing.T, app *core.App) *core.App {
	t.Helper()
	updated, err := testEnv.Repo.UpdateAppRegistration(context.Background(), app.WorkspaceID, app.ProjectID, app.ID, repo.AppRegistrationUpdate{
		AllowRegistration:    app.AllowRegistration,
		AllowAccountDeletion: app.AllowAccountDeletion,
		AllowEmailChange:     app.AllowEmailChange,
		Require2FA:           true,
	})
	if err != nil {
		t.Fatalf("UpdateAppRegistration: %v", err)
	}
	return &updated
}

// preCreateUser inserts a user via the repo's GetOrCreateUser. Returns
// the user record so tests can read its ID for token signing.
func preCreateUser(t *testing.T, app *core.App, email string) *core.User {
	t.Helper()
	user, _, err := testEnv.GetOrCreateUserWithMembership(context.Background(), email, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	return user
}

// =====================
// setup-init
// =====================

func TestTOTPSetupInit_Success(t *testing.T) {
	router := setupClientAPIRouter(t)

	owner := testEnv.CreateTestAccount(t, "tsi-owner-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, owner)

	user := preCreateUser(t, app, "tsi-user-"+GenerateUniqueSlug("test")+"@example.com")
	defer cleanupUser(t, user.ID)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: owner, Workspace: ws})

	token := signTestSetupChallenge(t, user.ID, app.ID, 10*time.Minute, false)

	body, _ := json.Marshal(map[string]any{"setupChallengeToken": token})
	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/totp/setup-init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Secret string `json:"secret"`
		URI    string `json:"uri"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Secret == "" || resp.URI == "" {
		t.Errorf("expected secret + uri populated, got %+v", resp)
	}

	// Verify the secret was actually persisted on the user row.
	got, err := testEnv.Repo.GetUserByIDWithTOTP(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("GetUserByIDWithTOTP: %v", err)
	}
	if len(got.TOTPSecretEncrypted) == 0 {
		t.Error("expected TOTPSecretEncrypted to be populated after setup-init")
	}
	if got.HasTOTP() {
		t.Error("expected HasTOTP=false after setup-init (only setup-complete should enable)")
	}
}

func TestTOTPSetupInit_RejectsInvalidToken(t *testing.T) {
	router := setupClientAPIRouter(t)
	owner := testEnv.CreateTestAccount(t, "tsi-bad-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, owner)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: owner, Workspace: ws})

	body, _ := json.Marshal(map[string]any{"setupChallengeToken": "totally-bogus-token"})
	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/totp/setup-init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401: %s", rr.Code, rr.Body.String())
	}
}

func TestTOTPSetupInit_RejectsCrossAppToken(t *testing.T) {
	// A challenge token issued for app A must NOT be accepted at
	// app B's setup-init endpoint. Without this gate, an attacker
	// who somehow obtained a token for one app could enroll TOTP on
	// a victim's account in a totally different app.
	router := setupClientAPIRouter(t)

	owner := testEnv.CreateTestAccount(t, "tsi-cross-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))
	appA := testEnv.CreateTestApp(t, ws, owner)
	appB := testEnv.CreateTestApp(t, ws, owner)

	user := preCreateUser(t, appA, "tsi-cross-user-"+GenerateUniqueSlug("test")+"@example.com")
	defer cleanupUser(t, user.ID)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: owner, Workspace: ws})

	// Token bound to appA, presented at appB's URL.
	token := signTestSetupChallenge(t, user.ID, appA.ID, 10*time.Minute, false)
	body, _ := json.Marshal(map[string]any{"setupChallengeToken": token})
	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+appB.ID.String()+"/auth/totp/setup-init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401 (cross-app token): %s", rr.Code, rr.Body.String())
	}
}

func TestTOTPSetupInit_RejectsAlreadyEnabled(t *testing.T) {
	// If the user already has TOTP enabled, setup-init must refuse
	// to clobber the existing secret. This guards against a stale
	// challenge token being used to displace a working enrollment.
	router := setupClientAPIRouter(t)
	ctx := context.Background()

	owner := testEnv.CreateTestAccount(t, "tsi-enrolled-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, owner)
	user := preCreateUser(t, app, "tsi-enrolled-user-"+GenerateUniqueSlug("test")+"@example.com")
	defer cleanupUser(t, user.ID)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: owner, Workspace: ws})

	// Force-enable TOTP on this user without going through the ceremony.
	if err := testEnv.Repo.EnableUserTOTP(ctx, user.ID, time.Now().UTC(), []byte("dummy")); err != nil {
		t.Fatalf("EnableUserTOTP: %v", err)
	}

	token := signTestSetupChallenge(t, user.ID, app.ID, 10*time.Minute, false)
	body, _ := json.Marshal(map[string]any{"setupChallengeToken": token})
	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/totp/setup-init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("status %d, want 409 (already enabled): %s", rr.Code, rr.Body.String())
	}
}

// =====================
// setup-complete
// =====================

// drainSetupInit calls setup-init and returns the freshly-issued secret.
// Lets the setup-complete tests skip duplicating the init plumbing.
func drainSetupInit(t *testing.T, router http.Handler, ws *core.Workspace, app *core.App, token string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"setupChallengeToken": token})
	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/totp/setup-init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("setup-init status %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse setup-init: %v", err)
	}
	return resp.Secret
}

func TestTOTPSetupComplete_HappyPath(t *testing.T) {
	router := setupClientAPIRouter(t)
	ctx := context.Background()

	owner := testEnv.CreateTestAccount(t, "tsc-owner-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, owner)
	user := preCreateUser(t, app, "tsc-user-"+GenerateUniqueSlug("test")+"@example.com")
	defer cleanupUser(t, user.ID)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: owner, Workspace: ws})

	token := signTestSetupChallenge(t, user.ID, app.ID, 10*time.Minute, true)
	secret := drainSetupInit(t, router, ws, app, token)

	code, err := totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"setupChallengeToken": token,
		"code":                code,
	})
	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/totp/setup-complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		AccessToken  string   `json:"accessToken"`
		RefreshToken string   `json:"refreshToken"`
		BackupCodes  []string `json:"backupCodes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Errorf("expected token pair in response, got %+v", resp)
	}
	if len(resp.BackupCodes) == 0 {
		t.Error("expected backup codes in response")
	}

	// Verify the user now actually has TOTP enabled.
	got, err := testEnv.Repo.GetUserByIDWithTOTP(ctx, user.ID)
	if err != nil {
		t.Fatalf("post-complete user lookup: %v", err)
	}
	if !got.HasTOTP() {
		t.Error("expected HasTOTP=true after setup-complete")
	}
}

func TestTOTPSetupComplete_RejectsWrongCode(t *testing.T) {
	router := setupClientAPIRouter(t)

	owner := testEnv.CreateTestAccount(t, "tsc-wrong-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, owner)
	user := preCreateUser(t, app, "tsc-wrong-user-"+GenerateUniqueSlug("test")+"@example.com")
	defer cleanupUser(t, user.ID)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: owner, Workspace: ws})

	token := signTestSetupChallenge(t, user.ID, app.ID, 10*time.Minute, false)
	_ = drainSetupInit(t, router, ws, app, token)

	body, _ := json.Marshal(map[string]any{
		"setupChallengeToken": token,
		"code":                "000000", // wrong code
	})
	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/totp/setup-complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401: %s", rr.Code, rr.Body.String())
	}

	// Verify TOTP was NOT enabled — wrong code must not enroll.
	got, err := testEnv.Repo.GetUserByIDWithTOTP(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("user lookup: %v", err)
	}
	if got.HasTOTP() {
		t.Error("TOTP should NOT be enabled after a failed setup-complete")
	}
}

func TestTOTPSetupComplete_RequiresPriorInit(t *testing.T) {
	// setup-complete called before setup-init must reject — there's
	// no persisted secret to validate the code against. Without this
	// gate, a misordered client could appear to "succeed" with any
	// code against an empty secret.
	router := setupClientAPIRouter(t)

	owner := testEnv.CreateTestAccount(t, "tsc-noinit-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, owner)
	user := preCreateUser(t, app, "tsc-noinit-user-"+GenerateUniqueSlug("test")+"@example.com")
	defer cleanupUser(t, user.ID)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: owner, Workspace: ws})

	token := signTestSetupChallenge(t, user.ID, app.ID, 10*time.Minute, false)

	body, _ := json.Marshal(map[string]any{
		"setupChallengeToken": token,
		"code":                "123456",
	})
	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/totp/setup-complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400 (no setup-init): %s", rr.Code, rr.Body.String())
	}
}

func TestTOTPSetupComplete_RejectsExpiredToken(t *testing.T) {
	router := setupClientAPIRouter(t)

	owner := testEnv.CreateTestAccount(t, "tsc-expired-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, owner)
	user := preCreateUser(t, app, "tsc-expired-user-"+GenerateUniqueSlug("test")+"@example.com")
	defer cleanupUser(t, user.ID)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: owner, Workspace: ws})

	expired := signTestSetupChallenge(t, user.ID, app.ID, -1*time.Second, false)

	body, _ := json.Marshal(map[string]any{
		"setupChallengeToken": expired,
		"code":                "123456",
	})
	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/totp/setup-complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401 (expired token): %s", rr.Code, rr.Body.String())
	}
}
