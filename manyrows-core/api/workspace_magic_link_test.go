package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
)

// =====================
// Magic-link helpers
// =====================

const testAppURL = "https://example.test"

// configureAppForMagicLink sets the app's PrimaryAuthMethod to magicLink
// and ensures it has an AppURL — both are required for the magic-link
// flow. Mirrors the admin handler validation in HandleUpdateAppAuthMethodConfig.
func configureAppForMagicLink(t *testing.T, app *core.App) *core.App {
	t.Helper()
	ctx := context.Background()

	appURL := testAppURL
	updated, err := testEnv.Repo.UpdateAppEnabled(ctx, app.WorkspaceID, app.ProjectID, app.ID, app.Enabled, repo.AppCoreUpdate{AppURL: &appURL})
	if err != nil {
		t.Fatalf("set app URL: %v", err)
	}
	updated, err = testEnv.Repo.UpdateAppPrimaryAuthMethod(ctx, app.WorkspaceID, app.ProjectID, app.ID, core.PrimaryAuthMethodMagicLink)
	if err != nil {
		t.Fatalf("set magicLink auth: %v", err)
	}
	return &updated
}

// generateTestMagicToken matches the token shape produced by
// auth.Service.NewMagicToken — 32 random bytes, base64url-encoded raw,
// sha256-hex of the encoded string for the on-disk hash.
func generateTestMagicToken(t *testing.T) (rawToken, tokenHash string) {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	rawToken = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(rawToken))
	tokenHash = hex.EncodeToString(sum[:])
	return
}

// insertTestMagicLink writes a magic_link row and returns the raw token.
func insertTestMagicLink(t *testing.T, app *core.App, email string) string {
	t.Helper()
	raw, hash := generateTestMagicToken(t)
	err := testEnv.Repo.CreateMagicLink(context.Background(), repo.CreateMagicLinkParams{
		Purpose:   "app_login:" + app.ID.String(),
		Email:     email,
		TokenHash: hash,
		ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
	})
	if err != nil {
		t.Fatalf("CreateMagicLink: %v", err)
	}
	return raw
}

func cleanupMagicLinks(t *testing.T, email string) {
	t.Helper()
	pool := testEnv.DB.Pool()
	_, _ = pool.Exec(context.Background(), "DELETE FROM magic_links WHERE lower(email) = lower($1)", email)
}

// =====================
// Request endpoint
// =====================

func TestRequestMagicLink_Success(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "ml-req-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	app = configureAppForMagicLink(t, app)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer cleanupMagicLinks(t, emailAddr)

	body, _ := json.Marshal(map[string]any{"email": emailAddr})
	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/request-magic-link", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp["ok"] != true {
		t.Errorf("expected ok:true, got %v", resp)
	}
}

func TestRequestMagicLink_RejectedWhenNotMagicLinkMode(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "ml-mode-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	// Default app is PrimaryAuthMethodPassword — leave it as-is.
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body, _ := json.Marshal(map[string]any{"email": emailAddr})
	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/request-magic-link", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403 (auth method disabled): %s", rr.Code, rr.Body.String())
	}
}

func TestRequestMagicLink_RejectedWhenNoAppURL(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "ml-noappurl-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	// Flip auth method but skip the app URL.
	ctx := context.Background()
	updated, err := testEnv.Repo.UpdateAppPrimaryAuthMethod(ctx, app.WorkspaceID, app.ProjectID, app.ID, core.PrimaryAuthMethodMagicLink)
	if err != nil {
		t.Fatalf("set magicLink auth: %v", err)
	}
	app = &updated

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body, _ := json.Marshal(map[string]any{"email": emailAddr})
	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/request-magic-link", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403 (missing app URL): %s", rr.Code, rr.Body.String())
	}
}

func TestRequestMagicLink_InvalidEmail(t *testing.T) {
	router := setupClientAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "ml-bademail-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	app = configureAppForMagicLink(t, app)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body, _ := json.Marshal(map[string]any{"email": "not-an-email"})
	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/request-magic-link", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code < 400 || rr.Code >= 500 {
		t.Errorf("status %d, want 4xx for invalid email: %s", rr.Code, rr.Body.String())
	}
}

// =====================
// Consume endpoint
// =====================

func TestConsumeMagicLink_RedirectsWithSessionForExistingUser(t *testing.T) {
	router := setupClientAPIRouter(t)
	ctx := context.Background()

	userEmail := "ml-existing-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, "ml-owner-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	app = configureAppForMagicLink(t, app)

	// Pre-create the user so consume takes the existing-user branch.
	if _, _, err := testEnv.GetOrCreateUserWithMembership(ctx, userEmail, app, core.UserSourceInvited); err != nil {
		t.Fatalf("pre-create user: %v", err)
	}

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer cleanupMagicLinks(t, userEmail)

	rawToken := insertTestMagicLink(t, app, userEmail)

	q := url.Values{}
	q.Set("token", rawToken)
	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/magic-link?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status %d, want 302: %s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, testAppURL) {
		t.Errorf("redirect location %q does not start with %q", loc, testAppURL)
	}
	if !strings.Contains(loc, "mr_session=") || !strings.Contains(loc, "mr_refresh=") || !strings.Contains(loc, "mr_expires=") {
		t.Errorf("expected mr_session/mr_refresh/mr_expires in fragment, got %q", loc)
	}
}

func TestConsumeMagicLink_AutoRegistersWhenAllowed(t *testing.T) {
	router := setupClientAPIRouter(t)
	ctx := context.Background()

	userEmail := "ml-newuser-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, "ml-owner2-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	app = configureAppForMagicLink(t, app)

	// Flip AllowRegistration on the app. UpdateAppRegistration now
	// requires a DefaultRoleID when registration is enabled, so create
	// a role and pass it through.
	defaultRole := createTestRole(t, app.ProjectID)
	upd, err := testEnv.Repo.UpdateAppRegistration(ctx, app.WorkspaceID, app.ProjectID, app.ID, repo.AppRegistrationUpdate{
		AllowRegistration:    true,
		AllowAccountDeletion: app.AllowAccountDeletion,
		AllowEmailChange:     app.AllowEmailChange,
		DefaultRoleID:        &defaultRole.ID,
	})
	if err != nil {
		t.Fatalf("UpdateAppRegistration: %v", err)
	}
	app = &upd

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer cleanupMagicLinks(t, userEmail)

	rawToken := insertTestMagicLink(t, app, userEmail)

	q := url.Values{}
	q.Set("token", rawToken)
	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/magic-link?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status %d, want 302: %s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "mr_session=") {
		t.Errorf("expected session redirect, got %q", loc)
	}

	// User row should now exist.
	user, err := testEnv.Repo.GetUserByEmail(ctx, userEmail, app)
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if user == nil {
		t.Fatalf("expected user to be auto-created, got nil")
	}
	if user.Source != core.UserSourceRegistered {
		t.Errorf("user source = %q, want %q", user.Source, core.UserSourceRegistered)
	}
}

func TestConsumeMagicLink_RejectsRegistrationWhenDisabled(t *testing.T) {
	router := setupClientAPIRouter(t)

	userEmail := "ml-noreg-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, "ml-owner3-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	app = configureAppForMagicLink(t, app)
	// AllowRegistration defaults to false.

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer cleanupMagicLinks(t, userEmail)

	rawToken := insertTestMagicLink(t, app, userEmail)

	q := url.Values{}
	q.Set("token", rawToken)
	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/magic-link?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status %d, want 302: %s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "mr_magic_error=registration_disabled") {
		t.Errorf("expected registration_disabled error in fragment, got %q", loc)
	}
	// And no session params should leak through.
	if strings.Contains(loc, "mr_session=") {
		t.Errorf("did not expect mr_session on registration-disabled redirect, got %q", loc)
	}
}

func TestConsumeMagicLink_InvalidToken(t *testing.T) {
	router := setupClientAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "ml-bad-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	app = configureAppForMagicLink(t, app)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	q := url.Values{}
	q.Set("token", "totally-bogus-token")
	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/magic-link?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status %d, want 302: %s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "mr_magic_error=invalid_token") {
		t.Errorf("expected invalid_token error, got %q", loc)
	}
}

func TestConsumeMagicLink_ExistingTOTPUserHandsOffChallenge(t *testing.T) {
	// User with TOTP enrolled should NOT get a session minted by
	// magic-link consume — they should be redirected to the app URL
	// with mr_totp_challenge=… in the fragment so AppKit can show
	// the TOTP entry view. Confirms the "session only after second
	// factor" rule for the existing-TOTP path on Tier 1.
	router := setupClientAPIRouter(t)
	ctx := context.Background()

	owner := testEnv.CreateTestAccount(t, "ml-totp-owner-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, owner)
	app = configureAppForMagicLink(t, app)

	userEmail := "ml-totp-user-" + GenerateUniqueSlug("test") + "@example.com"
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, userEmail, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := testEnv.Repo.EnableUserTOTP(ctx, user.ID, time.Now().UTC(), []byte("dummy")); err != nil {
		t.Fatalf("EnableUserTOTP: %v", err)
	}
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: owner, Workspace: ws})
	defer cleanupMagicLinks(t, userEmail)

	rawToken := insertTestMagicLink(t, app, userEmail)

	q := url.Values{}
	q.Set("token", rawToken)
	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/magic-link?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status %d, want 302: %s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "mr_totp_challenge=") {
		t.Errorf("expected mr_totp_challenge fragment, got %q", loc)
	}
	// CRITICAL: no session credentials should leak through alongside
	// the challenge — that would re-introduce the bug we just fixed.
	if strings.Contains(loc, "mr_session=") || strings.Contains(loc, "mr_refresh=") {
		t.Errorf("expected NO session/refresh credentials before TOTP verify, got %q", loc)
	}
}

func TestConsumeMagicLink_Require2FANoTOTPHandsOffSetupChallenge(t *testing.T) {
	// app.Require2FA && !user.HasTOTP → server hands the user a
	// setup-challenge fragment so AppKit can drive TOTP enrollment.
	// No session must be minted before enrollment finishes.
	router := setupClientAPIRouter(t)

	owner := testEnv.CreateTestAccount(t, "ml-2fa-owner-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, owner)
	app = configureAppForMagicLink(t, app)
	app = configureAppRequire2FA(t, app)

	userEmail := "ml-2fa-user-" + GenerateUniqueSlug("test") + "@example.com"
	user := preCreateUser(t, app, userEmail)
	_ = user
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: owner, Workspace: ws})
	defer cleanupMagicLinks(t, userEmail)

	rawToken := insertTestMagicLink(t, app, userEmail)

	q := url.Values{}
	q.Set("token", rawToken)
	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/magic-link?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status %d, want 302: %s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "mr_totp_setup_challenge=") {
		t.Errorf("expected mr_totp_setup_challenge fragment, got %q", loc)
	}
	if strings.Contains(loc, "mr_session=") {
		t.Errorf("expected NO session before TOTP setup, got %q", loc)
	}
}

func TestConsumeMagicLink_TokenSingleUse(t *testing.T) {
	router := setupClientAPIRouter(t)
	ctx := context.Background()

	userEmail := "ml-replay-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, "ml-owner4-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	app = configureAppForMagicLink(t, app)

	if _, _, err := testEnv.GetOrCreateUserWithMembership(ctx, userEmail, app, core.UserSourceInvited); err != nil {
		t.Fatalf("pre-create user: %v", err)
	}

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer cleanupMagicLinks(t, userEmail)

	rawToken := insertTestMagicLink(t, app, userEmail)

	consume := func() *httptest.ResponseRecorder {
		q := url.Values{}
		q.Set("token", rawToken)
		req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/magic-link?"+q.Encode(), nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	first := consume()
	if first.Code != http.StatusFound || !strings.Contains(first.Header().Get("Location"), "mr_session=") {
		t.Fatalf("first consume should succeed; got status=%d loc=%q", first.Code, first.Header().Get("Location"))
	}

	second := consume()
	if second.Code != http.StatusFound {
		t.Fatalf("second consume status=%d, want 302", second.Code)
	}
	if !strings.Contains(second.Header().Get("Location"), "mr_magic_error=invalid_token") {
		t.Errorf("replay should redirect with invalid_token, got %q", second.Header().Get("Location"))
	}
}
