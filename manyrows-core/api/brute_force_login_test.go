package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"manyrows-core/core"
	"manyrows-core/crypto/passwordhash"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

const bfpLoginPurpose = "workspace_login_pw"

// bfpLoginUser creates a workspace user with a verified email + password and
// returns the email. Mirrors the setup in TestWorkspaceLoginPassword_Success.
func bfpLoginUser(t *testing.T, app *core.App, password string) (string, core.User) {
	t.Helper()
	ctx := context.Background()
	email := "bfp-login-" + GenerateUniqueSlug("u") + "@example.com"
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, email, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	hash, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	now := time.Now().UTC()
	if _, err := testEnv.DB.Pool().Exec(ctx,
		`UPDATE users SET password_hash = $1, password_set_at = $2, email_verified_at = $3 WHERE id = $4`,
		hash, now, now, user.ID); err != nil {
		t.Fatalf("set password: %v", err)
	}
	return email, *user
}

func bfpSetProtection(t *testing.T, appID uuid.UUID, enabled bool) {
	t.Helper()
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`UPDATE apps SET brute_force_protection_enabled = $2 WHERE id = $1`,
		appID, enabled); err != nil {
		t.Fatalf("set protection flag: %v", err)
	}
}

func bfpPostLogin(t *testing.T, router *chi.Mux, ws *core.Workspace, app *core.App, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"email": email, "password": password, "appId": app.ID.String()})
	req := httptest.NewRequest(http.MethodPost,
		"/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// Regression (passes after Task 4): a locked user is bypassed end-to-end when
// protection is off.
func TestBFPLogin_LockoutBypassWhenOff(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	router := setupClientAPIRouter(t)
	acc := testEnv.CreateTestAccount(t, "bfp-lo-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "BFP LO WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	const pw = "correcthorse123"
	email, user := bfpLoginUser(t, app, pw)

	// Lock the user.
	if err := testEnv.Repo.SetUserLockedUntil(context.Background(), user.ID, time.Now().UTC().Add(15*time.Minute)); err != nil {
		t.Fatalf("lock user: %v", err)
	}

	// Protection ON (default): locked → 403.
	if rr := bfpPostLogin(t, router, ws, app, email, pw); rr.Code != http.StatusForbidden {
		t.Fatalf("protection on: expected 403, got %d (body=%s)", rr.Code, rr.Body.String())
	}

	// Re-lock (the on-attempt above hit 403 before clearing anything, but be explicit).
	if err := testEnv.Repo.SetUserLockedUntil(context.Background(), user.ID, time.Now().UTC().Add(15*time.Minute)); err != nil {
		t.Fatalf("re-lock user: %v", err)
	}

	// Protection OFF: locked user + correct password → 200.
	bfpSetProtection(t, app.ID, false)
	if rr := bfpPostLogin(t, router, ws, app, email, pw); rr.Code != http.StatusOK {
		t.Fatalf("protection off: expected 200 (lockout bypassed), got %d (body=%s)", rr.Code, rr.Body.String())
	}
}

// Rate-limit gating: a pre-tripped subject rate limit blocks login when on and
// is bypassed when off.
func TestBFPLogin_RateLimitGated(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	router := setupClientAPIRouter(t)
	acc := testEnv.CreateTestAccount(t, "bfp-rl-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "BFP RL WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	const pw = "correcthorse123"
	email, _ := bfpLoginUser(t, app, pw)

	// Trip the per-subject rate limit (cap is 10 / 10 min) with recent attempts.
	ctx := context.Background()
	for i := 0; i < 15; i++ {
		if err := testEnv.Repo.InsertAttempt(ctx, bfpLoginPurpose, email, "203.0.113.7"); err != nil {
			t.Fatalf("seed attempt: %v", err)
		}
	}

	// Protection ON (default): rate limit fires → NOT 200.
	if rr := bfpPostLogin(t, router, ws, app, email, pw); rr.Code == http.StatusOK {
		t.Fatalf("protection on: expected rate-limit block (non-200), got 200")
	}

	// Protection OFF: rate limit skipped, valid creds → 200.
	bfpSetProtection(t, app.ID, false)
	if rr := bfpPostLogin(t, router, ws, app, email, pw); rr.Code != http.StatusOK {
		t.Fatalf("protection off: expected 200 (rate limit bypassed), got %d (body=%s)", rr.Code, rr.Body.String())
	}
}

// Lockout-application gating: with protection off, a wrong-password attempt
// does not lock the account even when the recent-failure count is over the
// threshold; with protection on, it does. Attempts are backdated to 30 min so
// they fall in the 1-hour lockout window but OUTSIDE the 10-min rate-limit
// window (otherwise the rate limit would short-circuit before lockout-apply).
func TestBFPLogin_LockoutApplyGated(t *testing.T) {
	router := setupClientAPIRouter(t)
	testEnv.ClearRateLimitAttempts(t)
	ctx := context.Background()

	// Read users.locked_until directly so the assertion doesn't depend on
	// which repo getter scans the column.
	lockedUntil := func(userID uuid.UUID) *time.Time {
		var lu *time.Time
		if err := testEnv.DB.Pool().QueryRow(ctx,
			`SELECT locked_until FROM users WHERE id = $1`, userID).Scan(&lu); err != nil {
			t.Fatalf("read locked_until: %v", err)
		}
		return lu
	}

	seedBackdated := func(email string) {
		for i := 0; i < 10; i++ {
			if _, err := testEnv.DB.Pool().Exec(ctx,
				`INSERT INTO attempts (id, purpose, subject, ip, created_at)
				 VALUES ($1, $2, $3, $4, now() - interval '30 minutes')`,
				uuid.Must(uuid.NewV4()), bfpLoginPurpose, email, "203.0.113.8"); err != nil {
				t.Fatalf("seed backdated attempt: %v", err)
			}
		}
	}

	// --- Protection OFF: no lock applied ---
	testEnv.ClearRateLimitAttempts(t)
	accOff := testEnv.CreateTestAccount(t, "bfp-apply-off-"+GenerateUniqueSlug("u")+"@example.com")
	wsOff := testEnv.CreateTestWorkspace(t, accOff, "BFP Apply Off", GenerateUniqueSlug("ws"))
	appOff := testEnv.CreateTestApp(t, wsOff, accOff)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: accOff, Workspace: wsOff})
	emailOff, userOff := bfpLoginUser(t, appOff, "correcthorse123")
	bfpSetProtection(t, appOff.ID, false)
	seedBackdated(emailOff)

	if rr := bfpPostLogin(t, router, wsOff, appOff, emailOff, "wrong-password"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("protection off: expected 401 wrong-password, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if lu := lockedUntil(userOff.ID); lu != nil {
		t.Fatalf("protection off: expected no lock applied, got locked_until=%v", lu)
	}

	// --- Protection ON: lock applied ---
	testEnv.ClearRateLimitAttempts(t)
	accOn := testEnv.CreateTestAccount(t, "bfp-apply-on-"+GenerateUniqueSlug("u")+"@example.com")
	wsOn := testEnv.CreateTestWorkspace(t, accOn, "BFP Apply On", GenerateUniqueSlug("ws"))
	appOn := testEnv.CreateTestApp(t, wsOn, accOn)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: accOn, Workspace: wsOn})
	emailOn, userOn := bfpLoginUser(t, appOn, "correcthorse123")
	// appOn keeps the default protection=true.
	seedBackdated(emailOn)

	if rr := bfpPostLogin(t, router, wsOn, appOn, emailOn, "wrong-password"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("protection on: expected 401 wrong-password, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if lu := lockedUntil(userOn.ID); lu == nil {
		t.Fatalf("protection on: expected lock applied, got locked_until=nil")
	}
}
