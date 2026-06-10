package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"manyrows-core/core"
	"manyrows-core/crypto/passwordhash"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// setAppReusePrevention enables or disables the password-reuse-prevention
// toggle for the given app directly in the DB.
func setAppReusePrevention(t *testing.T, appID uuid.UUID, on bool) {
	t.Helper()
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`UPDATE apps SET password_reuse_prevention = $2 WHERE id = $1`, appID, on); err != nil {
		t.Fatalf("set reuse prevention: %v", err)
	}
}

// doSetPassword is a helper to hit POST /x/{slug}/apps/{appID}/a/set-password.
// Returns the recorded response.
func doSetPassword(t *testing.T, router http.Handler, wsSlug, appID, accessToken, currentPW, newPW string) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{
		"password":        newPW,
		"currentPassword": currentPW,
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/x/"+wsSlug+"/apps/"+appID+"/a/set-password", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// TestSetPassword_ReuseBlocked verifies that reusing the current password is
// rejected when password_reuse_prevention is enabled.
func TestSetPassword_ReuseBlocked(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "reuse-blocked-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	clientSes, accessToken := createTestClientSessionForApp(t, ws, acc, app)

	// Seed password A directly (no history recording — mirrors mirrored test).
	pwA := "OldPassword!2026a"
	hashA, err := passwordhash.Hash(pwA)
	if err != nil {
		t.Fatalf("hash password A: %v", err)
	}
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		"UPDATE users SET password_hash = $1 WHERE id = $2", hashA, clientSes.UserID,
	); err != nil {
		t.Fatalf("seed password_hash: %v", err)
	}

	setAppReusePrevention(t, app.ID, true)

	// Attempt to set the same password A → must be blocked.
	// The safety-net check against the live users.password_hash catches this
	// even without a history row.
	rr := doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwA, pwA)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "passwordRecentlyUsed") {
		t.Errorf("expected error.passwordRecentlyUsed in body, got: %s", rr.Body.String())
	}
}

// TestSetPassword_ReuseOfOlderBlocked_ThenRotatesOut verifies:
//   - A password in the rolling window is rejected.
//   - A password that has been evicted from the window (older than newest 5) is accepted.
//
// Password sequence:
//
//	Fixture seeds P0 (no history).
//	API: P0→A  (history: [A])          — step 1
//	API: A→B   (history: [B, A])       — step 2
//	API: B→A   → 400 (A is in history) — step 3 (blocked)
//	API: B→C   (history: [C, B, A])    — step 4
//	API: C→D   (history: [D, C, B, A]) — step 5
//	API: D→E   (history: [E, D, C, B, A]) — step 6, window full (5 entries)
//	API: E→F   (history: [F, E, D, C, B], A evicted) — step 7
//	API: F→A   → 200 (A has rotated out) — step 8 (allowed)
func TestSetPassword_ReuseOfOlderBlocked_ThenRotatesOut(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "reuse-rotate-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	clientSes, accessToken := createTestClientSessionForApp(t, ws, acc, app)

	// Seed fixture password P0 directly — no history row created.
	// P0 is distinct from A so that A enters the history table through the API.
	pwP0 := "OldPassword!2026a-seed"
	hashP0, err := passwordhash.Hash(pwP0)
	if err != nil {
		t.Fatalf("hash P0: %v", err)
	}
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		"UPDATE users SET password_hash = $1 WHERE id = $2", hashP0, clientSes.UserID,
	); err != nil {
		t.Fatalf("seed password_hash: %v", err)
	}

	setAppReusePrevention(t, app.ID, true)

	pwA := "OldPassword!2026a"
	pwB := "NewPassword!2026b"
	pwC := "ThirdPassword!2026c"
	pwD := "FourthPassword!2026d"
	pwE := "FifthPassword!2026e"
	pwF := "SixthPassword!2026f"

	// Step 1: P0→A  (records A in history)
	rr := doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwP0, pwA)
	if rr.Code != http.StatusOK {
		t.Fatalf("step 1 P0→A: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Step 2: A→B  (records B; history [B, A])
	rr = doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwA, pwB)
	if rr.Code != http.StatusOK {
		t.Fatalf("step 2 A→B: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Step 3: B→A  → blocked (A is in history)
	rr = doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwB, pwA)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("step 3 B→A: expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "passwordRecentlyUsed") {
		t.Errorf("step 3: expected error.passwordRecentlyUsed in body, got: %s", rr.Body.String())
	}

	// Step 4: B→C  (records C; history [C, B, A])
	rr = doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwB, pwC)
	if rr.Code != http.StatusOK {
		t.Fatalf("step 4 B→C: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Step 5: C→D  (records D; history [D, C, B, A])
	rr = doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwC, pwD)
	if rr.Code != http.StatusOK {
		t.Fatalf("step 5 C→D: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Step 6: D→E  (records E; history [E, D, C, B, A] — window full at 5)
	rr = doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwD, pwE)
	if rr.Code != http.StatusOK {
		t.Fatalf("step 6 D→E: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Step 7: E→F  (records F; history [F, E, D, C, B] — A evicted)
	rr = doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwE, pwF)
	if rr.Code != http.StatusOK {
		t.Fatalf("step 7 E→F: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Step 8: F→A  → allowed (A has rotated out of the newest-5 window)
	rr = doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwF, pwA)
	if rr.Code != http.StatusOK {
		t.Fatalf("step 8 F→A: expected 200 (A rotated out), got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestSetPassword_RateLimited verifies that a single user is throttled after
// exhausting the per-subject budget on /a/set-password. Each request is made
// with a wrong currentPassword so the argon2id comparison work is done but
// the password is never actually changed — the test is about the rate cap,
// not correctness. The cap+1-th request must return 429.
func TestSetPassword_RateLimited(t *testing.T) {
	// const mirrors api.maxAttemptsPerSubject10Min (unexported); keep in sync.
	const setPasswordSubjectCap = 10

	testEnv.ClearRateLimitAttempts(t)
	defer testEnv.ClearRateLimitAttempts(t)

	router := setupClientAPIRouter(t)

	emailAddr := "rate-limit-sp-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	_, accessToken := createTestClientSessionForApp(t, ws, acc, app)

	// Burn the full budget with wrong currentPassword (cheap — the
	// current hash is empty so the handler 400s early, but it has already
	// recorded an attempt for each call).
	for i := 0; i < setPasswordSubjectCap; i++ {
		rr := doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, "wrongcurrent", "SomeNewPassword!2026x")
		if rr.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d: hit 429 too early (cap=%d)", i+1, setPasswordSubjectCap)
		}
	}

	// The cap+1-th attempt must be rate-limited.
	rr := doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, "wrongcurrent", "SomeNewPassword!2026x")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d attempts, got %d (body=%s)", setPasswordSubjectCap, rr.Code, rr.Body.String())
	}
	if ra := rr.Header().Get("Retry-After"); ra == "" {
		t.Errorf("expected Retry-After header on 429, got none")
	}
}

// mintResetOTP inserts a fresh, unused client OTP for the password-reset flow
// and returns the plain-text 6-digit code.  It replicates the server-side
// insertion so that WorkspaceResetPassword can verify it.
func mintResetOTP(t *testing.T, appID uuid.UUID, emailAddr string) string {
	t.Helper()
	ctx := context.Background()
	knownCode := "654321"
	otpID := utils.NewUUID()
	codeHash := testHashOTP(otpID, knownCode, testOTPPepper)
	now := time.Now().UTC()

	otp := core.ClientOTPCode{
		ID:        otpID,
		AppID:     appID,
		EmailNorm: strings.ToLower(strings.TrimSpace(emailAddr)),
		CodeHash:  codeHash,
		CreatedAt: now,
		ExpiresAt: now.Add(15 * time.Minute),
	}
	if err := testEnv.Repo.InsertClientOTP(ctx, otp); err != nil {
		t.Fatalf("mintResetOTP: insert OTP: %v", err)
	}
	return knownCode
}

// doResetPassword hits POST /x/{slug}/apps/{appID}/auth/reset-password.
func doResetPassword(t *testing.T, router http.Handler, wsSlug, appID, email, code, newPW string) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{
		"email":       email,
		"code":        code,
		"newPassword": newPW,
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/x/"+wsSlug+"/apps/"+appID+"/auth/reset-password", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// TestResetPassword_ReuseBlocked verifies that password-reuse prevention is
// enforced on the forgot-password reset flow.
func TestResetPassword_ReuseBlocked(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	defer testEnv.ClearRateLimitAttempts(t)

	router := setupClientAPIRouter(t)

	emailAddr := "reset-reuse-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	// Create a user in this app's scope.
	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	defer func() {
		_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	// Seed password A directly (no history row — live hash acts as safety net).
	pwA := "OldPassword!2026a"
	hashA, err := passwordhash.Hash(pwA)
	if err != nil {
		t.Fatalf("hash A: %v", err)
	}
	if _, err := testEnv.DB.Pool().Exec(ctx,
		"UPDATE users SET password_hash = $1, email_verified_at = now() WHERE id = $2", hashA, user.ID,
	); err != nil {
		t.Fatalf("seed password: %v", err)
	}

	setAppReusePrevention(t, app.ID, true)

	pwB := "NewPassword!2026b"

	// --- Step 1: reset to A → must be blocked (A is the live hash) ---
	code1 := mintResetOTP(t, app.ID, emailAddr)
	rr := doResetPassword(t, router, ws.Slug, app.ID.String(), emailAddr, code1, pwA)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("step 1 (reset to A): expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "passwordRecentlyUsed") {
		t.Errorf("step 1: expected error.passwordRecentlyUsed in body, got: %s", rr.Body.String())
	}

	// --- Step 2: reset to B → must succeed (records B in history) ---
	code2 := mintResetOTP(t, app.ID, emailAddr)
	rr = doResetPassword(t, router, ws.Slug, app.ID.String(), emailAddr, code2, pwB)
	if rr.Code != http.StatusOK {
		t.Fatalf("step 2 (reset to B): expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// --- Step 3: reset to B again → must be blocked (B is the live hash) ---
	// NOTE: this is satisfied by the live-hash safety net alone and does NOT
	// prove that recordPasswordHistory ran on the reset path.
	code3 := mintResetOTP(t, app.ID, emailAddr)
	rr = doResetPassword(t, router, ws.Slug, app.ID.String(), emailAddr, code3, pwB)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("step 3 (reset to B again): expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "passwordRecentlyUsed") {
		t.Errorf("step 3: expected error.passwordRecentlyUsed in body, got: %s", rr.Body.String())
	}

	pwC := "ThirdPassword!2026c"

	// --- Step 4: reset to C → must succeed (live hash is now C) ---
	code4 := mintResetOTP(t, app.ID, emailAddr)
	rr = doResetPassword(t, router, ws.Slug, app.ID.String(), emailAddr, code4, pwC)
	if rr.Code != http.StatusOK {
		t.Fatalf("step 4 (reset to C): expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// --- Step 5: reset to B → must be blocked (B is in history from step 2,
	// but the live hash is now C — only the history row recorded during step 2
	// can catch this reuse, pinning recordPasswordHistory on the reset path) ---
	code5 := mintResetOTP(t, app.ID, emailAddr)
	rr = doResetPassword(t, router, ws.Slug, app.ID.String(), emailAddr, code5, pwB)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("step 5 (reset to B after rotating to C): expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "passwordRecentlyUsed") {
		t.Errorf("step 5: expected error.passwordRecentlyUsed in body, got: %s", rr.Body.String())
	}
}

// setupPasswordPolicyRouter builds the minimal admin router that exposes
// PUT /admin/workspace/{workspaceId}/projects/{projectId}/apps/{appId}/password-policy.
func setupPasswordPolicyRouter(t *testing.T) *chi.Mux {
	t.Helper()
	svc := NewTestServices(t)
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)
	wsRouter.Put("/projects/{projectId}/apps/{appId}/password-policy", svc.Handler.HandleUpdateAppPasswordPolicy)
	return r
}

// putPasswordPolicy is a test helper that hits the password-policy endpoint.
func putPasswordPolicy(t *testing.T, router *chi.Mux, ws *core.Workspace, proj *core.Project, appID uuid.UUID, claims core.TokenClaims, body any) *httptest.ResponseRecorder {
	t.Helper()
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPut,
		"/admin/workspace/"+ws.ID.String()+"/projects/"+proj.ID.String()+"/apps/"+appID.String()+"/password-policy",
		bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// TestUpdatePasswordPolicy_ReuseToggle verifies that the password-policy
// endpoint correctly persists passwordReusePrevention, preserves
// minLength/minScore when only the toggle changes, and that setting only
// minLength preserves the current reuse value.
func TestUpdatePasswordPolicy_ReuseToggle(t *testing.T) {
	router := setupPasswordPolicyRouter(t)

	acc := testEnv.CreateTestAccount(t, "pp-reuse-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "PP Reuse WS", GenerateUniqueSlug("ws"))
	proj := testEnv.CreateTestProject(t, ws, acc, "Test", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, proj.ID, uuid.Nil, "PP Reuse App")
	_, claims := testEnv.CreateTestSession(t, acc)

	// Seed known minLength / minScore so we can assert they are unchanged.
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`UPDATE apps SET password_min_length = 10, password_min_zxcvbn_score = 2 WHERE id = $1`, appID,
	); err != nil {
		t.Fatalf("seed password policy: %v", err)
	}

	// --- sub-test 1: set reuse=true, expect true; minLength/minScore unchanged ---
	rr := putPasswordPolicy(t, router, ws, proj, appID, claims, map[string]any{
		"passwordReusePrevention": true,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("enable reuse: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp1 struct {
		PasswordReusePrevention bool `json:"passwordReusePrevention"`
		PasswordMinLength       int  `json:"passwordMinLength"`
		PasswordMinZxcvbnScore  int  `json:"passwordMinZxcvbnScore"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp1); err != nil {
		t.Fatalf("decode resp1: %v", err)
	}
	if !resp1.PasswordReusePrevention {
		t.Errorf("enable reuse: expected PasswordReusePrevention=true, got false")
	}
	if resp1.PasswordMinLength != 10 {
		t.Errorf("enable reuse: expected minLength=10 unchanged, got %d", resp1.PasswordMinLength)
	}
	if resp1.PasswordMinZxcvbnScore != 2 {
		t.Errorf("enable reuse: expected minScore=2 unchanged, got %d", resp1.PasswordMinZxcvbnScore)
	}

	// --- sub-test 2: set reuse=false, expect false ---
	rr = putPasswordPolicy(t, router, ws, proj, appID, claims, map[string]any{
		"passwordReusePrevention": false,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("disable reuse: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp2 struct {
		PasswordReusePrevention bool `json:"passwordReusePrevention"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp2); err != nil {
		t.Fatalf("decode resp2: %v", err)
	}
	if resp2.PasswordReusePrevention {
		t.Errorf("disable reuse: expected PasswordReusePrevention=false, got true")
	}

	// --- sub-test 3: set reuse=true again then update only minLength;
	//     reuse value must survive the update. ---
	rr = putPasswordPolicy(t, router, ws, proj, appID, claims, map[string]any{
		"passwordReusePrevention": true,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("re-enable reuse: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = putPasswordPolicy(t, router, ws, proj, appID, claims, map[string]any{
		"passwordMinLength": 12,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("update minLength only: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp3 struct {
		PasswordReusePrevention bool `json:"passwordReusePrevention"`
		PasswordMinLength       int  `json:"passwordMinLength"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp3); err != nil {
		t.Fatalf("decode resp3: %v", err)
	}
	if !resp3.PasswordReusePrevention {
		t.Errorf("update minLength only: expected reuse still true, got false")
	}
	if resp3.PasswordMinLength != 12 {
		t.Errorf("update minLength only: expected minLength=12, got %d", resp3.PasswordMinLength)
	}
}

// TestSetPassword_ReuseAllowedWhenToggleOff verifies that when reuse
// prevention is disabled (the default), reusing a recent password is
// permitted.
func TestSetPassword_ReuseAllowedWhenToggleOff(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "reuse-off-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	clientSes, accessToken := createTestClientSessionForApp(t, ws, acc, app)

	// Seed password A directly.
	pwA := "OldPassword!2026a"
	hashA, err := passwordhash.Hash(pwA)
	if err != nil {
		t.Fatalf("hash password A: %v", err)
	}
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		"UPDATE users SET password_hash = $1 WHERE id = $2", hashA, clientSes.UserID,
	); err != nil {
		t.Fatalf("seed password_hash: %v", err)
	}

	// Explicitly disable (default, set for clarity).
	setAppReusePrevention(t, app.ID, false)

	pwB := "NewPassword!2026b"

	// A→B: must succeed.
	rr := doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwA, pwB)
	if rr.Code != http.StatusOK {
		t.Fatalf("A→B: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// B→A: must succeed (reuse prevention is off).
	rr = doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwB, pwA)
	if rr.Code != http.StatusOK {
		t.Fatalf("B→A: expected 200 (toggle off), got %d: %s", rr.Code, rr.Body.String())
	}
}
