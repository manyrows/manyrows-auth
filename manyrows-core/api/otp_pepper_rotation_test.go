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
	"manyrows-core/utils"
)

// TestOTPPepperRotation verifies that an OTP hashed under the OLD pepper is
// rejected when the pepper rotates — unless the old pepper is listed in
// OTP_PEPPER_PREVIOUS.
//
// Config.GetOTPPepper/GetOTPPepperPrevious both call os.Getenv directly on
// every invocation (no caching), so t.Setenv works without rebuilding the
// router.
func TestOTPPepperRotation(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	defer testEnv.ClearRateLimitAttempts(t)

	// Build the router once; config reads env on every request.
	router := setupClientAPIRouter(t)

	emailAddr := "otp-rotation-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	// Create a workspace user for this app (reset-password looks up users).
	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	defer func() {
		_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	// Seed a valid password so the handler can reach the OTP-check code.
	if _, err := testEnv.DB.Pool().Exec(ctx,
		"UPDATE users SET email_verified_at = now() WHERE id = $1", user.ID,
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	newPepper := "rotated-pepper-for-tests-only-xyzzy"

	// ── Phase 1: rotate WITHOUT previous → old-pepper OTP rejected ──────

	t.Setenv("MANYROWS_OTP_PEPPER", newPepper)
	t.Setenv("MANYROWS_OTP_PEPPER_PREVIOUS", "")

	// Mint an OTP row hashed under testOTPPepper (the OLD pepper).
	otpID1 := utils.NewUUID()
	knownCode1 := "111111"
	codeHash1 := testHashOTP(otpID1, knownCode1, testOTPPepper)
	now1 := time.Now().UTC()
	otp1 := core.ClientOTPCode{
		ID:        otpID1,
		AppID:     app.ID,
		EmailNorm: emailAddr,
		CodeHash:  codeHash1,
		CreatedAt: now1,
		ExpiresAt: now1.Add(15 * time.Minute),
	}
	if err := testEnv.Repo.InsertClientOTP(ctx, otp1); err != nil {
		t.Fatalf("phase1: insert OTP: %v", err)
	}

	rr1 := doResetPasswordWithPW(t, router, ws.Slug, app.ID.String(), emailAddr, knownCode1, "Phase1Password!9876")
	if rr1.Code != http.StatusUnauthorized {
		t.Errorf("phase 1 (no previous): expected 401, got %d: %s", rr1.Code, rr1.Body.String())
	}

	// ── Phase 2: old pepper in _PREVIOUS → verifies ───────────────────

	t.Setenv("MANYROWS_OTP_PEPPER_PREVIOUS", testOTPPepper)

	// Mint a fresh OTP (the phase-1 row burned an attempt slot; mint anew
	// to avoid interaction with the attempt cap).
	otpID2 := utils.NewUUID()
	knownCode2 := "222222"
	codeHash2 := testHashOTP(otpID2, knownCode2, testOTPPepper)
	now2 := time.Now().UTC()
	otp2 := core.ClientOTPCode{
		ID:        otpID2,
		AppID:     app.ID,
		EmailNorm: emailAddr,
		CodeHash:  codeHash2,
		CreatedAt: now2,
		ExpiresAt: now2.Add(15 * time.Minute),
	}
	if err := testEnv.Repo.InsertClientOTP(ctx, otp2); err != nil {
		t.Fatalf("phase2: insert OTP: %v", err)
	}

	rr2 := doResetPasswordWithPW(t, router, ws.Slug, app.ID.String(), emailAddr, knownCode2, "Phase2Password!8765")
	if rr2.Code != http.StatusOK {
		t.Errorf("phase 2 (with previous): expected 200, got %d: %s", rr2.Code, rr2.Body.String())
	}
}

// doResetPasswordWithPW hits POST /x/{slug}/apps/{appID}/auth/reset-password.
func doResetPasswordWithPW(t *testing.T, router http.Handler, wsSlug, appID, email, code, newPW string) *httptest.ResponseRecorder {
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
