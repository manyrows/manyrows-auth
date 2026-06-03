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
	"manyrows-core/crypto"

	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
)

// bfpEnableTOTPForUser sets a TOTP secret and enables TOTP on an existing
// workspace user, returning the base32 secret so the test can generate codes.
func bfpEnableTOTPForUser(t *testing.T, user core.User) string {
	t.Helper()
	cfg := GetTestConfig()
	encryptor := crypto.NewMySecretEncryptor(cfg)

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Manyrows", AccountName: user.Email})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}
	secret := key.Secret()

	enc, err := encryptor.EncryptToBytesWithAAD([]byte(secret), crypto.AAD("users", "totp_secret_encrypted", user.ID))
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}
	if err := testEnv.Repo.SetUserTOTPSecret(context.Background(), user.ID, enc); err != nil {
		t.Fatalf("SetUserTOTPSecret: %v", err)
	}

	codes := []string{"aabbccdd", "11223344", "55667788", "99aabbcc", "ddeeff00", "11335577", "22446688", "33557799"}
	codesJSON, _ := json.Marshal(codes)
	encCodes, err := encryptor.EncryptToBytesWithAAD(codesJSON, crypto.AAD("users", "totp_backup_codes_encrypted", user.ID))
	if err != nil {
		t.Fatalf("encrypt backup codes: %v", err)
	}
	if err := testEnv.Repo.EnableUserTOTP(context.Background(), user.ID, time.Now().UTC(), encCodes); err != nil {
		t.Fatalf("EnableUserTOTP: %v", err)
	}
	return secret
}

func bfpPostTOTPVerify(t *testing.T, router *chi.Mux, ws *core.Workspace, app *core.App, challengeToken, code string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"challengeToken": challengeToken, "code": code})
	req := httptest.NewRequest(http.MethodPost,
		"/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/totp/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// A locked 2FA user is blocked at the TOTP step when protection is on, and
// admitted (lockout bypassed) when protection is off — so the toggle governs
// the whole workspace-user login, not just the password step.
func TestBFPTOTP_LockoutCheckGated(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	router := setupClientAPIRouter(t)
	acc := testEnv.CreateTestAccount(t, "bfp-totp-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "BFP TOTP WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	// Verified user with a password, then TOTP enabled. (bfpLoginUser is
	// defined in brute_force_login_test.go.)
	_, user := bfpLoginUser(t, app, "correcthorse123")
	secret := bfpEnableTOTPForUser(t, user)

	// Lock the user.
	if err := testEnv.Repo.SetUserLockedUntil(context.Background(), user.ID, time.Now().UTC().Add(1*time.Hour)); err != nil {
		t.Fatalf("lock user: %v", err)
	}

	cfg := GetTestConfig()
	totpKey, err := cfg.GetSessionAuthKey()
	if err != nil {
		t.Fatalf("GetSessionAuthKey: %v", err)
	}
	challengeToken := auth.SignTOTPChallengeWithFlags([]byte(totpKey), user.ID, 5*time.Minute, false)

	// Protection ON (default): locked → 403 even with a valid code (the
	// lockout check fires before the code is verified, so the code is not
	// consumed).
	codeOn, err := totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("gen code: %v", err)
	}
	if rr := bfpPostTOTPVerify(t, router, ws, app, challengeToken, codeOn); rr.Code != http.StatusForbidden {
		t.Fatalf("protection on: expected 403 accountLocked at TOTP step, got %d (body=%s)", rr.Code, rr.Body.String())
	}

	// Protection OFF: lockout bypassed → a valid code completes login (200).
	bfpSetProtection(t, app.ID, false)
	codeOff, err := totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("gen code: %v", err)
	}
	if rr := bfpPostTOTPVerify(t, router, ws, app, challengeToken, codeOff); rr.Code != http.StatusOK {
		t.Fatalf("protection off: expected 200 (lockout bypassed at TOTP step), got %d (body=%s)", rr.Code, rr.Body.String())
	}
}
