package api_test

// Tests for backup-code verification after an OTP pepper rotation.
//
// Scenario: backup codes were hashed under pepper-A (the "old" pepper).
// After rotating to pepper-B the codes must still verify when pepper-A is
// listed in MANYROWS_OTP_PEPPER_PREVIOUS. Without PREVIOUS the codes must
// reject. Hashed backup codes cannot be re-hashed under a new pepper (no plaintexts)
// — operators keep the old pepper in OTP_PEPPER_PREVIOUS until users regenerate or
// exhaust codes minted before the rotation.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/crypto"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/pquerna/otp/totp"
)

// hashBackupCodeForTest returns the HMAC-SHA256 of a normalized backup code keyed
// by pepper and bound to the ownerID — mirrors the package-private hashBackupCode
// helper so the test can pre-compute hashes for a specific pepper.
func hashBackupCodeForTest(code string, ownerID uuid.UUID, pepper string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	m := hmac.New(sha256.New, []byte(pepper))
	m.Write([]byte(ownerID.String()))
	m.Write([]byte(":"))
	m.Write([]byte(code))
	return hex.EncodeToString(m.Sum(nil))
}

// plainBackupCodesForRotation is a fixed set of plaintext backup codes used
// by the pepper-rotation tests.
var plainBackupCodesForRotation = []string{
	"bc001122334455aa",
	"bc112233445566bb",
	"bc223344556677cc",
	"bc334455667788dd",
	"bc445566778899ee",
	"bc5566778899aabb",
	"bc66778899aabbcc",
	"bc778899aabbccdd",
}

// enableTOTPWithHashedCodes sets up a full TOTP account (TOTP secret encrypted,
// backup codes stored in the new hashed format) with hashes computed under the
// given pepper. Returns the account, the TOTP secret, and the plaintext backup
// codes.
func enableTOTPWithHashedCodes(t *testing.T, pepper string) (acc *core.Account, secret string, backupCodes []string) {
	t.Helper()

	acc = createAccountWithPassword(t, "securepassword123")

	cfg := GetTestConfig()
	encryptor := crypto.NewMySecretEncryptor(cfg)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Manyrows",
		AccountName: acc.Email,
	})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}
	secret = key.Secret()

	encSecret, err := encryptor.EncryptToBytesWithAAD(
		[]byte(secret),
		crypto.AAD("accounts", "totp_secret_encrypted", acc.ID),
	)
	if err != nil {
		t.Fatalf("encrypt totp secret: %v", err)
	}
	if err := testEnv.Repo.SetTOTPSecret(context.Background(), acc.ID, encSecret); err != nil {
		t.Fatalf("SetTOTPSecret: %v", err)
	}

	backupCodes = plainBackupCodesForRotation
	hashes := make([]string, len(backupCodes))
	for i, c := range backupCodes {
		hashes[i] = hashBackupCodeForTest(c, acc.ID, pepper)
	}
	blob, err := json.Marshal(hashes)
	if err != nil {
		t.Fatalf("json.Marshal hashes: %v", err)
	}

	now := time.Now().UTC()
	if err := testEnv.Repo.EnableTOTP(context.Background(), acc.ID, now, blob); err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}

	return acc, secret, backupCodes
}

// setupTOTPRouterWithPeppers builds the same router as setupTOTPTestRouter but
// with MANYROWS_OTP_PEPPER overridden to pepperCurrent and
// MANYROWS_OTP_PEPPER_PREVIOUS set to the comma-joined pepperPrevious list.
func setupTOTPRouterWithPeppers(t *testing.T, pepperCurrent string, pepperPrevious []string) *chi.Mux {
	t.Helper()
	t.Setenv("MANYROWS_OTP_PEPPER", pepperCurrent)
	t.Setenv("MANYROWS_OTP_PEPPER_PREVIOUS", strings.Join(pepperPrevious, ","))
	router, _ := setupTOTPTestRouter(t)
	return router
}

// signTOTPChallengeFor returns a fresh TOTP challenge token for the given
// account using the session auth key from the current test config.
func signTOTPChallengeFor(t *testing.T, acc *core.Account) string {
	t.Helper()
	cfg := GetTestConfig()
	totpKey, _ := cfg.GetSessionAuthKey()
	return auth.SignTOTPChallenge(auth.DeriveTokenSigningKey([]byte(totpKey)), acc.ID, 5*time.Minute)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

// TestBackupCodePepperRotation_AcceptsOldPepperWhenPreviousSet verifies that a
// backup code hashed under an old pepper can still be consumed after rotating,
// provided the old pepper is listed in MANYROWS_OTP_PEPPER_PREVIOUS.
func TestBackupCodePepperRotation_AcceptsOldPepperWhenPreviousSet(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)

	const pepperOld = "old-pepper-before-rotation"
	const pepperNew = "new-pepper-after-rotation"

	acc, _, backupCodes := enableTOTPWithHashedCodes(t, pepperOld)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	router := setupTOTPRouterWithPeppers(t, pepperNew, []string{pepperOld})
	challengeToken := signTOTPChallengeFor(t, acc)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/totp/verify",
		jsonBody(t, map[string]string{
			"challengeToken": challengeToken,
			"code":           backupCodes[0],
		}))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("backup code under old pepper with PREVIOUS set: expected 200, got %d: %s",
			rec.Code, rec.Body.String())
	}
}

// TestBackupCodePepperRotation_RejectsWhenPreviousNotSet verifies that a
// backup code hashed under an old pepper fails when _PREVIOUS is not set.
func TestBackupCodePepperRotation_RejectsWhenPreviousNotSet(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)

	const pepperOld = "old-pepper-before-rotation-2"
	const pepperNew = "new-pepper-after-rotation-2"

	acc, _, backupCodes := enableTOTPWithHashedCodes(t, pepperOld)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	// No previous pepper.
	router := setupTOTPRouterWithPeppers(t, pepperNew, nil)
	challengeToken := signTOTPChallengeFor(t, acc)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/totp/verify",
		jsonBody(t, map[string]string{
			"challengeToken": challengeToken,
			"code":           backupCodes[0],
		}))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("backup code under old pepper without PREVIOUS: expected 401, got %d: %s",
			rec.Code, rec.Body.String())
	}
}

// TestBackupCodePepperRotation_MultipleCodesWorkDuringRotationWindow verifies
// that multiple backup codes can be consumed while the old pepper remains in
// PREVIOUS — i.e. the rotation window stays open for all remaining codes.
func TestBackupCodePepperRotation_MultipleCodesWorkDuringRotationWindow(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)

	const pepperOld = "old-pepper-before-rotation-3"
	const pepperNew = "new-pepper-after-rotation-3"

	acc, _, backupCodes := enableTOTPWithHashedCodes(t, pepperOld)
	defer testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)

	// Consume backupCodes[0] while pepperOld is in PREVIOUS.
	router1 := setupTOTPRouterWithPeppers(t, pepperNew, []string{pepperOld})
	tok1 := signTOTPChallengeFor(t, acc)
	req1 := httptest.NewRequest(http.MethodPost, "/admin/auth/totp/verify",
		jsonBody(t, map[string]string{"challengeToken": tok1, "code": backupCodes[0]}))
	req1.Header.Set("Content-Type", "application/json")
	rec1 := httptest.NewRecorder()
	router1.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first consume: expected 200, got %d: %s", rec1.Code, rec1.Body.String())
	}

	// Consume backupCodes[1] in a second session — pepperOld still in PREVIOUS.
	testEnv.ClearRateLimitAttempts(t)
	router2 := setupTOTPRouterWithPeppers(t, pepperNew, []string{pepperOld})
	tok2 := signTOTPChallengeFor(t, acc)
	req2 := httptest.NewRequest(http.MethodPost, "/admin/auth/totp/verify",
		jsonBody(t, map[string]string{"challengeToken": tok2, "code": backupCodes[1]}))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	router2.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Errorf("second consume: expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
}
