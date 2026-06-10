package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/crypto"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
	"manyrows-core/crypto/passwordhash"
)

// AdminTOTPSetup generates a new TOTP secret and stores it (encrypted) on the account.
// The secret is not yet "enabled" — the user must confirm with a valid code via Enable.
func (handler *RequestHandler) AdminTOTPSetup(w http.ResponseWriter, r *http.Request) {
	acc, ok := core.AdminAccountFromContext(r.Context())
	if !ok || acc == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	if acc.HasTOTP() {
		WriteError(w, r, "error.totpAlreadyEnabled", http.StatusConflict)
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Manyrows",
		AccountName: acc.Email,
	})
	if err != nil {
		log.Err(err).Msg("failed to generate TOTP key")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	encrypted, err := handler.encryptor.EncryptToBytesWithAAD(
		[]byte(key.Secret()),
		crypto.AAD("accounts", "totp_secret_encrypted", acc.ID),
	)
	if err != nil {
		log.Err(err).Msg("failed to encrypt TOTP secret")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if err := handler.repo.SetTOTPSecret(r.Context(), acc.ID, encrypted); err != nil {
		log.Err(err).Msg("failed to store TOTP secret")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{
		"secret": key.Secret(),
		"uri":    key.URL(),
	})
}

// AdminTOTPEnable verifies a TOTP code against the stored (but not yet enabled) secret,
// then marks TOTP as enabled and returns one-time backup codes.
func (handler *RequestHandler) AdminTOTPEnable(w http.ResponseWriter, r *http.Request) {
	acc, ok := core.AdminAccountFromContext(r.Context())
	if !ok || acc == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	if acc.HasTOTP() {
		WriteError(w, r, "error.totpAlreadyEnabled", http.StatusConflict)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	code := strings.TrimSpace(req.Code)
	if code == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Re-fetch account to get the stored encrypted secret
	freshAcc, err := handler.repo.GetAccountByID(r.Context(), acc.ID)
	if err != nil {
		log.Err(err).Msg("failed to fetch account for TOTP enable")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if len(freshAcc.TOTPSecretEncrypted) == 0 {
		WriteError(w, r, "error.totpNotSetUp", http.StatusBadRequest)
		return
	}

	secret, err := handler.encryptor.DecryptFromBytesWithAAD(
		freshAcc.TOTPSecretEncrypted,
		crypto.AAD("accounts", "totp_secret_encrypted", freshAcc.ID),
	)
	if err != nil {
		log.Err(err).Msg("failed to decrypt TOTP secret")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Use the shared verify primitive (not pquerna's totp.Validate) so we learn
	// which step matched and can record it below — the live-verify path's
	// replay guard. Without recording it, the code used to enroll could be
	// replayed at the very next login within its 30s window.
	enrollStep, ok := auth.VerifyTOTPCode(code, string(secret))
	if !ok {
		WriteError(w, r, "error.invalidTOTPCode", http.StatusUnauthorized)
		return
	}

	// Generate backup codes
	backupCodes, err := generateBackupCodes(8)
	if err != nil {
		log.Err(err).Msg("failed to generate backup codes")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	storedCodes, err := handler.hashBackupCodes(backupCodes, acc.ID)
	if err != nil {
		log.Err(err).Msg("failed to hash backup codes")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC()
	if err := handler.repo.EnableTOTP(r.Context(), acc.ID, now, storedCodes); err != nil {
		log.Err(err).Msg("failed to enable TOTP")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	// Burn the enrollment step so the same code can't be replayed at the first
	// login verify. Non-fatal: enrollment already committed.
	if _, err := handler.repo.AdvanceAccountTOTPStep(r.Context(), acc.ID, enrollStep); err != nil {
		log.Err(err).Msg("AdvanceAccountTOTPStep after enroll failed (non-fatal)")
	}

	utils.WriteJson(w, map[string]any{
		"backupCodes": backupCodes,
	})
}

// AdminTOTPDisable disables TOTP after password confirmation.
func (handler *RequestHandler) AdminTOTPDisable(w http.ResponseWriter, r *http.Request) {
	acc, ok := core.AdminAccountFromContext(r.Context())
	if !ok || acc == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	if !acc.HasTOTP() {
		WriteError(w, r, "error.totpNotEnabled", http.StatusBadRequest)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	if err := handler.verifyAccountPassword(r.Context(), acc.ID, req.Password); err != nil {
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	if err := handler.repo.DisableTOTP(r.Context(), acc.ID); err != nil {
		log.Err(err).Msg("failed to disable TOTP")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{"ok": true})
}

// AdminTOTPRegenerateBackupCodes regenerates backup codes after password confirmation.
func (handler *RequestHandler) AdminTOTPRegenerateBackupCodes(w http.ResponseWriter, r *http.Request) {
	acc, ok := core.AdminAccountFromContext(r.Context())
	if !ok || acc == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	if !acc.HasTOTP() {
		WriteError(w, r, "error.totpNotEnabled", http.StatusBadRequest)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	if err := handler.verifyAccountPassword(r.Context(), acc.ID, req.Password); err != nil {
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	backupCodes, err := generateBackupCodes(8)
	if err != nil {
		log.Err(err).Msg("failed to generate backup codes")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	storedCodes, err := handler.hashBackupCodes(backupCodes, acc.ID)
	if err != nil {
		log.Err(err).Msg("failed to hash backup codes")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if err := handler.repo.UpdateTOTPBackupCodes(r.Context(), acc.ID, storedCodes); err != nil {
		log.Err(err).Msg("failed to update backup codes")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{
		"backupCodes": backupCodes,
	})
}

// AdminTOTPVerify verifies TOTP code (or backup code) after password login.
// This is an unauthenticated endpoint — uses the HMAC challenge token from login.
func (handler *RequestHandler) AdminTOTPVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChallengeToken string `json:"challengeToken"`
		Code           string `json:"code"`
	}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	if req.ChallengeToken == "" || req.Code == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	ip := auth.ClientIP(r)

	// Resolve the account from the (HMAC-signed, unforgeable) challenge token
	// BEFORE rate limiting, so we can key the limit on the email subject too.
	// Without a per-subject cap, a multi-IP attacker who already cleared the
	// password step gets the full per-IP budget against each IP for the same
	// account; the per-subject cap bounds the total across IPs.
	accountID, _, err := auth.VerifyTOTPChallenge(handler.totpKey, req.ChallengeToken)
	if err != nil {
		if errors.Is(err, auth.ErrTOTPChallengeExpired) {
			WriteError(w, r, "error.totpChallengeExpired", http.StatusUnauthorized)
			return
		}
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	acc, err := handler.repo.GetAccountByID(r.Context(), accountID)
	if err != nil {
		log.Err(err).Msg("failed to fetch account for TOTP verify")
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	if !acc.HasTOTP() {
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	// Rate limit by IP AND subject (shares counter with password login).
	if !handler.checkAttemptRateLimit(w, r, attemptPurposeAdminLogin, ip, strings.ToLower(acc.Email), "admin TOTP verify", nil) {
		return
	}

	// Check account lockout
	if handler.checkAccountLocked(w, r, acc.LockedUntil) {
		return
	}

	secret, err := handler.encryptor.DecryptFromBytesWithAAD(
		acc.TOTPSecretEncrypted,
		crypto.AAD("accounts", "totp_secret_encrypted", acc.ID),
	)
	if err != nil {
		log.Err(err).Msg("failed to decrypt TOTP secret")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	code := strings.TrimSpace(req.Code)
	subject := strings.ToLower(acc.Email)

	// Try TOTP code first. Replay protection (M1): VerifyTOTPCode tells us
	// which step matched; AdvanceAccountTOTPStep is an atomic "set iff >"
	// that fails when the step has already been consumed.
	if step, ok := auth.VerifyTOTPCode(code, string(secret)); ok {
		advanced, advErr := handler.repo.AdvanceAccountTOTPStep(r.Context(), acc.ID, step)
		if advErr != nil {
			log.Err(advErr).Msg("AdvanceAccountTOTPStep failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if advanced {
			// Clear any lockout on success
			if acc.LockedUntil != nil {
				_ = handler.repo.ClearAccountLockedUntil(r.Context(), acc.ID)
			}

			if _, err := handler.adminAuthService.DoLogin(w, r, acc); err != nil {
				log.Err(err).Msg("failed to login after TOTP verify")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
			utils.WriteJson(w, map[string]any{"ok": true})
			return
		}
		// Step <= last_totp_step → replay. Fall through to backup-code
		// path and the eventual generic failure response.
	}

	// Try backup code (case-insensitive)
	if handler.tryBackupCode(r, acc, code) {
		// Clear any lockout on success
		if acc.LockedUntil != nil {
			_ = handler.repo.ClearAccountLockedUntil(r.Context(), acc.ID)
		}

		if _, err := handler.adminAuthService.DoLogin(w, r, acc); err != nil {
			log.Err(err).Msg("failed to login after backup code verify")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		utils.WriteJson(w, map[string]any{"ok": true})
		return
	}

	// Both failed — record attempt
	_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeAdminLogin, subject, ip)
	handler.maybeApplyAdminLockout(r.Context(), acc.ID, attemptPurposeAdminLogin, subject)
	WriteError(w, r, "error.invalidTOTPCode", http.StatusUnauthorized)
}

// tryBackupCode checks if the code matches any remaining backup code for an
// admin account and, if so, consumes it. Read-compatible with legacy encrypted
// codes (migrated to hashes on first use) via consumeBackupCode.
func (handler *RequestHandler) tryBackupCode(r *http.Request, acc *core.Account, code string) bool {
	return handler.consumeBackupCode(
		r.Context(), acc.TOTPBackupCodesEncrypted, code, acc.ID,
		crypto.AAD("accounts", "totp_backup_codes_encrypted", acc.ID),
		func(ctx context.Context, ownerID uuid.UUID, newBlob []byte) error {
			return handler.repo.UpdateTOTPBackupCodes(ctx, ownerID, newBlob)
		},
	)
}

// verifyAccountPassword fetches the password hash and compares it
// using passwordhash.Verify.
func (handler *RequestHandler) verifyAccountPassword(ctx context.Context, accountID uuid.UUID, password string) error {
	acc, err := handler.repo.GetAccountByID(ctx, accountID)
	if err != nil {
		return err
	}
	_, passwordHash, _, err := handler.repo.GetAccountWithPasswordByEmail(ctx, acc.Email)
	if err != nil {
		return err
	}
	if passwordHash == "" {
		return errors.New("no password set")
	}
	ok, err := passwordhash.Verify(passwordHash, password)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("incorrect password")
	}
	return nil
}

// generateBackupCodes generates n random hex backup codes.
func generateBackupCodes(n int) ([]string, error) {
	codes := make([]string, n)
	for i := range codes {
		b := make([]byte, 8) // 8 bytes = 16 hex chars (64-bit; defense-in-depth)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		codes[i] = hex.EncodeToString(b)
	}
	return codes, nil
}

// normalizeBackupCode canonicalizes a backup code for hashing / comparison.
func normalizeBackupCode(code string) string {
	return strings.ToLower(strings.TrimSpace(code))
}

// hashBackupCode returns the hex HMAC-SHA256 of a normalized backup code,
// keyed by the OTP pepper and bound to the owner id. Backup codes are 64-bit
// random, so a one-way hash (vs. the prior reversible AES-GCM encryption) means
// a DB+key compromise yields nothing usable — matching how OTPs are stored. The
// owner binding stops the same code hashing identically across two accounts.
func hashBackupCode(code string, ownerID uuid.UUID, pepper string) string {
	m := hmac.New(sha256.New, []byte(pepper))
	m.Write([]byte(ownerID.String()))
	m.Write([]byte(":"))
	m.Write([]byte(normalizeBackupCode(code)))
	return hex.EncodeToString(m.Sum(nil))
}

// hashBackupCodes hashes each plaintext code and marshals the hashes to JSON
// for at-rest storage. The plaintext codes are shown to the user once at
// generation; the stored form is one-way and needs no encryption. Replaces the
// old encrypt-at-rest path for new / regenerated codes.
func (handler *RequestHandler) hashBackupCodes(codes []string, ownerID uuid.UUID) ([]byte, error) {
	pepper, err := handler.getOTPPepper()
	if err != nil {
		return nil, err
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = hashBackupCode(c, ownerID, pepper)
	}
	return json.Marshal(hashes)
}

// consumeBackupCode verifies a presented code against the stored set and, on a
// match, removes it and rewrites the remaining set in the hashed format. It is
// read-compatible with legacy AES-GCM-encrypted-plaintext blobs: those decrypt
// to the plaintext codes, are matched there, then migrated forward to hashes on
// first use (a new hashed blob is plain JSON and won't decrypt, so a decrypt
// error simply routes to the hashed branch). store persists the new blob.
func (handler *RequestHandler) consumeBackupCode(
	ctx context.Context,
	blob []byte,
	code string,
	ownerID uuid.UUID,
	legacyAAD []byte,
	store func(ctx context.Context, ownerID uuid.UUID, newBlob []byte) error,
) bool {
	if len(blob) == 0 {
		return false
	}

	// Legacy format: blob decrypts to a JSON array of plaintext codes.
	if dec, derr := handler.encryptor.DecryptFromBytesWithAAD(blob, legacyAAD); derr == nil {
		var codes []string
		if json.Unmarshal(dec, &codes) != nil {
			return false
		}
		want := normalizeBackupCode(code)
		idx := -1
		for i, c := range codes {
			if subtle.ConstantTimeCompare([]byte(normalizeBackupCode(c)), []byte(want)) == 1 {
				idx = i
				break
			}
		}
		if idx < 0 {
			return false
		}
		remaining := append(codes[:idx:idx], codes[idx+1:]...)
		newBlob, herr := handler.hashBackupCodes(remaining, ownerID) // migrate forward
		if herr != nil {
			log.Err(herr).Msg("backup code: rehash of legacy remaining failed")
			return false
		}
		if err := store(ctx, ownerID, newBlob); err != nil {
			log.Err(err).Msg("backup code: store after legacy consume failed")
			return false
		}
		return true
	}

	// New format: JSON array of HMAC hashes.
	pepper, err := handler.getOTPPepper()
	if err != nil {
		log.Err(err).Msg("backup code: missing OTP pepper")
		return false
	}
	var hashes []string
	if json.Unmarshal(blob, &hashes) != nil {
		return false
	}
	want := hashBackupCode(code, ownerID, pepper)
	idx := -1
	for i, h := range hashes {
		if subtle.ConstantTimeCompare([]byte(h), []byte(want)) == 1 {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false
	}
	remaining := append(hashes[:idx:idx], hashes[idx+1:]...)
	newBlob, merr := json.Marshal(remaining)
	if merr != nil {
		log.Err(merr).Msg("backup code: marshal remaining hashes failed")
		return false
	}
	if err := store(ctx, ownerID, newBlob); err != nil {
		log.Err(err).Msg("backup code: store after consume failed")
		return false
	}
	return true
}
