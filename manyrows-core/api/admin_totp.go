package api

import (
	"context"
	"crypto/rand"
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

	if !totp.Validate(code, string(secret)) {
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

	encryptedCodes, err := encryptBackupCodes(
		handler,
		backupCodes,
		crypto.AAD("accounts", "totp_backup_codes_encrypted", acc.ID),
	)
	if err != nil {
		log.Err(err).Msg("failed to encrypt backup codes")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC()
	if err := handler.repo.EnableTOTP(r.Context(), acc.ID, now, encryptedCodes); err != nil {
		log.Err(err).Msg("failed to enable TOTP")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
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

	encryptedCodes, err := encryptBackupCodes(
		handler,
		backupCodes,
		crypto.AAD("accounts", "totp_backup_codes_encrypted", acc.ID),
	)
	if err != nil {
		log.Err(err).Msg("failed to encrypt backup codes")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if err := handler.repo.UpdateTOTPBackupCodes(r.Context(), acc.ID, encryptedCodes); err != nil {
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

	// Rate limit (shares counter with password login)
	ip := auth.ClientIP(r)

	if !handler.checkAttemptRateLimit(w, r, attemptPurposeAdminLogin, ip, "", "admin TOTP verify", nil) {
		return
	}

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

// tryBackupCode checks if the code matches any remaining backup code.
// If matched, consumes it (removes from the stored list).
func (handler *RequestHandler) tryBackupCode(r *http.Request, acc *core.Account, code string) bool {
	if len(acc.TOTPBackupCodesEncrypted) == 0 {
		return false
	}

	decrypted, err := handler.encryptor.DecryptFromBytesWithAAD(
		acc.TOTPBackupCodesEncrypted,
		crypto.AAD("accounts", "totp_backup_codes_encrypted", acc.ID),
	)
	if err != nil {
		log.Err(err).Msg("failed to decrypt backup codes")
		return false
	}

	var codes []string
	if err := json.Unmarshal(decrypted, &codes); err != nil {
		log.Err(err).Msg("failed to unmarshal backup codes")
		return false
	}

	codeNorm := strings.ToLower(strings.TrimSpace(code))
	matchIdx := -1
	for i, c := range codes {
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(c)), []byte(codeNorm)) == 1 {
			matchIdx = i
			break
		}
	}
	if matchIdx < 0 {
		return false
	}

	// Remove the matched code
	codes = append(codes[:matchIdx], codes[matchIdx+1:]...)

	encryptedCodes, err := encryptBackupCodes(
		handler,
		codes,
		crypto.AAD("accounts", "totp_backup_codes_encrypted", acc.ID),
	)
	if err != nil {
		log.Err(err).Msg("failed to re-encrypt backup codes after consumption")
		return false
	}

	if err := handler.repo.UpdateTOTPBackupCodes(r.Context(), acc.ID, encryptedCodes); err != nil {
		log.Err(err).Msg("failed to update backup codes after consumption")
		return false
	}

	return true
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

// encryptBackupCodes marshals codes to JSON and encrypts with AAD-bound
// GCM. aad should be crypto.AAD(table, column, ownerID) for whichever
// table holds the codes (accounts for admin, users for workspace).
func encryptBackupCodes(handler *RequestHandler, codes []string, aad []byte) ([]byte, error) {
	data, err := json.Marshal(codes)
	if err != nil {
		return nil, err
	}
	return handler.encryptor.EncryptToBytesWithAAD(data, aad)
}
