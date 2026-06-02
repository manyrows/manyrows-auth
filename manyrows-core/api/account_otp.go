package api

import (
	"crypto/subtle"
	"errors"
	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	adminOTP_TTL = 15 * time.Minute

	// Same idea as client OTP
	adminOTPRequestWindow  = 10 * time.Minute
	adminOTPResendCooldown = 20 * time.Second

	attemptPurposeAdminEmailValidate       = "admin_email_validate_otp"
	attemptPurposeAdminEmailValidateVerify = "admin_email_validate_verify"
)

type VerifyValidationCodeRequest struct {
	Code string `json:"code"`
}

func (handler *RequestHandler) SendValidateEmail(w http.ResponseWriter, r *http.Request) {
	acc, _, err := handler.adminAuthService.GetLoggedInAccount(r)
	if err != nil {
		log.Err(err).Msg("failed to get logged in account for send validate email")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if acc == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	// Reload for latest validated_at
	acc2, err := handler.repo.GetAccountByID(r.Context(), acc.ID)
	if err != nil {
		log.Err(err).Msg("Could not load account by id (admin validate)")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if acc2 == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	// If already validated, idempotent OK
	if acc2.ValidatedAt != nil && !acc2.ValidatedAt.IsZero() {
		utils.WriteJson(w, map[string]any{"ok": true, "validated": true})
		return
	}

	now := time.Now().UTC()

	// ✅ Cooldown: if there is an active OTP created recently, don't send again.
	if existing, err := handler.repo.GetLatestActiveAccountEmailOTP(r.Context(), acc2.ID); err == nil && existing != nil {
		if existing.IsActive(now) && existing.CreatedAt.After(now.Add(-adminOTPResendCooldown)) {
			utils.WriteJson(w, map[string]any{"ok": true})
			return
		}
	} else if err != nil && !errors.Is(err, repo.ErrAccountEmailOTPNotFound) {
		log.Err(err).Msg("Could not check existing admin otp for cooldown")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	subject := strings.TrimSpace(strings.ToLower(acc2.Email))
	if subject == "" {
		WriteError(w, r, "error.emailRequired", http.StatusBadRequest)
		return
	}

	// Rate limit SEND step using attempts table (IP + subject)
	ip := auth.ClientIP(r)

	if !handler.checkAttemptRateLimit(w, r, attemptPurposeAdminEmailValidate, ip, subject, "admin email validate", nil) {
		return
	}

	pepper, err := handler.getOTPPepper()
	if err != nil {
		log.Err(err).Msg("Missing OTP pepper")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	code, err := generateOTP6()
	if err != nil {
		log.Err(err).Msg("Could not generate otp")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	otpID := utils.NewUUID()
	codeHash, err := hashOTP(otpID, code, pepper)
	if err != nil {
		log.Err(err).Msg("Could not hash otp")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Ensure one active OTP per account
	if err := handler.repo.DeleteUnusedAccountEmailOTPs(r.Context(), acc2.ID); err != nil {
		log.Err(err).Msg("Could not delete unused account email otps")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	otp := core.AccountEmailOTP{
		ID:        otpID,
		AccountID: acc2.ID,
		CodeHash:  codeHash,
		ExpiresAt: now.Add(adminOTP_TTL),
		UsedAt:    nil,
		CreatedAt: now,
	}

	if err := handler.repo.InsertAccountEmailOTP(r.Context(), otp); err != nil {
		log.Err(err).Msg("Could not insert account email otp")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// ✅ Send email first...
	lang := acc2.Language
	if lang == "" {
		lang = "en"
	}
	if err := handler.emailService.SendAdminEmailValidationCode(subject, code, lang); err != nil {
		log.Err(err).Msg("Could not send admin validation code email")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// ✅ ...then burn attempt budget only if we actually sent.
	if err := handler.repo.InsertAttempt(r.Context(), attemptPurposeAdminEmailValidate, subject, ip); err != nil {
		// Email already sent; treat as non-fatal
		log.Err(err).Msg("Could not insert admin otp attempt (post-send)")
	}

	utils.WriteJson(w, map[string]any{"ok": true})
}

// VerifyValidationCode verifies the code for the *logged-in* admin account and sets validated_at.
func (handler *RequestHandler) VerifyValidationCode(w http.ResponseWriter, r *http.Request) {
	acc, _, err := handler.adminAuthService.GetLoggedInAccount(r)
	if err != nil {
		log.Err(err).Msg("failed to get logged in account for verify validation code")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if acc == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	req := VerifyValidationCodeRequest{}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	code := strings.TrimSpace(req.Code)
	if len(code) != 6 || !isDigits(code) {
		WriteError(w, r, "error.invalidCode", http.StatusBadRequest)
		return
	}

	// Rate limit verification attempts
	ip := auth.ClientIP(r)
	subject := strings.TrimSpace(strings.ToLower(acc.Email))
	now := time.Now().UTC()

	if !handler.checkAttemptRateLimit(w, r, attemptPurposeAdminEmailValidateVerify, ip, subject, "admin email validate verify", nil) {
		return
	}
	_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeAdminEmailValidateVerify, subject, ip)

	pepper, err := handler.getOTPPepper()
	if err != nil {
		log.Err(err).Msg("Missing OTP pepper")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// If already validated: idempotent OK.
	acc2, err := handler.repo.GetAccountByID(r.Context(), acc.ID)
	if err != nil {
		log.Err(err).Msg("Could not load account by id (admin verify)")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if acc2 == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}
	if acc2.ValidatedAt != nil && !acc2.ValidatedAt.IsZero() {
		utils.WriteJson(w, map[string]any{"ok": true, "validated": true})
		return
	}

	// Transaction: lock OTP row, compare, mark used, set validated_at
	pool := handler.repo.DB().Pool()
	tx, err := pool.Begin(r.Context())
	if err != nil {
		log.Err(err).Msg("Could not begin tx (admin verify)")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(r.Context())

	otp, err := handler.repo.GetLatestActiveAccountEmailOTPForUpdate(r.Context(), tx, acc2.ID)
	if err != nil {
		if errors.Is(err, repo.ErrAccountEmailOTPNotFound) {
			WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
			return
		}
		log.Err(err).Msg("Could not load otp for update")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if otp == nil || !otp.IsActive(time.Now().UTC()) {
		WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
		return
	}

	// Atomically claim an attempt slot — single SQL statement does
	// the attempts < cap check AND the increment. Closes the TOCTOU
	// race where N concurrent verifies all observed attempts < cap
	// and all incremented past it. On cap hit, burn the OTP so
	// further attempts fall through the "no active OTP" branch.
	newAttempts, claimErr := handler.repo.ClaimAccountEmailOTPAttemptTx(r.Context(), tx, otp.ID, otpMaxAttempts)
	if claimErr != nil {
		if errors.Is(claimErr, repo.ErrAccountEmailOTPAttemptsCapHit) {
			now := time.Now().UTC()
			if burnErr := handler.repo.MarkAccountEmailOTPUsedTx(r.Context(), tx, otp.ID, now); burnErr != nil &&
				!errors.Is(burnErr, repo.ErrAccountEmailOTPNotFound) {
				log.Err(burnErr).Msg("Could not burn saturated email otp")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
			if err := tx.Commit(r.Context()); err != nil {
				log.Err(err).Msg("Could not commit tx (burn saturated email otp)")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
			WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
			return
		}
		if errors.Is(claimErr, repo.ErrAccountEmailOTPNotFound) {
			WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
			return
		}
		log.Err(claimErr).Msg("Could not claim email otp attempt")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	expectedHash, err := hashOTP(otp.ID, code, pepper)
	if err != nil {
		log.Err(err).Msg("Could not hash otp for verify")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if subtle.ConstantTimeCompare([]byte(otp.CodeHash), []byte(expectedHash)) != 1 {
		// Attempt counter already incremented atomically above.
		// If we just hit the cap, burn the OTP so retries don't
		// see an active row.
		if newAttempts >= otpMaxAttempts {
			if err := handler.repo.MarkAccountEmailOTPUsedTx(r.Context(), tx, otp.ID, time.Now().UTC()); err != nil &&
				!errors.Is(err, repo.ErrAccountEmailOTPNotFound) {
				log.Err(err).Msg("Could not burn maxed-out email otp")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
		}
		if err := tx.Commit(r.Context()); err != nil {
			log.Err(err).Msg("Could not commit tx (admin verify, wrong code)")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
		return
	}

	now = time.Now().UTC()

	if err := handler.repo.MarkAccountEmailOTPUsedTx(r.Context(), tx, otp.ID, now); err != nil {
		log.Err(err).Msg("Could not mark account otp used")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if err := handler.repo.SetAccountValidatedAt(r.Context(), tx, acc2.ID, now); err != nil {
		log.Err(err).Msg("Could not set account validated_at")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		log.Err(err).Msg("Could not commit tx (admin verify)")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{"ok": true, "validated": true})
}
