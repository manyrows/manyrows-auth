package api

import (
	"crypto/subtle"
	"errors"
	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/core/validation"
	"manyrows-core/crypto/passwordhash"
	"manyrows-core/utils"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	emailChangeOTP_TTL = 15 * time.Minute

	emailChangeOTPRequestWindow  = 10 * time.Minute
	emailChangeOTPResendCooldown = 20 * time.Second

	attemptPurposeEmailChange       = "admin_email_change_otp"
	attemptPurposeEmailChangeVerify = "admin_email_change_verify"
)

type RequestEmailChangeRequest struct {
	NewEmail string `json:"newEmail"`
	Password string `json:"password"`
}

type VerifyEmailChangeRequest struct {
	Code string `json:"code"`
}

// RequestEmailChange initiates an email change by verifying the password and sending an OTP to the new email.
func (handler *RequestHandler) RequestEmailChange(w http.ResponseWriter, r *http.Request) {
	acc, _, err := handler.adminAuthService.GetLoggedInAccount(r)
	if err != nil {
		log.Err(err).Msg("failed to get logged in account for email change request")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if acc == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	req := RequestEmailChangeRequest{}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	newEmail := strings.TrimSpace(strings.ToLower(req.NewEmail))
	password := strings.TrimSpace(req.Password)

	if newEmail == "" {
		WriteValidationError(w, r, validation.NewIssue("newEmail", "required", "new email is required"))
		return
	}

	if password == "" {
		WriteValidationError(w, r, validation.NewIssue("password", "required", "password is required"))
		return
	}

	// Validate email format
	toEmail, vr := auth.ValidateEmail(newEmail)
	if !vr.Ok() {
		WriteValidationError(w, r, vr)
		return
	}

	// Check if new email is same as current
	if strings.EqualFold(toEmail, acc.Email) {
		WriteValidationError(w, r, validation.NewIssue("newEmail", "same_as_current", "new email must be different from current email"))
		return
	}

	// Rate limiting
	now := time.Now().UTC()
	ip := auth.ClientIP(r)
	subject := strings.TrimSpace(strings.ToLower(acc.Email))

	if !handler.checkAttemptRateLimit(w, r, attemptPurposeEmailChange, ip, subject, "email change", nil) {
		return
	}
	if !handler.checkEmailSendDailyQuota(w, r, attemptPurposeEmailChange, subject, "email change", nil) {
		return
	}

	// Verify password
	_, passwordHash, vr2, err := handler.repo.GetAccountWithPasswordByEmail(r.Context(), acc.Email)
	if err != nil {
		log.Err(err).Msg("Could not lookup account with password for email change")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !vr2.Ok() {
		WriteValidationError(w, r, vr2)
		return
	}
	// Dummy verify on the "no password set" branch so the response
	// time matches the wrong-password branch — otherwise we leak
	// "this account has no password" via timing. Same passwordhash
	// surface used everywhere for consistent timing.
	if passwordHash == "" {
		passwordhash.DummyVerify(password)
		_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeEmailChange, subject, ip)
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	ok, vErr := passwordhash.Verify(passwordHash, password)
	if vErr != nil || !ok {
		_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeEmailChange, subject, ip)
		vr3 := validation.NewIssue("password", "incorrect", "incorrect password")
		vr3.Status = http.StatusUnauthorized
		WriteValidationError(w, r, vr3)
		return
	}

	// Check if new email is already taken by another account
	taken, err := handler.repo.IsEmailTaken(r.Context(), toEmail, acc.ID)
	if err != nil {
		log.Err(err).Msg("Could not check if email is taken")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if taken {
		vr4 := validation.NewIssue("newEmail", "duplicate", "email is already in use")
		vr4.Status = http.StatusConflict
		WriteValidationError(w, r, vr4)
		return
	}

	// Check if another account has a pending change to this email
	pending, err := handler.repo.IsEmailPendingChange(r.Context(), toEmail, acc.ID)
	if err != nil {
		log.Err(err).Msg("Could not check if email is pending change")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if pending {
		vr5 := validation.NewIssue("newEmail", "duplicate", "email is already in use")
		vr5.Status = http.StatusConflict
		WriteValidationError(w, r, vr5)
		return
	}

	// Cooldown: check if there's an active OTP created recently
	if existing, err := handler.repo.GetLatestActiveAccountEmailChangeOTP(r.Context(), acc.ID); err == nil && existing != nil {
		if existing.IsActive(now) && existing.CreatedAt.After(now.Add(-emailChangeOTPResendCooldown)) {
			utils.WriteJson(w, map[string]any{"ok": true})
			return
		}
	} else if err != nil && !errors.Is(err, repo.ErrAccountEmailChangeOTPNotFound) {
		log.Err(err).Msg("Could not check existing email change otp for cooldown")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
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

	// Delete any existing unused OTPs for this account
	if err := handler.repo.DeleteUnusedAccountEmailChangeOTPs(r.Context(), acc.ID); err != nil {
		log.Err(err).Msg("Could not delete unused email change otps")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	otp := core.AccountEmailChangeOTP{
		ID:        otpID,
		AccountID: acc.ID,
		NewEmail:  toEmail,
		CodeHash:  codeHash,
		ExpiresAt: now.Add(emailChangeOTP_TTL),
		UsedAt:    nil,
		CreatedAt: now,
	}

	if err := handler.repo.InsertAccountEmailChangeOTP(r.Context(), otp); err != nil {
		log.Err(err).Msg("Could not insert email change otp")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Send email to the NEW email address
	lang := acc.Language
	if lang == "" {
		lang = "en"
	}
	if err := handler.emailService.SendEmailChangeCode(toEmail, code, lang); err != nil {
		log.Err(err).Msg("Could not send email change code")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Burn attempt only after we sent the email
	if err := handler.repo.InsertAttempt(r.Context(), attemptPurposeEmailChange, subject, ip); err != nil {
		log.Err(err).Msg("Could not insert email change attempt (post-send)")
	}

	utils.WriteJson(w, map[string]any{"ok": true})
}

// VerifyEmailChange verifies the OTP code and updates the account email.
func (handler *RequestHandler) VerifyEmailChange(w http.ResponseWriter, r *http.Request) {
	acc, _, err := handler.adminAuthService.GetLoggedInAccount(r)
	if err != nil {
		log.Err(err).Msg("failed to get logged in account for email change verification")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if acc == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	req := VerifyEmailChangeRequest{}
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
	verifySubject := strings.TrimSpace(strings.ToLower(acc.Email))
	now := time.Now().UTC()

	if !handler.checkAttemptRateLimit(w, r, attemptPurposeEmailChangeVerify, ip, verifySubject, "email change verify", nil) {
		return
	}
	_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeEmailChangeVerify, verifySubject, ip)

	pepper, err := handler.getOTPPepper()
	if err != nil {
		log.Err(err).Msg("Missing OTP pepper")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Transaction: lock OTP row, compare, mark used, update email
	pool := handler.repo.DB().Pool()
	tx, err := pool.Begin(r.Context())
	if err != nil {
		log.Err(err).Msg("Could not begin tx (email change verify)")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(r.Context())

	otp, err := handler.repo.GetLatestActiveAccountEmailChangeOTPForUpdate(r.Context(), tx, acc.ID)
	if err != nil {
		if errors.Is(err, repo.ErrAccountEmailChangeOTPNotFound) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		log.Err(err).Msg("Could not load email change otp for update")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if otp == nil || !otp.IsActive(time.Now().UTC()) {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Atomically claim an attempt slot — single SQL statement does
	// the attempts < cap check AND the increment. Closes the TOCTOU
	// race where N concurrent verifies all observed attempts < cap
	// and all incremented past it. On cap hit, burn the OTP.
	newAttempts, claimErr := handler.repo.ClaimAccountEmailChangeOTPAttemptTx(r.Context(), tx, otp.ID, otpMaxAttempts)
	if claimErr != nil {
		if errors.Is(claimErr, repo.ErrAccountEmailChangeOTPAttemptsCapHit) {
			now := time.Now().UTC()
			if err := handler.repo.MarkAccountEmailChangeOTPUsedTx(r.Context(), tx, otp.ID, now); err != nil &&
				!errors.Is(err, repo.ErrAccountEmailChangeOTPNotFound) {
				log.Err(err).Msg("Could not burn saturated email change otp")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
			if err := tx.Commit(r.Context()); err != nil {
				log.Err(err).Msg("Could not commit tx (burn saturated email change otp)")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		if errors.Is(claimErr, repo.ErrAccountEmailChangeOTPNotFound) {
			WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
			return
		}
		log.Err(claimErr).Msg("Could not claim email change otp attempt")
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
		// If we just hit the cap, burn the OTP so retries fall
		// through the "no active OTP" branch.
		if newAttempts >= otpMaxAttempts {
			if err := handler.repo.MarkAccountEmailChangeOTPUsedTx(r.Context(), tx, otp.ID, time.Now().UTC()); err != nil &&
				!errors.Is(err, repo.ErrAccountEmailChangeOTPNotFound) {
				log.Err(err).Msg("Could not burn maxed-out email change otp")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
		}
		if err := tx.Commit(r.Context()); err != nil {
			log.Err(err).Msg("Could not commit tx (email change verify, wrong code)")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
		return
	}

	now = time.Now().UTC()

	if err := handler.repo.MarkAccountEmailChangeOTPUsedTx(r.Context(), tx, otp.ID, now); err != nil {
		log.Err(err).Msg("Could not mark email change otp used")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	oldEmail := acc.Email
	if err := handler.repo.UpdateAccountEmailTx(r.Context(), tx, acc.ID, otp.NewEmail); err != nil {
		log.Err(err).Msg("Could not update account email")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		log.Err(err).Msg("Could not commit tx (email change verify)")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Notify the OLD address that the swap happened. Account-takeover
	// victim sees this in their inbox and can act before the attacker
	// pivots deeper. Best-effort: swap is already committed, so a
	// transient SMTP failure logs and moves on.
	if err := handler.emailService.SendEmailChangeNotice(oldEmail, "en"); err != nil {
		log.Err(err).Str("old_email", oldEmail).Msg("email-change notice to old address failed (non-fatal)")
	}

	utils.WriteJson(w, map[string]any{"ok": true, "newEmail": otp.NewEmail})
}
