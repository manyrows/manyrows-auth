package api

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/core/validation"
	"manyrows-core/crypto/passwordhash"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

const (
	adminResetOTP_TTL = 15 * time.Minute

	adminResetOTPRequestWindow  = 10 * time.Minute
	adminResetOTPResendCooldown = 20 * time.Second

	// SEND step (email OTP issuance)
	attemptPurposeAdminForgotPW = "admin_forgot_password_otp"

	// ✅ NEW: preflight/IP throttling for /forgot (burn even if account doesn't exist)
	attemptPurposeAdminForgotPWPreflight = "admin_forgot_password_preflight"

	// ✅ NEW: VERIFY step throttling for /reset (burn on invalid/expired attempts)
	attemptPurposeAdminResetPW = "admin_reset_password_verify"
)

type AdminForgotPasswordRequest struct {
	Email          string `json:"email"`
	TurnstileToken string `json:"turnstileToken"`
}

type AdminResetPasswordRequest struct {
	Email       string `json:"email"`
	Code        string `json:"code"`
	NewPassword string `json:"password"`
}

func (handler *RequestHandler) AdminForgotPassword(w http.ResponseWriter, r *http.Request) {
	// must be logged out
	acc, _, err := handler.adminAuthService.GetLoggedInAccount(r)
	if err != nil {
		log.Err(err).Msg("failed to get logged in account for forgot password")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if acc != nil {
		WriteError(w, r, "error.alreadyLoggedIn", http.StatusForbidden)
		return
	}

	req := AdminForgotPasswordRequest{}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	if !handler.verifyTurnstile(w, r, req.TurnstileToken) {
		return
	}

	email := strings.TrimSpace(strings.ToLower(req.Email))
	toEmail, vr := auth.ValidateEmail(email)
	if !vr.Ok() {
		WriteValidationError(w, r, vr)
		return
	}

	now := time.Now().UTC()
	ip := auth.ClientIP(r)

	// Preflight IP rate limit (burn even if account doesn't exist)
	if !handler.checkAttemptRateLimit(w, r, attemptPurposeAdminForgotPWPreflight, ip, "", "forgot password preflight", nil) {
		return
	}
	if err := handler.repo.InsertAttempt(r.Context(), attemptPurposeAdminForgotPWPreflight, "forgot_pw", ip); err != nil {
		// don't fail the request if logging fails
		log.Err(err).Msg("Could not insert forgot pw preflight attempt")
	}

	// Rate limit SEND step (IP + subject) - only counts successful sends
	subject := strings.TrimSpace(strings.ToLower(toEmail))
	if !handler.checkAttemptRateLimit(w, r, attemptPurposeAdminForgotPW, ip, subject, "forgot password", nil) {
		return
	}
	if !handler.checkEmailSendDailyQuota(w, r, attemptPurposeAdminForgotPW, subject, "forgot password", nil) {
		return
	}

	// Lookup account, but DO NOT leak existence
	acc2, vr2, err := handler.repo.GetAccountByEmail(r.Context(), toEmail)
	if err != nil {
		log.Err(err).Msg("Could not lookup account by email (forgot password)")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !vr2.Ok() {
		WriteValidationError(w, r, vr2)
		return
	}
	if acc2 == nil {
		utils.WriteJson(w, map[string]any{"ok": true})
		return
	}

	// Cooldown: if there's already a recent active OTP, don't resend
	if existing, err := handler.repo.GetLatestActiveAccountPasswordResetOTP(r.Context(), acc2.ID); err == nil && existing != nil {
		if existing.IsActive(now) && existing.CreatedAt.After(now.Add(-adminResetOTPResendCooldown)) {
			utils.WriteJson(w, map[string]any{"ok": true})
			return
		}
	} else if err != nil && !errors.Is(err, repo.ErrAccountPasswordResetOTPNotFound) {
		log.Err(err).Msg("Could not check existing reset otp for cooldown")
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

	// One active OTP per account
	if err := handler.repo.DeleteUnusedAccountPasswordResetOTPs(r.Context(), acc2.ID); err != nil {
		log.Err(err).Msg("Could not delete unused reset otps")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	otp := core.AccountPasswordResetOTP{
		ID:        otpID,
		AccountID: acc2.ID,
		CodeHash:  codeHash,
		ExpiresAt: now.Add(adminResetOTP_TTL),
		UsedAt:    nil,
		CreatedAt: now,
	}

	if err := handler.repo.InsertAccountPasswordResetOTP(r.Context(), otp); err != nil {
		log.Err(err).Msg("Could not insert reset otp")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Send email
	lang := acc2.Language
	if lang == "" {
		lang = "en"
	}
	if err := handler.emailService.SendAdminPasswordResetCode(toEmail, code, lang); err != nil {
		log.Err(err).Msg("Could not send reset code email")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// burn attempts only after successful send
	if err := handler.repo.InsertAttempt(r.Context(), attemptPurposeAdminForgotPW, subject, ip); err != nil {
		log.Err(err).Msg("Could not insert forgot pw attempt (post-send)")
	}

	utils.WriteJson(w, map[string]any{"ok": true})
}

func (handler *RequestHandler) AdminResetPassword(w http.ResponseWriter, r *http.Request) {
	// must be logged out
	acc, _, err := handler.adminAuthService.GetLoggedInAccount(r)
	if err != nil {
		log.Err(err).Msg("failed to get logged in account for reset password")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if acc != nil {
		WriteError(w, r, "error.alreadyLoggedIn", http.StatusForbidden)
		return
	}

	req := AdminResetPasswordRequest{}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	email := strings.TrimSpace(strings.ToLower(req.Email))
	toEmail, vr := auth.ValidateEmail(email)
	if !vr.Ok() {
		WriteValidationError(w, r, vr)
		return
	}

	code := strings.TrimSpace(req.Code)
	if len(code) != 6 || !isDigits(code) {
		WriteError(w, r, "error.invalidCode", http.StatusBadRequest)
		return
	}

	newPw := strings.TrimSpace(req.NewPassword)
	if len(newPw) < minAdminPasswordLen {
		WriteValidationError(w, r, validation.NewIssue("newPassword", "too_short", "password is too short"))
		return
	}
	if len(newPw) > 128 {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Rate limit VERIFY step (IP + subject)
	now := time.Now().UTC()
	ip := auth.ClientIP(r)

	subject := strings.TrimSpace(strings.ToLower(toEmail))
	if !handler.checkAttemptRateLimit(w, r, attemptPurposeAdminResetPW, ip, subject, "reset password", nil) {
		return
	}

	acc2, vr2, err := handler.repo.GetAccountByEmail(r.Context(), toEmail)
	if err != nil {
		log.Err(err).Msg("Could not lookup account by email (reset password)")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !vr2.Ok() {
		WriteValidationError(w, r, vr2)
		return
	}
	if acc2 == nil {
		// burn (but don't leak more than necessary)
		_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeAdminResetPW, subject, ip)
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	pepper, err := handler.getOTPPepper()
	if err != nil {
		log.Err(err).Msg("Missing OTP pepper")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Hash new password now (so tx is shorter)
	newHash, err := passwordhash.Hash(newPw)
	if err != nil {
		log.Err(err).Msg("Could not hash password")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	pool := handler.repo.DB().Pool()
	tx, err := pool.Begin(r.Context())
	if err != nil {
		log.Err(err).Msg("Could not begin tx (reset password)")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(r.Context())

	otp, err := handler.repo.GetLatestActiveAccountPasswordResetOTPForUpdate(r.Context(), tx, acc2.ID)
	if err != nil {
		if errors.Is(err, repo.ErrAccountPasswordResetOTPNotFound) {
			_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeAdminResetPW, subject, ip)
			WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
			return
		}
		log.Err(err).Msg("Could not load reset otp for update")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Atomically claim an attempt slot — single SQL statement does
	// the attempts < cap check AND the increment. Closes the TOCTOU
	// race where N concurrent verifies all observed attempts < cap
	// and all incremented past it. On cap hit, burn the OTP.
	newAttempts, claimErr := handler.repo.ClaimAccountPasswordResetOTPAttemptTx(r.Context(), tx, otp.ID, otpMaxAttempts)
	if claimErr != nil {
		if errors.Is(claimErr, repo.ErrAccountPasswordResetOTPAttemptsCapHit) {
			burnNow := time.Now().UTC()
			if err := handler.repo.MarkAccountPasswordResetOTPUsedTx(r.Context(), tx, otp.ID, burnNow); err != nil &&
				!errors.Is(err, repo.ErrAccountPasswordResetOTPNotFound) {
				log.Err(err).Msg("Could not burn saturated password reset otp")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
			if err := tx.Commit(r.Context()); err != nil {
				log.Err(err).Msg("Could not commit tx (burn saturated password reset otp)")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
			_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeAdminResetPW, subject, ip)
			WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
			return
		}
		if errors.Is(claimErr, repo.ErrAccountPasswordResetOTPNotFound) {
			_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeAdminResetPW, subject, ip)
			WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
			return
		}
		log.Err(claimErr).Msg("Could not claim password reset otp attempt")
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
			if err := handler.repo.MarkAccountPasswordResetOTPUsedTx(r.Context(), tx, otp.ID, time.Now().UTC()); err != nil &&
				!errors.Is(err, repo.ErrAccountPasswordResetOTPNotFound) {
				log.Err(err).Msg("Could not burn maxed-out password reset otp")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
		}
		if err := tx.Commit(r.Context()); err != nil {
			log.Err(err).Msg("Could not commit tx (reset password verify, wrong code)")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeAdminResetPW, subject, ip)
		WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
		return
	}

	if err := handler.repo.MarkAccountPasswordResetOTPUsedTx(r.Context(), tx, otp.ID, now); err != nil {
		log.Err(err).Msg("Could not mark reset otp used")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if err := handler.repo.UpdateAccountPasswordTx(r.Context(), tx, acc2.ID, newHash, now); err != nil {
		log.Err(err).Msg("Could not update password")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		log.Err(err).Msg("Could not commit tx (reset password)")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Revoke every existing session for this account before issuing a fresh
	// one. Anyone who'd hijacked a session prior to the reset is now evicted.
	if _, err := handler.repo.DeleteSessionsByAccount(r.Context(), acc2.ID); err != nil {
		// Don't block the user from logging in if eviction fails — but log
		// loudly because this is a security-relevant invariant.
		log.Err(err).Str("accountId", acc2.ID.String()).Msg("Could not revoke sessions after admin password reset")
	}

	// Log them in immediately after reset (this issues a brand-new session)
	if _, err := handler.adminAuthService.DoLogin(w, r, acc2); err != nil {
		log.Err(err).Msg("Could not login after password reset")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{"ok": true})
}
