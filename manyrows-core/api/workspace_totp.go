package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/crypto"
	"manyrows-core/crypto/passwordhash"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
)

const totpChallengeTTL = 5 * time.Minute

// attemptPurposeReauthSensitive is the rate-limit bucket for the
// sensitive-operation re-auth gate (TOTP setup/disable, passkey
// delete). Keyed per-account so that a brute-force password guess
// against /totp/setup gets the same per-account lockout as the
// login flow.
const attemptPurposeReauthSensitive = "client_sensitive_reauth"

// HandleWorkspaceTOTPSetup generates a new TOTP secret for the logged-in user.
// The secret is stored encrypted but not yet enabled — user must confirm via Enable.
// POST /x/{slug}/a/totp/setup
//
// Re-auth required: the response returns the plaintext TOTP secret so
// the user can scan it into an authenticator. Without a re-auth gate,
// a stolen access token would let an attacker silently bind a new
// authenticator they control to the victim's account. Accepts the
// same EITHER-password-OR-emailed-code surface as TOTP disable.
func (handler *RequestHandler) HandleWorkspaceTOTPSetup(w http.ResponseWriter, r *http.Request) {
	ses, ok := core.ClientSessionFromContext(r.Context())
	if !ok || ses == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	ctxApp, appOk := core.AppFromContext(r.Context())
	if !appOk || ctxApp == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	userWithTOTP, err := handler.repo.GetUserByIDWithTOTP(r.Context(), ses.UserID)
	if err != nil || userWithTOTP == nil {
		log.Err(err).Msg("failed to get user for TOTP setup")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if userWithTOTP.HasTOTP() {
		WriteError(w, r, "error.totpAlreadyEnabled", http.StatusConflict)
		return
	}

	if !handler.requireSensitivePasswordOrCodeReauth(w, r, userWithTOTP, ctxApp, req.Password, req.Code) {
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Manyrows",
		AccountName: userWithTOTP.Email,
	})
	if err != nil {
		log.Err(err).Msg("failed to generate TOTP key")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	encrypted, err := handler.encryptor.EncryptToBytesWithAAD(
		[]byte(key.Secret()),
		crypto.AAD("users", "totp_secret_encrypted", userWithTOTP.ID),
	)
	if err != nil {
		log.Err(err).Msg("failed to encrypt TOTP secret")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if err := handler.repo.SetUserTOTPSecret(r.Context(), userWithTOTP.ID, encrypted); err != nil {
		log.Err(err).Msg("failed to store TOTP secret")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{
		"secret": key.Secret(),
		"uri":    key.URL(),
	})
}

// HandleWorkspaceTOTPEnable verifies a TOTP code and enables 2FA, returning backup codes.
// POST /x/{slug}/a/totp/enable
func (handler *RequestHandler) HandleWorkspaceTOTPEnable(w http.ResponseWriter, r *http.Request) {
	ses, ok := core.ClientSessionFromContext(r.Context())
	if !ok || ses == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
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

	userWithTOTP, err := handler.repo.GetUserByIDWithTOTP(r.Context(), ses.UserID)
	if err != nil || userWithTOTP == nil {
		log.Err(err).Msg("failed to get user for TOTP enable")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if userWithTOTP.HasTOTP() {
		WriteError(w, r, "error.totpAlreadyEnabled", http.StatusConflict)
		return
	}

	if len(userWithTOTP.TOTPSecretEncrypted) == 0 {
		WriteError(w, r, "error.totpNotSetUp", http.StatusBadRequest)
		return
	}

	secret, err := handler.encryptor.DecryptFromBytesWithAAD(
		userWithTOTP.TOTPSecretEncrypted,
		crypto.AAD("users", "totp_secret_encrypted", userWithTOTP.ID),
	)
	if err != nil {
		log.Err(err).Msg("failed to decrypt TOTP secret")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Shared verify primitive (see admin enroll): learn the matched step so we
	// can burn it after enable and stop the enrollment code being replayed at
	// the first login verify.
	enrollStep, ok := auth.VerifyTOTPCode(code, string(secret))
	if !ok {
		WriteError(w, r, "error.invalidTOTPCode", http.StatusUnauthorized)
		return
	}

	backupCodes, err := generateBackupCodes(8)
	if err != nil {
		log.Err(err).Msg("failed to generate backup codes")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	storedCodes, err := handler.hashBackupCodes(backupCodes, userWithTOTP.ID)
	if err != nil {
		log.Err(err).Msg("failed to hash backup codes")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC()
	if err := handler.repo.EnableUserTOTP(r.Context(), userWithTOTP.ID, now, storedCodes); err != nil {
		log.Err(err).Msg("failed to enable user TOTP")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	// Burn the enrollment step so the same code can't be replayed at the first
	// login verify. Non-fatal: enrollment already committed.
	if _, err := handler.repo.AdvanceUserTOTPStep(r.Context(), userWithTOTP.ID, enrollStep); err != nil {
		log.Err(err).Msg("AdvanceUserTOTPStep after enroll failed (non-fatal)")
	}

	utils.WriteJson(w, map[string]any{
		"backupCodes": backupCodes,
	})
}

// HandleWorkspaceTOTPDisable disables TOTP after the user proves they
// still control either the account's password OR their email inbox.
// POST /x/{slug}/a/totp/disable
//
// Accepts EITHER:
//   - { "password": "..." }   — verifies password against users.password_hash
//   - { "code": "123456" }    — verifies an OTP previously emailed via
//     /auth/forgot-password to the user's address
//
// Why both: when the app's primary auth method is "code" or "none"
// (or the user signed up via OAuth and never set a password), the
// password gate is unusable. Email-OTP gives a working out-of-band
// factor — same threat model: a stolen access token can't pass it.
func (handler *RequestHandler) HandleWorkspaceTOTPDisable(w http.ResponseWriter, r *http.Request) {
	ses, ok := core.ClientSessionFromContext(r.Context())
	if !ok || ses == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	ctxApp, appOk := core.AppFromContext(r.Context())
	if !appOk || ctxApp == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	userWithTOTP, err := handler.repo.GetUserByIDWithTOTP(r.Context(), ses.UserID)
	if err != nil || userWithTOTP == nil {
		log.Err(err).Msg("failed to get user for TOTP disable")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if !userWithTOTP.HasTOTP() {
		WriteError(w, r, "error.totpNotEnabled", http.StatusBadRequest)
		return
	}

	if !handler.requireSensitivePasswordOrCodeReauth(w, r, userWithTOTP, ctxApp, req.Password, req.Code) {
		return
	}

	if err := handler.repo.DisableUserTOTP(r.Context(), userWithTOTP.ID); err != nil {
		log.Err(err).Msg("failed to disable user TOTP")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	handler.dispatchMFAEvent(whMFADisabled, ctxApp.ID, userWithTOTP.ID)

	if ws, ok := core.WorkspaceFromContext(r.Context()); ok && ws != nil {
		userID := userWithTOTP.ID
		sessionID := ses.ID
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:   ws.ID,
			AppID:         &ctxApp.ID,
			Event:         core.AuthEventTOTPDisabled,
			Method:        core.AuthMethodTOTP,
			Outcome:       core.AuthOutcomeSuccess,
			SubjectUserID: &userID,
			ActorType:     core.AuthActorSelf,
			ActorLabel:    userWithTOTP.Email,
			SessionID:     &sessionID,
		})
	}

	utils.WriteJson(w, map[string]any{"ok": true})
}

// verifyClientEmailOTP validates a 6-digit OTP previously generated by
// /auth/forgot-password (or any client-OTP-issuing endpoint) against
// the (app, email) pair, marks it used, and returns nil on success.
// Returns a generic error otherwise — caller maps to 401 / 400.
//
// Lifted from WorkspaceResetPassword so the TOTP disable handler can
// share the same OTP store + format.
func (handler *RequestHandler) verifyClientEmailOTP(ctx context.Context, appID uuid.UUID, email, code string) error {
	if len(code) != 6 || !isDigits(code) {
		return errors.New("invalid code format")
	}
	peppers, err := handler.getOTPPeppers()
	if err != nil {
		return err
	}
	emailNorm := normalizeEmail(email)
	otp, err := handler.repo.GetLatestUnusedClientOTP(ctx, appID, emailNorm)
	if err != nil {
		return err
	}
	if otp == nil {
		return errors.New("no otp")
	}
	now := time.Now().UTC()
	if otp.UsedAt != nil && !otp.UsedAt.IsZero() {
		return errors.New("otp used")
	}
	if otp.ExpiresAt.Before(now) {
		_ = handler.repo.IncrementClientOTPAttempts(ctx, otp.ID)
		return errors.New("otp expired")
	}
	// Atomically claim an attempt slot — single SQL statement does the
	// attempts < cap check AND the increment. Closes the TOCTOU race
	// where N concurrent verifies all observed attempts < cap.
	if _, err := handler.repo.ClaimClientOTPAttempt(ctx, otp.ID, otpMaxAttempts); err != nil {
		if errors.Is(err, repo.ErrClientOTPAttemptsCapHit) {
			return errors.New("otp rate limited")
		}
		if errors.Is(err, repo.ErrClientOTPNotFound) {
			return errors.New("otp used")
		}
		return err
	}
	match, err := otpHashMatches(otp.ID, code, peppers, otp.CodeHash)
	if err != nil {
		return err
	}
	if !match {
		// Attempt counter already incremented atomically above.
		return errors.New("otp mismatch")
	}
	return handler.repo.MarkClientOTPUsed(ctx, otp.ID, now)
}

// HandleWorkspaceTOTPRegenerateBackupCodes regenerates backup codes after password confirmation.
// POST /x/{slug}/a/totp/backup-codes
func (handler *RequestHandler) HandleWorkspaceTOTPRegenerateBackupCodes(w http.ResponseWriter, r *http.Request) {
	ses, ok := core.ClientSessionFromContext(r.Context())
	if !ok || ses == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	userWithTOTP, err := handler.repo.GetUserByIDWithTOTP(r.Context(), ses.UserID)
	if err != nil || userWithTOTP == nil {
		log.Err(err).Msg("failed to get user for backup codes regen")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if !userWithTOTP.HasTOTP() {
		WriteError(w, r, "error.totpNotEnabled", http.StatusBadRequest)
		return
	}

	if err := handler.verifyUserPassword(r.Context(), userWithTOTP, req.Password); err != nil {
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	backupCodes, err := generateBackupCodes(8)
	if err != nil {
		log.Err(err).Msg("failed to generate backup codes")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	storedCodes, err := handler.hashBackupCodes(backupCodes, userWithTOTP.ID)
	if err != nil {
		log.Err(err).Msg("failed to hash backup codes")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if err := handler.repo.UpdateUserTOTPBackupCodes(r.Context(), userWithTOTP.ID, storedCodes); err != nil {
		log.Err(err).Msg("failed to update user backup codes")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{
		"backupCodes": backupCodes,
	})
}

// HandleWorkspaceTOTPVerify verifies TOTP code (or backup code) using a challenge token.
// This is a public (unauthenticated) endpoint used after password/Google login returns totpRequired.
// POST /x/{slug}/auth/totp/verify
func (handler *RequestHandler) HandleWorkspaceTOTPVerify(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	// App context is set by the /x/{slug}/apps/{appId}/... route. Pull it
	// once so failure-event recording at every exit can attribute correctly.
	ctxApp, _ := core.AppFromContext(r.Context())

	// Brute-force protection gates the same three enforcement points here as
	// in the password-login step (rate-limit check, lockout check, lockout
	// apply), because TOTP is the second factor of the same workspace-user
	// login. A nil app (shouldn't happen on this route) defaults to protected.
	bfpEnabled := ctxApp == nil || ctxApp.BruteForceProtectionEnabled

	recordTOTPFailure := func(reason, email string) {
		if ctxApp == nil {
			return
		}
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:    ws.ID,
			AppID:          &ctxApp.ID,
			Event:          core.AuthEventTOTPFailed,
			Method:         core.AuthMethodTOTP,
			Outcome:        core.AuthOutcomeFailed,
			FailureReason:  authFailFromLoginFailure(reason),
			EmailAttempted: email,
			ActorType:      core.AuthActorSelf,
		})
	}

	var req struct {
		ChallengeToken string `json:"challengeToken"`
		Code           string `json:"code"`
		RememberMe     bool   `json:"rememberMe,omitempty"`
	}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	if req.ChallengeToken == "" || req.Code == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Rate limit shares the counter with workspace password login. We key it on
	// the email subject too (not just IP), so a multi-IP attacker who cleared
	// the password step can't get the full per-IP budget against each IP for
	// the same account. The subject needs the resolved user, so the limit is
	// applied just below, after the (unforgeable) challenge token is verified.
	ip := auth.ClientIP(r)

	userID, rememberMe, err := auth.VerifyTOTPChallengeAny(handler.tokenVerifyKeys(), req.ChallengeToken)
	if err != nil {
		recordTOTPFailure(core.LoginFailureTOTPInvalid, "")
		if errors.Is(err, auth.ErrTOTPChallengeExpired) {
			WriteError(w, r, "error.totpChallengeExpired", http.StatusUnauthorized)
			return
		}
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}
	// The signed challenge is the only source of truth for "Keep me signed
	// in" — req.RememberMe is intentionally ignored. A holder of the
	// challenge + TOTP code can't flip the flag, since flipping invalidates
	// the HMAC. v1 in-flight challenges (from before deploy) decode as
	// rememberMe=false; affected users keep their app default TTL until
	// they log in again.
	_ = req.RememberMe

	userWithTOTP, err := handler.repo.GetUserByIDWithTOTP(r.Context(), userID)
	if err != nil || userWithTOTP == nil {
		log.Err(err).Msg("failed to fetch user for TOTP verify")
		recordTOTPFailure(core.LoginFailureNoUser, "")
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	if !userWithTOTP.HasTOTP() {
		recordTOTPFailure(core.LoginFailureTOTPInvalid, maskEmail(userWithTOTP.Email))
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	// Rate limit by IP AND subject (email). Gated by bfpEnabled, matching the
	// password step. Applied here (not before challenge verification) so the
	// per-subject key is available.
	if bfpEnabled {
		if !handler.checkAttemptRateLimit(w, r, attemptPurposeWorkspaceLoginPassword, ip, strings.ToLower(userWithTOTP.Email), "workspace TOTP verify",
			func() { recordTOTPFailure(core.LoginFailureRateLimit, maskEmail(userWithTOTP.Email)) }) {
			return
		}
	}

	// Check account lockout (gated; see bfpEnabled above)
	if bfpEnabled && handler.checkAccountLocked(w, r, userWithTOTP.LockedUntil) {
		recordTOTPFailure(core.LoginFailureLocked, maskEmail(userWithTOTP.Email))
		return
	}

	secret, err := handler.encryptor.DecryptFromBytesWithAAD(
		userWithTOTP.TOTPSecretEncrypted,
		crypto.AAD("users", "totp_secret_encrypted", userWithTOTP.ID),
	)
	if err != nil {
		log.Err(err).Msg("failed to decrypt user TOTP secret")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	code := strings.TrimSpace(req.Code)
	subject := strings.ToLower(userWithTOTP.Email)

	// Try TOTP code first. Replay protection (M1): VerifyTOTPCode tells us
	// which step matched; AdvanceUserTOTPStep is an atomic "set iff >"
	// that fails when the step has already been consumed. The library's
	// totp.Validate accepts a code anywhere in the ±1-step skew window
	// without tracking which step matched, so without this gate the same
	// 30-second code is replayable inside its window.
	if step, ok := auth.VerifyTOTPCode(code, string(secret)); ok {
		advanced, err := handler.repo.AdvanceUserTOTPStep(r.Context(), userWithTOTP.ID, step)
		if err != nil {
			log.Err(err).Msg("AdvanceUserTOTPStep failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if advanced {
			if userWithTOTP.LockedUntil != nil {
				_ = handler.repo.ClearUserLockedUntil(r.Context(), userWithTOTP.ID)
			}
			handler.completeWorkspaceTOTPLogin(w, r, ws, userWithTOTP, rememberMe)
			return
		}
		// Step <= last_totp_step → replay. Fall through to backup-code
		// path and the eventual generic failure response so we don't
		// reveal "this code was already used".
	}

	// Try backup code
	if handler.tryWorkspaceBackupCode(r, userWithTOTP, code) {
		if userWithTOTP.LockedUntil != nil {
			_ = handler.repo.ClearUserLockedUntil(r.Context(), userWithTOTP.ID)
		}
		handler.completeWorkspaceTOTPLogin(w, r, ws, userWithTOTP, rememberMe)
		return
	}

	// Both failed — record attempt
	_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeWorkspaceLoginPassword, subject, ip)
	if bfpEnabled {
		handler.maybeApplyUserLockout(r, userWithTOTP.ID, attemptPurposeWorkspaceLoginPassword, subject)
	}
	recordTOTPFailure(core.LoginFailureTOTPInvalid, maskEmail(userWithTOTP.Email))
	WriteError(w, r, "error.invalidTOTPCode", http.StatusUnauthorized)
}

// completeWorkspaceTOTPLogin creates a session and issues tokens after successful TOTP verification.
//
// rememberMe is plumbed from the verify request body — clients pass it
// through alongside the TOTP code so the long TTL chosen at the original
// password/OTP step survives the 2FA round-trip.
func (handler *RequestHandler) completeWorkspaceTOTPLogin(
	w http.ResponseWriter,
	r *http.Request,
	ws *core.Workspace,
	user *core.User,
	rememberMe bool,
) {
	// Block banned users / assign default role
	if ctxApp, appOk := core.AppFromContext(r.Context()); appOk {
		handler.ensureDefaultRole(r.Context(), ctxApp, user)
	}

	ua := strings.TrimSpace(r.UserAgent())
	ip := auth.ClientIP(r)

	ctxApp, _ := core.AppFromContext(r.Context())
	ses, err := handler.clientAuthService.CreateSessionWithOptions(r.Context(), user.ID, ctxApp.ID, ua, ip, rememberMe, ctxApp.SessionTTL(), ctxApp.RememberMeTTL(), ctxApp.MaxSessions())
	if err != nil {
		log.Err(err).Msg("Could not create client session after TOTP verify")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	dpopJKT, dpopErr := handler.extractDPoPJKT(w, r)
	if dpopErr != nil {
		_ = handler.clientAuthService.DeleteSession(r.Context(), ses.ID)
		return
	}

	tokenPair, err := handler.clientAuthService.IssueTokenPair(r.Context(), ses, ua, ip, effectiveSessionTTL(ctxApp, rememberMe), ctxApp.AccessTokenTTL(), dpopJKT, handler.clientAuthService.IssuerForApp(ctxApp), "")
	if err != nil {
		log.Err(err).Msg("Could not issue token pair after TOTP verify")
		_ = handler.clientAuthService.DeleteSession(r.Context(), ses.ID)
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	loginAt := time.Now().UTC()
	_ = handler.repo.UpdateUserLastLogin(r.Context(), user.ID, loginAt)
	_ = handler.repo.UpdateAppUserLastLogin(r.Context(), ctxApp.ID, user.ID, loginAt)
	userID := user.ID
	sessionID := ses.ID
	handler.writeAuthLogFromRequest(r, AuthLogInput{
		WorkspaceID:   ws.ID,
		AppID:         &ctxApp.ID,
		Event:         core.AuthEventLoginSuccess,
		Method:        core.AuthMethodTOTP,
		Outcome:       core.AuthOutcomeSuccess,
		SubjectUserID: &userID,
		ActorType:     core.AuthActorSelf,
		ActorLabel:    user.Email,
		SessionID:     &sessionID,
	})

	handler.dispatchWebhook(ctxApp.ID, "user.login", map[string]any{"userId": user.ID, "email": user.Email, "appId": ctxApp.ID, "method": "totp"})

	handler.setSessionCookies(w, r, ws, ctxApp, tokenPair, effectiveSessionTTL(ctxApp, rememberMe))
	utils.WriteJson(w, map[string]any{
		"accessToken":  tokenPair.AccessToken,
		"refreshToken": tokenPair.RefreshToken,
		"expiresAt":    tokenPair.ExpiresAt,
		"expiresIn":    tokenPair.ExpiresIn,
		"session":      toClientSessionResource(ses),
	})
}

// tryWorkspaceBackupCode checks if the code matches any remaining backup code
// for a user and, if so, consumes it. Read-compatible with legacy encrypted
// codes (migrated to hashes on first use) via consumeBackupCode.
func (handler *RequestHandler) tryWorkspaceBackupCode(r *http.Request, user *core.User, code string) bool {
	return handler.consumeBackupCode(
		r.Context(), user.TOTPBackupCodesEncrypted, code, user.ID,
		crypto.AAD("users", "totp_backup_codes_encrypted", user.ID),
		func(ctx context.Context, ownerID uuid.UUID, newBlob []byte) error {
			return handler.repo.UpdateUserTOTPBackupCodes(ctx, ownerID, newBlob)
		},
	)
}

// requireSensitivePasswordOrCodeReauth gates a sensitive operation
// behind a fresh proof-of-possession: the caller must supply EITHER
// the account's password (verified against users.password_hash) OR a
// 6-digit OTP code previously emailed via /auth/forgot-password.
//
// Defends against the stolen-bearer escalation path: an access token
// alone gives an attacker passive access for ~15 minutes, but each of
// the operations gated by this helper (TOTP setup, TOTP disable,
// passkey delete) is destructive and irreversible from the user's
// perspective — locking out the legitimate owner or backdoor-enabling
// a second factor under attacker control. Requiring a separate factor
// ensures the token alone isn't enough.
//
// Rate-limited per account so an attacker can't brute-force the
// password by hammering the gate. On failure: writes the error
// response, records the rate-limit attempt, returns false. Caller
// must abort on false.
func (handler *RequestHandler) requireSensitivePasswordOrCodeReauth(
	w http.ResponseWriter, r *http.Request,
	user *core.User, app *core.App,
	password, code string,
) bool {
	ctx := r.Context()
	ip := auth.ClientIP(r)
	subject := strings.TrimSpace(strings.ToLower(user.Email))

	if !handler.checkAttemptRateLimit(w, r, attemptPurposeReauthSensitive, ip, subject, "sensitive reauth", nil) {
		return false
	}

	password = strings.TrimSpace(password)
	code = strings.TrimSpace(code)

	switch {
	case password != "":
		if err := handler.verifyUserPassword(ctx, user, password); err != nil {
			_ = handler.repo.InsertAttempt(ctx, attemptPurposeReauthSensitive, subject, ip)
			WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
			return false
		}
	case code != "":
		if app == nil {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return false
		}
		if err := handler.verifyClientEmailOTP(ctx, app.ID, user.Email, code); err != nil {
			_ = handler.repo.InsertAttempt(ctx, attemptPurposeReauthSensitive, subject, ip)
			WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
			return false
		}
	default:
		WriteError(w, r, "error.reauthRequired", http.StatusUnauthorized)
		return false
	}
	return true
}

// verifyUserPassword verifies the password for a user.
func (handler *RequestHandler) verifyUserPassword(ctx context.Context, user *core.User, password string) error {
	var passwordHash string
	err := handler.repo.DB().Pool().QueryRow(ctx,
		`SELECT COALESCE(password_hash, '') FROM users WHERE id = $1`, user.ID,
	).Scan(&passwordHash)
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
