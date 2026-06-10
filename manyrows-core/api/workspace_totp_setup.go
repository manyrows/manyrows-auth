package api

import (
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
)

// =====================================================================
// TOTP setup ceremony — pre-session ENROLLMENT for users hitting an
// app with Require2FA = true who haven't yet enrolled TOTP.
//
// Until the user proves they control a TOTP authenticator (by entering
// a valid code from a freshly-generated secret), no session is issued.
// The setup-challenge token is the only credential they hold during
// enrollment — bound to userID, appID, and the original rememberMe
// choice from the upstream sign-in step (OTP / password / OAuth /
// magic-link).
//
// Endpoints:
//
//   POST /x/{slug}/apps/{appId}/auth/totp/setup-init
//     body  : { setupChallengeToken }
//     reply : { secret, uri }
//     side  : encrypts + persists the new secret on the user row
//             (totp_secret_encrypted set, totp_enabled_at still null)
//
//   POST /x/{slug}/apps/{appId}/auth/totp/setup-complete
//     body  : { setupChallengeToken, code }
//     reply : { accessToken, refreshToken, expiresAt, expiresIn,
//               session, backupCodes }
//     side  : validates the first TOTP code against the persisted
//             secret, enables TOTP, mints session + token pair.
// =====================================================================

const totpSetupChallengeTTL = 10 * time.Minute

// IssueTOTPSetupChallenge wraps the signing call so handlers don't
// have to reach for handler.totpKey directly.
func (handler *RequestHandler) IssueTOTPSetupChallenge(userID, appID uuid.UUID, rememberMe bool) string {
	return auth.SignTOTPSetupChallenge(handler.totpKey, userID, appID, totpSetupChallengeTTL, rememberMe)
}

// resolveTOTPSetupChallenge verifies the token + cross-checks the
// bound appID against the URL-resolved app, returns the user record
// and rememberMe flag, or writes an HTTP error and returns false.
func (handler *RequestHandler) resolveTOTPSetupChallenge(w http.ResponseWriter, r *http.Request, ctxApp *core.App, rawToken string) (*core.User, bool, bool) {
	userID, appID, rememberMe, err := auth.VerifyTOTPSetupChallengeAny(handler.tokenVerifyKeys(), strings.TrimSpace(rawToken))
	if err != nil {
		if errors.Is(err, auth.ErrTOTPSetupChallengeExpired) {
			WriteError(w, r, "error.totpSetupChallengeExpired", http.StatusUnauthorized)
			return nil, false, false
		}
		WriteError(w, r, "error.totpSetupChallengeInvalid", http.StatusUnauthorized)
		return nil, false, false
	}
	if appID != ctxApp.ID {
		// Token issued for a different app — refuse rather than reveal
		// any details about the bound user.
		WriteError(w, r, "error.totpSetupChallengeInvalid", http.StatusUnauthorized)
		return nil, false, false
	}
	user, err := handler.repo.GetUserByIDWithTOTP(r.Context(), userID)
	if err != nil || user == nil {
		log.Err(err).Msg("totp setup: user lookup failed")
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return nil, false, false
	}
	return user, rememberMe, true
}

// HandleWorkspaceTOTPSetupInit takes a setup challenge token, generates
// a fresh TOTP secret, persists it (encrypted), and returns it so the
// client can render a QR. The user is NOT authenticated by a session
// — only by holding the signed challenge token bound to their userID
// and the current appID.
//
// POST /x/{slug}/apps/{appId}/auth/totp/setup-init
func (handler *RequestHandler) HandleWorkspaceTOTPSetupInit(w http.ResponseWriter, r *http.Request) {
	ctxApp, ok := core.AppFromContext(r.Context())
	if !ok || ctxApp == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	var req struct {
		SetupChallengeToken string `json:"setupChallengeToken"`
	}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	user, _, ok := handler.resolveTOTPSetupChallenge(w, r, ctxApp, req.SetupChallengeToken)
	if !ok {
		return
	}
	if user.HasTOTP() {
		WriteError(w, r, "error.totpAlreadyEnabled", http.StatusConflict)
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Manyrows",
		AccountName: user.Email,
	})
	if err != nil {
		log.Err(err).Msg("totp setup-init: generate failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	encrypted, err := handler.encryptor.EncryptToBytesWithAAD(
		[]byte(key.Secret()),
		crypto.AAD("users", "totp_secret_encrypted", user.ID),
	)
	if err != nil {
		log.Err(err).Msg("totp setup-init: encrypt failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if err := handler.repo.SetUserTOTPSecret(r.Context(), user.ID, encrypted); err != nil {
		log.Err(err).Msg("totp setup-init: persist failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{
		"secret": key.Secret(),
		"uri":    key.URL(),
	})
}

// totpSetupCompletionResult is what enrollSetupCompletionShared
// returns on success — the freshly-minted session + the user's
// backup codes. Caller wraps these in whatever response shape its
// surface uses (e.g. the Tier-1 token-pair response).
type totpSetupCompletionResult struct {
	Session     *core.ClientSession
	User        *core.User
	BackupCodes []string
	RememberMe  bool
}

// runTOTPSetupCompletion does the full "validate code → enable TOTP →
// banned/default-role checks → create session" pipeline. Returns
// false when an HTTP error has already been written (caller stops).
// On success, caller writes the response (e.g. Tier 1 includes a
// token pair).
//
// Auth-logs: emits totp.enabled when enrollment succeeds and
// login.success when the session is created.
func (handler *RequestHandler) runTOTPSetupCompletion(
	w http.ResponseWriter,
	r *http.Request,
	ctxApp *core.App,
	rawToken, rawCode string,
) (*totpSetupCompletionResult, bool) {
	user, rememberMe, ok := handler.resolveTOTPSetupChallenge(w, r, ctxApp, rawToken)
	if !ok {
		return nil, false
	}
	if user.HasTOTP() {
		WriteError(w, r, "error.totpAlreadyEnabled", http.StatusConflict)
		return nil, false
	}
	if len(user.TOTPSecretEncrypted) == 0 {
		WriteError(w, r, "error.totpNotSetUp", http.StatusBadRequest)
		return nil, false
	}
	code := strings.TrimSpace(rawCode)
	if code == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return nil, false
	}

	// Brute-force gate. Setup challenge TTL is 10m, but 6-digit codes
	// are still tractable inside that window — a per-IP cap makes the
	// wall. Reuses the login-password attempt bucket since it shares
	// the same enforcement surface.
	subject := strings.ToLower(user.Email)
	ip := auth.ClientIP(r)
	if !handler.checkAttemptRateLimit(w, r, attemptPurposeWorkspaceLoginPassword, ip, "", "workspace TOTP setup", nil) {
		return nil, false
	}

	secret, err := handler.encryptor.DecryptFromBytesWithAAD(
		user.TOTPSecretEncrypted,
		crypto.AAD("users", "totp_secret_encrypted", user.ID),
	)
	if err != nil {
		log.Err(err).Msg("totp setup-complete: decrypt failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return nil, false
	}
	// Shared verify primitive (see admin enroll): capture the matched step so
	// we can burn it after enable — this path logs the user straight in, so an
	// un-burned enrollment code would be replayable at the next verify.
	enrollStep, ok := auth.VerifyTOTPCode(code, string(secret))
	if !ok {
		_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeWorkspaceLoginPassword, subject, ip)
		WriteError(w, r, "error.invalidTOTPCode", http.StatusUnauthorized)
		return nil, false
	}

	backupCodes, err := generateBackupCodes(8)
	if err != nil {
		log.Err(err).Msg("totp setup-complete: backup-codes generate failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return nil, false
	}
	storedCodes, err := handler.hashBackupCodes(backupCodes, user.ID)
	if err != nil {
		log.Err(err).Msg("totp setup-complete: backup-codes hash failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return nil, false
	}

	now := time.Now().UTC()
	if err := handler.repo.EnableUserTOTP(r.Context(), user.ID, now, storedCodes); err != nil {
		log.Err(err).Msg("totp setup-complete: EnableUserTOTP failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return nil, false
	}
	// Burn the enrollment step so the same code can't be replayed at the next
	// verify (this path mints a session immediately). Non-fatal.
	if _, err := handler.repo.AdvanceUserTOTPStep(r.Context(), user.ID, enrollStep); err != nil {
		log.Err(err).Msg("totp setup-complete: AdvanceUserTOTPStep failed (non-fatal)")
	}
	handler.dispatchMFAEvent(whMFAEnabled, ctxApp.ID, user.ID)
	handler.writeAuthLogFromRequest(r, AuthLogInput{
		WorkspaceID:   ctxApp.WorkspaceID,
		AppID:         &ctxApp.ID,
		Event:         core.AuthEventTOTPEnabled,
		Method:        core.AuthMethodTOTP,
		Outcome:       core.AuthOutcomeSuccess,
		SubjectUserID: &user.ID,
		ActorType:     core.AuthActorSelf,
		ActorLabel:    user.Email,
	})
	handler.ensureDefaultRole(r.Context(), ctxApp, user)

	ua := strings.TrimSpace(r.UserAgent())
	ses, err := handler.clientAuthService.CreateSessionWithOptions(r.Context(), user.ID, ctxApp.ID, ua, ip, rememberMe, ctxApp.SessionTTL(), ctxApp.RememberMeTTL(), ctxApp.MaxSessions())
	if err != nil {
		log.Err(err).Msg("totp setup-complete: CreateSession failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return nil, false
	}

	_ = handler.repo.UpdateUserLastLogin(r.Context(), user.ID, now)
	_ = handler.repo.UpdateAppUserLastLogin(r.Context(), ctxApp.ID, user.ID, now)
	userID := user.ID
	sessionID := ses.ID
	handler.writeAuthLogFromRequest(r, AuthLogInput{
		WorkspaceID:   ctxApp.WorkspaceID,
		AppID:         &ctxApp.ID,
		Event:         core.AuthEventLoginSuccess,
		Method:        core.AuthMethodTOTP,
		Outcome:       core.AuthOutcomeSuccess,
		SubjectUserID: &userID,
		ActorType:     core.AuthActorSelf,
		ActorLabel:    user.Email,
		SessionID:     &sessionID,
	})
	handler.dispatchWebhook(ctxApp.ID, "user.login", map[string]any{
		"userId": user.ID, "email": user.Email, "appId": ctxApp.ID, "method": "totp_setup",
	})

	return &totpSetupCompletionResult{
		Session:     ses,
		User:        user,
		BackupCodes: backupCodes,
		RememberMe:  rememberMe,
	}, true
}

// HandleWorkspaceTOTPSetupComplete is the Tier 1 (AppKit-direct) path.
// On success returns access + refresh token pair plus backup codes.
//
// POST /x/{slug}/apps/{appId}/auth/totp/setup-complete
func (handler *RequestHandler) HandleWorkspaceTOTPSetupComplete(w http.ResponseWriter, r *http.Request) {
	ctxApp, ok := core.AppFromContext(r.Context())
	if !ok || ctxApp == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	var req struct {
		SetupChallengeToken string `json:"setupChallengeToken"`
		Code                string `json:"code"`
	}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	result, ok := handler.runTOTPSetupCompletion(w, r, ctxApp, req.SetupChallengeToken, req.Code)
	if !ok {
		return
	}

	dpopJKT, dpopErr := handler.extractDPoPJKT(w, r)
	if dpopErr != nil {
		_ = handler.clientAuthService.DeleteSession(r.Context(), result.Session.ID)
		return
	}
	tokenPair, err := handler.clientAuthService.IssueTokenPair(
		r.Context(),
		result.Session,
		strings.TrimSpace(r.UserAgent()),
		auth.ClientIP(r),
		effectiveSessionTTL(ctxApp, result.RememberMe),
		ctxApp.AccessTokenTTL(),
		dpopJKT,
		handler.clientAuthService.IssuerForApp(ctxApp),
		"",
	)
	if err != nil {
		log.Err(err).Msg("totp setup-complete (tier 1): IssueTokenPair failed")
		_ = handler.clientAuthService.DeleteSession(r.Context(), result.Session.ID)
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Look up workspace for cookie-domain resolution. Best-effort —
	// failure just means cookies are scoped to the request host.
	ws, _, _ := handler.repo.GetWorkspaceByID(r.Context(), ctxApp.WorkspaceID)
	handler.setSessionCookies(w, r, ws, ctxApp, tokenPair, effectiveSessionTTL(ctxApp, result.RememberMe))
	utils.WriteJson(w, map[string]any{
		"accessToken":  tokenPair.AccessToken,
		"refreshToken": tokenPair.RefreshToken,
		"expiresAt":    tokenPair.ExpiresAt,
		"expiresIn":    tokenPair.ExpiresIn,
		"session":      toClientSessionResource(result.Session),
		"backupCodes":  result.BackupCodes,
	})
}
