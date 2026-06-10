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
	"fmt"
	"io"
	"manyrows-core/auth"
	clientauth "manyrows-core/auth/client"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/crypto/passwordhash"
	"manyrows-core/email"
	"manyrows-core/utils"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// NOTE:
// - This file is for WORKSPACE client-app auth (external apps).
// - No cookies. No session_workspaces. Client sessions are app-scoped.
// - Login completion returns JWT (Bearer) + session resource.

func toClientSessionResource(s *core.ClientSession) *core.ClientSessionResource {
	if s == nil {
		return nil
	}
	return &core.ClientSessionResource{
		ID:         s.ID,
		UserID:     s.UserID,
		CreatedAt:  s.CreatedAt,
		ExpiresAt:  s.ExpiresAt,
		LastSeenAt: s.LastSeenAt,
	}
}

func maskEmail(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	parts := strings.SplitN(s, "@", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "***"
	}
	local := parts[0]
	domain := parts[1]
	if len(local) == 1 {
		return local + "***@" + domain
	}
	return string(local[0]) + "***" + string(local[len(local)-1]) + "@" + domain
}

// =====================
// OTP helpers
// =====================

const (
	otpTTL           = 10 * time.Minute
	otpMaxAttempts   = 5
	otpRequestWindow = 10 * time.Minute

	// Prevent "resend spam" and UI double-submits from hammering send + attempts.
	// If a valid unused OTP exists newer than this, we do NOT send a new email.
	otpResendCooldown = 20 * time.Second
)

// ensureDefaultRole assigns the app's default role to the user if they have
// no existing roles in the app. Called on every login path (OTP, password,
// Google, TOTP) so that users always get at least the default role when
// signing in through an app with self-registration enabled.
//
// Checks user_roles directly. Reading "is a member" would be wrong here
// post user-pool refactor: every sign-in path calls EnsureAppMember
// first, so a membership check would always pass and the default role
// would never be assigned.
func (handler *RequestHandler) ensureDefaultRole(ctx context.Context, app *core.App, user *core.User) {
	if app == nil || app.DefaultRoleID == nil {
		return
	}
	appID := app.ID

	existing, err := handler.repo.GetUserRolesByUserAndAppID(ctx, app.ProjectID, user.ID, appID)
	if err != nil {
		log.Err(err).Msg("Could not check existing user roles during login")
		return
	}
	if len(existing) > 0 {
		return
	}
	log.Info().Str("app", app.ID.String()).Str("email", user.Email).Str("appId", appID.String()).Msg("Assigning default role to user on login")
	if err := handler.repo.ReplaceUserRoles(ctx, repo.ReplaceUserRolesParams{
		ProjectID: app.ProjectID,
		AppID:     appID,
		UserID:    user.ID,
		RoleIDs:   []uuid.UUID{*app.DefaultRoleID},
		Now:       time.Now().UTC(),
	}); err != nil {
		log.Err(err).Msg("Could not assign default role during login")
	}
}

// NOTE: you should wire this to config (required), e.g. env OTP_PEPPER.
// Keep this secret server-side. It is NOT the JWT signing key.
func (handler *RequestHandler) getOTPPepper() (string, error) {
	type otpPepperGetter interface {
		GetOTPPepper() (string, error)
	}
	if handler.config == nil {
		return "", errors.New("missing config")
	}
	if g, ok := any(handler.config).(otpPepperGetter); ok {
		s, err := g.GetOTPPepper()
		if err != nil {
			return "", err
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return "", errors.New("missing otp pepper")
		}
		return s, nil
	}
	return "", errors.New("config missing GetOTPPepper()")
}

func normalizeEmail(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}

func generateOTP6() (string, error) {
	// rand.Int with a max of 1_000_000 gives a uniform draw over [0, 999999]
	// — no modulo bias. The previous implementation read 4 bytes and
	// reduced mod 1_000_000, which biased ~0.07% toward digits 0..147483
	// (2^31 % 1_000_000 = 147_483_648). Not exploitable at the 5-attempt
	// cap, but the textbook fix is small.
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func hashOTP(otpID uuid.UUID, code string, pepper string) (string, error) {
	code = strings.TrimSpace(code)
	if otpID == uuid.Nil || code == "" || pepper == "" {
		return "", errors.New("invalid otp hash input")
	}
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte(otpID.String() + ":" + code))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

type OTPVerifyRequest struct {
	Email      string     `json:"email"`
	Code       string     `json:"code"`
	AppID      *uuid.UUID `json:"appId,omitempty"` // Optional: if provided, this is a registration flow
	RememberMe bool       `json:"rememberMe,omitempty"`
}

type WorkspaceRegisterRequest struct {
	AppID uuid.UUID `json:"appId"`
	Email string    `json:"email"`
}

type WorkspaceOTPLoginRequest struct {
	Email      string    `json:"email"`
	AppID      uuid.UUID `json:"appId"`
	RememberMe bool      `json:"rememberMe,omitempty"`
}

// effectiveSessionTTL computes the refresh-token TTL for a login.
// Precedence: per-app remember-me override → per-app absolute TTL →
// the auth-service RememberMeTTL constant default → 0 (fall back to
// the auth-service default 7 days inside CreateSessionWithOptions).
//
// When rememberMe is false we use the absolute SessionTTL — the
// AppKit "Keep me signed in" checkbox is what gates the extended
// duration, just like before.
func effectiveSessionTTL(app *core.App, rememberMe bool) time.Duration {
	ttl := app.SessionTTL()
	if rememberMe {
		rmTTL := app.RememberMeTTL()
		if rmTTL == 0 {
			rmTTL = clientauth.RememberMeTTL
		}
		if ttl < rmTTL {
			ttl = rmTTL
		}
	}
	return ttl
}

// WorkspaceLoginRequest starts OTP login for a workspace (client apps).
// This sends an OTP code to the user's email.
func (handler *RequestHandler) WorkspaceLoginRequest(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	ctxApp, appOk := core.AppFromContext(r.Context())
	if !appOk || ctxApp == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	// Reject if app's primary email mode is "none" (OAuth-only). When
	// primary mode is "password" or "code", OTP is allowed — either as
	// the primary path (code) or the no-password-set fallback (password).
	if ctxApp.PrimaryAuthMethod == core.PrimaryAuthMethodNone {
		WriteError(w, r, "error.authMethodDisabled", http.StatusForbidden)
		return
	}

	// If already have an active bearer session for this app, forbid.
	loggedIn, _, err := handler.clientAuthService.IsLoggedIntoApp(r, ctxApp.ID)
	if err != nil {
		log.Err(err).Msg("Could not resolve client session")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if loggedIn {
		WriteError(w, r, "error.alreadyLoggedIn", http.StatusForbidden)
		return
	}

	req := WorkspaceOTPLoginRequest{}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	toEmail, vr := auth.ValidateEmail(req.Email)
	if !vr.Ok() {
		WriteValidationError(w, r, vr)
		return
	}

	ip := auth.ClientIP(r)
	now := time.Now().UTC()

	otpReqFail := func(reason core.AuthLogFailureReason) {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:    ws.ID,
			AppID:          &ctxApp.ID,
			Event:          core.AuthEventLoginFailed,
			Method:         core.AuthMethodEmailOTP,
			Outcome:        core.AuthOutcomeFailed,
			FailureReason:  reason,
			EmailAttempted: toEmail,
			ActorType:      core.AuthActorSelf,
		})
	}

	// Rate limit only the "send code" step.
	// IMPORTANT: we only "burn" attempt budget AFTER the email is successfully sent.
	if !handler.checkAttemptRateLimit(w, r, attemptPurposeOTP, ip, toEmail, "workspace OTP login request",
		func() { otpReqFail(core.AuthFailRateLimited) }) {
		return
	}
	// 24h drip-flood cap on top of the 10/10min burst cap: stops a
	// botnet rotating IPs from sending hundreds of OTP emails to one
	// inbox over the course of a day.
	if !handler.checkEmailSendDailyQuota(w, r, attemptPurposeOTP, toEmail, "workspace OTP login request",
		func() { otpReqFail(core.AuthFailRateLimited) }) {
		return
	}

	// Cooldown: if there's already a recent unused OTP, don't send a new email.
	// This prevents UI double-submits/resends from immediately tripping rate limits.
	emailNorm := normalizeEmail(toEmail)
	if existing, err := handler.repo.GetLatestUnusedClientOTP(r.Context(), ctxApp.ID, emailNorm); err == nil && existing != nil {
		if existing.UsedAt == nil && existing.ExpiresAt.After(now) && existing.CreatedAt.After(now.Add(-otpResendCooldown)) {
			utils.WriteJson(w, map[string]any{"ok": true})
			return
		}
	} else if err != nil && !errors.Is(err, repo.ErrClientOTPNotFound) {
		log.Err(err).Msg("Could not check existing otp for cooldown")
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

	ua := strings.TrimSpace(r.UserAgent())

	// Ensure only one active/unused OTP per email+app.
	if err := handler.repo.DeleteUnusedClientOTPs(r.Context(), ctxApp.ID, emailNorm); err != nil {
		log.Err(err).Msg("Could not delete unused otps")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	otp := core.ClientOTPCode{
		ID:                 otpID,
		AppID:              ctxApp.ID,
		EmailNorm:          emailNorm,
		CodeHash:           codeHash,
		RequestedIP:        strings.TrimSpace(ip),
		RequestedUserAgent: ua,
		CreatedAt:          now,
		ExpiresAt:          now.Add(otpTTL),
		UsedAt:             nil,
		Attempts:           0,
		LastAttemptAt:      nil,
	}

	if err := handler.repo.InsertClientOTP(r.Context(), otp); err != nil {
		log.Err(err).Msg("Could not insert otp")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Send email
	lang := "en"
	emailName := ws.Name
	if ctxApp.DisplayName() != "" {
		emailName = ctxApp.DisplayName()
	}
	otpEmail := &email.Email{
		To:      toEmail,
		From:    email.WorkspaceFrom(emailName),
		Subject: fmt.Sprintf(email.T(lang, "workspace.otp.subject"), emailName),
		Body:    fmt.Sprintf(email.T(lang, "workspace.otp.body"), emailName, code),
	}
	if err := handler.sendWorkspaceEmail(r.Context(), ws.ID, otpEmail); err != nil {
		log.Err(err).Msg("Could not send otp email")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// ...then burn the attempt budget only if we actually sent.
	if err := handler.repo.InsertAttempt(r.Context(), attemptPurposeOTP, toEmail, ip); err != nil {
		// We already sent the email; treat this as non-fatal.
		log.Err(err).Msg("Could not insert otp attempt (post-send)")
	}

	// "OTP sent" is a side-effect of attempting to log in, not an auth
	// event itself — the actual login.success or login.failed lands when
	// the user submits the code in WorkspaceLogin. Failed attempts to
	// request the OTP (rate-limited above) DO get logged because they
	// represent a blocked auth attempt.

	utils.WriteJson(w, map[string]any{"ok": true})
}

// WorkspaceRegister starts OTP registration for a workspace via an app.
// This validates that the app allows registration, then sends an OTP code.
// POST /x/{slug}/auth/register
func (handler *RequestHandler) WorkspaceRegister(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	var req WorkspaceRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	toEmail, vr := auth.ValidateEmail(req.Email)
	if !vr.Ok() {
		WriteValidationError(w, r, vr)
		return
	}

	// App is already validated (enabled, belongs to workspace) by appFromURLMiddleware.
	app, appOk := core.AppFromContext(r.Context())
	if !appOk || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	registerFailed := func(reason core.AuthLogFailureReason) {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:    ws.ID,
			AppID:          &app.ID,
			Event:          core.AuthEventRegisterFailed,
			Method:         core.AuthMethodEmailOTP,
			Outcome:        core.AuthOutcomeFailed,
			FailureReason:  reason,
			EmailAttempted: toEmail,
			ActorType:      core.AuthActorSelf,
			Metadata:       core.RegisterMetadata{Source: core.RegisterSourceSelfSignup},
		})
	}

	if !app.AllowRegistration {
		registerFailed(core.AuthFailRegistrationDisabled)
		WriteError(w, r, "error.forbidden", http.StatusForbidden)
		return
	}

	// Validate email domain if allowlist is configured
	if len(app.AllowedEmailDomains) > 0 {
		emailParts := strings.Split(toEmail, "@")
		if len(emailParts) != 2 {
			WriteError(w, r, "error.emailInvalid", http.StatusBadRequest)
			return
		}
		userDomain := strings.ToLower(emailParts[1])
		allowed := false
		for _, d := range app.AllowedEmailDomains {
			if strings.ToLower(d) == userDomain {
				allowed = true
				break
			}
		}
		if !allowed {
			registerFailed(core.AuthFailDomainNotAllowed)
			WriteError(w, r, "error.forbidden", http.StatusForbidden)
			return
		}
	}

	// Check if user already exists in this app's scope. If so, reject
	// up front rather than silently logging them in after they verify
	// the OTP code — the silent-login behavior was meant to defend
	// against account enumeration, but the leak is already present
	// in adjacent flows (login timing, /auth/forgot-password mailbox
	// signal, OAuth provider lookup) and the UX cost was high: users
	// would think they were creating an account and end up confused
	// when the post-verify set-password screen errored. Industry
	// practice (GitHub / Stripe / Vercel etc.) is to reject with an
	// explicit "sign in instead" hint, which is what AppKit shows.
	existingUser, _ := handler.repo.GetUserByEmail(r.Context(), toEmail, app)
	if existingUser != nil {
		// Not emitted as register.failed — "email already registered" is a
		// UX rejection, not a policy block, and would clutter security review.
		WriteError(w, r, "error.emailAlreadyRegistered", http.StatusConflict)
		return
	}

	// If already have an active bearer session for this app, forbid.
	loggedIn, _, err := handler.clientAuthService.IsLoggedIntoApp(r, app.ID)
	if err != nil {
		log.Err(err).Msg("Could not resolve client session")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if loggedIn {
		WriteError(w, r, "error.alreadyLoggedIn", http.StatusForbidden)
		return
	}

	ip := auth.ClientIP(r)
	now := time.Now().UTC()

	if !handler.checkAttemptRateLimit(w, r, attemptPurposeOTP, ip, toEmail, "workspace registration", nil) {
		return
	}
	if !handler.checkEmailSendDailyQuota(w, r, attemptPurposeOTP, toEmail, "workspace registration", nil) {
		return
	}

	// Cooldown check
	emailNorm := normalizeEmail(toEmail)
	if existing, err := handler.repo.GetLatestUnusedClientOTP(r.Context(), app.ID, emailNorm); err == nil && existing != nil {
		if existing.UsedAt == nil && existing.ExpiresAt.After(now) && existing.CreatedAt.After(now.Add(-otpResendCooldown)) {
			utils.WriteJson(w, map[string]any{"ok": true})
			return
		}
	} else if err != nil && !errors.Is(err, repo.ErrClientOTPNotFound) {
		log.Err(err).Msg("Could not check existing otp for cooldown")
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

	ua := strings.TrimSpace(r.UserAgent())

	// Delete old unused OTPs
	if err := handler.repo.DeleteUnusedClientOTPs(r.Context(), app.ID, emailNorm); err != nil {
		log.Err(err).Msg("Could not delete unused otps")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	otp := core.ClientOTPCode{
		ID:                 otpID,
		AppID:              app.ID,
		EmailNorm:          emailNorm,
		CodeHash:           codeHash,
		RequestedIP:        strings.TrimSpace(ip),
		RequestedUserAgent: ua,
		CreatedAt:          now,
		ExpiresAt:          now.Add(otpTTL),
		UsedAt:             nil,
		Attempts:           0,
		LastAttemptAt:      nil,
	}

	if err := handler.repo.InsertClientOTP(r.Context(), otp); err != nil {
		log.Err(err).Msg("Could not insert otp")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Send email
	lang := "en"
	emailName := ws.Name
	if app.DisplayName() != "" {
		emailName = app.DisplayName()
	}
	otpEmail2 := &email.Email{
		To:      toEmail,
		From:    email.WorkspaceFrom(emailName),
		Subject: fmt.Sprintf(email.T(lang, "workspace.otp.subject"), emailName),
		Body:    fmt.Sprintf(email.T(lang, "workspace.otp.body"), emailName, code),
	}
	if err := handler.sendWorkspaceEmail(r.Context(), ws.ID, otpEmail2); err != nil {
		log.Err(err).Msg("Could not send otp email")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Burn attempt budget
	if err := handler.repo.InsertAttempt(r.Context(), attemptPurposeOTP, toEmail, ip); err != nil {
		log.Err(err).Msg("Could not insert otp attempt (post-send)")
	}

	// Same rationale as WorkspaceLoginRequest above: "OTP sent" isn't an
	// auth event — register.success or register.failed will be written
	// by WorkspaceLogin once the user submits the code.

	utils.WriteJson(w, map[string]any{"ok": true})
}

// WorkspaceLogin verifies OTP and returns JWT + client session resource.
// This creates a user if needed and issues tokens.
func (handler *RequestHandler) WorkspaceLogin(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	ctxApp, appOk := core.AppFromContext(r.Context())
	if !appOk || ctxApp == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	req := OTPVerifyRequest{}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	toEmail, vr := auth.ValidateEmail(req.Email)
	if !vr.Ok() {
		WriteValidationError(w, r, vr)
		return
	}

	otpLoginFailed := func(reason core.AuthLogFailureReason) {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:    ws.ID,
			AppID:          &ctxApp.ID,
			Event:          core.AuthEventLoginFailed,
			Method:         core.AuthMethodEmailOTP,
			Outcome:        core.AuthOutcomeFailed,
			FailureReason:  reason,
			EmailAttempted: toEmail,
			ActorType:      core.AuthActorSelf,
		})
	}

	code := strings.TrimSpace(req.Code)
	if code == "" || len(code) != 6 || !isDigits(code) {
		WriteError(w, r, "error.invalidCode", http.StatusBadRequest)
		return
	}

	pepper, err := handler.getOTPPepper()
	if err != nil {
		log.Err(err).Msg("Missing OTP pepper")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	emailNorm := normalizeEmail(toEmail)

	otp, err := handler.repo.GetLatestUnusedClientOTP(r.Context(), ctxApp.ID, emailNorm)
	if err != nil {
		if errors.Is(err, repo.ErrClientOTPNotFound) {
			otpLoginFailed(core.AuthFailInvalidCode)
			WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
			return
		}
		log.Err(err).Msg("Could not load otp")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if otp == nil {
		otpLoginFailed(core.AuthFailInvalidCode)
		WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
		return
	}

	now := time.Now().UTC()
	if otp.UsedAt != nil && !otp.UsedAt.IsZero() {
		otpLoginFailed(core.AuthFailInvalidCode)
		WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
		return
	}
	if otp.ExpiresAt.Before(now) {
		// Still increment attempt counter to prevent brute-force across
		// expired codes. best-effort: a DB blip just means this one
		// probe doesn't count toward the per-OTP attempt cap.
		_ = handler.repo.IncrementClientOTPAttempts(r.Context(), otp.ID)
		otpLoginFailed(core.AuthFailExpiredCode)
		WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
		return
	}
	// Atomically claim an attempt slot — single-query check-and-
	// increment with the cap enforced in SQL. Closes the TOCTOU race
	// where N concurrent verifies all observed attempts < cap and all
	// passed before any of them incremented.
	if _, err := handler.repo.ClaimClientOTPAttempt(r.Context(), otp.ID, otpMaxAttempts); err != nil {
		if errors.Is(err, repo.ErrClientOTPAttemptsCapHit) {
			otpLoginFailed(core.AuthFailRateLimited)
			WriteRateLimitError(w, r, 600)
			return
		}
		if errors.Is(err, repo.ErrClientOTPNotFound) {
			otpLoginFailed(core.AuthFailInvalidCode)
			WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
			return
		}
		log.Err(err).Msg("Could not claim otp attempt")
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
		otpLoginFailed(core.AuthFailInvalidCode)
		WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
		return
	}

	if err := handler.repo.MarkClientOTPUsed(r.Context(), otp.ID, now); err != nil {
		log.Err(err).Msg("Could not mark otp used")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Resolve identity. The OTP code proves email control; auto-create
	// of the pool user and/or app_users membership is gated on
	// ctxApp.AllowRegistration. Body req.AppID used to flip a separate
	// "this is a registration" code path but the gate is the same
	// either way under Position B, so we drop the special handling.
	user, created, err := handler.ResolveSignInIdentity(r.Context(), ctxApp, toEmail, core.UserSourceRegistered)
	if err != nil {
		switch {
		case errors.Is(err, ErrRegistrationDisabled):
			otpLoginFailed(core.AuthFailRegistrationDisabled)
			WriteError(w, r, "error.forbidden", http.StatusForbidden)
			return
		case errors.Is(err, ErrAppUserDisabled):
			otpLoginFailed(core.AuthFailAccountDisabled)
			WriteError(w, r, "error.accountDisabled", http.StatusForbidden)
			return
		}
		log.Err(err).Msg("Could not resolve sign-in identity")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Mark email as verified (they just proved ownership via OTP)
	if !user.IsEmailVerified() {
		if err := handler.repo.SetUserEmailVerified(r.Context(), user.ID, now); err != nil {
			log.Err(err).Msg("Could not mark user email verified")
			// Non-fatal - continue with login
		}
	}

	// Block pool-disabled users. App-level disable is already handled
	// by ResolveSignInIdentity returning ErrAppUserDisabled above.
	if user.IsDisabled() {
		WriteError(w, r, "error.accountDisabled", http.StatusForbidden)
		return
	}

	ip := auth.ClientIP(r)

	// Check if user has TOTP enabled (voluntary or required by app)
	{
		userTOTP, totpErr := handler.repo.GetUserByIDWithTOTP(r.Context(), user.ID)
		if totpErr != nil {
			log.Err(totpErr).Msg("failed to fetch user TOTP data for OTP login")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if userTOTP.HasTOTP() {
			challengeToken := auth.SignTOTPChallengeWithFlags(handler.totpKey, user.ID, totpChallengeTTL, req.RememberMe)
			utils.WriteJson(w, map[string]any{
				"totpRequired":   true,
				"challengeToken": challengeToken,
			})
			return
		}
		if ctxApp.Require2FA {
			// User doesn't have TOTP yet but app requires it. Hand
			// back a setup challenge token — NO session, NO tokens —
			// so /auth/totp/setup-init and /auth/totp/setup-complete
			// can drive enrollment. The session is minted only after
			// the user proves possession of the new TOTP secret.
			setupChallenge := handler.IssueTOTPSetupChallenge(user.ID, ctxApp.ID, req.RememberMe)
			utils.WriteJson(w, map[string]any{
				"setupChallengeToken": setupChallenge,
				"totpSetupRequired":   true,
			})
			return
		}
	}

	handler.ensureDefaultRole(r.Context(), ctxApp, user)

	ua := strings.TrimSpace(r.UserAgent())

	// Create session with user ID (scoped to app)
	ses, err := handler.clientAuthService.CreateSessionWithOptions(r.Context(), user.ID, ctxApp.ID, ua, ip, req.RememberMe, ctxApp.SessionTTL(), ctxApp.RememberMeTTL(), ctxApp.MaxSessions())
	if err != nil {
		log.Err(err).Msg("Could not create client session")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	dpopJKT, dpopErr := handler.extractDPoPJKT(w, r)
	if dpopErr != nil {
		// best-effort: the session row exists but we can't issue a token
		// pair without DPoP validation. Roll back so a dangling session
		// doesn't sit in the DB consuming the per-user cap.
		_ = handler.clientAuthService.DeleteSession(r.Context(), ses.ID)
		return
	}

	// Issue token pair (access + refresh)
	tokenPair, err := handler.clientAuthService.IssueTokenPair(r.Context(), ses, ua, ip, effectiveSessionTTL(ctxApp, req.RememberMe), ctxApp.AccessTokenTTL(), dpopJKT, handler.clientAuthService.IssuerForApp(ctxApp))
	if err != nil {
		log.Err(err).Msg("Could not issue token pair")
		// best-effort: token issuance failed after we created the session
		// row; clean up so the user isn't holding a phantom session.
		_ = handler.clientAuthService.DeleteSession(r.Context(), ses.ID)
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	userID := user.ID
	sessionID := ses.ID
	if created {
		// register.success precedes login.success — captures the
		// account-creation event distinct from the login itself, so
		// admins can see "user X was created via OTP signup at T"
		// separately from subsequent logins.
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:   ws.ID,
			AppID:         &ctxApp.ID,
			Event:         core.AuthEventRegisterSuccess,
			Method:        core.AuthMethodEmailOTP,
			Outcome:       core.AuthOutcomeSuccess,
			SubjectUserID: &userID,
			ActorType:     core.AuthActorSelf,
			ActorLabel:    user.Email,
			Metadata:      core.RegisterMetadata{Source: core.RegisterSourceSelfSignup},
		})
	}
	handler.writeAuthLogFromRequest(r, AuthLogInput{
		WorkspaceID:   ws.ID,
		AppID:         &ctxApp.ID,
		Event:         core.AuthEventLoginSuccess,
		Method:        core.AuthMethodEmailOTP,
		Outcome:       core.AuthOutcomeSuccess,
		SubjectUserID: &userID,
		ActorType:     core.AuthActorSelf,
		ActorLabel:    user.Email,
		SessionID:     &sessionID,
	})

	if created {
		handler.dispatchWebhook(ctxApp.ID, "user.register", map[string]any{"userId": user.ID, "email": toEmail, "appId": ctxApp.ID})
	}
	handler.dispatchWebhook(ctxApp.ID, "user.login", map[string]any{"userId": user.ID, "email": toEmail, "appId": ctxApp.ID, "method": "otp"})

	// Track last login at both pool and app scope. Best-effort: a
	// failure here only hides the last-login UI line.
	loginAt := time.Now().UTC()
	_ = handler.repo.UpdateUserLastLogin(r.Context(), user.ID, loginAt)
	_ = handler.repo.UpdateAppUserLastLogin(r.Context(), ctxApp.ID, user.ID, loginAt)

	// passwordAlreadySet lets AppKit's create-account flow skip the
	// "set your password" screen when an existing user re-verifies via
	// the registration path — they already have a password, so the
	// follow-up POST /a/set-password would just bounce as 400 with
	// "currentPasswordRequired" and leave the user staring at an error
	// while actually being logged in.
	handler.setSessionCookies(w, r, ws, ctxApp, tokenPair, effectiveSessionTTL(ctxApp, req.RememberMe))
	utils.WriteJson(w, map[string]any{
		"accessToken":        tokenPair.AccessToken,
		"refreshToken":       tokenPair.RefreshToken,
		"expiresAt":          tokenPair.ExpiresAt,
		"expiresIn":          tokenPair.ExpiresIn,
		"session":            toClientSessionResource(ses),
		"passwordAlreadySet": user.HasPassword(),
	})
}

// WorkspaceRefresh exchanges a valid refresh token for a new token pair.
func (handler *RequestHandler) WorkspaceRefresh(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}
	ctxApp, _ := core.AppFromContext(r.Context())

	// In cookie mode the refresh token rides in mr_rt_<appID> and the
	// body is empty; in bearer mode it's in the JSON body. Cookie wins
	// (so a stale body token can't override the live cookie).
	var refreshToken string
	if ctxApp != nil {
		if c, err := r.Cookie(clientauth.RefreshCookieName(ctxApp.ID)); err == nil && c != nil {
			refreshToken = strings.TrimSpace(c.Value)
		}
	}
	if refreshToken == "" {
		var req struct {
			RefreshToken string `json:"refreshToken"`
		}
		if !utils.ReadJson(w, r, &req) {
			return
		}
		refreshToken = strings.TrimSpace(req.RefreshToken)
	}

	if refreshToken == "" {
		WriteError(w, r, "error.invalidToken", http.StatusBadRequest)
		return
	}

	ua := strings.TrimSpace(r.UserAgent())
	ip := auth.ClientIP(r)

	if !handler.checkAttemptRateLimit(w, r, attemptPurposeWorkspaceRefresh, ip, "", "workspace refresh", nil) {
		return
	}

	dpopJKT, dpopErr := handler.extractDPoPJKT(w, r)
	if dpopErr != nil {
		// Count toward the refresh rate limit so a flood of malformed DPoP
		// proofs gets throttled the same way as a flood of bad refresh tokens.
		// extractDPoPJKT has already written a 400 response.
		// best-effort: rate-limit bookkeeping; a DB blip here doesn't change
		// the outcome of the current request.
		_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeWorkspaceRefresh, "", ip)
		return
	}

	tokenPair, err := handler.clientAuthService.RefreshTokenPair(r.Context(), refreshToken, ctxApp.ID, ua, ip, ctxApp.SessionTTL(), ctxApp.AccessTokenTTL(), ctxApp.IdleTimeout(), ctxApp.RememberMeTTL(), dpopJKT, handler.clientAuthService.IssuerForApp(ctxApp))
	if err != nil {
		if errors.Is(err, clientauth.ErrInvalidRefreshToken) || errors.Is(err, clientauth.ErrDPoPRequired) || errors.Is(err, clientauth.ErrDPoPBindingMismatch) {
			// best-effort: rate-limit bookkeeping (see DPoP branch above).
			_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeWorkspaceRefresh, "", ip)
			WriteError(w, r, "error.invalidToken", http.StatusUnauthorized)
			return
		}
		if errors.Is(err, clientauth.ErrSessionExpired) {
			// best-effort: rate-limit bookkeeping (see DPoP branch above).
			_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeWorkspaceRefresh, "", ip)
			WriteError(w, r, "error.sessionNotFound", http.StatusUnauthorized)
			return
		}
		log.Err(err).Msg("Could not refresh token pair")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Use the token pair's own RefreshExpiresIn rather than ctxApp.SessionTTL()
	// so the refresh-cookie Max-Age tracks the actual TTL we just issued —
	// remember-me sessions get the long TTL inside RefreshTokenPair and the
	// cookie has to match or the browser drops it early.
	refreshTTL := time.Duration(tokenPair.RefreshExpiresIn) * time.Second
	handler.setSessionCookies(w, r, ws, ctxApp, tokenPair, refreshTTL)
	utils.WriteJson(w, map[string]any{
		"accessToken":      tokenPair.AccessToken,
		"refreshToken":     tokenPair.RefreshToken,
		"expiresAt":        tokenPair.ExpiresAt,
		"expiresIn":        tokenPair.ExpiresIn,
		"refreshExpiresIn": tokenPair.RefreshExpiresIn,
	})
}

// WorkspaceLogout revokes the current client session (JWT).
func (handler *RequestHandler) WorkspaceLogout(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	ctxApp, appOk := core.AppFromContext(r.Context())

	ses, err := handler.clientAuthService.GetSession(r)
	if err != nil {
		log.Err(err).Msg("Could not get client session")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if ses == nil {
		WriteError(w, r, "error.sessionNotFound", http.StatusConflict)
		return
	}
	// Validate session belongs to the current app
	if !appOk || ctxApp == nil || ses.AppID == nil || *ses.AppID != ctxApp.ID {
		WriteError(w, r, "error.sessionNotFound", http.StatusConflict)
		return
	}

	var actorLabel string
	if user, err := handler.repo.GetUserByID(r.Context(), ses.UserID); err == nil && user != nil {
		actorLabel = strings.TrimSpace(user.Email)
	}

	// Revoke all refresh tokens for this session first
	if err := handler.clientAuthService.RevokeAllSessionTokens(r.Context(), ses.ID); err != nil {
		log.Err(err).Msg("Could not revoke refresh tokens")
		// Continue with session deletion even if token revocation fails
	}

	if err := handler.clientAuthService.DeleteSession(r.Context(), ses.ID); err != nil {
		log.Err(err).Msg("Could not revoke client session")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	subjectUserID := ses.UserID
	sessionID := ses.ID
	var appIDForLog *uuid.UUID
	if ctxApp, ok := core.AppFromContext(r.Context()); ok && ctxApp != nil {
		appIDForLog = &ctxApp.ID
	}
	handler.writeAuthLogFromRequest(r, AuthLogInput{
		WorkspaceID:   ws.ID,
		AppID:         appIDForLog,
		Event:         core.AuthEventLogout,
		Outcome:       core.AuthOutcomeSuccess,
		SubjectUserID: &subjectUserID,
		ActorType:     core.AuthActorSelf,
		ActorLabel:    actorLabel,
		SessionID:     &sessionID,
	})

	if ctxApp, ok := core.AppFromContext(r.Context()); ok && ctxApp != nil {
		handler.dispatchWebhook(ctxApp.ID, "user.logout", map[string]any{"userId": ses.UserID, "appId": ctxApp.ID})
	}

	handler.clearSessionCookies(w, ws, ctxApp)
	utils.WriteJson(w, map[string]any{"ok": true})
}

// WorkspacePublicLogout revokes a session using only the refresh
// token (mr_rt cookie or JSON body). Public because cookie-mode
// clients still need to log out after the access cookie has expired,
// at which point the authed /a/logout route would 401 and leave the
// browser holding stale cookies. Idempotent — an unknown or missing
// refresh token returns 200 with cookies cleared, since the goal is
// "this browser is logged out."
func (handler *RequestHandler) WorkspacePublicLogout(w http.ResponseWriter, r *http.Request) {
	ws, _ := core.WorkspaceFromContext(r.Context())
	ctxApp, _ := core.AppFromContext(r.Context())

	// Cookie wins; fall back to JSON body. Tolerate empty body so
	// cookie-only callers don't have to send anything.
	var refreshToken string
	if ctxApp != nil {
		if c, err := r.Cookie(clientauth.RefreshCookieName(ctxApp.ID)); err == nil && c != nil {
			refreshToken = strings.TrimSpace(c.Value)
		}
	}
	if refreshToken == "" {
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 {
			var req struct {
				RefreshToken string `json:"refreshToken"`
			}
			if err := json.Unmarshal(body, &req); err == nil {
				refreshToken = strings.TrimSpace(req.RefreshToken)
			}
		}
	}

	if refreshToken != "" {
		info, err := handler.clientAuthService.LogoutSessionByRefreshToken(r.Context(), refreshToken)
		if err != nil {
			log.Err(err).Msg("public logout: revoke failed")
			// Continue — still clear cookies on the way out.
		}
		if info.Found && ws != nil {
			subjectUserID := info.UserID
			sessionID := info.SessionID
			var appIDForLog *uuid.UUID
			if info.AppID != nil {
				appIDForLog = info.AppID
			} else if ctxApp != nil {
				appIDForLog = &ctxApp.ID
			}
			handler.writeAuthLogFromRequest(r, AuthLogInput{
				WorkspaceID:   ws.ID,
				AppID:         appIDForLog,
				Event:         core.AuthEventLogout,
				Outcome:       core.AuthOutcomeSuccess,
				SubjectUserID: &subjectUserID,
				ActorType:     core.AuthActorSelf,
				SessionID:     &sessionID,
			})
			if ctxApp != nil {
				handler.dispatchWebhook(ctxApp.ID, "user.logout", map[string]any{"userId": info.UserID, "appId": ctxApp.ID})
			}
		}
	}

	handler.clearSessionCookies(w, ws, ctxApp)
	utils.WriteJson(w, map[string]any{"ok": true})
}

// Reuse the attempts table for OTP rate limiting (SEND step only).
const attemptPurposeOTP = "client_otp"

// Rate limit failed refresh-token exchanges per IP. Only failures are counted
// (valid refreshes are bounded by the access-token TTL anyway), so legitimate
// clients are never throttled. The limit catches token-grinding from a single
// source.
const attemptPurposeWorkspaceRefresh = "workspace_refresh"

// =====================
// Password Authentication
// =====================

const (
	workspacePasswordAuthWindow          = 10 * time.Minute
	attemptPurposeWorkspaceLoginPassword = "workspace_login_pw"
	attemptPurposeWorkspaceResetPassword = "workspace_reset_pw"
	// attemptPurposeWorkspaceResetPWVerify buckets the reset *verify* step
	// (code + new password), separate from the send step above so the two
	// don't share a budget. Mirrors the admin split (forgot vs reset-verify).
	attemptPurposeWorkspaceResetPWVerify = "workspace_reset_pw_verify"

	// passwordSetAfterRegisterWindow gates the initial-set escape hatch
	// in WorkspaceSetPassword for users who recently proved email
	// control via an OTP at this app — fresh registration OR existing
	// user logging in via the create-account / email-OTP flow. The OTP
	// they entered moments ago IS the proof of email control, so
	// requiring forgot-password+reset on top would just be awkward UX
	// with no security benefit. 10 minutes covers slow networks,
	// distractions, and the user reading the password rules.
	passwordSetAfterRegisterWindow = 10 * time.Minute
)

// recentlyUsedOTPForApp returns true when there's a client_otp_codes
// row for (appID, user's email) with used_at within the given window.
// Used to gate the initial-set password path in WorkspaceSetPassword
// for users who came in via the create-account / email-OTP flow but
// don't yet have a password set.
//
// Returns false (no error) when appID is nil — workspace-level
// sessions don't go through app-scoped OTP, so the gate doesn't apply.
func (handler *RequestHandler) recentlyUsedOTPForApp(ctx context.Context, appID *uuid.UUID, email string, window time.Duration) (bool, error) {
	if appID == nil || email == "" {
		return false, nil
	}
	const q = `
SELECT EXISTS (
  SELECT 1 FROM client_otp_codes
  WHERE app_id = $1
    AND email_norm = $2
    AND used_at IS NOT NULL
    AND used_at > $3
);`
	var ok bool
	err := handler.repo.DB().Pool().QueryRow(ctx, q,
		*appID, normalizeEmail(email), time.Now().UTC().Add(-window),
	).Scan(&ok)
	return ok, err
}

type WorkspaceLoginPasswordRequest struct {
	Email      string    `json:"email"`
	Password   string    `json:"password"`
	AppID      uuid.UUID `json:"appId"`
	RememberMe bool      `json:"rememberMe,omitempty"`
}

// WorkspaceLoginPassword handles password login for workspace accounts.
// POST /x/{slug}/auth/password
func (handler *RequestHandler) WorkspaceLoginPassword(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	ctxApp, appOk := core.AppFromContext(r.Context())
	if !appOk || ctxApp == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	// Reject if app's primary email mode isn't password
	if ctxApp.PrimaryAuthMethod != core.PrimaryAuthMethodPassword {
		WriteError(w, r, "error.authMethodDisabled", http.StatusForbidden)
		return
	}

	var req WorkspaceLoginPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	toEmail, vr := auth.ValidateEmail(req.Email)
	if !vr.Ok() {
		WriteValidationError(w, r, vr)
		return
	}

	pw := strings.TrimSpace(req.Password)
	if pw == "" {
		WriteError(w, r, "error.passwordRequired", http.StatusBadRequest)
		return
	}
	if len(pw) > 128 {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	ip := auth.ClientIP(r)

	pwLoginFailed := func(reason core.AuthLogFailureReason, subjectID *uuid.UUID) {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:    ws.ID,
			AppID:          &ctxApp.ID,
			Event:          core.AuthEventLoginFailed,
			Method:         core.AuthMethodPassword,
			Outcome:        core.AuthOutcomeFailed,
			FailureReason:  reason,
			SubjectUserID:  subjectID,
			EmailAttempted: toEmail,
			ActorType:      core.AuthActorSelf,
		})
	}

	if ctxApp.BruteForceProtectionEnabled {
		if !handler.checkAttemptRateLimit(w, r, attemptPurposeWorkspaceLoginPassword, ip, toEmail, "workspace password login",
			func() { pwLoginFailed(core.AuthFailRateLimited, nil) }) {
			return
		}
	}

	// Validate credentials. The helper does the security-critical
	// part (lookup, constant-time password verify, lockout check,
	// email-verification check) so any future password surface shares
	// exactly the same logic.
	authResult, err := validateAppPasswordCredentials(r.Context(), handler.repo, ctxApp, toEmail, pw)
	if err != nil {
		log.Err(err).Msg("failed to validate password credentials")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	user := authResult.User

	subjectIDIfKnown := func() *uuid.UUID {
		if user != nil && user.ID != uuid.Nil {
			id := user.ID
			return &id
		}
		return nil
	}

	switch authResult.Outcome {
	case PWAuthNoUser:
		// best-effort: failed-attempt counter for the throttle; a DB blip
		// just means this one bad try doesn't count toward the limit.
		_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeWorkspaceLoginPassword, toEmail, ip)
		pwLoginFailed(core.AuthFailUnknownUser, subjectIDIfKnown())
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return

	case PWAuthLocked:
		// Mirror the old checkAccountLocked: 403 with Retry-After.
		if user.LockedUntil != nil {
			retryAfter := int(time.Until(*user.LockedUntil).Seconds()) + 1
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
		}
		WriteError(w, r, "error.accountLocked", http.StatusForbidden)
		pwLoginFailed(core.AuthFailAccountLocked, subjectIDIfKnown())
		return

	case PWAuthNotVerified:
		// best-effort: rate-limit bookkeeping (see PWAuthNoUser).
		_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeWorkspaceLoginPassword, toEmail, ip)
		pwLoginFailed(core.AuthFailEmailNotVerified, subjectIDIfKnown())
		WriteError(w, r, "error.emailNotVerified", http.StatusForbidden)
		return

	case PWAuthWrongPassword:
		// best-effort: rate-limit bookkeeping (see PWAuthNoUser).
		_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeWorkspaceLoginPassword, toEmail, ip)
		if ctxApp.BruteForceProtectionEnabled {
			handler.maybeApplyUserLockout(r, user.ID, attemptPurposeWorkspaceLoginPassword, toEmail)
		}
		pwLoginFailed(core.AuthFailWrongPassword, subjectIDIfKnown())
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	// Success: clear any lockout. best-effort: lockout will fall off
	// naturally at LockedUntil; a failure here just means the next
	// login attempt re-checks instead of skipping the check.
	if user.LockedUntil != nil {
		_ = handler.repo.ClearUserLockedUntil(r.Context(), user.ID)
	}

	// Block banned users before any session creation

	// Block disabled users
	if user.IsDisabled() {
		WriteError(w, r, "error.accountDisabled", http.StatusForbidden)
		return
	}

	// Check if user has TOTP enabled (voluntary or required by app)
	{
		userTOTP, totpErr := handler.repo.GetUserByIDWithTOTP(r.Context(), user.ID)
		if totpErr != nil {
			log.Err(totpErr).Msg("failed to fetch user TOTP data")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if userTOTP.HasTOTP() {
			// User has TOTP — return challenge token, no session
			challengeToken := auth.SignTOTPChallengeWithFlags(handler.totpKey, user.ID, totpChallengeTTL, req.RememberMe)
			utils.WriteJson(w, map[string]any{
				"totpRequired":   true,
				"challengeToken": challengeToken,
			})
			return
		}
		// User doesn't have TOTP — if app requires it, hand back a
		// setup challenge token. NO session, NO tokens; the
		// /auth/totp/setup-* endpoints drive enrollment and only mint
		// a session after the user verifies their first TOTP code.
		if ctxApp.Require2FA {
			setupChallenge := handler.IssueTOTPSetupChallenge(user.ID, ctxApp.ID, req.RememberMe)
			utils.WriteJson(w, map[string]any{
				"setupChallengeToken": setupChallenge,
				"totpSetupRequired":   true,
			})
			return
		}
	}

	handler.ensureDefaultRole(r.Context(), ctxApp, user)

	ua := strings.TrimSpace(r.UserAgent())

	// Create session
	ses, err := handler.clientAuthService.CreateSessionWithOptions(r.Context(), user.ID, ctxApp.ID, ua, ip, req.RememberMe, ctxApp.SessionTTL(), ctxApp.RememberMeTTL(), ctxApp.MaxSessions())
	if err != nil {
		log.Err(err).Msg("Could not create client session for password login")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	dpopJKT, dpopErr := handler.extractDPoPJKT(w, r)
	if dpopErr != nil {
		// best-effort: roll back the just-created session row so a
		// failed DPoP probe doesn't leak a dangling session.
		_ = handler.clientAuthService.DeleteSession(r.Context(), ses.ID)
		return
	}

	// Issue token pair
	tokenPair, err := handler.clientAuthService.IssueTokenPair(r.Context(), ses, ua, ip, effectiveSessionTTL(ctxApp, req.RememberMe), ctxApp.AccessTokenTTL(), dpopJKT, handler.clientAuthService.IssuerForApp(ctxApp))
	if err != nil {
		log.Err(err).Msg("Could not issue token pair for password login")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	userID := user.ID
	sessionID := ses.ID
	handler.writeAuthLogFromRequest(r, AuthLogInput{
		WorkspaceID:   ws.ID,
		AppID:         &ctxApp.ID,
		Event:         core.AuthEventLoginSuccess,
		Method:        core.AuthMethodPassword,
		Outcome:       core.AuthOutcomeSuccess,
		SubjectUserID: &userID,
		ActorType:     core.AuthActorSelf,
		ActorLabel:    user.Email,
		SessionID:     &sessionID,
	})

	handler.dispatchWebhook(ctxApp.ID, "user.login", map[string]any{"userId": user.ID, "email": toEmail, "appId": ctxApp.ID, "method": "password"})

	// Track last login at both pool and app scope. Best-effort.
	loginAt := time.Now().UTC()
	_ = handler.repo.UpdateUserLastLogin(r.Context(), user.ID, loginAt)
	_ = handler.repo.UpdateAppUserLastLogin(r.Context(), ctxApp.ID, user.ID, loginAt)

	handler.setSessionCookies(w, r, ws, ctxApp, tokenPair, effectiveSessionTTL(ctxApp, req.RememberMe))
	utils.WriteJson(w, map[string]any{
		"accessToken":  tokenPair.AccessToken,
		"refreshToken": tokenPair.RefreshToken,
		"expiresAt":    tokenPair.ExpiresAt.Format(time.RFC3339),
		"expiresIn":    int(time.Until(tokenPair.ExpiresAt).Seconds()),
		"session":      toClientSessionResource(ses),
	})
}

type WorkspaceSetPasswordRequest struct {
	Password        string `json:"password"`
	CurrentPassword string `json:"currentPassword"`
}

// WorkspaceSetPassword sets or updates password for the logged-in user.
// POST /x/{slug}/a/set-password (requires auth)
// If the user already has a password, currentPassword is required.
func (handler *RequestHandler) WorkspaceSetPassword(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

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

	var req WorkspaceSetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	pw := strings.TrimSpace(req.Password)
	if len(pw) > 128 {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// CHANGE-password path requires the current password. INITIAL-set
	// path (no password yet) is gated tighter: by default the user
	// must prove email control via /auth/forgot-password + /auth/reset-
	// password, otherwise a stolen access token on an OAuth-only user
	// could install a backdoor password without the legitimate owner
	// noticing.
	//
	// Exception: a user who recently proved email control via an OTP
	// at this app — fresh self-register OR existing user verifying via
	// the create-account / OTP-login flow — already cleared the same
	// "prove email control" bar that forgot-password would. The OTP
	// they entered moments ago IS the proof. Reusing the already-burned
	// OTP via /auth/reset-password isn't possible, so we let them
	// initial-set straight from the post-OTP session within a short
	// window. OAuth-only / invited / passkey-only users (no recent OTP
	// at this app) still go through forgot-password.
	var existingHash string
	var userEmail string
	// best-effort: a no-rows result (user deleted out from under the
	// session) falls through to the existingHash == "" branch, which
	// then routes through the recent-OTP check or rejects. Any other
	// DB error would surface there too.
	_ = handler.repo.DB().Pool().QueryRow(r.Context(), `
		SELECT COALESCE(password_hash, ''), email
		FROM users WHERE id = $1`, ses.UserID,
	).Scan(&existingHash, &userEmail)

	if existingHash == "" {
		recentOTP, otpErr := handler.recentlyUsedOTPForApp(r.Context(), ses.AppID, userEmail, passwordSetAfterRegisterWindow)
		if otpErr != nil {
			log.Err(otpErr).Msg("failed to check recent OTP for initial password set")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if !recentOTP {
			WriteError(w, r, "error.passwordSetRequiresOTP", http.StatusBadRequest)
			return
		}
		// Recent OTP at this app — skip the current-password check
		// entirely, fall through to hashing and persisting below.
	} else {
		currentPw := strings.TrimSpace(req.CurrentPassword)
		if currentPw == "" {
			WriteError(w, r, "error.currentPasswordRequired", http.StatusBadRequest)
			return
		}
		ok, verr := passwordhash.Verify(existingHash, currentPw)
		if verr != nil || !ok {
			WriteError(w, r, "error.invalidCurrentPassword", http.StatusBadRequest)
			return
		}
	}

	// Per-app password policy: length floor + zxcvbn strength score.
	// Email is fed in as a userInput so passwords like "<localpart>123"
	// score lower.
	if pol := checkPasswordPolicy(ctxApp, pw, userEmail); !pol.OK {
		switch pol.Issue {
		case "too_short":
			WriteErrorf(w, r, "error.passwordTooShort", http.StatusBadRequest, pol.MinLength)
		default:
			WriteError(w, r, "error.passwordTooWeak", http.StatusBadRequest)
		}
		return
	}

	// Per-app reuse prevention: block the newest 5 recorded passwords.
	if appBlocksPasswordReuse(ctxApp) {
		reused, rerr := passwordRecentlyUsed(r.Context(), handler.repo, ses.UserID, pw, existingHash)
		if rerr != nil {
			log.Err(rerr).Msg("password reuse check failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if reused {
			WriteError(w, r, "error.passwordRecentlyUsed", http.StatusBadRequest)
			return
		}
	}

	// Hash password
	newHash, err := passwordhash.Hash(pw)
	if err != nil {
		log.Err(err).Msg("failed to hash password")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC()

	// Get user by ID (user already exists — they are authenticated)
	user, err := handler.repo.GetUserByID(r.Context(), ses.UserID)
	if err != nil {
		log.Err(err).Msg("failed to get user for set password")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if err := handler.repo.UpdateUserPassword(r.Context(), user.ID, newHash, now); err != nil {
		log.Err(err).Msg("failed to update user password")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Record regardless of the toggle so enabling it later has history.
	recordPasswordHistory(r.Context(), handler.repo, user.ID, newHash)

	// Invalidate all other sessions — password change should revoke
	// existing access. best-effort: a failure here would leave stale
	// sessions alive but the password is already rotated, so existing
	// JWTs are still time-bounded by their TTL; logging the failure
	// would be ideal but never blocking the user's success path.
	if ses != nil {
		_, _ = handler.repo.DeleteClientSessionsByUser(r.Context(), user.ID, &ses.ID)
	}

	// Mark email as verified if not already — the user is authenticated (proved ownership via OTP/Google)
	if !user.IsEmailVerified() {
		// best-effort: marking verified is opportunistic — the user just
		// proved ownership via OTP. A failure here would only delay the
		// "email verified" flag to a future flow.
		_ = handler.repo.SetUserEmailVerified(r.Context(), user.ID, now)
	}

	if ctxApp, ok := core.AppFromContext(r.Context()); ok && ctxApp != nil {
		handler.dispatchWebhook(ctxApp.ID, "user.password_change", map[string]any{"userId": user.ID, "appId": ctxApp.ID})
	}

	event := core.AuthEventPasswordChanged
	if existingHash == "" {
		event = core.AuthEventPasswordSet
	}
	userID := user.ID
	sessionID := ses.ID
	handler.writeAuthLogFromRequest(r, AuthLogInput{
		WorkspaceID:   ws.ID,
		AppID:         &ctxApp.ID,
		Event:         event,
		Method:        core.AuthMethodPassword,
		Outcome:       core.AuthOutcomeSuccess,
		SubjectUserID: &userID,
		ActorType:     core.AuthActorSelf,
		ActorLabel:    user.Email,
		SessionID:     &sessionID,
	})

	utils.WriteJson(w, map[string]any{"ok": true})
}

type WorkspaceUpdateDisplayNameRequest struct {
	DisplayName string `json:"displayName"`
}

// WorkspaceUpdateDisplayName is a no-op handler kept for backward compatibility.
// The new User model does not have a display_name field.
// POST /x/{slug}/a/profile/display-name (requires auth)
func (handler *RequestHandler) WorkspaceUpdateDisplayName(w http.ResponseWriter, r *http.Request) {
	_, ok := core.WorkspaceFromContext(r.Context())
	if !ok {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	ses, ok := core.ClientSessionFromContext(r.Context())
	if !ok || ses == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	// Consume the request body but don't act on it
	var req WorkspaceUpdateDisplayNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	utils.WriteJson(w, map[string]any{"ok": true})
}

type WorkspaceForgotPasswordRequest struct {
	Email string    `json:"email"`
	AppID uuid.UUID `json:"appId"`
}

// WorkspaceForgotPassword sends a password reset OTP code.
// POST /x/{slug}/auth/forgot-password
func (handler *RequestHandler) WorkspaceForgotPassword(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	ctxApp, appOk := core.AppFromContext(r.Context())
	if !appOk || ctxApp == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	var req WorkspaceForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	toEmail, vr := auth.ValidateEmail(req.Email)
	if !vr.Ok() {
		WriteValidationError(w, r, vr)
		return
	}

	ip := auth.ClientIP(r)
	now := time.Now().UTC()

	if !handler.checkAttemptRateLimit(w, r, attemptPurposeWorkspaceResetPassword, ip, toEmail, "workspace password reset", nil) {
		return
	}
	if !handler.checkEmailSendDailyQuota(w, r, attemptPurposeWorkspaceResetPassword, toEmail, "workspace password reset", nil) {
		return
	}

	// Burn attempt budget BEFORE doing the existence-dependent work so
	// the rate limit gates enumeration attempts too — the previous
	// "burn after successful send" pattern only counted exists-branch
	// hits, letting an attacker probe non-existent emails infinitely.
	// best-effort: a DB blip here means this one probe doesn't count,
	// not that we should refuse to send. The actual reset-token path
	// still runs after this.
	_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeWorkspaceResetPassword, toEmail, ip)

	ua := strings.TrimSpace(r.UserAgent())

	// Move all existence-dependent work (user lookup, cooldown check,
	// OTP generation+insert, SMTP send) into a goroutine so the wire
	// timing of this endpoint is invariant from the attacker's
	// perspective regardless of whether the email exists. Synchronous
	// SMTP delivery used to take 200ms-2s for valid users vs ~5ms for
	// non-existent users — observable side channel for enumeration.
	//
	// Detached context with a generous timeout: the request context
	// is cancelled the moment we write the response, so we can't reuse
	// it. 30s covers SMTP latency on the slowest providers without
	// leaking the request goroutine indefinitely.
	asyncCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	go func() {
		defer cancel()
		handler.dispatchForgotPasswordAsync(asyncCtx, dispatchForgotPasswordArgs{
			Workspace: ws,
			App:       ctxApp,
			ToEmail:   toEmail,
			IP:        ip,
			UA:        ua,
			Now:       now,
		})
	}()

	handler.writeAuthLogFromRequest(r, AuthLogInput{
		WorkspaceID:    ws.ID,
		AppID:          &ctxApp.ID,
		Event:          core.AuthEventPasswordResetRequested,
		Method:         core.AuthMethodPassword,
		Outcome:        core.AuthOutcomeSuccess,
		EmailAttempted: toEmail,
		ActorType:      core.AuthActorSelf,
		ActorLabel:     toEmail,
	})

	utils.WriteJson(w, map[string]any{"ok": true})
}

type dispatchForgotPasswordArgs struct {
	Workspace *core.Workspace
	App       *core.App
	ToEmail   string
	IP        string
	UA        string
	Now       time.Time
}

// dispatchForgotPasswordAsync runs the existence-dependent half of the
// forgot-password flow off the request goroutine. Errors are logged
// only — no observable signal makes it back to the wire, by design.
func (handler *RequestHandler) dispatchForgotPasswordAsync(ctx context.Context, args dispatchForgotPasswordArgs) {
	user, _, err := handler.repo.GetUserWithPasswordByEmailAndApp(ctx, args.ToEmail, args.App)
	if err != nil || user == nil {
		// Account doesn't exist (or transient lookup error). The wire
		// response was already 200 ok; nothing else to do here.
		return
	}

	emailNorm := normalizeEmail(args.ToEmail)

	// Cooldown: if a fresh unused OTP exists, skip the resend.
	if existing, err := handler.repo.GetLatestUnusedClientOTP(ctx, args.App.ID, emailNorm); err == nil && existing != nil {
		if existing.UsedAt == nil && existing.ExpiresAt.After(args.Now) && existing.CreatedAt.After(args.Now.Add(-otpResendCooldown)) {
			return
		}
	} else if err != nil && !errors.Is(err, repo.ErrClientOTPNotFound) {
		log.Err(err).Msg("forgot-password async: cooldown check failed")
		return
	}

	pepper, err := handler.getOTPPepper()
	if err != nil {
		log.Err(err).Msg("forgot-password async: missing OTP pepper")
		return
	}

	code, err := generateOTP6()
	if err != nil {
		log.Err(err).Msg("forgot-password async: generate OTP failed")
		return
	}

	otpID := utils.NewUUID()
	codeHash, err := hashOTP(otpID, code, pepper)
	if err != nil {
		log.Err(err).Msg("forgot-password async: hash OTP failed")
		return
	}

	if err := handler.repo.DeleteUnusedClientOTPs(ctx, args.App.ID, emailNorm); err != nil {
		log.Err(err).Msg("forgot-password async: delete old OTPs failed")
		return
	}

	otp := core.ClientOTPCode{
		ID:                 otpID,
		AppID:              args.App.ID,
		EmailNorm:          emailNorm,
		CodeHash:           codeHash,
		RequestedIP:        strings.TrimSpace(args.IP),
		RequestedUserAgent: args.UA,
		CreatedAt:          args.Now,
		ExpiresAt:          args.Now.Add(otpTTL),
		UsedAt:             nil,
		Attempts:           0,
		LastAttemptAt:      nil,
	}

	if err := handler.repo.InsertClientOTP(ctx, otp); err != nil {
		log.Err(err).Msg("forgot-password async: insert OTP failed")
		return
	}

	lang := "en"
	emailName := args.Workspace.Name
	if args.App.DisplayName() != "" {
		emailName = args.App.DisplayName()
	}
	if emailName == "" {
		emailName = "your workspace"
	}
	resetEmail := &email.Email{
		To:      args.ToEmail,
		From:    email.WorkspaceFrom(emailName),
		Subject: fmt.Sprintf(email.T(lang, "workspace.password_reset.subject"), emailName),
		Body:    fmt.Sprintf(email.T(lang, "workspace.password_reset.body"), emailName, code),
	}
	if err := handler.sendWorkspaceEmail(ctx, args.Workspace.ID, resetEmail); err != nil {
		log.Err(err).Msg("forgot-password async: send email failed")
		return
	}
}

type WorkspaceResetPasswordRequest struct {
	Email       string    `json:"email"`
	Code        string    `json:"code"`
	NewPassword string    `json:"newPassword"`
	AppID       uuid.UUID `json:"appId"`
	LogoutAll   *bool     `json:"logoutAll"` // nil or true → revoke all sessions; false → keep sessions
}

// WorkspaceResetPassword verifies OTP and sets new password.
// POST /x/{slug}/auth/reset-password
func (handler *RequestHandler) WorkspaceResetPassword(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	ctxApp, appOk := core.AppFromContext(r.Context())
	if !appOk || ctxApp == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	var req WorkspaceResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	toEmail, vr := auth.ValidateEmail(req.Email)
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
	if len(newPw) > 128 {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if pol := checkPasswordPolicy(ctxApp, newPw, toEmail); !pol.OK {
		switch pol.Issue {
		case "too_short":
			WriteErrorf(w, r, "error.passwordTooShort", http.StatusBadRequest, pol.MinLength)
		default:
			WriteError(w, r, "error.passwordTooWeak", http.StatusBadRequest)
		}
		return
	}

	// Rate-limit the verify step by IP + subject. The per-OTP-row cap
	// (ClaimClientOTPAttempt) bounds guesses against a single code, but
	// without this an attacker rotating freshly-requested OTPs — or hitting
	// from many IPs — has no cross-OTP / cross-IP ceiling. Burn one attempt
	// per call (success included; a real user verifies once), so a flood is
	// counted regardless of outcome. Mirrors AdminResetPassword.
	ip := auth.ClientIP(r)
	if !handler.checkAttemptRateLimit(w, r, attemptPurposeWorkspaceResetPWVerify, ip, toEmail, "workspace password reset verify", nil) {
		return
	}
	_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeWorkspaceResetPWVerify, toEmail, ip)

	pepper, err := handler.getOTPPepper()
	if err != nil {
		log.Err(err).Msg("Missing OTP pepper")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	emailNorm := normalizeEmail(toEmail)

	// Get latest unused OTP
	otp, err := handler.repo.GetLatestUnusedClientOTP(r.Context(), ctxApp.ID, emailNorm)
	if err != nil {
		if errors.Is(err, repo.ErrClientOTPNotFound) {
			WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
			return
		}
		log.Err(err).Msg("Could not get otp for password reset")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if otp == nil {
		WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
		return
	}

	now := time.Now().UTC()
	if otp.UsedAt != nil && !otp.UsedAt.IsZero() {
		WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
		return
	}
	if otp.ExpiresAt.Before(now) {
		_ = handler.repo.IncrementClientOTPAttempts(r.Context(), otp.ID)
		WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
		return
	}

	// Atomically claim an attempt slot — single-query check-and-
	// increment with the cap enforced in SQL. Closes the TOCTOU race
	// where N concurrent verifies all observed attempts < cap and all
	// passed before any of them incremented.
	if _, err := handler.repo.ClaimClientOTPAttempt(r.Context(), otp.ID, otpMaxAttempts); err != nil {
		if errors.Is(err, repo.ErrClientOTPAttemptsCapHit) {
			WriteRateLimitError(w, r, 600)
			return
		}
		if errors.Is(err, repo.ErrClientOTPNotFound) {
			// Row was used between GetLatest and now (concurrent
			// verify won) or got deleted. Same surface as a wrong code.
			WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
			return
		}
		log.Err(err).Msg("Could not claim otp attempt")
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
		WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
		return
	}

	// Code is valid - mark as used
	if err := handler.repo.MarkClientOTPUsed(r.Context(), otp.ID, now); err != nil {
		log.Err(err).Msg("Could not mark otp used")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Get user by email
	user, err := handler.repo.GetUserByEmail(r.Context(), toEmail, ctxApp)
	if err != nil {
		log.Err(err).Msg("Could not get user for password reset")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if user == nil {
		WriteError(w, r, "error.workspaceAccountNotFound", http.StatusNotFound)
		return
	}

	// Setting password is allowed even if the user had no password before (OTP-only).
	// This lets users add password auth via the reset flow.
	newHash, err := passwordhash.Hash(newPw)
	if err != nil {
		log.Err(err).Msg("failed to hash password")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Update password
	if err := handler.repo.UpdateUserPassword(r.Context(), user.ID, newHash, now); err != nil {
		log.Err(err).Msg("failed to update user password")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Mark email as verified — the user just proved ownership via OTP code
	if !user.IsEmailVerified() {
		// best-effort: marking verified is opportunistic — the user just
		// proved ownership via OTP. A failure here would only delay the
		// "email verified" flag to a future flow.
		_ = handler.repo.SetUserEmailVerified(r.Context(), user.ID, now)
	}

	// Revoke all sessions unless explicitly opted out (default: true)
	if req.LogoutAll == nil || *req.LogoutAll {
		if _, err := handler.repo.DeleteClientSessionsByUser(r.Context(), user.ID, nil); err != nil {
			log.Err(err).Msg("failed to delete sessions after password reset")
		}
	}

	if ctxApp, ok := core.AppFromContext(r.Context()); ok && ctxApp != nil {
		handler.dispatchWebhook(ctxApp.ID, "user.password_reset", map[string]any{"userId": user.ID, "email": toEmail, "appId": ctxApp.ID})
	}

	userID := user.ID
	handler.writeAuthLogFromRequest(r, AuthLogInput{
		WorkspaceID:    ws.ID,
		AppID:          &ctxApp.ID,
		Event:          core.AuthEventPasswordResetCompleted,
		Method:         core.AuthMethodPassword,
		Outcome:        core.AuthOutcomeSuccess,
		SubjectUserID:  &userID,
		EmailAttempted: toEmail,
		ActorType:      core.AuthActorSelf,
		ActorLabel:     user.Email,
	})

	utils.WriteJson(w, map[string]any{"ok": true})
}
