package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/email"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// =====================
// Magic-link login (end-user, app-scoped)
// =====================
//
// Two endpoints:
//   POST /x/{slug}/apps/{appId}/auth/request-magic-link
//     -> sends an email with a one-time link
//   GET  /x/{slug}/apps/{appId}/auth/magic-link?token=...
//     -> consumes the token, mints a session, redirects to the app URL
//        with tokens in the URL fragment (where AppKit reads them)
//
// Magic links are stored in the existing magic_links table, namespaced
// by app via the purpose column: "app_login:<appId>".

const (
	magicLinkTTL = 15 * time.Minute

	// Resend cooldown — if the user has a still-fresh unused link
	// younger than this, the second request is silently treated as a
	// success (no new email, no attempt burned). Prevents accidental
	// double-clicks from the email form generating N emails. Matches
	// otpResendCooldown from the OTP path.
	magicLinkResendCooldown = 20 * time.Second

	// Reuse the OTP request rate-limit bucket — both surface as
	// "send me an email to sign in to this app" from a user/IP POV,
	// so we don't want a magic-link request to bypass an OTP rate cap.
	// (The admin-side magic-link flow uses a separate purpose constant.)
	attemptPurposeAppMagicLink = "client_otp"
)

func appLoginMagicPurpose(appID uuid.UUID) string {
	return "app_login:" + appID.String()
}

type WorkspaceMagicLinkRequest struct {
	Email      string `json:"email"`
	RememberMe bool   `json:"rememberMe,omitempty"`
}

// WorkspaceLoginRequestMagicLink starts a passwordless login by emailing
// a one-time link. Always returns 200 unless rate-limited or input is
// malformed — we don't leak whether an email exists.
func (handler *RequestHandler) WorkspaceLoginRequestMagicLink(w http.ResponseWriter, r *http.Request) {
	ws, app, ok := handler.requireMagicLinkContext(w, r)
	if !ok {
		return
	}

	loggedIn, _, err := handler.clientAuthService.IsLoggedIntoApp(r, app.ID)
	if err != nil {
		log.Err(err).Msg("magic-link: IsLoggedIntoApp failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if loggedIn {
		WriteError(w, r, "error.alreadyLoggedIn", http.StatusForbidden)
		return
	}

	req := WorkspaceMagicLinkRequest{}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	if !handler.sendAppMagicLink(w, r, ws, app, req.Email, req.RememberMe) {
		return
	}
	utils.WriteJson(w, map[string]any{"ok": true})
}

// requireMagicLinkContext loads the workspace + app from request
// context and enforces the gates: app must be in magicLink mode and
// have an AppURL set.
func (handler *RequestHandler) requireMagicLinkContext(w http.ResponseWriter, r *http.Request) (*core.Workspace, *core.App, bool) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return nil, nil, false
	}

	app, ok := core.AppFromContext(r.Context())
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return nil, nil, false
	}

	if app.PrimaryAuthMethod != core.PrimaryAuthMethodMagicLink {
		WriteError(w, r, "error.authMethodDisabled", http.StatusForbidden)
		return nil, nil, false
	}

	if app.AppURL == nil || strings.TrimSpace(*app.AppURL) == "" {
		WriteError(w, r, "error.magicLinkRequiresAppUrl", http.StatusForbidden)
		return nil, nil, false
	}
	return ws, app, true
}

// sendAppMagicLink runs rate-limiting, token generation, persistence,
// and email delivery for the magic-link request path. Returns false
// when an HTTP error has already been written (caller should not write
// further), true on success.
func (handler *RequestHandler) sendAppMagicLink(
	w http.ResponseWriter,
	r *http.Request,
	ws *core.Workspace,
	app *core.App,
	rawEmail string,
	rememberMe bool,
) bool {
	toEmail, vr := auth.ValidateEmail(rawEmail)
	if !vr.Ok() {
		WriteValidationError(w, r, vr)
		return false
	}

	ip := auth.ClientIP(r)
	now := time.Now().UTC()

	logFail := func(reason core.AuthLogFailureReason) {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:    ws.ID,
			AppID:          &app.ID,
			Event:          core.AuthEventLoginFailed,
			Method:         core.AuthMethodMagicLink,
			Outcome:        core.AuthOutcomeFailed,
			FailureReason:  reason,
			EmailAttempted: toEmail,
			ActorType:      core.AuthActorSelf,
		})
	}

	if !handler.checkAttemptRateLimit(w, r, attemptPurposeAppMagicLink, ip, toEmail, "magic link",
		func() { logFail(core.AuthFailRateLimited) }) {
		return false
	}
	if !handler.checkEmailSendDailyQuota(w, r, attemptPurposeAppMagicLink, toEmail, "magic link",
		func() { logFail(core.AuthFailRateLimited) }) {
		return false
	}

	purpose := appLoginMagicPurpose(app.ID)

	// Resend cooldown: if a still-fresh unused link exists for the
	// same purpose+email and was created within the cooldown window,
	// silently no-op. The earlier link is still valid, so the user's
	// inbox already has a working sign-in path.
	if existing, createdAt, err := handler.repo.LatestUnusedMagicLink(r.Context(), purpose, toEmail); err == nil && existing != nil {
		if !createdAt.IsZero() && createdAt.After(now.Add(-magicLinkResendCooldown)) {
			return true
		}
	} else if err != nil {
		log.Err(err).Msg("magic-link: LatestUnusedMagicLink failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return false
	}

	rawToken, tokenHash, err := handler.adminAuthService.NewMagicToken()
	if err != nil {
		log.Err(err).Msg("magic-link: NewMagicToken failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return false
	}

	if err := handler.repo.CreateMagicLink(r.Context(), repo.CreateMagicLinkParams{
		Purpose:   purpose,
		Email:     toEmail,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(magicLinkTTL),
	}); err != nil {
		log.Err(err).Msg("magic-link: CreateMagicLink failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return false
	}

	consumeURL := buildMagicLinkConsumeURL(handler.AppBaseURL(app), ws.Slug, app.ID, rawToken, rememberMe)

	lang := "en"
	emailName := ws.Name
	if app.DisplayName() != "" {
		emailName = app.DisplayName()
	}
	mlEmail := &email.Email{
		To:      toEmail,
		From:    email.WorkspaceFrom(emailName),
		Subject: fmt.Sprintf(email.T(lang, "apps.magicLink.subject"), emailName),
		Body:    fmt.Sprintf(email.T(lang, "apps.magicLink.body"), emailName, consumeURL),
	}
	if err := handler.sendWorkspaceEmail(r.Context(), ws.ID, mlEmail); err != nil {
		log.Err(err).Msg("magic-link: send email failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return false
	}

	if err := handler.repo.InsertAttempt(r.Context(), attemptPurposeAppMagicLink, toEmail, ip); err != nil {
		log.Err(err).Msg("magic-link: InsertAttempt (post-send) failed")
	}
	return true
}

// WorkspaceConsumeMagicLink handles the GET request when the user clicks
// the link in their email. On success it redirects to the app URL with
// session tokens in the URL fragment so AppKit can pick them up. On
// failure it redirects to the app URL with mr_magic_error=<code>.
func (handler *RequestHandler) WorkspaceConsumeMagicLink(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusForbidden)
		return
	}

	ctxApp, appOk := core.AppFromContext(r.Context())
	if !appOk || ctxApp == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	appURL := ""
	if ctxApp.AppURL != nil {
		appURL = strings.TrimSpace(*ctxApp.AppURL)
	}
	if appURL == "" {
		WriteErrorMsg(w, r, "app URL not configured", http.StatusBadRequest)
		return
	}

	rememberMe := r.URL.Query().Get("r") == "1"

	// Failures write `mr_magic_error` into the app URL fragment for
	// AppKit to read.
	failRedirect := func(code string) {
		http.Redirect(w, r, appendFragment(appURL, "mr_magic_error="+url.QueryEscape(code)), http.StatusFound)
	}

	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		failRedirect("invalid_token")
		return
	}

	tokenHash := handler.adminAuthService.HashMagicToken(token)
	ml, found, err := handler.repo.ConsumeMagicLink(r.Context(), tokenHash)
	if err != nil {
		log.Err(err).Msg("magic-link consume: repo error")
		failRedirect("server_error")
		return
	}
	if !found || ml == nil {
		failRedirect("invalid_token")
		return
	}

	expectedPurpose := appLoginMagicPurpose(ctxApp.ID)
	if ml.Purpose != expectedPurpose {
		failRedirect("invalid_token")
		return
	}

	logFail := func(reason core.AuthLogFailureReason) {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:    ws.ID,
			AppID:          &ctxApp.ID,
			Event:          core.AuthEventLoginFailed,
			Method:         core.AuthMethodMagicLink,
			Outcome:        core.AuthOutcomeFailed,
			FailureReason:  reason,
			EmailAttempted: ml.Email,
			ActorType:      core.AuthActorSelf,
		})
	}
	registerFail := func(reason core.AuthLogFailureReason) {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:    ws.ID,
			AppID:          &ctxApp.ID,
			Event:          core.AuthEventRegisterFailed,
			Method:         core.AuthMethodMagicLink,
			Outcome:        core.AuthOutcomeFailed,
			FailureReason:  reason,
			EmailAttempted: ml.Email,
			ActorType:      core.AuthActorSelf,
			Metadata:       core.RegisterMetadata{Source: core.RegisterSourceSelfSignup},
		})
	}

	// Identity resolution. Magic-link click proves email ownership;
	// ResolveSignInIdentity gates pool-user and membership creation on
	// ctxApp.AllowRegistration (Position B - pre-existing membership
	// OR AllowRegistration=true to issue a session). Domain allowlist
	// runs before the resolver so a domain-blocked email never lands
	// in the pool.
	if len(ctxApp.AllowedEmailDomains) > 0 {
		parts := strings.Split(ml.Email, "@")
		if len(parts) != 2 {
			registerFail(core.AuthFailDomainNotAllowed)
			failRedirect("domain_not_allowed")
			return
		}
		userDomain := strings.ToLower(parts[1])
		allowed := false
		for _, d := range ctxApp.AllowedEmailDomains {
			if strings.ToLower(d) == userDomain {
				allowed = true
				break
			}
		}
		if !allowed {
			registerFail(core.AuthFailDomainNotAllowed)
			failRedirect("domain_not_allowed")
			return
		}
	}

	user, created, err := handler.ResolveSignInIdentity(r.Context(), ctxApp, ml.Email, core.UserSourceRegistered)
	if err != nil {
		switch {
		case errors.Is(err, ErrRegistrationDisabled):
			registerFail(core.AuthFailRegistrationDisabled)
			failRedirect("registration_disabled")
			return
		case errors.Is(err, ErrAppUserDisabled):
			logFail(core.AuthFailAccountDisabled)
			failRedirect("account_disabled")
			return
		}
		log.Err(err).Msg("magic-link: ResolveSignInIdentity failed")
		failRedirect("server_error")
		return
	}

	handler.finishClientSignInRedirect(w, r, ws, ctxApp, user, created, rememberMe, appURL, core.AuthMethodMagicLink, ml.Email, failRedirect)
	return
}

// finishClientSignInRedirect runs the post-identity-resolution tail
// shared by the magic-link and org-invite accept flows: marks email
// verified, enforces the disabled check, enforces TOTP/Require2FA
// (bouncing via the URL fragment), ensures the default role, mints a
// session + token pair, sets cookies, records success, and redirects to
// appURL with mr_session/mr_refresh/mr_expires in the fragment. `method`
// is the auth-log method (core.AuthMethodMagicLink for magic links).
// `sourceEmail` is the email the flow was initiated for (for
// webhooks/logs). `failRedirect` is the caller's failure redirect
// closure. On the 2FA bounce paths this returns WITHOUT creating a
// session.
func (handler *RequestHandler) finishClientSignInRedirect(
	w http.ResponseWriter, r *http.Request,
	ws *core.Workspace, ctxApp *core.App, user *core.User,
	created bool, rememberMe bool, appURL string,
	method core.AuthLogMethod, sourceEmail string,
	failRedirect func(code string),
) {
	logFail := func(reason core.AuthLogFailureReason) {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:    ws.ID,
			AppID:          &ctxApp.ID,
			Event:          core.AuthEventLoginFailed,
			Method:         method,
			Outcome:        core.AuthOutcomeFailed,
			FailureReason:  reason,
			EmailAttempted: sourceEmail,
			ActorType:      core.AuthActorSelf,
		})
	}

	if !user.IsEmailVerified() {
		now := time.Now().UTC()
		if err := handler.repo.SetUserEmailVerified(r.Context(), user.ID, now); err != nil {
			log.Err(err).Msg("magic-link: SetUserEmailVerified failed")
		}
	}

	if user.IsDisabled() {
		logFail(core.AuthFailAccountDisabled)
		failRedirect("account_disabled")
		return
	}

	// TOTP / 2FA. Tier 1 doesn't have a TOTP screen plumbed for the
	// magic-link fragment-bootstrap yet, so it still bounces — adding
	// it would need an `mr_totp_required=1&mr_totp_challenge=…`
	// handler in AppKit-ui.
	userTOTP, totpErr := handler.repo.GetUserByIDWithTOTP(r.Context(), user.ID)
	if totpErr != nil {
		log.Err(totpErr).Msg("magic-link: GetUserByIDWithTOTP failed")
		failRedirect("server_error")
		return
	}
	if userTOTP.HasTOTP() {
		challengeToken := auth.SignTOTPChallengeWithFlags(handler.totpKey, user.ID, totpChallengeTTL, rememberMe)
		// Hand the challenge back to AppKit via the URL fragment.
		// AppKit's bootstrap effect picks it up, switches to the TOTP
		// view, and the existing /auth/totp/verify flow takes it from
		// there. rememberMe is encoded in the signed token, so the
		// verify endpoint enforces the original user choice regardless
		// of what AppKit's local checkbox says.
		frag := url.Values{}
		frag.Set("mr_totp_challenge", challengeToken)
		http.Redirect(w, r, appendFragment(appURL, frag.Encode()), http.StatusFound)
		return
	}
	if ctxApp.Require2FA {
		// User doesn't have TOTP set up yet but the app requires
		// it. Hand back a setup challenge token; the AppKit setup
		// view drives /auth/totp/setup-init and setup-complete.
		// NO session is created until TOTP enrollment finishes.
		setupChallenge := handler.IssueTOTPSetupChallenge(user.ID, ctxApp.ID, rememberMe)
		frag := url.Values{}
		frag.Set("mr_totp_setup_challenge", setupChallenge)
		http.Redirect(w, r, appendFragment(appURL, frag.Encode()), http.StatusFound)
		return
	}

	handler.ensureDefaultRole(r.Context(), ctxApp, user)

	ua := strings.TrimSpace(r.UserAgent())
	ip := auth.ClientIP(r)

	ses, err := handler.clientAuthService.CreateSessionWithOptions(r.Context(), user.ID, ctxApp.ID, ua, ip, rememberMe, ctxApp.SessionTTL(), ctxApp.RememberMeTTL(), ctxApp.MaxSessions())
	if err != nil {
		log.Err(err).Msg("magic-link: CreateSession failed")
		failRedirect("server_error")
		return
	}

	userID := user.ID
	sessionID := ses.ID

	// Magic-link is consumed via a
	// top-level browser navigation from the user's email client —
	// there's no DPoP proof to bind. Issue the token pair without a
	// JKT and write tokens into the URL fragment of the app URL.
	// Auth-log only AFTER the token pair issues so a failure here
	// doesn't get logged as a successful login.
	tokenPair, err := handler.clientAuthService.IssueTokenPair(r.Context(), ses, ua, ip, effectiveSessionTTL(ctxApp, rememberMe), ctxApp.AccessTokenTTL(), "", handler.clientAuthService.IssuerForApp(ctxApp))
	if err != nil {
		log.Err(err).Msg("magic-link: IssueTokenPair failed")
		_ = handler.clientAuthService.DeleteSession(r.Context(), ses.ID)
		failRedirect("server_error")
		return
	}

	handler.recordClientSignInSuccess(r, ws.ID, ctxApp.ID, &userID, &sessionID, user.Email, sourceEmail, created, method)

	// Set cookies before the redirect so cookie-mode clients land
	// already-authenticated. Bearer-mode clients (AppKit-direct,
	// native) ignore the cookies and read the tokens from the URL
	// fragment as before.
	handler.setSessionCookies(w, r, ws, ctxApp, tokenPair, effectiveSessionTTL(ctxApp, rememberMe))

	frag := url.Values{}
	frag.Set("mr_session", tokenPair.AccessToken)
	frag.Set("mr_refresh", tokenPair.RefreshToken)
	frag.Set("mr_expires", strconv.FormatInt(tokenPair.ExpiresAt.Unix(), 10))
	http.Redirect(w, r, appendFragment(appURL, frag.Encode()), http.StatusFound)
}

// recordClientSignInSuccess writes the auth log entries, dispatches
// webhooks, and bumps the user's last-login timestamp once the
// session has been minted. When `created` is true, a register.success
// log + user.register webhook precede the login.success pair —
// matching the OTP and OAuth flows. `method` is the auth-log method
// (e.g. core.AuthMethodMagicLink); the webhook `"method"` string is
// mapped from it via webhookMethodString.
func (handler *RequestHandler) recordClientSignInSuccess(
	r *http.Request,
	workspaceID, appID uuid.UUID,
	userID, sessionID *uuid.UUID,
	userEmail, sourceEmail string,
	created bool,
	method core.AuthLogMethod,
) {
	if created {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:   workspaceID,
			AppID:         &appID,
			Event:         core.AuthEventRegisterSuccess,
			Method:        method,
			Outcome:       core.AuthOutcomeSuccess,
			SubjectUserID: userID,
			ActorType:     core.AuthActorSelf,
			ActorLabel:    userEmail,
			Metadata:      core.RegisterMetadata{Source: core.RegisterSourceSelfSignup},
		})
		handler.dispatchWebhook(appID, "user.register", map[string]any{
			"userId": *userID,
			"email":  sourceEmail,
			"appId":  appID,
		})
	}
	handler.writeAuthLogFromRequest(r, AuthLogInput{
		WorkspaceID:   workspaceID,
		AppID:         &appID,
		Event:         core.AuthEventLoginSuccess,
		Method:        method,
		Outcome:       core.AuthOutcomeSuccess,
		SubjectUserID: userID,
		ActorType:     core.AuthActorSelf,
		ActorLabel:    userEmail,
		SessionID:     sessionID,
	})
	handler.dispatchWebhook(appID, "user.login", map[string]any{
		"userId": *userID,
		"email":  sourceEmail,
		"appId":  appID,
		"method": webhookMethodString(method),
	})
	if userID != nil {
		loginAt := time.Now().UTC()
		_ = handler.repo.UpdateUserLastLogin(r.Context(), *userID, loginAt)
		_ = handler.repo.UpdateAppUserLastLogin(r.Context(), appID, *userID, loginAt)
	}
}

// webhookMethodString maps an auth-log method to the camelCase string
// used in the user.login webhook payload's "method" field. Magic links
// historically emitted "magicLink"; unknown methods fall back to the
// raw auth-log method value.
func webhookMethodString(method core.AuthLogMethod) string {
	switch method {
	case core.AuthMethodMagicLink:
		return "magicLink"
	default:
		return string(method)
	}
}

// buildMagicLinkConsumeURL builds the link sent in the email. The link
// points at this server (not the app), so the token is consumed
// server-side before any redirect to the app URL.
func buildMagicLinkConsumeURL(baseURL, workspaceSlug string, appID uuid.UUID, token string, rememberMe bool) string {
	baseURL = strings.TrimRight(baseURL, "/")
	q := url.Values{}
	q.Set("token", token)
	if rememberMe {
		q.Set("r", "1")
	}
	return fmt.Sprintf("%s/x/%s/apps/%s/auth/magic-link?%s", baseURL, workspaceSlug, appID.String(), q.Encode())
}

// appendFragment appends a fragment to a URL, replacing any existing one.
func appendFragment(rawURL, fragment string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		// Fallback to naive append. Better than dropping the redirect.
		return rawURL + "#" + fragment
	}
	u.Fragment = fragment
	return u.String()
}
