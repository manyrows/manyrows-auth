package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// tier1OAuthLoginOpts is the per-provider configuration for the
// Tier-1 (AppKit-direct) OAuth completion worker. The provider-
// specific bits — token claims source, audit/source/attempt labels,
// and Apple's IsPrivateEmail domain-check skip — are pulled out so
// the bulk of the flow (existing-user lookup, registration gate,
// domain check, over-limit check, GetOrCreateUser, disable check,
// default role, email-verified bump, 2FA challenge gate, session
// creation, token-pair issue, audit logs, webhooks, cookies) is
// shared across all four providers.
//
// Tier 1 returns JSON tokens and sets cookies; the gating logic
// above is provider-agnostic and shared across all four providers.
type tier1OAuthLoginOpts struct {
	// AuthMethod is what appears in the auth_log rows.
	AuthMethod core.AuthLogMethod

	// UserSource is what GetOrCreateUser writes when this flow
	// registers a new user. It doubles as the provider key in the
	// user_identities table (UserSourceGoogle == "google", etc.).
	UserSource core.UserSource

	// ProviderSubject is the IdP's stable subject claim (`sub`) for
	// the authenticated identity. ResolveOAuthSignInIdentity matches
	// against this first so a user whose email changes on the
	// provider side still resolves to the same pool user.
	ProviderSubject string

	// ProviderKey is the user_identities.provider value used to link the
	// identity. Leave "" for the bespoke providers — it defaults to
	// string(UserSource) ("google", "apple", ...), so their behavior is
	// unchanged. The generic external-IdP flow sets "idp:<slug>" so each
	// configured IdP links as a distinct identity (a `sub` is unique only
	// per-issuer, so the link key must be per-IdP).
	ProviderKey string

	// AttemptPurpose is the string passed to InsertAttempt when
	// burning attempt budget on a successful exchange ("google_oauth",
	// "apple_oauth", "microsoft_oauth", "github_oauth").
	AttemptPurpose string

	// WebhookMethod is the value of the "method" field in the
	// user.login webhook payload.
	WebhookMethod string

	// SkipDomainCheck is consulted when the app has
	// AllowedEmailDomains configured. Returning true bypasses the
	// per-domain allow-list — Apple uses this to skip the check for
	// users who opted into private-relay (the relay address can
	// never match a customer domain). All other providers pass
	// nil (or a function that always returns false).
	SkipDomainCheck func() bool

	// PreloginSessionID is the client-session that was already active
	// for this app when the flow started at /authorize (rode the
	// signed-state DB row, surfaced by VerifyOAuthState at callback).
	// nil when the flow began unauthenticated. Drives the "honor an
	// existing session" path in completeTier1OAuthLogin: a prior
	// session for the *same* resolved user is reused instead of
	// stacking a new one; a prior session for a *different* user is
	// rejected (the silent session-swap / confused-deputy guard the
	// callback login-state gate exists to enforce — but which is a
	// no-op for the popup flow without this, since that callback
	// carries no bearer/cookie of its own).
	PreloginSessionID *uuid.UUID
}

// completeTier1OAuthLogin runs the post-exchange half of a Tier-1
// OAuth login: takes the verified email + per-provider configuration
// and either issues tokens + cookies + JSON response or a 2FA
// challenge / setup challenge per the app's policy.
//
// Caller's responsibility (provider-specific):
//   - Verify the OAuth state and exchange the code/credential.
//   - Validate the token's audience matches the app's client_id.
//   - Confirm tokenInfo.Email is non-empty and EmailVerified is true
//     (or accept emailVerified=true via private-relay semantics).
//   - Burn an attempt budget row on every failed exchange (rate
//     limiting must remain pre-existence-check on this path).
//
// On success, writes a JSON response of the form
//
//	{ accessToken, refreshToken, expiresAt, expiresIn, session }
//
// and sets the access/refresh cookies on the response.
func (handler *RequestHandler) completeTier1OAuthLogin(
	w http.ResponseWriter, r *http.Request,
	ws *core.Workspace, ctxApp *core.App,
	email string,
	ip string, rememberMe bool,
	opts tier1OAuthLoginOpts,
) {
	// DPoP is best-effort here: the redirect-from-provider callback
	// path won't carry a DPoP header (top-level navigation, not an
	// AppKit-issued fetch). The AppKit-driven implicit / direct flows
	// do carry the header and get a DPoP-bound session.
	dpopJKT, dpopErr := handler.extractDPoPJKT(w, r)
	if dpopErr != nil {
		return
	}

	now := time.Now().UTC()

	// Domain check, before any user/member side effects. Skipped when
	// the provider opts the user out (Apple's private-relay case, those
	// addresses are always @privaterelay.appleid.com and can't match
	// customer domains).
	skipDomain := opts.SkipDomainCheck != nil && opts.SkipDomainCheck()
	if !skipDomain && len(ctxApp.AllowedEmailDomains) > 0 {
		parts := strings.Split(email, "@")
		if len(parts) != 2 {
			WriteError(w, r, "error.emailInvalid", http.StatusBadRequest)
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
			WriteError(w, r, "error.forbidden", http.StatusForbidden)
			return
		}
	}

	if opts.ProviderSubject == "" {
		log.Warn().
			Str("provider", opts.WebhookMethod).
			Str("email", email).
			Msg("OAuth login completed without a provider subject - identity will not be linked")
	}

	user, created, err := handler.ResolveOAuthSignInIdentity(
		r.Context(), ctxApp, email, opts.UserSource,
		opts.ProviderKey, opts.ProviderSubject,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrRegistrationDisabled):
			handler.writeAuthLogFromRequest(r, AuthLogInput{
				WorkspaceID:    ws.ID,
				AppID:          &ctxApp.ID,
				Event:          core.AuthEventLoginFailed,
				Method:         opts.AuthMethod,
				Outcome:        core.AuthOutcomeFailed,
				FailureReason:  core.AuthFailRegistrationDisabled,
				EmailAttempted: email,
				ActorType:      core.AuthActorSelf,
			})
			WriteError(w, r, "error.forbidden", http.StatusForbidden)
			return
		case errors.Is(err, ErrAppUserDisabled):
			WriteError(w, r, "error.accountDisabled", http.StatusForbidden)
			return
		case errors.Is(err, ErrIdentityConflict):
			handler.writeAuthLogFromRequest(r, AuthLogInput{
				WorkspaceID:    ws.ID,
				AppID:          &ctxApp.ID,
				Event:          core.AuthEventLoginFailed,
				Method:         opts.AuthMethod,
				Outcome:        core.AuthOutcomeFailed,
				FailureReason:  core.AuthFailIdentityConflict,
				EmailAttempted: email,
				ActorType:      core.AuthActorSelf,
			})
			WriteError(w, r, "error.identityConflict", http.StatusConflict)
			return
		}
		log.Err(err).Msgf("Could not resolve %s sign-in identity", opts.WebhookMethod)
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if user.IsDisabled() {
		WriteError(w, r, "error.accountDisabled", http.StatusForbidden)
		return
	}

	handler.ensureDefaultRole(r.Context(), ctxApp, user)

	if !user.IsEmailVerified() {
		if err := handler.repo.SetUserEmailVerified(r.Context(), user.ID, now); err != nil {
			log.Err(err).Msg("Could not mark user email verified")
		}
	}

	// Enforce TOTP before issuing any session — voluntary (the user
	// enrolled it) or required by the app. This must run regardless of
	// ctxApp.Require2FA so a user who turned on 2FA is challenged on OAuth
	// logins too, matching the password and email-OTP paths
	// (workspace_auth.go) and magic links (workspace_magic_link.go).
	// Gating it behind Require2FA let an OAuth sign-in skip a second
	// factor the user had explicitly enabled.
	{
		userTOTP, totpErr := handler.repo.GetUserByIDWithTOTP(r.Context(), user.ID)
		if totpErr != nil {
			log.Err(totpErr).Msgf("failed to fetch user TOTP data for %s login", opts.WebhookMethod)
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if userTOTP.HasTOTP() {
			challengeToken := auth.SignTOTPChallengeWithFlags(handler.totpKey, user.ID, totpChallengeTTL, rememberMe)
			utils.WriteJson(w, map[string]any{
				"totpRequired":   true,
				"challengeToken": challengeToken,
			})
			return
		}
		// No TOTP enrolled — if the app requires it, hand back a setup
		// challenge. NO session, NO tokens until /auth/totp/setup-*
		// completes enrollment.
		if ctxApp.Require2FA {
			setupChallenge := handler.IssueTOTPSetupChallenge(user.ID, ctxApp.ID, rememberMe)
			utils.WriteJson(w, map[string]any{
				"setupChallengeToken": setupChallenge,
				"totpSetupRequired":   true,
			})
			return
		}
	}

	ua := strings.TrimSpace(r.UserAgent())

	// Honor an existing session. If this OAuth flow was started while a
	// session for this app was already active, its id rode the signed-
	// state DB row from /authorize. Now that we know which user the
	// OAuth identity resolved to:
	//   - same user  -> reuse that session; don't stack a fresh one.
	//   - other user -> the silent session-swap / confused-deputy case
	//                    (logged in as A, completes OAuth as B). Reject;
	//                    this is the guard the callback login-state gate
	//                    is meant to enforce but can't see in the popup
	//                    flow without the prelogin id.
	//   - gone       -> session was legitimately revoked/expired between
	//                    /authorize and here. Fall through to a new one.
	var ses *core.ClientSession
	reusedSession := false
	if opts.PreloginSessionID != nil {
		prior, perr := handler.repo.GetClientSessionByID(r.Context(), *opts.PreloginSessionID)
		if perr == nil && prior != nil && prior.AppID != nil && *prior.AppID == ctxApp.ID {
			if prior.UserID != user.ID {
				handler.writeAuthLogFromRequest(r, AuthLogInput{
					WorkspaceID:    ws.ID,
					AppID:          &ctxApp.ID,
					Event:          core.AuthEventLoginFailed,
					Method:         opts.AuthMethod,
					Outcome:        core.AuthOutcomeFailed,
					FailureReason:  core.AuthFailIdentityConflict,
					EmailAttempted: email,
					ActorType:      core.AuthActorSelf,
				})
				WriteError(w, r, "error.alreadyLoggedIn", http.StatusForbidden)
				return
			}
			ses = prior
			reusedSession = true
		}
	}
	if ses == nil {
		ses, err = handler.clientAuthService.CreateSessionWithOptions(r.Context(), user.ID, ctxApp.ID, ua, ip, rememberMe, ctxApp.SessionTTL(), ctxApp.RememberMeTTL(), ctxApp.MaxSessions())
		if err != nil {
			log.Err(err).Msgf("Could not create client session for %s login", opts.WebhookMethod)
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
	}

	// The OAuth callback always arrives with rememberMe=false — the
	// sign-in checkbox can't survive the provider round-trip. For a
	// honored session that was originally created with rememberMe, that
	// would silently downgrade its (and its new refresh token's) TTL
	// from long-lived to short. Inherit the reused session's own
	// persistence instead. Only mutate on the reuse path; a fresh
	// session's TTL was already fixed by CreateSessionWithOptions above.
	if reusedSession {
		rememberMe = ses.RememberMe
	}

	tokenPair, err := handler.clientAuthService.IssueTokenPair(r.Context(), ses, ua, ip, effectiveSessionTTL(ctxApp, rememberMe), ctxApp.AccessTokenTTL(), dpopJKT, handler.clientAuthService.IssuerForApp(ctxApp))
	if err != nil {
		log.Err(err).Msgf("Could not issue token pair for %s login", opts.WebhookMethod)
		// Only tear down a session we just created — never the caller's
		// pre-existing one we chose to honor.
		if !reusedSession {
			_ = handler.clientAuthService.DeleteSession(r.Context(), ses.ID)
		}
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	_ = handler.repo.InsertAttempt(r.Context(), opts.AttemptPurpose, email, ip)

	userID := user.ID
	sessionID := ses.ID
	appIDForLog := &ctxApp.ID
	if created {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:   ws.ID,
			AppID:         appIDForLog,
			Event:         core.AuthEventRegisterSuccess,
			Method:        opts.AuthMethod,
			Outcome:       core.AuthOutcomeSuccess,
			SubjectUserID: &userID,
			ActorType:     core.AuthActorSelf,
			ActorLabel:    user.Email,
			Metadata:      core.RegisterMetadata{Source: core.RegisterSourceSelfSignup},
		})
	}
	handler.writeAuthLogFromRequest(r, AuthLogInput{
		WorkspaceID:   ws.ID,
		AppID:         appIDForLog,
		Event:         core.AuthEventLoginSuccess,
		Method:        opts.AuthMethod,
		Outcome:       core.AuthOutcomeSuccess,
		SubjectUserID: &userID,
		ActorType:     core.AuthActorSelf,
		ActorLabel:    user.Email,
		SessionID:     &sessionID,
	})

	if created {
		handler.dispatchWebhook(ctxApp.ID, "user.register", map[string]any{"userId": user.ID, "email": email, "appId": ctxApp.ID})
	}
	handler.dispatchWebhook(ctxApp.ID, "user.login", map[string]any{"userId": user.ID, "email": email, "appId": ctxApp.ID, "method": opts.WebhookMethod})

	loginAt := time.Now().UTC()
	_ = handler.repo.UpdateUserLastLogin(r.Context(), user.ID, loginAt)
	_ = handler.repo.UpdateAppUserLastLogin(r.Context(), ctxApp.ID, user.ID, loginAt)

	handler.setSessionCookies(w, r, ws, ctxApp, tokenPair, effectiveSessionTTL(ctxApp, rememberMe))
	utils.WriteJson(w, map[string]any{
		"accessToken":  tokenPair.AccessToken,
		"refreshToken": tokenPair.RefreshToken,
		"expiresAt":    tokenPair.ExpiresAt,
		"expiresIn":    tokenPair.ExpiresIn,
		"session":      toClientSessionResource(ses),
	})
}
