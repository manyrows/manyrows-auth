package api

import (
	"manyrows-core/auth"
	naverauth "manyrows-core/auth/naver"
	"manyrows-core/core"
	"manyrows-core/crypto"
	"net/http"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// =====================
// Sign in with Naver (Authorization Code Flow)
// =====================
//
// Naver is OAuth2-only: the callback arrives as a GET with code+state, the
// token exchange returns a bare access_token, and identity is read from
// Naver's userinfo endpoint (see auth/naver). Mirrors the Kakao popup flow,
// minus the id_token verification.

func (handler *RequestHandler) naverConfigured(a *core.App) bool {
	return a != nil &&
		a.NaverClientID != nil && *a.NaverClientID != "" &&
		len(a.NaverClientSecretEncrypted) > 0
}

// WorkspaceNaverAuthorize returns the Naver authorization URL.
// GET /x/{slug}/apps/{appId}/auth/naver/authorize?openerOrigin=https://...
func (handler *RequestHandler) WorkspaceNaverAuthorize(w http.ResponseWriter, r *http.Request) {
	handler.workspaceOAuthAuthorize(w, r, tier1OAuthAuthorizeOpts{
		Provider:             "naver",
		AuthMethodEnabled:    func(a *core.App) bool { return a.AuthMethodNaver },
		Configured:           handler.naverConfigured,
		NotConfiguredCode:    "error.naverNotConfigured",
		OpenerOriginRequired: true,
		StateTTL:             oauthStateTTL,
		CallbackPath:         "auth/naver/callback",
		BuildAuthorizeURL: func(a *core.App, redirectURI, state string) string {
			return naverauth.BuildAuthorizeURL(*a.NaverClientID, redirectURI, state)
		},
	})
}

// WorkspaceNaverCallback handles Naver's GET redirect with code + state in the
// query string. Same buffered-then-wrap pattern as the other providers, with
// messageType=naver-oauth-callback.
//
// GET /x/{slug}/apps/{appId}/auth/naver/callback?code=...&state=...
func (handler *RequestHandler) WorkspaceNaverCallback(w http.ResponseWriter, r *http.Request) {
	state := strings.TrimSpace(r.URL.Query().Get("state"))

	rawOrigin := auth.PeekOAuthStateOpenerOrigin(r.Context(), handler.repo, handler.totpKey, state)
	targetOrigin := sanitizeTargetOrigin(rawOrigin)

	buf := newBufferedResponse()
	handler.processNaverCallback(buf, r)
	writeOAuthCallbackHTML(w, buf, targetOrigin, "naver-oauth-callback")
}

func (handler *RequestHandler) processNaverCallback(w http.ResponseWriter, r *http.Request) {
	ws, ctxApp, ok := handler.requireOAuthAppContext(w, r,
		func(a *core.App) bool { return a.AuthMethodNaver },
		handler.naverConfigured,
		"error.naverNotConfigured")
	if !ok {
		return
	}

	// Forbid OAuth completion when a session for this app is already active —
	// same forced-linking guard as the other providers.
	loggedIn, _, sesErr := handler.clientAuthService.IsLoggedIntoApp(r, ctxApp.ID)
	if sesErr != nil {
		log.Err(sesErr).Msg("Could not resolve client session for naver callback")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if loggedIn {
		WriteError(w, r, "error.alreadyLoggedIn", http.StatusForbidden)
		return
	}

	if e := strings.TrimSpace(r.URL.Query().Get("error")); e != "" {
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if code == "" || state == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	stateAppID, _, preloginSesID, err := auth.VerifyOAuthState(r.Context(), handler.repo, handler.totpKey, state, "naver")
	if err != nil || stateAppID != ctxApp.ID {
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	ip := auth.ClientIP(r)

	if !handler.checkAttemptRateLimit(w, r, "naver_oauth", ip, "", "naver oauth callback", nil) {
		return
	}

	clientSecret, err := handler.encryptor.DecryptFromBytesWithAAD(
		ctxApp.NaverClientSecretEncrypted,
		crypto.AAD("apps", "naver_client_secret_encrypted", ctxApp.ID),
	)
	if err != nil {
		log.Err(err).Msg("failed to decrypt naver client secret")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Naver's token exchange echoes the same `state` and (unlike the OAuth2
	// spec) takes no redirect_uri.
	tokenInfo, err := naverauth.ExchangeAuthCode(r.Context(), code, state, *ctxApp.NaverClientID, string(clientSecret))
	if err != nil {
		_ = handler.repo.InsertAttempt(r.Context(), "naver_oauth", "naver_oauth_code_failed", ip)
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:   ws.ID,
			AppID:         &ctxApp.ID,
			Event:         core.AuthEventLoginFailed,
			Method:        core.AuthMethodNaver,
			Outcome:       core.AuthOutcomeFailed,
			FailureReason: core.AuthFailProviderExchangeFail,
			ActorType:     core.AuthActorSelf,
		})
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	// Naver provides no email-verification flag at all, so we can't confirm the
	// account email is owned by this user. No email → can't key a user.
	if tokenInfo.Email == "" {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:   ws.ID,
			AppID:         &ctxApp.ID,
			Event:         core.AuthEventLoginFailed,
			Method:        core.AuthMethodNaver,
			Outcome:       core.AuthOutcomeFailed,
			FailureReason: core.AuthFailEmailNotProvided,
			ActorType:     core.AuthActorSelf,
		})
		WriteError(w, r, "error.emailNotProvided", http.StatusBadRequest)
		return
	}

	// Naver exposes no email-verification signal, so unlike every other
	// provider we can't establish that the address is owned by this user.
	// Refuse sign-in unless the operator has explicitly opted into trusting
	// Naver's emails for this app — otherwise a Naver account asserting a
	// victim's address could hijack their account via the email-fallback link
	// in ResolveOAuthSignInIdentity. Mirrors the external-IdP
	// TrustUnverifiedEmail gate; default false = secure.
	if !ctxApp.NaverTrustUnverifiedEmail {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:    ws.ID,
			AppID:          &ctxApp.ID,
			Event:          core.AuthEventLoginFailed,
			Method:         core.AuthMethodNaver,
			Outcome:        core.AuthOutcomeFailed,
			FailureReason:  core.AuthFailEmailNotVerified,
			EmailAttempted: tokenInfo.Email,
			ActorType:      core.AuthActorSelf,
		})
		WriteError(w, r, "error.emailNotVerified", http.StatusForbidden)
		return
	}

	handler.completeNaverLogin(w, r, ws, ctxApp, tokenInfo, ip, false, preloginSesID)
}

// completeNaverLogin mirrors completeKakaoLogin / completeMicrosoftLogin:
// lookup-or-create user by email, 2FA gate, session issuance, JSON response.
func (handler *RequestHandler) completeNaverLogin(
	w http.ResponseWriter, r *http.Request,
	ws *core.Workspace, ctxApp *core.App,
	tokenInfo *naverauth.TokenInfo, ip string, rememberMe bool,
	preloginSessionID *uuid.UUID,
) {
	handler.completeTier1OAuthLogin(w, r, ws, ctxApp, tokenInfo.Email, ip, rememberMe, tier1OAuthLoginOpts{
		AuthMethod:        core.AuthMethodNaver,
		UserSource:        core.UserSourceNaver,
		ProviderSubject:   tokenInfo.Sub,
		AttemptPurpose:    "naver_oauth",
		WebhookMethod:     "naver",
		PreloginSessionID: preloginSessionID,
	})
}
