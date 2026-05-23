package api

import (
	"manyrows-core/auth"
	kakaoauth "manyrows-core/auth/kakao"
	"manyrows-core/core"
	"manyrows-core/crypto"
	"net/http"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// =====================
// Sign in with Kakao (Authorization Code Flow)
// =====================
//
// Kakao uses a normal `response_type=code` redirect, so the callback
// arrives as a GET with code+state in the query string. The static client
// secret is decrypted from the app row at exchange time. ID-token
// verification (against Kakao's JWKS) + the userinfo email fallback live
// in auth/kakao. Mirrors the Microsoft popup flow.

func (handler *RequestHandler) kakaoConfigured(a *core.App) bool {
	return a != nil &&
		a.KakaoClientID != nil && *a.KakaoClientID != "" &&
		len(a.KakaoClientSecretEncrypted) > 0
}

// WorkspaceKakaoAuthorize returns the Kakao authorization URL.
// GET /x/{slug}/apps/{appId}/auth/kakao/authorize?openerOrigin=https://...
func (handler *RequestHandler) WorkspaceKakaoAuthorize(w http.ResponseWriter, r *http.Request) {
	handler.workspaceOAuthAuthorize(w, r, tier1OAuthAuthorizeOpts{
		Provider:             "kakao",
		AuthMethodEnabled:    func(a *core.App) bool { return a.AuthMethodKakao },
		Configured:           handler.kakaoConfigured,
		NotConfiguredCode:    "error.kakaoNotConfigured",
		OpenerOriginRequired: true,
		StateTTL:             oauthStateTTL,
		CallbackPath:         "auth/kakao/callback",
		BuildAuthorizeURL: func(a *core.App, redirectURI, state string) string {
			return kakaoauth.BuildAuthorizeURL(*a.KakaoClientID, redirectURI, state)
		},
	})
}

// WorkspaceKakaoCallback handles Kakao's GET redirect with code + state in
// the query string. Same buffered-then-wrap pattern as Microsoft, with
// messageType=kakao-oauth-callback.
//
// GET /x/{slug}/apps/{appId}/auth/kakao/callback?code=...&state=...
func (handler *RequestHandler) WorkspaceKakaoCallback(w http.ResponseWriter, r *http.Request) {
	state := strings.TrimSpace(r.URL.Query().Get("state"))

	rawOrigin := auth.PeekOAuthStateOpenerOrigin(r.Context(), handler.repo, handler.totpKey, state)
	targetOrigin := sanitizeTargetOrigin(rawOrigin)

	buf := newBufferedResponse()
	handler.processKakaoCallback(buf, r)
	writeOAuthCallbackHTML(w, buf, targetOrigin, "kakao-oauth-callback")
}

func (handler *RequestHandler) processKakaoCallback(w http.ResponseWriter, r *http.Request) {
	ws, ctxApp, ok := handler.requireOAuthAppContext(w, r,
		func(a *core.App) bool { return a.AuthMethodKakao },
		handler.kakaoConfigured,
		"error.kakaoNotConfigured")
	if !ok {
		return
	}

	// Forbid OAuth completion when a session for this app is already
	// active — same forced-linking guard as the other providers.
	loggedIn, _, sesErr := handler.clientAuthService.IsLoggedIntoApp(r, ctxApp.ID)
	if sesErr != nil {
		log.Err(sesErr).Msg("Could not resolve client session for kakao callback")
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

	stateAppID, _, preloginSesID, err := auth.VerifyOAuthState(r.Context(), handler.repo, handler.totpKey, state, "kakao")
	if err != nil || stateAppID != ctxApp.ID {
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	ip := auth.ClientIP(r)

	if !handler.checkAttemptRateLimit(w, r, "kakao_oauth", ip, "", "kakao oauth callback", nil) {
		return
	}

	clientSecret, err := handler.encryptor.DecryptFromBytesWithAAD(
		ctxApp.KakaoClientSecretEncrypted,
		crypto.AAD("apps", "kakao_client_secret_encrypted", ctxApp.ID),
	)
	if err != nil {
		log.Err(err).Msg("failed to decrypt kakao client secret")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	baseURL := handler.AppBaseURL(ctxApp)
	redirectURI := baseURL + "/x/" + ws.Slug + "/apps/" + ctxApp.ID.String() + "/auth/kakao/callback"

	tokenInfo, err := kakaoauth.ExchangeAuthCode(
		r.Context(),
		code,
		*ctxApp.KakaoClientID,
		string(clientSecret),
		redirectURI,
	)
	if err != nil {
		_ = handler.repo.InsertAttempt(r.Context(), "kakao_oauth", "kakao_oauth_code_failed", ip)
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:   ws.ID,
			AppID:         &ctxApp.ID,
			Event:         core.AuthEventLoginFailed,
			Method:        core.AuthMethodKakao,
			Outcome:       core.AuthOutcomeFailed,
			FailureReason: core.AuthFailProviderExchangeFail,
			ActorType:     core.AuthActorSelf,
		})
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	// Kakao only releases an email once it's verified+valid; an app that
	// wants Kakao sign-in must request account_email as required consent
	// (see the admin prerequisites note). No email → can't key a user.
	if tokenInfo.Email == "" {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:   ws.ID,
			AppID:         &ctxApp.ID,
			Event:         core.AuthEventLoginFailed,
			Method:        core.AuthMethodKakao,
			Outcome:       core.AuthOutcomeFailed,
			FailureReason: core.AuthFailEmailNotProvided,
			ActorType:     core.AuthActorSelf,
		})
		WriteError(w, r, "error.emailNotProvided", http.StatusBadRequest)
		return
	}
	if !tokenInfo.EmailVerified {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:    ws.ID,
			AppID:          &ctxApp.ID,
			Event:          core.AuthEventLoginFailed,
			Method:         core.AuthMethodKakao,
			Outcome:        core.AuthOutcomeFailed,
			FailureReason:  core.AuthFailEmailNotVerified,
			EmailAttempted: tokenInfo.Email,
			ActorType:      core.AuthActorSelf,
		})
		WriteError(w, r, "error.emailNotVerified", http.StatusForbidden)
		return
	}

	handler.completeKakaoLogin(w, r, ws, ctxApp, tokenInfo, ip, false, preloginSesID)
}

// completeKakaoLogin mirrors completeMicrosoftLogin / completeGoogleLogin:
// lookup-or-create user by email, 2FA gate, session issuance, JSON response.
func (handler *RequestHandler) completeKakaoLogin(
	w http.ResponseWriter, r *http.Request,
	ws *core.Workspace, ctxApp *core.App,
	tokenInfo *kakaoauth.TokenInfo, ip string, rememberMe bool,
	preloginSessionID *uuid.UUID,
) {
	handler.completeTier1OAuthLogin(w, r, ws, ctxApp, tokenInfo.Email, ip, rememberMe, tier1OAuthLoginOpts{
		AuthMethod:        core.AuthMethodKakao,
		UserSource:        core.UserSourceKakao,
		ProviderSubject:   tokenInfo.Sub,
		AttemptPurpose:    "kakao_oauth",
		WebhookMethod:     "kakao",
		PreloginSessionID: preloginSessionID,
	})
}
