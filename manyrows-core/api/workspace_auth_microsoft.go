package api

import (
	"errors"
	"manyrows-core/auth"
	microsoftauth "manyrows-core/auth/microsoft"
	"manyrows-core/core"
	"manyrows-core/crypto"
	"net/http"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// =====================
// Sign in with Microsoft (Authorization Code Flow)
// =====================
//
// Microsoft uses a normal `response_mode=query` redirect (no
// form_post), so the callback arrives as GET with code+state in the
// query string. The static client_secret is decrypted from the app
// row at exchange time. ID-token verification + tenant-scope rules
// live in auth/microsoft.

func (handler *RequestHandler) microsoftConfigured(a *core.App) bool {
	return a != nil &&
		a.MicrosoftClientID != nil && *a.MicrosoftClientID != "" &&
		len(a.MicrosoftClientSecretEncrypted) > 0 &&
		microsoftauth.IsValidTenant(a.MicrosoftTenant)
}

// WorkspaceMicrosoftAuthorize returns the Microsoft authorization URL.
// Mirrors WorkspaceAppleAuthorize: validate openerOrigin against the
// app's CORS allowlist, record it keyed by state, return the URL.
//
// GET /x/{slug}/apps/{appId}/auth/microsoft/authorize?openerOrigin=https://...
func (handler *RequestHandler) WorkspaceMicrosoftAuthorize(w http.ResponseWriter, r *http.Request) {
	handler.workspaceOAuthAuthorize(w, r, tier1OAuthAuthorizeOpts{
		Provider:             "microsoft",
		AuthMethodEnabled:    func(a *core.App) bool { return a.AuthMethodMicrosoft },
		Configured:           handler.microsoftConfigured,
		NotConfiguredCode:    "error.microsoftNotConfigured",
		OpenerOriginRequired: true,
		StateTTL:             oauthStateTTL,
		CallbackPath:         "auth/microsoft/callback",
		BuildAuthorizeURL: func(a *core.App, redirectURI, state string) string {
			return microsoftauth.BuildAuthorizeURL(a.MicrosoftTenant, *a.MicrosoftClientID, redirectURI, state)
		},
	})
}

// WorkspaceMicrosoftCallback handles Microsoft's GET redirect with
// code + state in the query string. Same buffered-then-wrap pattern
// as Apple, just with messageType=microsoft-oauth-callback.
//
// GET /x/{slug}/apps/{appId}/auth/microsoft/callback?code=...&state=...
func (handler *RequestHandler) WorkspaceMicrosoftCallback(w http.ResponseWriter, r *http.Request) {
	state := strings.TrimSpace(r.URL.Query().Get("state"))

	rawOrigin := auth.PeekOAuthStateOpenerOrigin(r.Context(), handler.repo, handler.totpKey, state)
	targetOrigin := sanitizeTargetOrigin(rawOrigin)

	buf := newBufferedResponse()
	handler.processMicrosoftCallback(buf, r)
	writeOAuthCallbackHTML(w, buf, targetOrigin, "microsoft-oauth-callback")
}

func (handler *RequestHandler) processMicrosoftCallback(w http.ResponseWriter, r *http.Request) {
	ws, ctxApp, ok := handler.requireOAuthAppContext(w, r,
		func(a *core.App) bool { return a.AuthMethodMicrosoft },
		handler.microsoftConfigured,
		"error.microsoftNotConfigured")
	if !ok {
		return
	}

	// Forbid OAuth completion when a session for this app is already
	// active — same forced-linking guard as the other providers.
	loggedIn, _, sesErr := handler.clientAuthService.IsLoggedIntoApp(r, ctxApp.ID)
	if sesErr != nil {
		log.Err(sesErr).Msg("Could not resolve client session for microsoft callback")
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

	stateAppID, _, preloginSesID, err := auth.VerifyOAuthState(r.Context(), handler.repo, handler.totpKey, state, "microsoft")
	if err != nil || stateAppID != ctxApp.ID {
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	ip := auth.ClientIP(r)

	if !handler.checkAttemptRateLimit(w, r, "microsoft_oauth", ip, "", "microsoft oauth callback", nil) {
		return
	}

	clientSecret, err := handler.encryptor.DecryptFromBytesWithAAD(
		ctxApp.MicrosoftClientSecretEncrypted,
		crypto.AAD("apps", "microsoft_client_secret_encrypted", ctxApp.ID),
	)
	if err != nil {
		log.Err(err).Msg("failed to decrypt microsoft client secret")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	baseURL := handler.AppBaseURL(ctxApp)
	redirectURI := baseURL + "/x/" + ws.Slug + "/apps/" + ctxApp.ID.String() + "/auth/microsoft/callback"

	tokenInfo, err := microsoftauth.ExchangeAuthCode(
		r.Context(),
		code,
		ctxApp.MicrosoftTenant,
		*ctxApp.MicrosoftClientID,
		string(clientSecret),
		redirectURI,
	)
	if err != nil {
		_ = handler.repo.InsertAttempt(r.Context(), "microsoft_oauth", "microsoft_oauth_code_failed", ip)

		// xms_edov-missing is a configuration issue on the customer's
		// side — they need to enable the optional claim in Entra. Give
		// it a distinct error code so the AppKit can surface a helpful
		// message instead of the generic "invalid credentials".
		errCode := "error.invalidCredentials"
		failReason := core.AuthFailProviderExchangeFail
		if errors.Is(err, microsoftauth.ErrEmailNotVerified) {
			errCode = "error.microsoftEmailDomainNotVerified"
			failReason = core.AuthFailEmailNotVerified
		}

		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:   ws.ID,
			AppID:         &ctxApp.ID,
			Event:         core.AuthEventLoginFailed,
			Method:        core.AuthMethodMicrosoft,
			Outcome:       core.AuthOutcomeFailed,
			FailureReason: failReason,
			ActorType:     core.AuthActorSelf,
		})
		WriteError(w, r, errCode, http.StatusUnauthorized)
		return
	}

	if tokenInfo.Email == "" {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:   ws.ID,
			AppID:         &ctxApp.ID,
			Event:         core.AuthEventLoginFailed,
			Method:        core.AuthMethodMicrosoft,
			Outcome:       core.AuthOutcomeFailed,
			FailureReason: core.AuthFailEmailNotProvided,
			ActorType:     core.AuthActorSelf,
		})
		WriteError(w, r, "error.emailNotProvided", http.StatusBadRequest)
		return
	}

	handler.completeMicrosoftLogin(w, r, ws, ctxApp, tokenInfo, ip, false, preloginSesID)
}

// completeMicrosoftLogin mirrors completeAppleLogin / completeGoogleLogin:
// lookup-or-create user by email, 2FA gate, session issuance, JSON
// response. Kept separate per-provider so audit metadata stays explicit.
func (handler *RequestHandler) completeMicrosoftLogin(
	w http.ResponseWriter, r *http.Request,
	ws *core.Workspace, ctxApp *core.App,
	tokenInfo *microsoftauth.TokenInfo, ip string, rememberMe bool,
	preloginSessionID *uuid.UUID,
) {
	handler.completeTier1OAuthLogin(w, r, ws, ctxApp, tokenInfo.Email, ip, rememberMe, tier1OAuthLoginOpts{
		AuthMethod:        core.AuthMethodMicrosoft,
		UserSource:        core.UserSourceMicrosoft,
		ProviderSubject:   tokenInfo.Sub,
		AttemptPurpose:    "microsoft_oauth",
		WebhookMethod:     "microsoft",
		PreloginSessionID: preloginSessionID,
	})
}
