package api

import (
	"errors"
	"manyrows-core/auth"
	githubauth "manyrows-core/auth/github"
	"manyrows-core/core"
	"manyrows-core/crypto"
	"net/http"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// =====================
// Sign in with GitHub (Authorization Code Flow)
// =====================
//
// GitHub uses plain OAuth 2.0 (no JWT id_token, no JWKS). Token
// exchange returns an access_token; auth/github calls /user and
// /user/emails to assemble verified identity. The popup-callback
// pattern is identical to Microsoft's — GET callback with code+state
// in query, HTML wrapper postMessages tokens to the opener.

func (handler *RequestHandler) githubConfigured(a *core.App) bool {
	return a != nil &&
		a.GithubClientID != nil && *a.GithubClientID != "" &&
		len(a.GithubClientSecretEncrypted) > 0
}

// WorkspaceGithubAuthorize returns the GitHub authorization URL.
// GET /x/{slug}/apps/{appId}/auth/github/authorize?openerOrigin=https://...
func (handler *RequestHandler) WorkspaceGithubAuthorize(w http.ResponseWriter, r *http.Request) {
	handler.workspaceOAuthAuthorize(w, r, tier1OAuthAuthorizeOpts{
		Provider:             "github",
		AuthMethodEnabled:    func(a *core.App) bool { return a.AuthMethodGithub },
		Configured:           handler.githubConfigured,
		NotConfiguredCode:    "error.githubNotConfigured",
		OpenerOriginRequired: true,
		StateTTL:             oauthStateTTL,
		CallbackPath:         "auth/github/callback",
		BuildAuthorizeURL: func(a *core.App, redirectURI, state string) string {
			return githubauth.BuildAuthorizeURL(*a.GithubClientID, redirectURI, state)
		},
	})
}

// WorkspaceGithubCallback handles GitHub's GET redirect with code+state.
// GET /x/{slug}/apps/{appId}/auth/github/callback?code=...&state=...
func (handler *RequestHandler) WorkspaceGithubCallback(w http.ResponseWriter, r *http.Request) {
	state := strings.TrimSpace(r.URL.Query().Get("state"))

	rawOrigin := auth.PeekOAuthStateOpenerOrigin(r.Context(), handler.repo, handler.totpKey, state)
	targetOrigin := sanitizeTargetOrigin(rawOrigin)

	buf := newBufferedResponse()
	handler.processGithubCallback(buf, r)
	writeOAuthCallbackHTML(w, buf, targetOrigin, "github-oauth-callback")
}

func (handler *RequestHandler) processGithubCallback(w http.ResponseWriter, r *http.Request) {
	ws, ctxApp, ok := handler.requireOAuthAppContext(w, r,
		func(a *core.App) bool { return a.AuthMethodGithub },
		handler.githubConfigured,
		"error.githubNotConfigured")
	if !ok {
		return
	}

	// Forbid OAuth completion when a session for this app is already
	// active — same forced-linking guard as the other providers.
	loggedIn, _, sesErr := handler.clientAuthService.IsLoggedIntoApp(r, ctxApp.ID)
	if sesErr != nil {
		log.Err(sesErr).Msg("Could not resolve client session for github callback")
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

	stateAppID, _, preloginSesID, err := auth.VerifyOAuthState(r.Context(), handler.repo, handler.totpKey, state, "github")
	if err != nil || stateAppID != ctxApp.ID {
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	ip := auth.ClientIP(r)

	if !handler.checkAttemptRateLimit(w, r, "github_oauth", ip, "", "github oauth callback", nil) {
		return
	}

	clientSecret, err := handler.encryptor.DecryptFromBytesWithAAD(
		ctxApp.GithubClientSecretEncrypted,
		crypto.AAD("apps", "github_client_secret_encrypted", ctxApp.ID),
	)
	if err != nil {
		log.Err(err).Msg("failed to decrypt github client secret")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	baseURL := handler.AppBaseURL(ctxApp)
	redirectURI := baseURL + "/x/" + ws.Slug + "/apps/" + ctxApp.ID.String() + "/auth/github/callback"

	tokenInfo, err := githubauth.ExchangeAuthCode(
		r.Context(),
		code,
		*ctxApp.GithubClientID,
		string(clientSecret),
		redirectURI,
	)
	if err != nil {
		_ = handler.repo.InsertAttempt(r.Context(), "github_oauth", "github_oauth_code_failed", ip)

		// No-verified-email is the customer's user's account state, not
		// a customer-config issue. Surface a distinct code so the
		// AppKit can tell the user to verify a primary email on GitHub.
		errCode := "error.invalidCredentials"
		failReason := core.AuthFailProviderExchangeFail
		if errors.Is(err, githubauth.ErrNoVerifiedEmail) {
			errCode = "error.githubNoVerifiedEmail"
			failReason = core.AuthFailEmailNotVerified
		}

		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:   ws.ID,
			AppID:         &ctxApp.ID,
			Event:         core.AuthEventLoginFailed,
			Method:        core.AuthMethodGithub,
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
			Method:        core.AuthMethodGithub,
			Outcome:       core.AuthOutcomeFailed,
			FailureReason: core.AuthFailEmailNotProvided,
			ActorType:     core.AuthActorSelf,
		})
		WriteError(w, r, "error.emailNotProvided", http.StatusBadRequest)
		return
	}

	handler.completeGithubLogin(w, r, ws, ctxApp, tokenInfo, ip, false, preloginSesID)
}

// completeGithubLogin mirrors completeMicrosoftLogin. GitHub's
// /user/emails verified flag is the trust source — we already
// filtered to verified addresses upstream.
func (handler *RequestHandler) completeGithubLogin(
	w http.ResponseWriter, r *http.Request,
	ws *core.Workspace, ctxApp *core.App,
	tokenInfo *githubauth.TokenInfo, ip string, rememberMe bool,
	preloginSessionID *uuid.UUID,
) {
	handler.completeTier1OAuthLogin(w, r, ws, ctxApp, tokenInfo.Email, ip, rememberMe, tier1OAuthLoginOpts{
		AuthMethod:        core.AuthMethodGithub,
		UserSource:        core.UserSourceGithub,
		ProviderSubject:   tokenInfo.Sub,
		AttemptPurpose:    "github_oauth",
		WebhookMethod:     "github",
		PreloginSessionID: preloginSessionID,
	})
}
