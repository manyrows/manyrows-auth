package api

import (
	"encoding/json"
	"fmt"
	"html"
	"manyrows-core/auth"
	googleauth "manyrows-core/auth/google"
	"manyrows-core/core"
	"manyrows-core/crypto"
	"net/http"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// =====================
// Google OAuth Authentication
// =====================

type WorkspaceLoginGoogleRequest struct {
	Credential string    `json:"credential"` // Google ID token from GSI
	AppID      uuid.UUID `json:"appId"`
	RememberMe bool      `json:"rememberMe,omitempty"`
}

// WorkspaceLoginGoogle handles Google OAuth login for workspace accounts.
// POST /x/{slug}/auth/google
func (handler *RequestHandler) WorkspaceLoginGoogle(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	// Resolve the app from context
	ctxApp, appOk := core.AppFromContext(r.Context())

	// Reject if app has Google auth disabled
	if appOk && ctxApp != nil && !ctxApp.AuthMethodGoogle {
		WriteError(w, r, "error.authMethodDisabled", http.StatusForbidden)
		return
	}

	// Check app has Google OAuth configured
	var googleClientID string
	if appOk && ctxApp != nil && ctxApp.GoogleOAuthClientID != nil && *ctxApp.GoogleOAuthClientID != "" {
		googleClientID = *ctxApp.GoogleOAuthClientID
	} else {
		WriteError(w, r, "error.googleOAuthNotConfigured", http.StatusBadRequest)
		return
	}

	// Reject if already logged in
	if ctxApp != nil {
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
	}

	var req WorkspaceLoginGoogleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	credential := strings.TrimSpace(req.Credential)
	if credential == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Rate limit by IP
	ip := auth.ClientIP(r)

	googleLoginFailed := func(reason core.AuthLogFailureReason, email string) {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:    ws.ID,
			AppID:          &ctxApp.ID,
			Event:          core.AuthEventLoginFailed,
			Method:         core.AuthMethodGoogle,
			Outcome:        core.AuthOutcomeFailed,
			FailureReason:  reason,
			EmailAttempted: email,
			ActorType:      core.AuthActorSelf,
		})
	}

	if !handler.checkAttemptRateLimit(w, r, "google_oauth", ip, "", "google oauth",
		func() { googleLoginFailed(core.AuthFailRateLimited, "") }) {
		return
	}

	// Verify Google ID token
	tokenInfo, err := googleauth.VerifyIDToken(r.Context(), credential)
	if err != nil {
		_ = handler.repo.InsertAttempt(r.Context(), "google_oauth", "google_oauth_failed", ip)
		googleLoginFailed(core.AuthFailProviderExchangeFail, "")
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	// Validate audience matches the configured client ID
	if tokenInfo.Aud != googleClientID {
		_ = handler.repo.InsertAttempt(r.Context(), "google_oauth", tokenInfo.Email, ip)
		googleLoginFailed(core.AuthFailAudienceMismatch, tokenInfo.Email)
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	// Require verified email
	if !tokenInfo.EmailVerified {
		googleLoginFailed(core.AuthFailEmailNotVerified, tokenInfo.Email)
		WriteError(w, r, "error.emailNotVerified", http.StatusForbidden)
		return
	}

	// Implicit (ID-token) flow: no /authorize round-trip, so no prelogin
	// session id to honor — always a fresh-session login.
	handler.completeGoogleLogin(w, r, ws, ctxApp, tokenInfo, ip, req.RememberMe, nil)
}

// completeGoogleLogin is the shared logic for both the implicit (ID token) and
// authorization code flows. It looks up or creates a user, handles
// 2FA, creates a session, and writes the JSON response.
//
// rememberMe is plumbed from whichever flow called us — the ID-token flow
// reads it from the request body; the auth-code flow recovers it from the
// signed state because the redirect happens out-of-band.
func (handler *RequestHandler) completeGoogleLogin(
	w http.ResponseWriter, r *http.Request,
	ws *core.Workspace, ctxApp *core.App,
	tokenInfo *googleauth.TokenInfo, ip string, rememberMe bool,
	preloginSessionID *uuid.UUID,
) {
	handler.completeTier1OAuthLogin(w, r, ws, ctxApp, tokenInfo.Email, ip, rememberMe, tier1OAuthLoginOpts{
		AuthMethod:        core.AuthMethodGoogle,
		UserSource:        core.UserSourceGoogle,
		ProviderSubject:   tokenInfo.Sub,
		AttemptPurpose:    "google_oauth",
		WebhookMethod:     "google",
		PreloginSessionID: preloginSessionID,
	})
}

// =====================
// Google OAuth Authorization Code Flow
// =====================

const googleOAuthStateTTL = 10 * time.Minute

// WorkspaceGoogleAuthorize returns a Google authorization URL for the OAuth
// Authorization Code Flow. Non-browser clients open this URL to start login.
// GET /x/{slug}/apps/{appId}/auth/google/authorize
func (handler *RequestHandler) WorkspaceGoogleAuthorize(w http.ResponseWriter, r *http.Request) {
	handler.workspaceOAuthAuthorize(w, r, tier1OAuthAuthorizeOpts{
		Provider:             "google",
		AuthMethodEnabled:    func(a *core.App) bool { return a.AuthMethodGoogle },
		Configured:           handler.googleConfigured,
		NotConfiguredCode:    "error.googleOAuthNotConfigured",
		OpenerOriginRequired: false,
		StateTTL:             googleOAuthStateTTL,
		CallbackPath:         "auth/google/callback",
		BuildAuthorizeURL: func(a *core.App, redirectURI, state string) string {
			return googleauth.BuildAuthorizeURL(*a.GoogleOAuthClientID, redirectURI, state)
		},
	})
}

type WorkspaceGoogleCallbackRequest struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

// WorkspaceGoogleCallbackGET handles the GET redirect from Google.
// Mirrors the Apple/Microsoft/GitHub callback pattern: runs the
// JSON-emitting processor against a bufferedResponse and then wraps
// whatever it produced in the standard postMessage HTML so the popup
// flow lines up with the other providers (single
// {type, status, payload} shape rather than the previous two-shot
// fetch-then-postMessage dance).
// GET /x/{slug}/apps/{appId}/auth/google/callback?code=...&state=...
func (handler *RequestHandler) WorkspaceGoogleCallbackGET(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	errParam := strings.TrimSpace(r.URL.Query().Get("error"))

	if errParam != "" {
		// errParam is attacker-controllable (anyone can craft a callback URL).
		// Escape before interpolating into the popup HTML — this page renders
		// on the auth origin, so any unescaped script tag would have access
		// to session cookies and could postMessage the opener.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<!DOCTYPE html><html><body><p>Google sign-in was cancelled or failed: %s</p></body></html>`, html.EscapeString(errParam))
		return
	}

	if code == "" || state == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Peek opener_origin from the state row WITHOUT consuming — the inner
	// processor will atomically consume via VerifyOAuthState. The peek
	// returns "" if the token is invalid/expired/already-consumed; in
	// that case the HTML wrapper will render without a postMessage
	// target, which is the right fail-closed behaviour.
	rawOrigin := auth.PeekOAuthStateOpenerOrigin(r.Context(), handler.repo, handler.totpKey, state)
	targetOrigin := sanitizeTargetOrigin(rawOrigin)

	buf := newBufferedResponse()
	handler.processGoogleCallback(buf, r, code, state)
	writeOAuthCallbackHTML(w, buf, targetOrigin, "google-oauth-callback")
}

// WorkspaceGoogleCallback handles the Google OAuth callback as a JSON
// POST endpoint. Originally the only Google callback path; now kept
// for back-compat with non-browser callers (native apps, integration
// tests). The browser popup flow goes through WorkspaceGoogleCallbackGET
// above instead, which uses the same shared processGoogleCallback
// helper to do the work.
// POST /x/{slug}/apps/{appId}/auth/google/callback
func (handler *RequestHandler) WorkspaceGoogleCallback(w http.ResponseWriter, r *http.Request) {
	var req WorkspaceGoogleCallbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	code := strings.TrimSpace(req.Code)
	state := strings.TrimSpace(req.State)
	handler.processGoogleCallback(w, r, code, state)
}

// processGoogleCallback runs the actual token-exchange + session-creation
// path for a Google authorization code. Called from both the GET handler
// (via bufferedResponse, for the popup flow) and the POST handler (for
// direct JSON callers).
func (handler *RequestHandler) processGoogleCallback(w http.ResponseWriter, r *http.Request, code, state string) {
	ws, ctxApp, ok := handler.requireOAuthAppContext(w, r,
		func(a *core.App) bool { return a.AuthMethodGoogle },
		handler.googleConfigured,
		"error.googleOAuthNotConfigured")
	if !ok {
		return
	}

	// Forbid OAuth completion when a session for this app is already
	// active. WorkspaceLoginGoogle (the legacy ID-token POST handler)
	// guards the same way at request start; the callback path needs
	// its own check because it's reached via redirect, not a fresh POST.
	loggedIn, _, sesErr := handler.clientAuthService.IsLoggedIntoApp(r, ctxApp.ID)
	if sesErr != nil {
		log.Err(sesErr).Msg("Could not resolve client session for google callback")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if loggedIn {
		WriteError(w, r, "error.alreadyLoggedIn", http.StatusForbidden)
		return
	}

	if code == "" || state == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Verify CSRF state and confirm app ID matches
	stateAppID, _, preloginSesID, err := auth.VerifyOAuthState(r.Context(), handler.repo, handler.totpKey, state, "google")
	if err != nil {
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}
	if stateAppID != ctxApp.ID {
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	// Rate limit by IP
	ip := auth.ClientIP(r)

	googleCBFail := func(reason core.AuthLogFailureReason, email string) {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:    ws.ID,
			AppID:          &ctxApp.ID,
			Event:          core.AuthEventLoginFailed,
			Method:         core.AuthMethodGoogle,
			Outcome:        core.AuthOutcomeFailed,
			FailureReason:  reason,
			EmailAttempted: email,
			ActorType:      core.AuthActorSelf,
		})
	}

	if !handler.checkAttemptRateLimit(w, r, "google_oauth", ip, "", "google oauth callback",
		func() { googleCBFail(core.AuthFailRateLimited, "") }) {
		return
	}

	// Decrypt client secret
	clientSecret, err := handler.encryptor.DecryptFromBytesWithAAD(
		ctxApp.GoogleOAuthClientSecretEncrypted,
		crypto.AAD("apps", "google_oauth_client_secret_encrypted", ctxApp.ID),
	)
	if err != nil {
		log.Err(err).Msg("failed to decrypt google oauth client secret")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Build the same redirect URI used in the authorize step
	baseURL := handler.AppBaseURL(ctxApp)
	redirectURI := baseURL + "/x/" + ws.Slug + "/apps/" + ctxApp.ID.String() + "/auth/google/callback"

	// Exchange authorization code for tokens
	tokenInfo, err := googleauth.ExchangeAuthCode(r.Context(), code, *ctxApp.GoogleOAuthClientID, string(clientSecret), redirectURI)
	if err != nil {
		_ = handler.repo.InsertAttempt(r.Context(), "google_oauth", "google_oauth_code_failed", ip)
		googleCBFail(core.AuthFailProviderExchangeFail, "")
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	// Validate audience matches configured client ID
	if tokenInfo.Aud != *ctxApp.GoogleOAuthClientID {
		_ = handler.repo.InsertAttempt(r.Context(), "google_oauth", tokenInfo.Email, ip)
		googleCBFail(core.AuthFailAudienceMismatch, tokenInfo.Email)
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	// Require verified email
	if !tokenInfo.EmailVerified {
		googleCBFail(core.AuthFailEmailNotVerified, tokenInfo.Email)
		WriteError(w, r, "error.emailNotVerified", http.StatusForbidden)
		return
	}

	// Auth-code flow defaults to rememberMe=false; the redirect-based handoff
	// would need rememberMe baked into the signed state token to preserve a
	// checkbox value across the round trip. ID-token flow honors it directly.
	handler.completeGoogleLogin(w, r, ws, ctxApp, tokenInfo, ip, false, preloginSesID)
}
