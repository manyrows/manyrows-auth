package api

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// originFromBaseURL reduces a base URL (which may carry a path) to
// its bare scheme://host[:port] origin, matching the shape of a
// browser's window.location.origin. Returns "" when the input isn't
// a usable absolute URL.
func originFromBaseURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// tier1OAuthAuthorizeOpts is the per-provider configuration for the
// shared Authorize handler. Each provider's WorkspaceXxxAuthorize
// becomes a thin wrapper that builds these opts and calls the helper.
//
// Keeps Tier-1's quirks visible:
// Google uniquely tolerates an empty openerOrigin (server-side /
// non-popup callers fall through with no postMessage target); the
// other three providers require it because the popup-postMessage
// flow has no fallback shape.
type tier1OAuthAuthorizeOpts struct {
	// Provider is the string passed to SignOAuthState — must match
	// what VerifyOAuthState gets at callback time. "google", "apple",
	// "microsoft", or "github".
	Provider string

	// AuthMethodEnabled returns the per-app boolean toggling this
	// provider on or off (a.AuthMethodGoogle, etc.).
	AuthMethodEnabled func(a *core.App) bool

	// Configured returns true when the app row carries every secret /
	// ID this provider needs to mint a token-exchange call. Returning
	// false yields a NotConfiguredCode response.
	Configured func(a *core.App) bool

	// NotConfiguredCode is the i18n key written when Configured returns
	// false ("error.googleOAuthNotConfigured" /
	// "error.appleNotConfigured" / "error.microsoftNotConfigured" /
	// "error.githubNotConfigured").
	NotConfiguredCode string

	// OpenerOriginRequired = true (Apple/Microsoft/GitHub) demands a
	// non-empty openerOrigin and rejects the request otherwise.
	// Google sets this false: empty origin is acceptable (the callback
	// HTML wrapper falls back to a no-postMessage flow), but a
	// supplied origin still must match the app's CORS allowlist.
	OpenerOriginRequired bool

	// StateTTL is the lifetime of the signed OAuth state row.
	// Google uses googleOAuthStateTTL; Apple/Microsoft/GitHub share
	// the longer oauthStateTTL.
	StateTTL time.Duration

	// BuildAuthorizeURL is the provider's URL builder. The shared
	// helper has already minted state and assembled the redirect URI.
	BuildAuthorizeURL func(a *core.App, redirectURI, state string) string

	// CallbackPath is the URL path that receives the provider's
	// callback ("auth/google/callback" / "auth/apple/callback" /
	// "auth/microsoft/callback" / "auth/github/callback"). Used to
	// build the redirect URI passed to BuildAuthorizeURL and recorded
	// at exchange time.
	CallbackPath string
}

// requireOAuthAppContext validates the workspace + app context, the
// per-app auth-method enable bit, and the per-provider Configured
// predicate. Returns ok=false (with the appropriate response already
// written) when any gate fails; the caller MUST return immediately
// without further writes.
//
// Shared by workspaceOAuthAuthorize, WorkspaceGoogleCallback, and
// the three processXxxCallback handlers — all four OAuth providers'
// callbacks open with this exact prefix.
func (handler *RequestHandler) requireOAuthAppContext(
	w http.ResponseWriter, r *http.Request,
	authMethodEnabled func(*core.App) bool,
	configured func(*core.App) bool,
	notConfiguredCode string,
) (*core.Workspace, *core.App, bool) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return nil, nil, false
	}
	ctxApp, appOk := core.AppFromContext(r.Context())
	if !appOk || ctxApp == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return nil, nil, false
	}
	if !authMethodEnabled(ctxApp) {
		WriteError(w, r, "error.authMethodDisabled", http.StatusForbidden)
		return nil, nil, false
	}
	if !configured(ctxApp) {
		WriteError(w, r, notConfiguredCode, http.StatusBadRequest)
		return nil, nil, false
	}
	return ws, ctxApp, true
}

// workspaceOAuthAuthorize is the shared body of the four Tier-1
// WorkspaceXxxAuthorize handlers. Validates the workspace + app
// context, the per-provider config, the popup opener origin against
// the app's CORS allowlist. Then signs an OAuth state row and returns
// {url, state} as JSON.
func (handler *RequestHandler) workspaceOAuthAuthorize(
	w http.ResponseWriter, r *http.Request,
	opts tier1OAuthAuthorizeOpts,
) {
	ws, ctxApp, ok := handler.requireOAuthAppContext(w, r, opts.AuthMethodEnabled, opts.Configured, opts.NotConfiguredCode)
	if !ok {
		return
	}

	openerOrigin := strings.TrimSpace(r.URL.Query().Get("openerOrigin"))
	if openerOrigin == "" {
		openerOrigin = strings.TrimSpace(r.Header.Get("Origin"))
	}
	if opts.OpenerOriginRequired && openerOrigin == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if openerOrigin != "" {
		origins, err := handler.repo.GetCorsOrigins(r.Context(), ctxApp.ID)
		if err != nil {
			log.Err(err).Msgf("%s authorize: GetCorsOrigins failed", opts.Provider)
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		allowed := false
		for i := range origins {
			if strings.EqualFold(strings.TrimSpace(origins[i].Origin), openerOrigin) {
				allowed = true
				break
			}
		}
		// Also allow the install's OWN origin. ManyRows serves AppKit
		// itself on a few pages (the OIDC /oidc/login shim and the QR
		// /pair landing), where window.location.origin is the auth
		// host — never the customer app domain, so it isn't in the
		// per-app CORS allowlist. Those pages are the IdP; trusting
		// the install origin is safe (an attacker can't receive a
		// postMessage targeted at the auth host unless their window is
		// actually served from it, which only ManyRows pages are).
		if !allowed {
			if installOrigin := originFromBaseURL(handler.AppBaseURL(ctxApp)); installOrigin != "" &&
				strings.EqualFold(installOrigin, openerOrigin) {
				allowed = true
			}
		}
		if !allowed {
			WriteError(w, r, "error.invalidOrigin", http.StatusBadRequest)
			return
		}
	}

	baseURL := handler.AppBaseURL(ctxApp)
	if baseURL == "" {
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	redirectURI := baseURL + "/x/" + ws.Slug + "/apps/" + ctxApp.ID.String() + "/" + opts.CallbackPath

	// If the caller already has an active session for this app (bearer or
	// cookie present on the /authorize request), ride its id along on the
	// signed-state DB row. The callback — a top-level redirect from the
	// provider that carries no credential of its own — uses it to honor
	// the existing session instead of stacking a new one, and to make the
	// "already logged in" guard effective for the popup flow. nil when the
	// flow starts unauthenticated (the common Auth-screen case), which
	// keeps the normal new-session path unchanged.
	var preloginSessionID *uuid.UUID
	if loggedIn, ses, lerr := handler.clientAuthService.IsLoggedIntoApp(r, ctxApp.ID); lerr == nil && loggedIn && ses != nil {
		sid := ses.ID
		preloginSessionID = &sid
	}

	state, err := auth.SignOAuthState(r.Context(), handler.repo, handler.totpKey, ctxApp.ID, opts.Provider, openerOrigin, preloginSessionID, opts.StateTTL)
	if err != nil {
		log.Err(err).Msgf("could not sign %s oauth state", opts.Provider)
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	authorizeURL := opts.BuildAuthorizeURL(ctxApp, redirectURI, state)

	utils.WriteJson(w, map[string]any{
		"url":   authorizeURL,
		"state": state,
	})
}

// googleConfigured mirrors appleConfigured / microsoftConfigured /
// githubConfigured: returns true when the app row carries every
// Google-OAuth secret needed to mint a token-exchange call. Used by
// the shared workspaceOAuthAuthorize helper. Was previously inlined
// at every call site as two separate clauses.
func (handler *RequestHandler) googleConfigured(a *core.App) bool {
	return a != nil &&
		a.GoogleOAuthClientID != nil && *a.GoogleOAuthClientID != "" &&
		len(a.GoogleOAuthClientSecretEncrypted) > 0
}
