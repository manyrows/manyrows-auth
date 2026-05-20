package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"manyrows-core/auth/client"
	"manyrows-core/core"
	"manyrows-core/core/repo"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// =====================
// OIDC provider handlers
// =====================
//
// Endpoints serving an app as an OpenID Connect provider. Each app is
// its own issuer; the issuer URL is either the per-app AuthDomain
// (e.g. "auth.drumkingdom.com" — customer reverse-proxies to this
// install) or, when no AuthDomain is set, the install base URL with
// the per-app path appended ("https://manyrows.example.com/x/<slug>/
// apps/<appId>") so multi-app installs don't collide at the bare
// /.well-known/openid-configuration path.

// AppOIDCIssuer returns the issuer URL for this app's OIDC provider.
// Differs from AppBaseURL: AuthDomain case is identical (bare https://
// host), but with no AuthDomain, AppBaseURL returns the install base
// while AppOIDCIssuer appends the per-app path so the discovery doc
// served at this URL maps 1:1 to a single app's config.
func (handler *RequestHandler) AppOIDCIssuer(ws *core.Workspace, a *core.App) string {
	if a != nil && a.AuthDomain != nil {
		if d := strings.TrimSpace(*a.AuthDomain); d != "" {
			return "https://" + strings.TrimRight(d, "/")
		}
	}
	base := strings.TrimRight(handler.config.GetBaseURL(), "/")
	if base == "" || ws == nil || a == nil {
		return ""
	}
	return base + "/x/" + ws.Slug + "/apps/" + a.ID.String()
}

// oidcDiscoveryDocument is the JSON returned at the discovery endpoint.
// Field order follows the order most RPs render it in for diff-friendly
// logs; spec-compliance does not depend on order.
type oidcDiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

// OIDCDiscovery serves /.well-known/openid-configuration for an app.
// 404 when OIDC isn't enabled on the app (matches OAuth/OIDC norm:
// presence of the doc is itself a signal that the IdP exists here).
//
// Mounted on the per-app router so workspace + app are already in
// context. Cache headers are conservative (5 min) because the URLs
// only change on AuthDomain edits or app rename — rare events.
func (handler *RequestHandler) OIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	cfg, err := handler.repo.GetAppOIDCConfig(ctx, app.ID)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("OIDCDiscovery: GetAppOIDCConfig failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if cfg == nil || !cfg.Enabled {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	issuer := handler.AppOIDCIssuer(ws, app)
	if issuer == "" {
		log.Error().Str("app_id", app.ID.String()).Msg("OIDCDiscovery: empty issuer (BASE_URL not set?)")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	jwksHost := handler.AppBaseURL(app)

	doc := oidcDiscoveryDocument{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/oidc/authorize",
		TokenEndpoint:         issuer + "/oidc/token",
		UserinfoEndpoint:      issuer + "/oidc/userinfo",
		JwksURI:               jwksHost + "/.well-known/jwks.json",
		EndSessionEndpoint:    issuer + "/oidc/end-session",
		ResponseTypesSupported: []string{
			core.OIDCResponseTypeCode,
		},
		SubjectTypesSupported: []string{
			core.OIDCSubjectTypePublic,
		},
		IDTokenSigningAlgValuesSupported: []string{
			core.OIDCIDTokenSigningAlgValueES256,
		},
		ScopesSupported: []string{
			core.OIDCScopeOpenID,
			core.OIDCScopeEmail,
			core.OIDCScopeProfile,
			core.OIDCScopeOfflineAccess,
		},
		TokenEndpointAuthMethodsSupported: []string{
			core.OIDCTokenEndpointAuthBasic,
			core.OIDCTokenEndpointAuthPost,
			core.OIDCTokenEndpointAuthNone,
		},
		CodeChallengeMethodsSupported: []string{
			core.OIDCCodeChallengeMethodS256,
		},
		GrantTypesSupported: []string{
			core.OIDCGrantTypeAuthorizationCode,
			core.OIDCGrantTypeRefreshToken,
		},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
			"email", "email_verified", "name", "preferred_username", "picture",
		},
	}

	// Discovery is intentionally public: any RP must be able to fetch
	// it before establishing trust. Cache for 5 minutes — long enough
	// to absorb a burst of new RPs configuring, short enough that an
	// AuthDomain edit propagates without operator intervention.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("OIDCDiscovery: encode failed")
	}
}

// =====================
// OIDC /authorize
// =====================

// oidcAuthorizeError is the OIDC §3.1.2.6 redirect-style error: when
// client_id + redirect_uri are valid, the spec says to redirect back
// to the RP with ?error=...&error_description=...&state=.... When
// they're NOT valid, we must render an error page so an attacker
// can't trick the IdP into redirecting somewhere uncontrolled.
type oidcAuthorizeError struct {
	Code        string // standard OAuth error code, e.g. "invalid_request"
	Description string
}

// OIDCAuthorize is the entry point for the OIDC code flow. Validates
// the request against the app's OIDC config; if the user is already
// signed in (via cookie session, see auth_session.go), mints a code
// straight away. Otherwise stashes the request in oidc_pending_authorize
// and bounces the browser to a ManyRows-hosted AppKit login page that
// completes via /oidc/authorize/resume.
func (handler *RequestHandler) OIDCAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	cfg, err := handler.repo.GetAppOIDCConfig(ctx, app.ID)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("OIDCAuthorize: GetAppOIDCConfig failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if cfg == nil || !cfg.Enabled {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	// OIDC sign-in flow needs a session cookie at /authorize/resume;
	// local-mode apps don't set one. Admin-config validation rejects
	// this combination on enable, but defend at request time in case a
	// raw SQL edit (or future skipped-validation path) leaves the DB
	// inconsistent. Render an error page rather than redirect back —
	// this is operator misconfiguration, not RP-fixable, and we don't
	// want a confused user bouncing between IdP and RP.
	if !oidcTransportModeSupported(app) {
		log.Error().
			Str("app_id", app.ID.String()).
			Str("transport_mode", app.TransportMode).
			Msg("OIDCAuthorize: OIDC enabled on non-cookie-mode app — config drift")
		renderOIDCAuthorizePageError(w, "server_error", "OIDC is enabled on this app but transport_mode is not 'cookie'. The operator must switch the app to cookie transport mode before OIDC sign-in works.")
		return
	}

	q := r.URL.Query()
	clientID := strings.TrimSpace(q.Get("client_id"))
	redirectURI := strings.TrimSpace(q.Get("redirect_uri"))

	// Per OIDC §3.1.2.6: validate client_id + redirect_uri FIRST and
	// render an error page (not a redirect) if they don't match.
	// Anything else is a redirect-back-to-RP error.
	if clientID != app.ID.String() {
		renderOIDCAuthorizePageError(w, "invalid_client", "client_id does not match this app")
		return
	}
	if !redirectURIAllowed(redirectURI, cfg.RedirectURIs) {
		renderOIDCAuthorizePageError(w, "invalid_request", "redirect_uri is not registered for this app")
		return
	}

	params := core.OIDCAuthorizeParams{
		ResponseType:        strings.TrimSpace(q.Get("response_type")),
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               strings.TrimSpace(q.Get("scope")),
		State:               strings.TrimSpace(q.Get("state")),
		Nonce:               strings.TrimSpace(q.Get("nonce")),
		CodeChallenge:       strings.TrimSpace(q.Get("code_challenge")),
		CodeChallengeMethod: strings.TrimSpace(q.Get("code_challenge_method")),
	}

	if e := validateOIDCAuthorizeParams(params); e != nil {
		redirectOIDCAuthorizeError(w, r, redirectURI, params.State, *e)
		return
	}

	// Already signed in to this app? Skip the AppKit round-trip.
	ses, err := handler.clientAuthService.GetSession(r)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("OIDCAuthorize: GetSession failed")
		redirectOIDCAuthorizeError(w, r, redirectURI, params.State, oidcAuthorizeError{
			Code:        "server_error",
			Description: "session lookup failed",
		})
		return
	}
	if ses != nil && ses.AppID != nil && *ses.AppID == app.ID {
		handler.mintCodeAndRedirect(w, r, app, ses, params)
		return
	}

	// Not signed in — stash request and route the browser through AppKit.
	pendingID, err := handler.repo.CreateOIDCPendingAuthorize(ctx, app.ID, params)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("OIDCAuthorize: CreateOIDCPendingAuthorize failed")
		redirectOIDCAuthorizeError(w, r, redirectURI, params.State, oidcAuthorizeError{
			Code:        "server_error",
			Description: "could not start authorize",
		})
		return
	}
	loginURL := fmt.Sprintf("/x/%s/apps/%s/oidc/login?req=%s",
		url.PathEscape(ws.Slug), app.ID.String(), pendingID.String())
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// OIDCAuthorizeResume is hit by the browser after AppKit sign-in
// completes. Consumes the pending row, re-resolves the (now-existing)
// session, and mints a code.
func (handler *RequestHandler) OIDCAuthorizeResume(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if !oidcTransportModeSupported(app) {
		renderOIDCAuthorizePageError(w, "server_error", "OIDC requires the app to be in cookie transport mode.")
		return
	}

	reqStr := strings.TrimSpace(r.URL.Query().Get("req"))
	reqID, err := uuid.FromString(reqStr)
	if err != nil {
		renderOIDCAuthorizePageError(w, "invalid_request", "missing or malformed req parameter")
		return
	}

	_, params, found, err := handler.repo.ConsumeOIDCPendingAuthorize(ctx, reqID)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("OIDCAuthorizeResume: ConsumeOIDCPendingAuthorize failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !found || params == nil {
		renderOIDCAuthorizePageError(w, "invalid_request", "authorize request expired or already consumed")
		return
	}

	// Defence in depth: the params were validated at /authorize, but the
	// pending row could in principle outlive a redirect_uri config edit.
	cfg, cfgErr := handler.repo.GetAppOIDCConfig(ctx, app.ID)
	if cfgErr != nil || cfg == nil || !cfg.Enabled {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if !redirectURIAllowed(params.RedirectURI, cfg.RedirectURIs) {
		renderOIDCAuthorizePageError(w, "invalid_request", "redirect_uri no longer registered for this app")
		return
	}

	ses, err := handler.clientAuthService.GetSession(r)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("OIDCAuthorizeResume: GetSession failed")
		redirectOIDCAuthorizeError(w, r, params.RedirectURI, params.State, oidcAuthorizeError{
			Code:        "server_error",
			Description: "session lookup failed",
		})
		return
	}
	if ses == nil || ses.AppID == nil || *ses.AppID != app.ID {
		// Sign-in didn't establish a session we can see. Either the app
		// isn't in cookie transport mode (OIDC currently needs it; see
		// docs) or the user cancelled out of AppKit.
		redirectOIDCAuthorizeError(w, r, params.RedirectURI, params.State, oidcAuthorizeError{
			Code:        "access_denied",
			Description: "sign-in did not complete",
		})
		return
	}

	handler.mintCodeAndRedirect(w, r, app, ses, *params)
}

// mintCodeAndRedirect is the shared tail of /authorize and /resume:
// generate a single-use authorization code, persist its hashed form
// with the original PKCE challenge + nonce + redirect_uri + scope,
// and redirect the browser back to the RP.
func (handler *RequestHandler) mintCodeAndRedirect(w http.ResponseWriter, r *http.Request, app *core.App, ses *core.ClientSession, params core.OIDCAuthorizeParams) {
	ctx := r.Context()

	rawCode, err := newOIDCCode()
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("mintCodeAndRedirect: newOIDCCode failed")
		redirectOIDCAuthorizeError(w, r, params.RedirectURI, params.State, oidcAuthorizeError{
			Code:        "server_error",
			Description: "could not generate code",
		})
		return
	}

	sessionID := ses.ID
	now := time.Now().UTC()
	if err := handler.repo.CreateOIDCAuthCode(ctx, repo.CreateOIDCAuthCodeParams{
		CodeHash:            hashOIDCCode(rawCode),
		AppID:               app.ID,
		UserID:              ses.UserID,
		SessionID:           &sessionID,
		Nonce:               params.Nonce,
		RedirectURI:         params.RedirectURI,
		Scope:               params.Scope,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		ExpiresAt:           now.Add(repo.OIDCAuthCodeTTL),
	}); err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("mintCodeAndRedirect: CreateOIDCAuthCode failed")
		redirectOIDCAuthorizeError(w, r, params.RedirectURI, params.State, oidcAuthorizeError{
			Code:        "server_error",
			Description: "could not store code",
		})
		return
	}

	u, err := url.Parse(params.RedirectURI)
	if err != nil {
		// Validated at allowlist time but defensive against config
		// edits sneaking malformed URIs through.
		renderOIDCAuthorizePageError(w, "invalid_request", "redirect_uri is malformed")
		return
	}
	qry := u.Query()
	qry.Set("code", rawCode)
	if params.State != "" {
		qry.Set("state", params.State)
	}
	u.RawQuery = qry.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// =====================
// OIDC /login (AppKit shim host page)
// =====================

// OIDCLoginPage renders a minimal HTML page that mounts AppKit and
// wires its onLogin callback to navigate to /oidc/authorize/resume.
// All the actual sign-in logic (passkeys, MFA, OAuth providers, etc.)
// lives in AppKit unchanged — this page is just the host shim.
func (handler *RequestHandler) OIDCLoginPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	cfg, err := handler.repo.GetAppOIDCConfig(ctx, app.ID)
	if err != nil || cfg == nil || !cfg.Enabled {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	reqStr := strings.TrimSpace(r.URL.Query().Get("req"))
	reqID, err := uuid.FromString(reqStr)
	if err != nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	data := struct {
		WorkspaceSlug string
		AppID         string
		ResumeURL     string
	}{
		WorkspaceSlug: ws.Slug,
		AppID:         app.ID.String(),
		ResumeURL: fmt.Sprintf("/x/%s/apps/%s/oidc/authorize/resume?req=%s",
			url.PathEscape(ws.Slug), app.ID.String(), reqID.String()),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// Anti-clickjacking. The OIDC login page collects credentials —
	// MUST NOT be framable by any origin. Both modern (CSP) and legacy
	// (X-Frame-Options) headers, per OWASP guidance for IdP login UIs.
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	if err := oidcLoginTmpl.Execute(w, data); err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("OIDCLoginPage: template execute failed")
	}
}

// oidcLoginTmpl is the AppKit shim. Loads the existing /appkit/assets/
// bundle and calls window.ManyRows.AppKit.init with an onLogin handler
// that completes the OIDC flow by navigating to /oidc/authorize/resume.
// All input values come from server-controlled trusted sources (the
// app + workspace from path resolution, the pending UUID we minted),
// so JS injection is a non-issue — html/template still escapes them
// for defence in depth.
var oidcLoginTmpl = template.Must(template.New("oidc_login").Parse(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Sign in</title>
    <script type="module" crossorigin src="/appkit/assets/appkit.js"></script>
    <link rel="stylesheet" crossorigin href="/appkit/assets/appkit.css">
    <style>html,body,#root{height:100%;margin:0;background:transparent}</style>
  </head>
  <body>
    <div id="root"></div>
    <script>
      (function () {
        var resumeURL = {{ .ResumeURL | js }};
        var workspace = {{ .WorkspaceSlug | js }};
        var appId = {{ .AppID | js }};
        function boot() {
          if (!window.ManyRows || !window.ManyRows.AppKit) {
            return setTimeout(boot, 50);
          }
          window.ManyRows.AppKit.init({
            container: document.getElementById("root"),
            workspace: workspace,
            appId: appId,
            onLogin: function () {
              window.location.assign(resumeURL);
            },
          });
        }
        boot();
      })();
    </script>
  </body>
</html>`))

// =====================
// Helpers
// =====================

// validateOIDCAuthorizeParams enforces every requirement that can be
// signalled to the RP via the redirect-error path (i.e., not the
// client_id / redirect_uri checks, which must be rendered as a page).
func validateOIDCAuthorizeParams(p core.OIDCAuthorizeParams) *oidcAuthorizeError {
	if p.ResponseType != core.OIDCResponseTypeCode {
		return &oidcAuthorizeError{Code: "unsupported_response_type", Description: "only response_type=code is supported"}
	}
	if !scopeContainsOpenID(p.Scope) {
		return &oidcAuthorizeError{Code: "invalid_scope", Description: "scope must contain 'openid'"}
	}
	if p.CodeChallenge == "" {
		return &oidcAuthorizeError{Code: "invalid_request", Description: "code_challenge is required (PKCE)"}
	}
	if p.CodeChallengeMethod != core.OIDCCodeChallengeMethodS256 {
		return &oidcAuthorizeError{Code: "invalid_request", Description: "code_challenge_method must be S256"}
	}
	// S256 always produces a 43-char base64url-no-padding string from
	// the 32-byte SHA-256 output. Anything else is malformed — reject
	// early per RFC 7636 §4.2.
	if len(p.CodeChallenge) != 43 {
		return &oidcAuthorizeError{Code: "invalid_request", Description: "code_challenge must be a 43-char base64url SHA-256"}
	}
	return nil
}

// redirectURIAllowed returns true when uri is exact-match in the
// allowlist. No prefix / wildcard matching — exact match per OIDC
// best practice.
func redirectURIAllowed(uri string, allowlist []string) bool {
	if uri == "" {
		return false
	}
	for _, u := range allowlist {
		if u == uri {
			return true
		}
	}
	return false
}

// scopeContainsOpenID is a space-tokenised scope check for the
// mandatory "openid" value.
func scopeContainsOpenID(scope string) bool {
	for _, t := range strings.Fields(scope) {
		if t == core.OIDCScopeOpenID {
			return true
		}
	}
	return false
}

// redirectOIDCAuthorizeError sends the RP back to its redirect_uri
// with OAuth-error query params (the "valid client_id+redirect_uri"
// branch of OIDC §3.1.2.6).
func redirectOIDCAuthorizeError(w http.ResponseWriter, r *http.Request, redirectURI, state string, e oidcAuthorizeError) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		renderOIDCAuthorizePageError(w, e.Code, e.Description)
		return
	}
	q := u.Query()
	q.Set("error", e.Code)
	if e.Description != "" {
		q.Set("error_description", e.Description)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// renderOIDCAuthorizePageError serves a plain HTML error page —
// the "untrusted client_id / redirect_uri" branch of OIDC §3.1.2.6,
// or any failure where redirecting back to an unvalidated URL would
// itself be a vulnerability.
func renderOIDCAuthorizePageError(w http.ResponseWriter, code, description string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Anti-clickjacking — this page is part of the OIDC auth surface
	// and should not be framable.
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>Authorization error</title></head><body style="font-family:system-ui;padding:2rem"><h1>Authorization error</h1><p><strong>%s</strong></p><p>%s</p></body></html>`,
		template.HTMLEscapeString(code), template.HTMLEscapeString(description))
}

// oidcTransportModeSupported is the OIDC requires-cookie predicate.
// Centralised so /authorize and /authorize/resume agree.
func oidcTransportModeSupported(app *core.App) bool {
	return app != nil && app.TransportMode == core.TransportModeCookie
}

// newOIDCCode returns a 32-byte URL-safe random code (256 bits of
// entropy — well above the OIDC §16.18 recommendation of 128).
func newOIDCCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashOIDCCode is the SHA-256-hex hash used everywhere oidc_auth_codes
// is keyed. Constant-time-safe: the lookup is by primary key, not by
// equality comparison with a user-supplied value, so the timing
// channel is in btree lookup latency rather than byte comparison.
func hashOIDCCode(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// =====================
// OIDC /token
// =====================

// oidcTokenResponse is the standard token-endpoint JSON shape per
// OIDC §3.1.3.3. RefreshToken is set only when offline_access was
// granted; omitempty drops it from the wire for the (more common)
// non-offline case.
type oidcTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

// oidcTokenError writes an RFC 6749 §5.2 token error response — the
// only structured-error format the OIDC token endpoint speaks.
func oidcTokenError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	body := struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description,omitempty"`
	}{Error: code, ErrorDescription: description}
	_ = json.NewEncoder(w).Encode(body)
}

// OIDCToken handles POST /oidc/token. Supports authorization_code +
// refresh_token grants; rejects everything else with unsupported_grant_type.
func (handler *RequestHandler) OIDCToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		oidcTokenError(w, http.StatusNotFound, "invalid_request", "app not resolved")
		return
	}

	cfg, err := handler.repo.GetAppOIDCConfig(ctx, app.ID)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("OIDCToken: GetAppOIDCConfig failed")
		oidcTokenError(w, http.StatusInternalServerError, "server_error", "config lookup failed")
		return
	}
	if cfg == nil || !cfg.Enabled {
		oidcTokenError(w, http.StatusNotFound, "invalid_request", "OIDC not enabled for this app")
		return
	}

	if err := r.ParseForm(); err != nil {
		oidcTokenError(w, http.StatusBadRequest, "invalid_request", "could not parse form body")
		return
	}

	grantType := strings.TrimSpace(r.PostForm.Get("grant_type"))

	// Client auth — Basic header takes precedence over form body.
	clientID, clientSecret, gotBasic := r.BasicAuth()
	if !gotBasic {
		clientID = strings.TrimSpace(r.PostForm.Get("client_id"))
		clientSecret = strings.TrimSpace(r.PostForm.Get("client_secret"))
	}
	if clientID != app.ID.String() {
		oidcTokenError(w, http.StatusUnauthorized, "invalid_client", "client_id does not match this app")
		return
	}
	if !verifyOIDCClientAuth(cfg, clientSecret) {
		oidcTokenError(w, http.StatusUnauthorized, "invalid_client", "client credentials are not valid")
		return
	}

	switch grantType {
	case core.OIDCGrantTypeAuthorizationCode:
		handler.handleOIDCAuthorizationCodeGrant(w, r, app)
	case core.OIDCGrantTypeRefreshToken:
		handler.handleOIDCRefreshTokenGrant(w, r, app)
	default:
		oidcTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type is not supported")
	}
}

// handleOIDCAuthorizationCodeGrant exchanges a code for tokens. Atomic
// consume on the code row + PKCE verify + redirect_uri rebinding,
// followed by access/id/refresh mint.
func (handler *RequestHandler) handleOIDCAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, app *core.App) {
	ctx := r.Context()
	ws, _ := core.WorkspaceFromContext(ctx)

	rawCode := strings.TrimSpace(r.PostForm.Get("code"))
	redirectURI := strings.TrimSpace(r.PostForm.Get("redirect_uri"))
	codeVerifier := strings.TrimSpace(r.PostForm.Get("code_verifier"))

	if rawCode == "" {
		oidcTokenError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}
	codeHash := hashOIDCCode(rawCode)

	code, found, err := handler.repo.ConsumeOIDCAuthCode(ctx, codeHash)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("handleOIDCAuthorizationCodeGrant: ConsumeOIDCAuthCode failed")
		oidcTokenError(w, http.StatusInternalServerError, "server_error", "code lookup failed")
		return
	}
	if !found || code == nil {
		// Could be: never existed, expired, OR replayed. Per OIDC §3.1.3.2
		// the safe response when the latter is suspected is to revoke
		// all tokens minted from that code — defends against attackers
		// who stole both the code and the tokens it produced.
		userID, sessionID, used, lookupErr := handler.repo.LookupUsedOIDCAuthCodeUser(ctx, codeHash)
		if lookupErr != nil {
			log.Err(lookupErr).Str("app_id", app.ID.String()).Msg("handleOIDCAuthorizationCodeGrant: LookupUsedOIDCAuthCodeUser failed")
		}
		if used && userID != uuid.Nil && sessionID != nil {
			log.Warn().
				Str("app_id", app.ID.String()).
				Str("user_id", userID.String()).
				Str("session_id", sessionID.String()).
				Msg("OIDC token: replay of consumed authorization code — revoking session")
			_ = handler.clientAuthService.RevokeAllSessionTokens(ctx, *sessionID)
		}
		oidcTokenError(w, http.StatusBadRequest, "invalid_grant", "code is invalid, expired, or already used")
		return
	}

	if code.AppID != app.ID {
		oidcTokenError(w, http.StatusBadRequest, "invalid_grant", "code does not belong to this app")
		return
	}
	if code.RedirectURI != redirectURI {
		oidcTokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the one used at /authorize")
		return
	}
	if !verifyPKCE(codeVerifier, code.CodeChallenge) {
		oidcTokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	// Re-fetch session (it could have been revoked between /authorize and now).
	if code.SessionID == nil {
		oidcTokenError(w, http.StatusBadRequest, "invalid_grant", "code has no session binding")
		return
	}
	ses, err := handler.repo.GetClientSessionByID(ctx, *code.SessionID)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("handleOIDCAuthorizationCodeGrant: GetClientSessionByID failed")
		oidcTokenError(w, http.StatusInternalServerError, "server_error", "session lookup failed")
		return
	}
	if ses == nil || !ses.IsActive(time.Now().UTC()) {
		oidcTokenError(w, http.StatusBadRequest, "invalid_grant", "session is no longer active")
		return
	}
	// Defence in depth: the code carries user_id (the subject at mint
	// time), the session carries user_id (the live binding). They MUST
	// agree — a divergence would mean issuing tokens whose access vs id
	// token subs disagree. Impossible today (sessions don't switch
	// users) but cheap to verify.
	if ses.UserID != code.UserID {
		log.Warn().
			Str("app_id", app.ID.String()).
			Str("code_user_id", code.UserID.String()).
			Str("session_user_id", ses.UserID.String()).
			Msg("OIDC token: session/code user mismatch — rejecting")
		oidcTokenError(w, http.StatusBadRequest, "invalid_grant", "session does not match code")
		return
	}

	user, err := handler.repo.GetUserByID(ctx, code.UserID)
	if err != nil || user == nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("handleOIDCAuthorizationCodeGrant: GetUserByID failed")
		oidcTokenError(w, http.StatusInternalServerError, "server_error", "user lookup failed")
		return
	}

	// Two issuer URLs:
	//   - access_token iss = AppBaseURL (host-only). Keeps OIDC-issued
	//     access tokens verifiable by existing customer backends that
	//     check iss against AppBaseURL (matches the SDK's iss).
	//   - id_token iss = AppOIDCIssuer (per-app path). MUST match the
	//     discovery doc's issuer per OIDC §3.1.3.7.
	atIssuer := handler.AppBaseURL(app)
	idIssuer := handler.AppOIDCIssuer(ws, app)
	if atIssuer == "" || idIssuer == "" {
		oidcTokenError(w, http.StatusInternalServerError, "server_error", "issuer not configured")
		return
	}

	handler.issueOIDCTokenSet(ctx, w, r, app, ses, user, atIssuer, idIssuer, code.Scope, code.Nonce, true)
}

// handleOIDCRefreshTokenGrant rotates the refresh-token chain and
// re-issues an id_token alongside. Reuses the existing RefreshTokenPair
// machinery so all the DPoP / rotation / grace-window logic carries
// over unchanged.
func (handler *RequestHandler) handleOIDCRefreshTokenGrant(w http.ResponseWriter, r *http.Request, app *core.App) {
	ctx := r.Context()
	ws, _ := core.WorkspaceFromContext(ctx)

	refreshTokenStr := strings.TrimSpace(r.PostForm.Get("refresh_token"))
	if refreshTokenStr == "" {
		oidcTokenError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	// scope is OPTIONAL on a refresh grant per OIDC. When absent, the
	// original grant's scope is reused. We track scope via the session
	// in v1 — coarse-grained — so the simplest correct behaviour is to
	// echo the requested scope when present, defaulting to "openid email".
	scope := strings.TrimSpace(r.PostForm.Get("scope"))
	if scope == "" {
		scope = core.OIDCScopeOpenID + " " + core.OIDCScopeEmail
	}

	atIssuer := handler.AppBaseURL(app)
	idIssuer := handler.AppOIDCIssuer(ws, app)
	if atIssuer == "" || idIssuer == "" {
		oidcTokenError(w, http.StatusInternalServerError, "server_error", "issuer not configured")
		return
	}

	// Resolve the refresh token to its session for the id_token claim
	// set before the rotate.
	rt, err := handler.repo.GetClientRefreshTokenByHash(ctx, hashTokenForRefresh(refreshTokenStr))
	if err != nil || rt == nil {
		oidcTokenError(w, http.StatusBadRequest, "invalid_grant", "refresh_token is invalid")
		return
	}
	ses, err := handler.repo.GetClientSessionByID(ctx, rt.SessionID)
	if err != nil || ses == nil {
		oidcTokenError(w, http.StatusBadRequest, "invalid_grant", "session is no longer active")
		return
	}
	if ses.AppID == nil || *ses.AppID != app.ID {
		oidcTokenError(w, http.StatusBadRequest, "invalid_grant", "refresh_token does not belong to this app")
		return
	}
	user, err := handler.repo.GetUserByID(ctx, ses.UserID)
	if err != nil || user == nil {
		oidcTokenError(w, http.StatusInternalServerError, "server_error", "user lookup failed")
		return
	}

	// Now do the actual rotation via the existing pair-issuance path.
	// Access token uses host-only iss for SDK compatibility.
	pair, err := handler.clientAuthService.RefreshTokenPair(
		ctx, refreshTokenStr, app.ID,
		r.UserAgent(), strings.TrimSpace(r.Header.Get("X-Forwarded-For")),
		ttlFromAppMinutes(app.SessionTTLMinutes),
		ttlFromAppMinutes(app.AccessTokenTTLMinutes),
		ttlFromAppMinutes(app.IdleTimeoutMinutes),
		ttlFromAppMinutes(app.RememberMeTTLMinutes),
		"", // DPoP not currently flowed through OIDC
		atIssuer,
	)
	if err != nil {
		oidcTokenError(w, http.StatusBadRequest, "invalid_grant", "refresh failed")
		return
	}

	// id_token does NOT echo a nonce on the refresh grant per OIDC §12.
	// Uses per-app-path iss to match discovery.
	idClaims := buildIDTokenClaimSet(idIssuer, app, ses, user, scope, "")
	idToken, _, err := handler.clientAuthService.IssueIDToken(idClaims)
	if err != nil {
		oidcTokenError(w, http.StatusInternalServerError, "server_error", "id_token issuance failed")
		return
	}

	writeOIDCTokenResponse(w, oidcTokenResponse{
		AccessToken:  pair.AccessToken,
		IDToken:      idToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    pair.ExpiresIn,
		Scope:        scope,
	})
}

// issueOIDCTokenSet mints access + id (+ refresh, when offline_access)
// for the authorization-code grant. atIssuer is the iss for the
// access token (host-only, SDK-compatible); idIssuer is the iss for
// the id_token (per-app path, matches discovery).
func (handler *RequestHandler) issueOIDCTokenSet(ctx context.Context, w http.ResponseWriter, r *http.Request, app *core.App, ses *core.ClientSession, user *core.User, atIssuer, idIssuer, scope, nonce string, mayIssueRefresh bool) {
	accessToken, expiresAt, err := handler.clientAuthService.IssueAccessToken(ses, ttlFromAppMinutes(app.AccessTokenTTLMinutes), atIssuer)
	if err != nil {
		oidcTokenError(w, http.StatusInternalServerError, "server_error", "access_token issuance failed")
		return
	}

	idClaims := buildIDTokenClaimSet(idIssuer, app, ses, user, scope, nonce)
	idToken, _, err := handler.clientAuthService.IssueIDToken(idClaims)
	if err != nil {
		oidcTokenError(w, http.StatusInternalServerError, "server_error", "id_token issuance failed")
		return
	}

	// Clamp expires_in to >= 0. time.Until can go negative under clock
	// skew or if expiresAt was already past at mint time — RPs expect
	// a non-negative integer.
	expiresIn := int(time.Until(expiresAt).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}
	resp := oidcTokenResponse{
		AccessToken: accessToken,
		IDToken:     idToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		Scope:       scope,
	}

	if mayIssueRefresh && scopeContainsOfflineAccess(scope) {
		refreshToken, _, err := handler.clientAuthService.IssueRefreshToken(
			ctx,
			ses.ID,
			r.UserAgent(),
			strings.TrimSpace(r.Header.Get("X-Forwarded-For")),
			ttlFromAppMinutes(app.SessionTTLMinutes),
			"",
		)
		if err == nil {
			resp.RefreshToken = refreshToken
		}
	}

	writeOIDCTokenResponse(w, resp)
}

// =====================
// Helpers for the token endpoint
// =====================

// verifyOIDCClientAuth implements the dual confidential/public model:
// confidential clients (those with a stored secret hash) must present
// the matching secret; public clients (no hash stored) must NOT present
// any secret. PKCE is required regardless and is verified separately.
func verifyOIDCClientAuth(cfg *core.OIDCAppConfig, presented string) bool {
	if cfg == nil {
		return false
	}
	if !cfg.HasClientSecret() {
		// Public client. Must NOT present a secret — that mismatch
		// catches misconfigured clients early.
		return presented == ""
	}
	if presented == "" {
		return false
	}
	sum := sha256.Sum256([]byte(presented))
	presentedHash := hex.EncodeToString(sum[:])
	return subtle_ConstantTimeCompare(presentedHash, *cfg.ClientSecretHash)
}

// verifyPKCE checks base64url_nopad(SHA256(code_verifier)) == challenge.
// Enforces RFC 7636 §4.1: code_verifier MUST be 43–128 characters from
// the unreserved set. Short verifiers are rejected before hashing so
// a low-entropy verifier can never match by chance even if the rest
// of the system somehow accepted a short challenge.
func verifyPKCE(verifier, challenge string) bool {
	if challenge == "" {
		return false
	}
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle_ConstantTimeCompare(computed, challenge)
}

// subtle_ConstantTimeCompare is a thin wrapper that compares two strings
// in constant time. Avoids pulling crypto/subtle into a third place.
func subtle_ConstantTimeCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// buildIDTokenClaimSet assembles the OIDC id_token claim set,
// filtering scope-gated claims (email / profile) per the granted
// scope value. ManyRows' user model doesn't currently store a name
// field (only email + verification timestamp), so profile-scope
// populates preferred_username from the email local part and leaves
// name / picture empty — both are spec-optional and absent rather
// than wrong.
func buildIDTokenClaimSet(issuer string, app *core.App, ses *core.ClientSession, user *core.User, scope, nonce string) client.IDTokenClaimSet {
	claims := client.IDTokenClaimSet{
		Issuer:   issuer,
		Audience: app.ID.String(),
		Subject:  user.ID,
		AuthTime: ses.CreatedAt,
		Nonce:    nonce,
	}
	if scopeContainsEmail(scope) {
		claims.HasEmail = true
		claims.Email = user.Email
		claims.EmailVerified = user.EmailVerifiedAt != nil
	}
	if scopeContainsProfile(scope) {
		if i := strings.IndexByte(user.Email, '@'); i > 0 {
			claims.PreferredUsername = user.Email[:i]
		}
	}
	return claims
}

// scopeContainsOfflineAccess is the scope-gate for issuing a refresh
// token on the authorization_code grant.
func scopeContainsOfflineAccess(scope string) bool {
	for _, t := range strings.Fields(scope) {
		if t == core.OIDCScopeOfflineAccess {
			return true
		}
	}
	return false
}

// scopeContainsEmail / scopeContainsProfile govern email + profile
// claim inclusion on the id_token / userinfo.
func scopeContainsEmail(scope string) bool {
	for _, t := range strings.Fields(scope) {
		if t == core.OIDCScopeEmail {
			return true
		}
	}
	return false
}

func scopeContainsProfile(scope string) bool {
	for _, t := range strings.Fields(scope) {
		if t == core.OIDCScopeProfile {
			return true
		}
	}
	return false
}

// ttlFromAppMinutes converts an *int minutes pointer to a time.Duration,
// returning 0 (caller default) for nil or non-positive values.
func ttlFromAppMinutes(m *int) time.Duration {
	if m == nil || *m <= 0 {
		return 0
	}
	return time.Duration(*m) * time.Minute
}

// hashTokenForRefresh mirrors auth/client/auth_tokens.go:hashToken so
// the refresh-token grant can resolve a token to its row without
// exporting the (lowercase) hashToken helper there.
func hashTokenForRefresh(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// writeOIDCTokenResponse writes the standard token response with the
// cache headers the spec requires.
func writeOIDCTokenResponse(w http.ResponseWriter, resp oidcTokenResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}

// =====================
// OIDC /userinfo
// =====================

// oidcUserInfoResponse is the JSON claim bag returned at /userinfo.
// Fields are scope-gated; v1 returns the full set when the token is
// valid (scope filtering at /userinfo is RECOMMENDED but not strictly
// required by OIDC §5.3 — a v2 enhancement is to thread the granted
// scope through the access_token claims and filter here).
type oidcUserInfoResponse struct {
	Sub               string `json:"sub"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
}

// OIDCUserInfo handles GET/POST /oidc/userinfo. Validates the bearer
// access_token and returns the user's claims. Per OIDC §5.3 the bound
// www-authenticate header lists the realm + error class on failure.
func (handler *RequestHandler) OIDCUserInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		writeOIDCBearerError(w, "invalid_token", "app not resolved")
		return
	}

	// GetSession parses + verifies the JWT, checks aud-binding against
	// the app in context, and loads the corresponding session. The
	// returned session is nil for any invalid/expired/wrong-app case,
	// which collapses to a single 401 with no information leak.
	ses, err := handler.clientAuthService.GetSession(r)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("OIDCUserInfo: GetSession failed")
		writeOIDCBearerError(w, "invalid_token", "session lookup failed")
		return
	}
	if ses == nil || ses.AppID == nil || *ses.AppID != app.ID {
		writeOIDCBearerError(w, "invalid_token", "access token is invalid or expired")
		return
	}

	user, err := handler.repo.GetUserByID(ctx, ses.UserID)
	if err != nil || user == nil {
		writeOIDCBearerError(w, "invalid_token", "user not found")
		return
	}

	resp := oidcUserInfoResponse{Sub: user.ID.String(), Email: user.Email}
	if user.EmailVerifiedAt != nil {
		resp.EmailVerified = true
	}
	if i := strings.IndexByte(user.Email, '@'); i > 0 {
		resp.PreferredUsername = user.Email[:i]
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}

// writeOIDCBearerError emits the WWW-Authenticate header form that
// RFC 6750 §3 mandates for bearer-token failures at /userinfo.
func writeOIDCBearerError(w http.ResponseWriter, code, description string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s", error_description="%s"`, code, description))
	w.WriteHeader(http.StatusUnauthorized)
}

// =====================
// OIDC /end-session
// =====================

// OIDCEndSession is the RP-initiated logout endpoint per OIDC Session
// Management 1.0 §5. Revokes the session if present and redirects to
// post_logout_redirect_uri when supplied and allowlisted; otherwise
// renders a minimal "signed out" page.
//
// id_token_hint is accepted per spec but treated as advisory — the
// cookie-bound session is the authoritative target of revocation, and
// the id_token signature/aud are verified via GetSession via the
// access cookie that brought us here.
func (handler *RequestHandler) OIDCEndSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ws, _ := core.WorkspaceFromContext(ctx)
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	cfg, err := handler.repo.GetAppOIDCConfig(ctx, app.ID)
	if err != nil || cfg == nil || !cfg.Enabled {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	q := r.URL.Query()
	postLogout := strings.TrimSpace(q.Get("post_logout_redirect_uri"))
	state := strings.TrimSpace(q.Get("state"))

	// post_logout_redirect_uri is OPTIONAL but when present must be
	// allowlisted — same exact-match policy as redirect_uris.
	if postLogout != "" && !redirectURIAllowed(postLogout, cfg.PostLogoutRedirectURIs) {
		renderOIDCAuthorizePageError(w, "invalid_request", "post_logout_redirect_uri is not registered for this app")
		return
	}

	// Resolve the session via the access cookie / bearer (best effort —
	// a missing session means the user is already signed out at this
	// IdP, which is a no-op for the logout endpoint).
	if ses, sesErr := handler.clientAuthService.GetSession(r); sesErr == nil && ses != nil && ses.AppID != nil && *ses.AppID == app.ID {
		if revokeErr := handler.clientAuthService.RevokeAllSessionTokens(ctx, ses.ID); revokeErr != nil {
			log.Err(revokeErr).Str("session_id", ses.ID.String()).Msg("OIDCEndSession: RevokeAllSessionTokens failed")
		}
		if delErr := handler.clientAuthService.DeleteSession(ctx, ses.ID); delErr != nil {
			log.Err(delErr).Str("session_id", ses.ID.String()).Msg("OIDCEndSession: DeleteSession failed")
		}
		// Use the shared helper so the clear-cookie attributes (Domain,
		// Secure, SameSite) MATCH what setSessionCookies wrote — otherwise
		// the browser keeps the stale cookie in its jar.
		handler.clearSessionCookies(w, ws, app)
	}

	if postLogout != "" {
		u, parseErr := url.Parse(postLogout)
		if parseErr != nil {
			renderOIDCAuthorizePageError(w, "invalid_request", "post_logout_redirect_uri is malformed")
			return
		}
		if state != "" {
			qry := u.Query()
			qry.Set("state", state)
			u.RawQuery = qry.Encode()
		}
		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	}

	// No post_logout_redirect_uri supplied — render a minimal page.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><title>Signed out</title></head><body style="font-family:system-ui;padding:2rem"><h1>Signed out</h1><p>You have been signed out.</p></body></html>`))
}

