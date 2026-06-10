package api

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// =====================
// Consent helpers
// =====================

// consentNeeded decides whether the consent screen interposes. prompt=
// consent always forces; otherwise the per-app toggle gates, satisfied by
// a remembered grant covering every requested scope token.
func consentNeeded(cfg *core.OIDCAppConfig, prompts []string, grantScope string, grantFound bool, requestedScope string) bool {
	for _, p := range prompts {
		if p == "consent" {
			return true
		}
	}
	if cfg == nil || !cfg.RequireConsent {
		return false
	}
	return !(grantFound && scopeCovered(grantScope, requestedScope))
}

// scopeCovered reports whether every token of requested is in granted.
func scopeCovered(granted, requested string) bool {
	have := make(map[string]bool)
	for _, t := range strings.Fields(granted) {
		have[t] = true
	}
	for _, t := range strings.Fields(requested) {
		if !have[t] {
			return false
		}
	}
	return true
}

// consentScopeDescriptions maps scope tokens to user-facing bullets;
// unknown tokens render verbatim (defensive — the authorize validator
// constrains scopes upstream).
func consentScopeDescriptions(scope string) []string {
	out := []string{}
	for _, t := range strings.Fields(scope) {
		switch t {
		case core.OIDCScopeOpenID:
			out = append(out, "Confirm your identity")
		case core.OIDCScopeEmail:
			out = append(out, "View your email address")
		case core.OIDCScopeProfile:
			out = append(out, "View your basic profile info")
		case core.OIDCScopeOfflineAccess:
			out = append(out, "Keep access while you're away")
		default:
			out = append(out, t)
		}
	}
	return out
}

// oidcConsentTmpl is the minimal consent screen. Centered card, app name
// heading, scope bullet list, two submit buttons. No JS.
var oidcConsentTmpl = template.Must(template.New("oidc_consent").Parse(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Authorize access</title>
    <style>
      html,body{height:100%;margin:0;background:#f5f5f5;font-family:system-ui,sans-serif}
      .card{max-width:400px;margin:4rem auto;background:#fff;border-radius:8px;
            box-shadow:0 2px 8px rgba(0,0,0,.12);padding:2rem}
      h1{font-size:1.25rem;margin:0 0 .25rem}
      .app-name{font-weight:600}
      ul{margin:.75rem 0 1.5rem;padding-left:1.25rem}
      li{margin:.3rem 0}
      .actions{display:flex;gap:.75rem}
      button{flex:1;padding:.65rem 1rem;border:none;border-radius:6px;
             font-size:.95rem;cursor:pointer}
      .allow{background:#2563eb;color:#fff}
      .allow:hover{background:#1d4ed8}
      .deny{background:#f3f4f6;color:#374151;border:1px solid #d1d5db}
      .deny:hover{background:#e5e7eb}
    </style>
  </head>
  <body>
    <div class="card">
      <h1><span class="app-name">{{.AppName}}</span> wants to:</h1>
      <ul>
        {{range .Scopes}}<li>{{.}}</li>{{end}}
      </ul>
      <form method="post" action="{{.ConsentPath}}">
        <input type="hidden" name="req" value="{{.ReqID}}" />
        <div class="actions">
          <button type="submit" name="decision" value="allow" class="allow">Allow</button>
          <button type="submit" name="decision" value="deny"  class="deny">Cancel</button>
        </div>
      </form>
    </div>
  </body>
</html>`))

// =====================
// OIDCConsentPage — GET /oidc/consent
// =====================

// OIDCConsentPage renders the consent screen for a pending /authorize request.
// Same cookie-mode/app/session validation chain as OIDCAuthorizeResume; reads
// the pending row non-destructively via PeekOIDCPendingAuthorize.
func (handler *RequestHandler) OIDCConsentPage(w http.ResponseWriter, r *http.Request) {
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
	if !oidcTransportModeSupported(app) {
		renderOIDCAuthorizePageError(w, "server_error", "OIDC requires the app to be in cookie transport mode.")
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
		renderOIDCAuthorizePageError(w, "invalid_request", "missing or malformed req parameter")
		return
	}

	// Require a valid session before touching the pending row — an
	// unauthenticated caller must not be able to probe req-id liveness.
	ses, err := handler.clientAuthService.GetSession(r)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("OIDCConsentPage: GetSession failed")
		renderOIDCAuthorizePageError(w, "server_error", "session lookup failed")
		return
	}
	if ses == nil || ses.AppID == nil || *ses.AppID != app.ID {
		renderOIDCAuthorizePageError(w, "login_required", "no active session for this app")
		return
	}

	// Non-destructive read — the POST will consume. A row minted for a
	// different app is treated exactly like a dead one (no oracle).
	p, params, found, err := handler.repo.PeekOIDCPendingAuthorize(ctx, reqID)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("OIDCConsentPage: PeekOIDCPendingAuthorize failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !found || params == nil || p == nil || p.AppID != app.ID {
		renderOIDCAuthorizePageError(w, "invalid_request", "consent request expired or already handled")
		return
	}

	consentPath := fmt.Sprintf("/x/%s/apps/%s/oidc/consent",
		url.PathEscape(ws.Slug), app.ID.String())

	data := struct {
		AppName     string
		Scopes      []string
		ConsentPath template.URL
		ReqID       string
	}{
		AppName:     app.DisplayName(),
		Scopes:      consentScopeDescriptions(params.Scope),
		ConsentPath: template.URL(consentPath), // #nosec G203 — server-constructed path, no user input
		ReqID:       reqID.String(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	if err := oidcConsentTmpl.Execute(w, data); err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("OIDCConsentPage: template execute failed")
	}
}

// =====================
// OIDCConsentDecision — POST /oidc/consent
// =====================

// OIDCConsentDecision handles the form submission from OIDCConsentPage.
// Consumes the pending row (single-use); on allow it persists the grant and
// mints a code; on deny it redirects with access_denied.
func (handler *RequestHandler) OIDCConsentDecision(w http.ResponseWriter, r *http.Request) {
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

	cfg, err := handler.repo.GetAppOIDCConfig(ctx, app.ID)
	if err != nil || cfg == nil || !cfg.Enabled {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		renderOIDCAuthorizePageError(w, "invalid_request", "could not parse form body")
		return
	}

	reqStr := strings.TrimSpace(r.PostForm.Get("req"))
	reqID, err := uuid.FromString(reqStr)
	if err != nil {
		renderOIDCAuthorizePageError(w, "invalid_request", "missing or malformed req parameter")
		return
	}
	decision := strings.TrimSpace(r.PostForm.Get("decision"))

	// Require a valid session.
	ses, err := handler.clientAuthService.GetSession(r)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("OIDCConsentDecision: GetSession failed")
		renderOIDCAuthorizePageError(w, "server_error", "session lookup failed")
		return
	}
	if ses == nil || ses.AppID == nil || *ses.AppID != app.ID {
		renderOIDCAuthorizePageError(w, "login_required", "no active session for this app")
		return
	}

	// Consume the pending row (single-use). A row minted for a different
	// app is treated exactly like a dead one (no oracle).
	p, params, found, err := handler.repo.ConsumeOIDCPendingAuthorize(ctx, reqID)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("OIDCConsentDecision: ConsumeOIDCPendingAuthorize failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !found || params == nil || p == nil || p.AppID != app.ID {
		renderOIDCAuthorizePageError(w, "invalid_request", "consent request expired or already handled")
		return
	}

	// Defence in depth: re-validate redirect_uri (config may have changed).
	if !redirectURIAllowed(params.RedirectURI, cfg.RedirectURIs) {
		renderOIDCAuthorizePageError(w, "invalid_request", "redirect_uri no longer registered for this app")
		return
	}

	if decision != "allow" {
		redirectOIDCAuthorizeError(w, r, params.RedirectURI, params.State, oidcAuthorizeError{
			Code:        "access_denied",
			Description: "user denied consent",
		})
		return
	}

	// Persist the grant (union with any existing).
	if err := handler.repo.UpsertOIDCConsent(ctx, ses.UserID, app.ID, params.Scope); err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("OIDCConsentDecision: UpsertOIDCConsent failed")
		redirectOIDCAuthorizeError(w, r, params.RedirectURI, params.State, oidcAuthorizeError{
			Code:        "server_error",
			Description: "could not record consent",
		})
		return
	}

	handler.mintCodeAndRedirect(w, r, app, ses, *params)
}
