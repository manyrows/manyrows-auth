package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

// =====================
// Admin: OIDC provider config
// =====================
//
// Per-app OIDC config endpoint matching the Google/Apple/Microsoft/GitHub
// handler pattern. The OIDC surface is configured here; the protocol
// itself runs out of oidcHandler.go. Together: this writes the per-app
// row in apps + oidc_redirect_uris etc.; oidcHandler.go reads it.

// updateAppOIDCConfigRequest is the JSON body shape. RedirectURIs and
// PostLogoutRedirectURIs use plain []string with tri-state semantics:
// nil (field absent in JSON) = keep current; empty (`[]`) = clear;
// non-empty = replace.
//
// RegenerateSecret mints a fresh client_secret server-side and returns
// the raw value once in the response (matches the api-keys "shown
// once" UX). ClearSecret downgrades the app to a public client by
// removing the stored hash. The two flags are mutually exclusive.
type updateAppOIDCConfigRequest struct {
	Enabled                *bool    `json:"enabled,omitempty"`
	RedirectURIs           []string `json:"redirectUris,omitempty"`
	PostLogoutRedirectURIs []string `json:"postLogoutRedirectUris,omitempty"`
	RegenerateSecret       bool     `json:"regenerateSecret,omitempty"`
	ClearSecret            bool     `json:"clearSecret,omitempty"`
	RequireConsent         *bool    `json:"requireConsent,omitempty"`
}

// adminAppOIDCResponse extends adminAppResponse with OIDC config so a
// single response carries everything the admin UI needs to render the
// "OIDC Provider" panel. OIDCClientSecret is the raw value returned
// ONLY on RegenerateSecret — every other read returns
// HasOIDCClientSecret=true/false without revealing the secret.
type adminAppOIDCResponse struct {
	adminAppResponse
	OIDCEnabled                bool     `json:"oidcEnabled"`
	HasOIDCClientSecret        bool     `json:"hasOIDCClientSecret"`
	OIDCClientSecret           string   `json:"oidcClientSecret,omitempty"`
	OIDCClientID               string   `json:"oidcClientId"`
	OIDCIssuerURL              string   `json:"oidcIssuerUrl"`
	OIDCDiscoveryURL           string   `json:"oidcDiscoveryUrl"`
	OIDCRedirectURIs           []string `json:"oidcRedirectUris"`
	OIDCPostLogoutRedirectURIs []string `json:"oidcPostLogoutRedirectUris"`
	OIDCRequireConsent         bool     `json:"oidcRequireConsent"`
}

// HandleUpdateAppOIDCConfig is PUT /admin/.../projects/{pid}/apps/{appId}/oidc-config.
// Whole-config replace; nil-slice means "no change" so the admin can
// toggle enable without re-sending the URI lists. Regenerating the
// secret is opt-in (RegenerateSecret=true) so a config-only update
// doesn't accidentally invalidate working integrations.
func (handler *RequestHandler) HandleUpdateAppOIDCConfig(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	projectID, appID, ok := handler.resolvePathIDs(w, r)
	if !ok {
		return
	}

	var req updateAppOIDCConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("HandleUpdateAppOIDCConfig: decode failed")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	if req.RegenerateSecret && req.ClearSecret {
		WriteError(w, r, "error.invalidRequest", http.StatusBadRequest)
		return
	}

	curApp, err := handler.repo.GetAppByIDForProject(r.Context(), ws.ID, projectID, appID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("HandleUpdateAppOIDCConfig: load app failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	curCfg, err := handler.repo.GetAppOIDCConfig(r.Context(), appID)
	if err != nil {
		log.Err(err).Msg("HandleUpdateAppOIDCConfig: load oidc config failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	enabled := curCfg.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	redirects := curCfg.RedirectURIs
	if req.RedirectURIs != nil {
		redirects = req.RedirectURIs
	}
	postLogout := curCfg.PostLogoutRedirectURIs
	if req.PostLogoutRedirectURIs != nil {
		postLogout = req.PostLogoutRedirectURIs
	}
	requireConsent := curCfg.RequireConsent
	if req.RequireConsent != nil {
		requireConsent = *req.RequireConsent
	}

	// Enabling OIDC with no redirect URIs leaves the app unusable.
	// Catch it here rather than letting the customer find out at
	// /authorize time. Same shape as the Google "client_id required
	// when enabled" guard.
	if enabled && len(redirects) == 0 {
		WriteError(w, r, "error.oidcRedirectUrisRequired", http.StatusBadRequest)
		return
	}

	// Generate-once secret if requested. The raw value is returned in
	// the response and never persisted; only the SHA-256 hash hits
	// the DB (matches api_keys + verifyOIDCClientAuth in oidcHandler.go).
	var rawSecret string
	params := repo.UpdateAppOIDCConfigParams{
		Enabled:                enabled,
		RedirectURIs:           redirects,
		PostLogoutRedirectURIs: postLogout,
		RequireConsent:         requireConsent,
	}
	switch {
	case req.RegenerateSecret:
		rawBytes := make([]byte, 32)
		if _, randErr := rand.Read(rawBytes); randErr != nil {
			log.Err(randErr).Msg("HandleUpdateAppOIDCConfig: secret gen failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		rawSecret = base64.RawURLEncoding.EncodeToString(rawBytes)
		sum := sha256.Sum256([]byte(rawSecret))
		hashHex := hex.EncodeToString(sum[:])
		params.ClientSecretHash = &hashHex
	case req.ClearSecret:
		empty := ""
		params.ClientSecretHash = &empty
	}

	if updateErr := handler.repo.UpdateAppOIDCConfig(r.Context(), appID, params); updateErr != nil {
		switch {
		case errors.Is(updateErr, repo.ErrOIDCRequiresCookieTransport):
			// Targeted error so the UI can render a "switch to cookie
			// transport mode first" hint rather than a generic failure.
			WriteError(w, r, "error.oidcRequiresCookieTransport", http.StatusBadRequest)
			return
		case errors.Is(updateErr, repo.ErrNotFound):
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		default:
			log.Err(updateErr).Msg("HandleUpdateAppOIDCConfig: update failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
	}

	// Re-read the row that now has the OIDC fields applied (for the
	// "after" state in the response). Doing the second SELECT keeps
	// the path simple — alternative would be threading the result
	// through UpdateAppOIDCConfig.
	newCfg, err := handler.repo.GetAppOIDCConfig(r.Context(), appID)
	if err != nil {
		log.Err(err).Msg("HandleUpdateAppOIDCConfig: re-load oidc config failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	resp := handler.buildAdminAppOIDCResponse(curApp, ws, newCfg, rawSecret)
	utils.WriteJsonWithStatusCode(w, resp, http.StatusOK)
}

// HandleGetAppOIDCConfig is GET /admin/.../projects/{pid}/apps/{appId}/oidc-config.
// Returns the same shape as the update endpoint (sans raw secret) so
// the admin UI can fetch the current config and prefill the form.
func (handler *RequestHandler) HandleGetAppOIDCConfig(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	projectID, appID, ok := handler.resolvePathIDs(w, r)
	if !ok {
		return
	}

	app, err := handler.repo.GetAppByIDForProject(r.Context(), ws.ID, projectID, appID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("HandleGetAppOIDCConfig: load app failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	cfg, err := handler.repo.GetAppOIDCConfig(r.Context(), appID)
	if err != nil {
		log.Err(err).Msg("HandleGetAppOIDCConfig: load oidc config failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	resp := handler.buildAdminAppOIDCResponse(app, ws, cfg, "")
	utils.WriteJsonWithStatusCode(w, resp, http.StatusOK)
}

// buildAdminAppOIDCResponse composes the admin response with OIDC
// fields. rawSecret is non-empty only on RegenerateSecret responses;
// every other path emits it omitempty-suppressed.
func (handler *RequestHandler) buildAdminAppOIDCResponse(app core.App, ws *core.Workspace, cfg *core.OIDCAppConfig, rawSecret string) adminAppOIDCResponse {
	base := handler.toAdminAppResponse(app, ws)

	issuer := handler.AppOIDCIssuer(ws, &app)
	resp := adminAppOIDCResponse{
		adminAppResponse:           base,
		OIDCEnabled:                cfg.Enabled,
		HasOIDCClientSecret:        cfg.HasClientSecret(),
		OIDCClientID:               app.ID.String(),
		OIDCIssuerURL:              issuer,
		OIDCRedirectURIs:           cfg.RedirectURIs,
		OIDCPostLogoutRedirectURIs: cfg.PostLogoutRedirectURIs,
		OIDCRequireConsent:         cfg.RequireConsent,
	}
	if issuer != "" {
		resp.OIDCDiscoveryURL = issuer + "/.well-known/openid-configuration"
	}
	if rawSecret != "" {
		resp.OIDCClientSecret = rawSecret
	}
	// Normalise nil slices to empty so the JSON shape is stable for
	// the UI (`[]` rather than `null`).
	if resp.OIDCRedirectURIs == nil {
		resp.OIDCRedirectURIs = []string{}
	}
	if resp.OIDCPostLogoutRedirectURIs == nil {
		resp.OIDCPostLogoutRedirectURIs = []string{}
	}
	return resp
}
