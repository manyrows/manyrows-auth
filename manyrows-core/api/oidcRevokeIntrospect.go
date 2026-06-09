package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
)

// oidcAuthClient resolves the app's OIDC config, parses the form body, and
// authenticates the client exactly like the /token endpoint (HTTP Basic
// header, or client_id/client_secret in the form). Returns false (with an
// OAuth-shaped error already written) on any failure. Shared by the
// revocation and introspection endpoints, both of which RFC-require the
// caller to be an authenticated client.
func (handler *RequestHandler) oidcAuthClient(w http.ResponseWriter, r *http.Request) (*core.App, bool) {
	app, ok := core.AppFromContext(r.Context())
	if !ok || app == nil {
		oidcTokenError(w, http.StatusNotFound, "invalid_request", "app not resolved")
		return nil, false
	}
	cfg, err := handler.repo.GetAppOIDCConfig(r.Context(), app.ID)
	if err != nil {
		oidcTokenError(w, http.StatusInternalServerError, "server_error", "config lookup failed")
		return nil, false
	}
	if cfg == nil || !cfg.Enabled {
		oidcTokenError(w, http.StatusNotFound, "invalid_request", "OIDC not enabled for this app")
		return nil, false
	}
	if err := r.ParseForm(); err != nil {
		oidcTokenError(w, http.StatusBadRequest, "invalid_request", "could not parse form body")
		return nil, false
	}
	clientID, clientSecret, gotBasic := r.BasicAuth()
	if !gotBasic {
		clientID = strings.TrimSpace(r.PostForm.Get("client_id"))
		clientSecret = strings.TrimSpace(r.PostForm.Get("client_secret"))
	}
	if clientID != app.ID.String() || !verifyOIDCClientAuth(cfg, clientSecret) {
		oidcTokenError(w, http.StatusUnauthorized, "invalid_client", "client credentials are not valid")
		return nil, false
	}
	return app, true
}

// oidcResolveTokenSession resolves a raw token — either an opaque refresh
// token or an access-token JWT — to the session it belongs to, scoped to
// the given app. ok is false for unknown, expired, or cross-app tokens.
func (handler *RequestHandler) oidcResolveTokenSession(ctx context.Context, app *core.App, token string) (uuid.UUID, bool) {
	// Opaque refresh token (sha256-hashed at rest).
	if rt, err := handler.repo.GetClientRefreshTokenByHash(ctx, hashTokenForRefresh(token)); err == nil && rt != nil {
		ses, err := handler.repo.GetClientSessionByID(ctx, rt.SessionID)
		if err == nil && ses != nil && ses.AppID != nil && *ses.AppID == app.ID {
			return ses.ID, true
		}
		return uuid.Nil, false
	}
	// Access-token JWT (signature + expiry verified by ParseAccessToken).
	if sid, _, _, aud, ok := handler.clientAuthService.ParseAccessToken(token); ok && aud == app.ID.String() {
		ses, err := handler.repo.GetClientSessionByID(ctx, sid)
		if err == nil && ses != nil && ses.AppID != nil && *ses.AppID == app.ID {
			return ses.ID, true
		}
	}
	return uuid.Nil, false
}

// OIDCRevoke implements RFC 7009. Revoking either a refresh or access token
// kills the underlying session (so both stop working) — the natural
// "log this user out" semantics for a session-backed provider. Per the RFC
// the endpoint returns 200 for a successful revocation AND for an unknown
// token (so a client can't probe), with 401 only on bad client auth.
func (handler *RequestHandler) OIDCRevoke(w http.ResponseWriter, r *http.Request) {
	app, ok := handler.oidcAuthClient(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	token := strings.TrimSpace(r.PostForm.Get("token"))
	if token != "" {
		if sessionID, found := handler.oidcResolveTokenSession(r.Context(), app, token); found {
			_ = handler.clientAuthService.RevokeAllSessionTokens(r.Context(), sessionID)
			_, _ = handler.repo.DeleteClientSession(r.Context(), sessionID)
		}
	}
	w.WriteHeader(http.StatusOK)
}

type oidcIntrospectionResponse struct {
	Active    bool   `json:"active"`
	Sub       string `json:"sub,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
}

// OIDCIntrospect implements RFC 7662. Returns {"active": <bool>, ...} for the
// presented token. Client-authenticated (prevents token scanning); an
// unknown/expired/revoked token is reported as {"active": false}, not an error.
func (handler *RequestHandler) OIDCIntrospect(w http.ResponseWriter, r *http.Request) {
	app, ok := handler.oidcAuthClient(w, r)
	if !ok {
		return
	}
	resp := handler.oidcIntrospect(r.Context(), app, strings.TrimSpace(r.PostForm.Get("token")))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

func (handler *RequestHandler) oidcIntrospect(ctx context.Context, app *core.App, token string) oidcIntrospectionResponse {
	inactive := oidcIntrospectionResponse{Active: false}
	if token == "" {
		return inactive
	}
	now := time.Now().UTC()

	// Opaque refresh token: active iff unrotated, unexpired, and its session
	// is still active and belongs to this app.
	if rt, err := handler.repo.GetClientRefreshTokenByHash(ctx, hashTokenForRefresh(token)); err == nil && rt != nil {
		if rt.RotatedAt == nil && now.Before(rt.ExpiresAt) {
			if ses, err := handler.repo.GetClientSessionByID(ctx, rt.SessionID); err == nil && ses != nil &&
				ses.AppID != nil && *ses.AppID == app.ID && ses.IsActive(now) {
				return oidcIntrospectionResponse{
					Active: true, Sub: ses.UserID.String(), ClientID: app.ID.String(),
					TokenType: "refresh_token", Exp: rt.ExpiresAt.Unix(),
				}
			}
		}
		return inactive
	}

	// Access-token JWT: ParseAccessToken already verified signature + expiry;
	// confirm the backing session is still active (revocation check).
	if sid, uid, exp, aud, ok := handler.clientAuthService.ParseAccessToken(token); ok && aud == app.ID.String() {
		if ses, err := handler.repo.GetClientSessionByID(ctx, sid); err == nil && ses != nil &&
			ses.AppID != nil && *ses.AppID == app.ID && ses.IsActive(now) {
			return oidcIntrospectionResponse{
				Active: true, Sub: uid.String(), ClientID: app.ID.String(),
				TokenType: "Bearer", Exp: exp.Unix(),
			}
		}
	}
	return inactive
}
