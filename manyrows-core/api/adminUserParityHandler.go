package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/crypto/passwordhash"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// These admin handlers bring the dashboard to parity with the S2S API for
// support operations on an app user. They mirror the S2S handlers in
// api/server*.go but use the admin auth + scoping helpers (parseAppContext /
// adminAndWorkspace / loadUserScopedToApp).

// HandleAdminCreateMagicLink generates a one-time passwordless sign-in link for
// an app user and returns it for an operator to deliver. Mirrors S2S
// ServerCreateMagicLink. Requires the app's primary auth method to be Magic
// Link with an App URL configured.
// POST /admin/workspace/{workspaceId}/projects/{projectId}/apps/{appId}/users/{userId}/magic-link
func (handler *RequestHandler) HandleAdminCreateMagicLink(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	appID, err := utils.GetPathUUID("appId", r)
	if err != nil || appID == uuid.Nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	app, err := handler.repo.GetAppByID(r.Context(), appID)
	if err != nil || app.WorkspaceID != ws.ID {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}
	if app.PrimaryAuthMethod != core.PrimaryAuthMethodMagicLink {
		WriteError(w, r, "error.authMethodDisabled", http.StatusForbidden)
		return
	}
	if app.AppURL == nil || strings.TrimSpace(*app.AppURL) == "" {
		WriteError(w, r, "error.magicLinkRequiresAppUrl", http.StatusForbidden)
		return
	}
	user, ok := handler.loadUserScopedToApp(w, r, appID)
	if !ok {
		return
	}

	var req struct {
		RememberMe bool `json:"rememberMe"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	rawToken, tokenHash, err := handler.adminAuthService.NewMagicToken()
	if err != nil {
		log.Err(err).Msg("HandleAdminCreateMagicLink: NewMagicToken failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	expiresAt := time.Now().UTC().Add(magicLinkTTL)
	if err := handler.repo.CreateMagicLink(r.Context(), repo.CreateMagicLinkParams{
		Purpose:   appLoginMagicPurpose(app.ID),
		Email:     user.Email,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	}); err != nil {
		log.Err(err).Msg("HandleAdminCreateMagicLink: CreateMagicLink failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	url := buildMagicLinkConsumeURL(handler.AppBaseURL(&app), ws.Slug, app.ID, rawToken, req.RememberMe)
	utils.WriteJson(w, map[string]any{"url": url, "expiresAt": expiresAt})
}

// HandleAdminSetUserPassword sets (or replaces) an app user's password,
// enforcing the app's password policy. Mirrors S2S ServerSetUserPassword.
// PUT /admin/workspace/{workspaceId}/projects/{projectId}/apps/{appId}/users/{userId}/password
func (handler *RequestHandler) HandleAdminSetUserPassword(w http.ResponseWriter, r *http.Request) {
	_, _, appID, ok := handler.parseAppContext(w, r)
	if !ok {
		return
	}
	app, err := handler.repo.GetAppByID(r.Context(), appID)
	if err != nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}
	user, ok := handler.loadUserScopedToApp(w, r, appID)
	if !ok {
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	if pol := checkPasswordPolicy(&app, req.Password, user.Email); !pol.OK {
		if pol.Issue == "too_short" {
			WriteErrorf(w, r, "error.passwordTooShort", http.StatusBadRequest, pol.MinLength)
		} else {
			WriteError(w, r, "error.passwordTooWeak", http.StatusBadRequest)
		}
		return
	}

	hash, err := passwordhash.Hash(req.Password)
	if err != nil {
		log.Err(err).Msg("HandleAdminSetUserPassword: hash failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if err := handler.repo.UpdateUserPassword(r.Context(), user.ID, hash, time.Now().UTC()); err != nil {
		log.Err(err).Msg("HandleAdminSetUserPassword: UpdateUserPassword failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleAdminSetUserEmailVerified marks an app user's email verified or
// unverified. Mirrors S2S ServerSetUserEmailVerified. Pool-level.
// PUT /admin/workspace/{workspaceId}/projects/{projectId}/apps/{appId}/users/{userId}/email-verified
func (handler *RequestHandler) HandleAdminSetUserEmailVerified(w http.ResponseWriter, r *http.Request) {
	_, _, appID, ok := handler.parseAppContext(w, r)
	if !ok {
		return
	}
	user, ok := handler.loadUserScopedToApp(w, r, appID)
	if !ok {
		return
	}

	var req struct {
		Verified bool `json:"verified"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	var err error
	if req.Verified {
		err = handler.repo.SetUserEmailVerified(r.Context(), user.ID, time.Now().UTC())
	} else {
		err = handler.repo.ClearUserEmailVerified(r.Context(), user.ID)
	}
	if err != nil {
		log.Err(err).Msg("HandleAdminSetUserEmailVerified: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleAdminCheckUserPermission answers whether an app user has a given
// permission (effective: via roles + direct grants). Mirrors S2S
// ServerCheckPermission.
// GET /admin/workspace/{workspaceId}/projects/{projectId}/apps/{appId}/users/{userId}/check-permission?permission=slug
func (handler *RequestHandler) HandleAdminCheckUserPermission(w http.ResponseWriter, r *http.Request) {
	_, projectID, appID, ok := handler.parseAppContext(w, r)
	if !ok {
		return
	}
	user, ok := handler.loadUserScopedToApp(w, r, appID)
	if !ok {
		return
	}
	permission := strings.TrimSpace(r.URL.Query().Get("permission"))
	if permission == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	_, perms, err := handler.resolveRolesAndPermissions(r.Context(), projectID, user.ID, appID)
	if err != nil {
		log.Err(err).Msg("HandleAdminCheckUserPermission: resolve failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, map[string]any{
		"allowed":    slices.Contains(perms, permission),
		"permission": permission,
		"userId":     user.ID.String(),
	})
}
