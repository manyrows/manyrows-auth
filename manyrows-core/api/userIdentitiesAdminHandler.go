package api

import (
	"context"
	"errors"
	"net/http"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// loadUserScopedToApp validates that the path's userId resolves to a
// user inside the app's user pool. Returns 404 in every "no" branch
// (bad uuid, user gone, user in a different pool) so a cross-workspace
// admin can't probe for user existence in another pool.
func (handler *RequestHandler) loadUserScopedToApp(
	w http.ResponseWriter, r *http.Request, appID uuid.UUID,
) (*core.User, bool) {
	uid, err := utils.GetPathUUID("userId", r)
	if err != nil || uid == uuid.Nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return nil, false
	}
	user, found, lookupErr := handler.lookupUserScopedToApp(r.Context(), appID, uid)
	if lookupErr != nil {
		// Transient/infra error (app or user load failed). Preserve the
		// original 500 so callers don't see a misleading "not found".
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return nil, false
	}
	if !found {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return nil, false
	}
	return user, true
}

// lookupUserScopedToApp loads a user and confirms app membership without
// writing an HTTP response (for batch loops). Returns (nil,false,nil) for a
// genuine miss — bad id, user gone, or a user belonging to a different pool —
// so callers can't distinguish "not found" from "wrong pool" (same probing
// guarantee loadUserScopedToApp gives its HTTP callers). The error return is
// non-nil ONLY for transient/infra failures (app or user load returning a
// non-ErrNotFound error) so callers can map those to 500 rather than 404.
func (handler *RequestHandler) lookupUserScopedToApp(
	ctx context.Context, appID, userID uuid.UUID,
) (*core.User, bool, error) {
	if userID == uuid.Nil {
		return nil, false, nil
	}
	app, err := handler.repo.GetAppByID(ctx, appID)
	if err != nil {
		log.Err(err).Msg("Could not load app for identity admin")
		return nil, false, err
	}
	user, err := handler.repo.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return nil, false, nil
		}
		log.Err(err).Msg("Could not load user for identity admin")
		return nil, false, err
	}
	if user.UserPoolID != app.UserPoolID {
		return nil, false, nil
	}
	return user, true, nil
}

// HandleAdminListUserIdentities returns one user's linked OAuth identities
// for support workflows ("which social account is this user signing in
// with?"). Mirrors HandleAdminListUserPasskeys - the app path is used
// even though identities are pool-scoped, because admin UI navigates
// app -> user.
// GET /admin/workspace/{workspaceId}/projects/{projectId}/apps/{appId}/users/{userId}/identities
func (handler *RequestHandler) HandleAdminListUserIdentities(w http.ResponseWriter, r *http.Request) {
	_, _, appID, ok := handler.parseAppContext(w, r)
	if !ok {
		return
	}
	user, ok := handler.loadUserScopedToApp(w, r, appID)
	if !ok {
		return
	}
	rows, err := handler.repo.ListUserIdentities(r.Context(), user.ID)
	if err != nil {
		log.Err(err).Msg("Could not list user identities (admin)")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	out := make([]*core.UserIdentityResource, 0, len(rows))
	for _, row := range rows {
		out = append(out, core.ToUserIdentityResource(row))
	}
	utils.WriteJson(w, map[string]any{"identities": out})
}

// HandleAdminDeleteUserIdentity unlinks one provider for a user. Used
// when admin needs to force a re-link (e.g. user lost access to the
// underlying Google account and is signing in via password from now on).
// DELETE /admin/workspace/{workspaceId}/projects/{projectId}/apps/{appId}/users/{userId}/identities/{provider}
func (handler *RequestHandler) HandleAdminDeleteUserIdentity(w http.ResponseWriter, r *http.Request) {
	_, _, appID, ok := handler.parseAppContext(w, r)
	if !ok {
		return
	}
	user, ok := handler.loadUserScopedToApp(w, r, appID)
	if !ok {
		return
	}
	provider := core.UserSource(utils.GetPathString("provider", r))
	switch provider {
	case core.UserSourceGoogle, core.UserSourceApple,
		core.UserSourceMicrosoft, core.UserSourceGithub:
	default:
		if !core.IsExternalIDPProviderKey(string(provider)) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
	}
	if err := handler.repo.DeleteUserIdentity(r.Context(), user.ID, provider); err != nil {
		log.Err(err).Msg("Could not delete user identity (admin)")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
