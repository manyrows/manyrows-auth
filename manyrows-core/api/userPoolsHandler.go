package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// User-pool admin API. Pools are workspace-scoped identity boundaries:
// every app points at one pool, two apps pointing at the same pool
// share users (SSO between related apps). The auto-create-on-app-create
// path still mints a 1:1 pool per app; this handler lets admins build
// shared pools and repoint apps.

// HandleListUserPools returns every pool in the workspace, annotated
// with app + user counts so the admin list can render them.
// GET /admin/workspace/{workspaceId}/userPools
func (handler *RequestHandler) HandleListUserPools(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	pools, err := handler.repo.ListUserPoolsByWorkspaceWithStats(r.Context(), ws.ID)
	if err != nil {
		log.Err(err).Msg("Could not list user pools")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if pools == nil {
		pools = []repo.UserPoolWithStats{}
	}
	utils.WriteJson(w, map[string]any{"pools": pools})
}

// HandleCreateUserPool creates a new empty pool. Admins typically hit
// this when setting up an SSO group ("Acme employees") so subsequent
// app creates can target it.
// POST /admin/workspace/{workspaceId}/userPools
func (handler *RequestHandler) HandleCreateUserPool(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		utils.WriteJsonWithStatusCode(w, map[string]any{
			"error": "name is required",
			"field": "name",
		}, http.StatusBadRequest)
		return
	}

	p, err := handler.repo.CreateUserPool(r.Context(), ws.ID, name)
	if err != nil {
		if repo.IsUniqueViolation(err) {
			utils.WriteJsonWithStatusCode(w, map[string]any{
				"error": "a pool with that name already exists",
				"field": "name",
			}, http.StatusConflict)
			return
		}
		log.Err(err).Msg("Could not create user pool")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJsonWithStatusCode(w, p, http.StatusCreated)
}

// HandleListAppsByUserPool returns the apps pointing at this pool so
// the admin drill-down dialog can surface "what's using it" without
// the operator hunting through every project. Each row carries the
// composed display name + member count so the dialog is one fetch.
// GET /admin/workspace/{workspaceId}/userPools/{poolId}/apps
func (handler *RequestHandler) HandleListAppsByUserPool(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}
	poolID, err := uuid.FromString(chi.URLParam(r, "poolId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	// Scope check: verify the pool belongs to this workspace before
	// returning anything. Otherwise a foreign pool id would leak its
	// app list to anyone with admin in any workspace.
	pool, err := handler.repo.GetUserPoolByID(r.Context(), poolID)
	if err != nil || pool == nil || pool.WorkspaceID != ws.ID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	apps, err := handler.repo.ListAppsByUserPool(r.Context(), poolID)
	if err != nil {
		log.Err(err).Msg("Could not list apps by user pool")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if apps == nil {
		apps = []repo.PoolApp{}
	}
	utils.WriteJson(w, map[string]any{"apps": apps})
}

// HandleUpdateUserPool renames a pool. The only mutable field on a
// pool today; SSO/MFA config will land here as separate sub-resources.
// PATCH /admin/workspace/{workspaceId}/userPools/{poolId}
func (handler *RequestHandler) HandleUpdateUserPool(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}
	poolID, err := uuid.FromString(chi.URLParam(r, "poolId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		utils.WriteJsonWithStatusCode(w, map[string]any{
			"error": "name is required",
			"field": "name",
		}, http.StatusBadRequest)
		return
	}

	p, err := handler.repo.RenameUserPool(r.Context(), ws.ID, poolID, name)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		if repo.IsUniqueViolation(err) {
			utils.WriteJsonWithStatusCode(w, map[string]any{
				"error": "a pool with that name already exists",
				"field": "name",
			}, http.StatusConflict)
			return
		}
		log.Err(err).Msg("Could not rename user pool")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, p)
}

// HandleDeleteUserPool removes an empty pool. Refuses when any app
// still references the pool; the admin must repoint or delete those
// apps first.
// DELETE /admin/workspace/{workspaceId}/userPools/{poolId}
func (handler *RequestHandler) HandleDeleteUserPool(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}
	poolID, err := uuid.FromString(chi.URLParam(r, "poolId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if err := handler.repo.DeleteUserPool(r.Context(), ws.ID, poolID); err != nil {
		switch {
		case errors.Is(err, repo.ErrNotFound):
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		case errors.Is(err, repo.ErrPoolInUse):
			utils.WriteJsonWithStatusCode(w, map[string]any{
				"error": "pool is in use by one or more apps",
				"code":  "poolInUse",
			}, http.StatusConflict)
			return
		}
		log.Err(err).Msg("Could not delete user pool")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, map[string]any{"ok": true})
}

// HandleDeletePoolUser permanently deletes a pool user — the identity
// itself — cascading their roles, permission overrides, OAuth
// identities, sessions, and field values (auth_log entries are kept
// with the user link nulled). Gated: only allowed when the user
// belongs to no apps. Removing them from every app first is the
// deliberate precondition, so "remove from app" never silently
// escalates into account deletion.
// DELETE /admin/workspace/{workspaceId}/userPools/{poolId}/users/{userId}
func (handler *RequestHandler) HandleDeletePoolUser(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}
	poolID, err := uuid.FromString(chi.URLParam(r, "poolId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	userID, err := uuid.FromString(chi.URLParam(r, "userId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Pool must belong to this workspace — blocks cross-workspace
	// deletes by guessing ids.
	pool, err := handler.repo.GetUserPoolByID(r.Context(), poolID)
	if err != nil || pool == nil || pool.WorkspaceID != ws.ID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	user, err := handler.repo.GetUserByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("Could not load user for pool delete")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	// The user must actually live in this pool — scopes the delete and
	// blocks reaching a user via some other pool's id.
	if user.UserPoolID != poolID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	userInApps := func() {
		utils.WriteJsonWithStatusCode(w, map[string]any{
			"error": "user still belongs to one or more apps; remove them from all apps first",
			"code":  "userInApps",
		}, http.StatusConflict)
	}

	// Friendly fast-path 409 for the common case (no extra round-trips
	// when the user is obviously still a member). NOT the safety guard
	// — see the atomic delete below.
	n, err := handler.repo.CountAppMembershipsByUser(r.Context(), userID)
	if err != nil {
		log.Err(err).Msg("Could not count app memberships for pool delete")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if n > 0 {
		userInApps()
		return
	}

	// The real guard: delete only if still pool-scoped AND has no app
	// memberships, atomically. This closes the race between the count
	// above and here — a concurrent login / admin-add could attach a
	// membership in that window.
	deleted, err := handler.repo.DeleteUserIfOrphanInPool(r.Context(), userID, poolID)
	if err != nil {
		log.Err(err).Msg("Could not delete pool user")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !deleted {
		// The guard didn't match. Either the user vanished between the
		// load and here (already deleted / double-submit → idempotent
		// success) or it raced into an app membership (refuse).
		if _, gErr := handler.repo.GetUserByID(r.Context(), userID); gErr != nil {
			if errors.Is(gErr, repo.ErrNotFound) {
				utils.WriteJson(w, map[string]any{"ok": true})
				return
			}
			log.Err(gErr).Msg("Could not re-check user after guarded delete")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		userInApps()
		return
	}

	utils.WriteJson(w, map[string]any{"ok": true})
}

// HandleDeletePoolOrphanUsers bulk-deletes every user in the pool that
// belongs to no app. Same cascade + irreversibility as the single
// delete; the no-app guard is enforced in SQL so it can never catch an
// app member. Returns the number deleted.
// DELETE /admin/workspace/{workspaceId}/userPools/{poolId}/orphan-users
func (handler *RequestHandler) HandleDeletePoolOrphanUsers(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}
	poolID, err := uuid.FromString(chi.URLParam(r, "poolId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	pool, err := handler.repo.GetUserPoolByID(r.Context(), poolID)
	if err != nil || pool == nil || pool.WorkspaceID != ws.ID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	n, err := handler.repo.DeleteOrphanPoolUsers(r.Context(), poolID)
	if err != nil {
		log.Err(err).Msg("Could not purge orphan pool users")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, map[string]any{"ok": true, "deleted": n})
}

// HandleRepointAppUserPool moves an app to a different pool in the
// same workspace. Refuses when the app has any app_users rows, since
// moving the app would orphan those memberships (their pool user
// lives in the old pool). The merge-pool wizard that handles the
// non-empty case is a separate, larger UX.
// POST /admin/workspace/{workspaceId}/projects/{projectId}/apps/{appId}/userPool
func (handler *RequestHandler) HandleRepointAppUserPool(w http.ResponseWriter, r *http.Request) {
	// adminAndProject validates the (workspace, project) pair belongs
	// to the caller; loading the app scoped to that project below
	// prevents a foreign-workspace app id from leaking its member
	// count through the 409 response.
	_, ws, project, ok := handler.adminAndProject(w, r)
	if !ok {
		return
	}
	appID, err := uuid.FromString(chi.URLParam(r, "appId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	app, err := handler.repo.GetAppByIDForProject(r.Context(), ws.ID, project.ID, appID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("Could not load app for repoint")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	var body struct {
		UserPoolID uuid.UUID `json:"userPoolId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if body.UserPoolID == uuid.Nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if body.UserPoolID == app.UserPoolID {
		// No-op; tell the caller they're already pointed at this pool.
		utils.WriteJson(w, map[string]any{"ok": true, "userPoolId": body.UserPoolID})
		return
	}

	// Confirm the target pool belongs to the same workspace - prevents
	// a stray pool id from another workspace sneaking through.
	targetPool, err := handler.repo.GetUserPoolByID(r.Context(), body.UserPoolID)
	if err != nil || targetPool == nil || targetPool.WorkspaceID != ws.ID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	// Refuse the repoint when the app has any members; otherwise we'd
	// orphan them in the old pool. The future merge wizard handles
	// this by reconciling memberships into the new pool.
	memberCount, err := handler.repo.CountAppMembers(r.Context(), app.ID)
	if err != nil {
		log.Err(err).Msg("Could not count app members")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if memberCount > 0 {
		utils.WriteJsonWithStatusCode(w, map[string]any{
			"error":       "app has existing members; pool repoint would orphan them",
			"code":        "appHasMembers",
			"memberCount": memberCount,
		}, http.StatusConflict)
		return
	}

	if err := handler.repo.UpdateAppUserPool(r.Context(), ws.ID, app.ID, body.UserPoolID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("Could not repoint app to new pool")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, map[string]any{"ok": true, "userPoolId": body.UserPoolID})
}
