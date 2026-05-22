package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

type ServerUserPermissionsResponse struct {
	Permissions []string `json:"permissions"`
}

type ServerSetPermissionsRequest struct {
	// Permissions is the full set of direct permission slugs the user should
	// have in this app (replace semantics). These are per-user grants on top
	// of whatever the user's roles already provide.
	Permissions []string `json:"permissions"`
}

// ServerGetUserPermissions lists a member's DIRECT permission overrides (slugs)
// in this app — the per-user grants set via SetDirectPermissions, not the
// permissions inherited from roles.
// GET /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/permissions
func (handler *RequestHandler) ServerGetUserPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	project, ok := core.ProductFromContext(ctx)
	if !ok || project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}
	if !handler.requireAppMember(w, r, app.ID, userID) {
		return
	}

	slugs, err := handler.repo.GetDirectPermissionSlugs(ctx, project.ID, userID, app.ID)
	if err != nil {
		log.Err(err).Msg("ServerGetUserPermissions: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if slugs == nil {
		slugs = []string{}
	}
	utils.WriteJson(w, ServerUserPermissionsResponse{Permissions: slugs})
}

// ServerSetUserPermissions replaces a member's direct permission overrides in
// this app (by slug). Returns the resulting slugs.
// PUT /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/permissions
func (handler *RequestHandler) ServerSetUserPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	project, ok := core.ProductFromContext(ctx)
	if !ok || project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}
	if !handler.requireAppMember(w, r, app.ID, userID) {
		return
	}

	var req ServerSetPermissionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	permIDs, slugs, ok := handler.resolvePermissionSlugs(w, r, project.ID, req.Permissions)
	if !ok {
		return
	}

	if err := handler.repo.SetDirectPermissions(ctx, project.ID, userID, app.ID, permIDs); err != nil {
		log.Err(err).Msg("ServerSetUserPermissions: SetDirectPermissions failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, ServerUserPermissionsResponse{Permissions: slugs})
}

// resolvePermissionSlugs maps permission slugs to IDs within the product,
// de-duplicating; an unknown slug is a 400. Mirrors resolveRoleSlugs.
func (handler *RequestHandler) resolvePermissionSlugs(w http.ResponseWriter, r *http.Request, productID uuid.UUID, rawSlugs []string) (permIDs []uuid.UUID, slugs []string, ok bool) {
	permIDs = []uuid.UUID{}
	slugs = []string{}
	if len(rawSlugs) == 0 {
		return permIDs, slugs, true
	}

	perms, err := handler.repo.GetPermissionsByProductID(r.Context(), productID)
	if err != nil {
		log.Err(err).Msg("resolvePermissionSlugs: GetPermissionsByProductID failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return nil, nil, false
	}
	bySlug := make(map[string]uuid.UUID, len(perms))
	for _, p := range perms {
		bySlug[p.Slug] = p.ID
	}

	seen := make(map[string]bool, len(rawSlugs))
	for _, raw := range rawSlugs {
		slug := strings.TrimSpace(raw)
		id, known := bySlug[slug]
		if !known {
			WriteError(w, r, "error.permissionsInvalid", http.StatusBadRequest)
			return nil, nil, false
		}
		if seen[slug] {
			continue
		}
		seen[slug] = true
		permIDs = append(permIDs, id)
		slugs = append(slugs, slug)
	}
	return permIDs, slugs, true
}
