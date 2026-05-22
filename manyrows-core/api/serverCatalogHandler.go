package api

import (
	"net/http"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

// Read-only catalog of the product's roles and permissions. Backends assign
// roles by slug (PUT /users/{userId}/roles), so they need a way to discover
// which slugs exist. These are product metadata, not user data, so there's no
// per-user membership gate — the API key's app already scopes to the product.

type ServerRoleSummary struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
	// Permissions is the set of permission slugs this role grants.
	Permissions []string `json:"permissions"`
}

type ServerRolesListResponse struct {
	Roles []ServerRoleSummary `json:"roles"`
}

// ServerListRoles lists the product's roles.
// GET /x/{workspaceSlug}/api/v1/apps/{appId}/roles
func (handler *RequestHandler) ServerListRoles(w http.ResponseWriter, r *http.Request) {
	project, ok := core.ProductFromContext(r.Context())
	if !ok || project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return
	}

	roles, err := handler.repo.GetRolesByProductID(r.Context(), project.ID)
	if err != nil {
		log.Err(err).Msg("ServerListRoles: GetRolesByProductID failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	out := make([]ServerRoleSummary, 0, len(roles))
	for _, role := range roles {
		perms := make([]string, 0, len(role.Permissions))
		for _, p := range role.Permissions {
			perms = append(perms, p.Slug)
		}
		out = append(out, ServerRoleSummary{Slug: role.Slug, Name: role.Name, Permissions: perms})
	}

	utils.WriteJson(w, ServerRolesListResponse{Roles: out})
}

type ServerPermissionSummary struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type ServerPermissionsListResponse struct {
	Permissions []ServerPermissionSummary `json:"permissions"`
}

// ServerListPermissions lists the product's permissions.
// GET /x/{workspaceSlug}/api/v1/apps/{appId}/permissions
func (handler *RequestHandler) ServerListPermissions(w http.ResponseWriter, r *http.Request) {
	project, ok := core.ProductFromContext(r.Context())
	if !ok || project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return
	}

	perms, err := handler.repo.GetPermissionsByProductID(r.Context(), project.ID)
	if err != nil {
		log.Err(err).Msg("ServerListPermissions: GetPermissionsByProductID failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	out := make([]ServerPermissionSummary, 0, len(perms))
	for _, p := range perms {
		out = append(out, ServerPermissionSummary{Slug: p.Slug, Name: p.Name})
	}

	utils.WriteJson(w, ServerPermissionsListResponse{Permissions: out})
}
