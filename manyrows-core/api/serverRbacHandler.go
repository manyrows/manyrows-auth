package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// Definition CRUD for the product's RBAC, over the S2S API — lets a backend
// programmatically manage roles/permissions (the read-only catalog lives in
// serverCatalogHandler.go; assignment in serverWriteHandlers.go). These are
// product metadata: the key's app scopes to the product, so there's no
// per-user membership gate.

func (handler *RequestHandler) serverProductCtx(w http.ResponseWriter, r *http.Request) (*core.Product, bool) {
	project, ok := core.ProductFromContext(r.Context())
	if !ok || project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return nil, false
	}
	return project, true
}

// serverRoleSummary reads one role (with its permission slugs) by slug.
func (handler *RequestHandler) serverRoleSummary(r *http.Request, productID uuid.UUID, slug string) (ServerRoleSummary, bool, error) {
	roles, err := handler.repo.GetRolesByProductID(r.Context(), productID)
	if err != nil {
		return ServerRoleSummary{}, false, err
	}
	for _, role := range roles {
		if role.Slug == slug {
			perms := make([]string, 0, len(role.Permissions))
			for _, p := range role.Permissions {
				perms = append(perms, p.Slug)
			}
			return ServerRoleSummary{Slug: role.Slug, Name: role.Name, Permissions: perms}, true, nil
		}
	}
	return ServerRoleSummary{}, false, nil
}

type ServerCreateRoleRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
	// Permissions optionally sets the role's granted permission slugs.
	Permissions []string `json:"permissions"`
}

type ServerUpdateRoleRequest struct {
	Name *string `json:"name"`
	// Permissions, when present, replaces the role's granted permission slugs.
	Permissions *[]string `json:"permissions"`
}

// ServerCreateRole defines a new role in the product, optionally with permissions.
// POST /x/{workspaceSlug}/api/v1/apps/{appId}/roles
func (handler *RequestHandler) ServerCreateRole(w http.ResponseWriter, r *http.Request) {
	project, ok := handler.serverProductCtx(w, r)
	if !ok {
		return
	}
	var req ServerCreateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	// Resolve permissions first so a bad slug fails before the role is created.
	var permIDs []uuid.UUID
	if len(req.Permissions) > 0 {
		ids, _, ok := handler.resolvePermissionSlugs(w, r, project.ID, req.Permissions)
		if !ok {
			return
		}
		permIDs = ids
	}

	role, err := handler.repo.CreateRole(r.Context(), repo.CreateRoleParams{
		ProductID: project.ID, Name: req.Name, Slug: req.Slug, Now: time.Now().UTC(),
	})
	if err != nil {
		switch {
		case errors.Is(err, repo.ErrBadRequest):
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		case errors.Is(err, repo.ErrConflict):
			WriteError(w, r, "error.conflict", http.StatusConflict)
		default:
			log.Err(err).Msg("ServerCreateRole: CreateRole failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		}
		return
	}

	if len(permIDs) > 0 {
		if err := handler.repo.ReplaceRolePermissions(r.Context(), repo.ReplaceRolePermissionsParams{
			ProductID: project.ID, RoleID: role.ID, PermissionIDs: permIDs, Now: time.Now().UTC(),
		}); err != nil {
			log.Err(err).Msg("ServerCreateRole: ReplaceRolePermissions failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
	}

	summary, _, err := handler.serverRoleSummary(r, project.ID, role.Slug)
	if err != nil {
		log.Err(err).Msg("ServerCreateRole: summary read failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJsonWithStatusCode(w, summary, http.StatusCreated)
}

// ServerUpdateRole updates a role's name and/or its granted permissions.
// PATCH /x/{workspaceSlug}/api/v1/apps/{appId}/roles/{slug}
func (handler *RequestHandler) ServerUpdateRole(w http.ResponseWriter, r *http.Request) {
	project, ok := handler.serverProductCtx(w, r)
	if !ok {
		return
	}
	roleIDs, _, ok := handler.resolveRoleSlugs(w, r, project.ID, []string{chi.URLParam(r, "slug")})
	if !ok {
		return
	}
	roleID := roleIDs[0]

	var req ServerUpdateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	// Resolve replacement permissions up front (fail-fast) if provided.
	var permIDs []uuid.UUID
	if req.Permissions != nil {
		ids, _, ok := handler.resolvePermissionSlugs(w, r, project.ID, *req.Permissions)
		if !ok {
			return
		}
		permIDs = ids
	}

	if req.Name != nil {
		if _, err := handler.repo.UpdateRole(r.Context(), repo.UpdateRoleParams{
			ProductID: project.ID, RoleID: roleID, Name: req.Name, Now: time.Now().UTC(),
		}); err != nil {
			switch {
			case errors.Is(err, repo.ErrBadRequest):
				WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			case errors.Is(err, repo.ErrConflict):
				WriteError(w, r, "error.conflict", http.StatusConflict)
			default:
				log.Err(err).Msg("ServerUpdateRole: UpdateRole failed")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			}
			return
		}
	}

	if req.Permissions != nil {
		if err := handler.repo.ReplaceRolePermissions(r.Context(), repo.ReplaceRolePermissionsParams{
			ProductID: project.ID, RoleID: roleID, PermissionIDs: permIDs, Now: time.Now().UTC(),
		}); err != nil {
			log.Err(err).Msg("ServerUpdateRole: ReplaceRolePermissions failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
	}

	summary, _, err := handler.serverRoleSummary(r, project.ID, chi.URLParam(r, "slug"))
	if err != nil {
		log.Err(err).Msg("ServerUpdateRole: summary read failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, summary)
}

// ServerDeleteRole deletes a role (and its assignments cascade).
// DELETE /x/{workspaceSlug}/api/v1/apps/{appId}/roles/{slug}
func (handler *RequestHandler) ServerDeleteRole(w http.ResponseWriter, r *http.Request) {
	project, ok := handler.serverProductCtx(w, r)
	if !ok {
		return
	}
	roleIDs, _, ok := handler.resolveRoleSlugs(w, r, project.ID, []string{chi.URLParam(r, "slug")})
	if !ok {
		return
	}
	if err := handler.repo.DeleteRole(r.Context(), project.ID, roleIDs[0]); err != nil {
		log.Err(err).Msg("ServerDeleteRole: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type ServerCreatePermissionRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type ServerUpdatePermissionRequest struct {
	Name *string `json:"name"`
}

// ServerCreatePermission defines a new permission in the product.
// POST /x/{workspaceSlug}/api/v1/apps/{appId}/permissions
func (handler *RequestHandler) ServerCreatePermission(w http.ResponseWriter, r *http.Request) {
	project, ok := handler.serverProductCtx(w, r)
	if !ok {
		return
	}
	var req ServerCreatePermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if req.Slug == "" || req.Name == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	perm := core.Permission{
		ID: utils.NewUUID(), ProductID: project.ID, Name: req.Name, Slug: req.Slug, CreatedAt: now, UpdatedAt: now,
	}
	if err := handler.repo.CreatePermission(r.Context(), perm); err != nil {
		if repo.IsUniqueViolation(err) {
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		}
		log.Err(err).Msg("ServerCreatePermission: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJsonWithStatusCode(w, ServerPermissionSummary{Slug: perm.Slug, Name: perm.Name}, http.StatusCreated)
}

// ServerUpdatePermission renames a permission (slug is immutable here).
// PATCH /x/{workspaceSlug}/api/v1/apps/{appId}/permissions/{slug}
func (handler *RequestHandler) ServerUpdatePermission(w http.ResponseWriter, r *http.Request) {
	project, ok := handler.serverProductCtx(w, r)
	if !ok {
		return
	}
	slug := chi.URLParam(r, "slug")
	permIDs, _, ok := handler.resolvePermissionSlugs(w, r, project.ID, []string{slug})
	if !ok {
		return
	}
	var req ServerUpdatePermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if req.Name == nil || *req.Name == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if err := handler.repo.UpdatePermission(r.Context(), core.Permission{
		ID: permIDs[0], ProductID: project.ID, Name: *req.Name, Slug: slug, UpdatedAt: time.Now().UTC(),
	}); err != nil {
		log.Err(err).Msg("ServerUpdatePermission: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, ServerPermissionSummary{Slug: slug, Name: *req.Name})
}

// ServerDeletePermission deletes a permission.
// DELETE /x/{workspaceSlug}/api/v1/apps/{appId}/permissions/{slug}
func (handler *RequestHandler) ServerDeletePermission(w http.ResponseWriter, r *http.Request) {
	project, ok := handler.serverProductCtx(w, r)
	if !ok {
		return
	}
	permIDs, _, ok := handler.resolvePermissionSlugs(w, r, project.ID, []string{chi.URLParam(r, "slug")})
	if !ok {
		return
	}
	if err := handler.repo.DeletePermission(r.Context(), permIDs[0], project.ID); err != nil {
		log.Err(err).Msg("ServerDeletePermission: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
