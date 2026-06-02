package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// =====================
// DTOs
// =====================

type PermissionsResponse struct {
	Permissions []core.Permission `json:"permissions"`
}

type CreatePermissionRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type UpdatePermissionRequest struct {
	Name *string `json:"name,omitempty"`
	Slug *string `json:"slug,omitempty"`
}

// =====================
// Handlers
// =====================

// GET /admin/workspace/{workspaceId}/projects/{projectId}/permissions
func (handler *RequestHandler) HandleGetPermissions(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProject(w, r)
	if !ok {
		return
	}

	perms, err := handler.repo.GetPermissionsByProjectID(r.Context(), project.ID)
	if err != nil {
		log.Err(err).Msg("Could not get permissions")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, PermissionsResponse{Permissions: perms})
}

// POST /admin/workspace/{workspaceId}/projects/{projectId}/permissions
func (handler *RequestHandler) HandleCreatePermission(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProject(w, r)
	if !ok {
		return
	}

	var req CreatePermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Slug = strings.TrimSpace(req.Slug)

	if req.Name == "" || req.Slug == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()

	perm := core.Permission{
		ID:        uuid.Must(uuid.NewV7()),
		ProjectID: project.ID,
		Name:      req.Name,
		Slug:      req.Slug,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := handler.repo.CreatePermission(r.Context(), perm); err != nil {
		if repo.IsUniqueViolation(err) {
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		}
		log.Err(err).Msg("Could not create permission")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, perm, http.StatusCreated)
}

// PATCH /admin/workspace/{workspaceId}/projects/{projectId}/permissions/{permissionId}
func (handler *RequestHandler) HandleUpdatePermission(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProject(w, r)
	if !ok {
		return
	}

	permissionID, err := utils.GetPathUUID("permissionId", r)
	if permissionID == uuid.Nil || err != nil {
		WriteError(w, r, "error.invalidPermissionId", http.StatusBadRequest)
		return
	}

	var req UpdatePermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode update permission request")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	// Load existing (ensures it belongs to project) then merge.
	existing, err := handler.repo.GetPermission(r.Context(), permissionID, project.ID)
	if err != nil {
		log.Err(err).Msg("Could not get permission")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if existing == nil {
		WriteError(w, r, "error.permissionNotFound", http.StatusNotFound)
		return
	}

	if req.Name != nil {
		v := strings.TrimSpace(*req.Name)
		if v == "" {
			WriteError(w, r, "error.nameEmpty", http.StatusBadRequest)
			return
		}
		existing.Name = v
	}
	if req.Slug != nil {
		v := strings.TrimSpace(*req.Slug)
		if v == "" {
			WriteError(w, r, "error.slugEmpty", http.StatusBadRequest)
			return
		}
		existing.Slug = v
	}
	existing.UpdatedAt = time.Now().UTC()

	if err := handler.repo.UpdatePermission(r.Context(), *existing); err != nil {
		if errors.Is(err, repo.ErrConflict) {
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		}
		log.Err(err).Msg("Could not update permission")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, existing)
}

// DELETE /admin/workspace/{workspaceId}/projects/{projectId}/permissions/{permissionId}
func (handler *RequestHandler) HandleDeletePermission(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProject(w, r)
	if !ok {
		return
	}

	permissionID, err := utils.GetPathUUID("permissionId", r)
	if permissionID == uuid.Nil || err != nil {
		WriteError(w, r, "error.invalidPermissionId", http.StatusBadRequest)
		return
	}

	// Ensure it belongs to the project.
	existing, err := handler.repo.GetPermission(r.Context(), permissionID, project.ID)
	if err != nil {
		log.Err(err).Msg("Could not get permission")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if existing == nil {
		WriteError(w, r, "error.permissionNotFound", http.StatusNotFound)
		return
	}

	if err := handler.repo.DeletePermission(r.Context(), permissionID, project.ID); err != nil {
		log.Err(err).Msg("Could not delete permission")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
