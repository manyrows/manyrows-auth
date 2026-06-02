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

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

type RolesResponse struct {
	Roles []core.Role `json:"roles"`
}

type CreateRoleRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type UpdateRoleRequest struct {
	Name *string `json:"name,omitempty"`
	Slug *string `json:"slug,omitempty"`
}

type UpdateRolePermissionsRequest struct {
	PermissionIDs []uuid.UUID `json:"permissionIds"`
}

func (handler *RequestHandler) HandleGetRoles(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProject(w, r)
	if !ok {
		return
	}

	roles, err := handler.repo.GetRolesByProjectID(r.Context(), project.ID)
	if err != nil {
		log.Err(err).Msg("failed to get roles by project ID")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, RolesResponse{Roles: roles}, http.StatusOK)
}

func (handler *RequestHandler) HandleCreateRole(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProject(w, r)
	if !ok {
		return
	}

	var req CreateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Slug = strings.TrimSpace(req.Slug)

	if req.Name == "" {
		WriteError(w, r, "error.nameRequired", http.StatusBadRequest)
		return
	}
	if req.Slug == "" {
		WriteError(w, r, "error.slugRequired", http.StatusBadRequest)
		return
	}

	created, err := handler.repo.CreateRole(r.Context(), repo.CreateRoleParams{
		ProjectID: project.ID,
		Name:      req.Name,
		Slug:      req.Slug,
		Now:       time.Now().UTC(),
	})
	if err != nil {
		if errors.Is(err, repo.ErrConflict) {
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		}
		if errors.Is(err, repo.ErrBadRequest) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		log.Err(err).Msg("failed to create role")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, created, http.StatusCreated)
}

func (handler *RequestHandler) HandleUpdateRole(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProject(w, r)
	if !ok {
		return
	}

	roleID, ok := handler.roleIDFromURL(w, r)
	if !ok {
		return
	}

	var req UpdateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	patch := repo.UpdateRoleParams{
		ProjectID: project.ID,
		RoleID:    roleID,
		Now:       time.Now().UTC(),
	}

	var changedFields []string

	if req.Name != nil {
		v := strings.TrimSpace(*req.Name)
		if v == "" {
			WriteError(w, r, "error.nameEmpty", http.StatusBadRequest)
			return
		}
		patch.Name = &v
		changedFields = append(changedFields, "name")
	}

	if req.Slug != nil {
		v := strings.TrimSpace(*req.Slug)
		if v == "" {
			WriteError(w, r, "error.slugEmpty", http.StatusBadRequest)
			return
		}
		patch.Slug = &v
		changedFields = append(changedFields, "slug")
	}

	updated, err := handler.repo.UpdateRole(r.Context(), patch)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.roleNotFound", http.StatusNotFound)
			return
		}
		if errors.Is(err, repo.ErrConflict) {
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		}
		if errors.Is(err, repo.ErrBadRequest) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		log.Err(err).Msg("failed to update role")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, updated, http.StatusOK)
}

func (handler *RequestHandler) HandleUpdateRolePermissions(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProject(w, r)
	if !ok {
		return
	}

	roleID, ok := handler.roleIDFromURL(w, r)
	if !ok {
		return
	}

	var req UpdateRolePermissionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	permissionIDs := req.PermissionIDs
	if permissionIDs == nil {
		permissionIDs = []uuid.UUID{}
	}

	err := handler.repo.ReplaceRolePermissions(r.Context(), repo.ReplaceRolePermissionsParams{
		ProjectID:     project.ID,
		RoleID:        roleID,
		PermissionIDs: permissionIDs,
		Now:           time.Now().UTC(),
	})
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.roleNotFound", http.StatusNotFound)
			return
		}
		if errors.Is(err, repo.ErrBadRequest) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		log.Err(err).Msg("failed to replace role permissions")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	updated, err := handler.repo.GetRoleByID(r.Context(), project.ID, roleID)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	utils.WriteJsonWithStatusCode(w, updated, http.StatusOK)
}

func (handler *RequestHandler) HandleDeleteRole(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProject(w, r)
	if !ok {
		return
	}

	roleID, ok := handler.roleIDFromURL(w, r)
	if !ok {
		return
	}

	if err := handler.repo.DeleteRole(r.Context(), project.ID, roleID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.roleNotFound", http.StatusNotFound)
			return
		}
		// If your repo uses ErrConflict for FK constraints etc.
		if errors.Is(err, repo.ErrConflict) {
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		}
		if errors.Is(err, repo.ErrBadRequest) {
			WriteError(w, r, "error.invalidRoleId", http.StatusBadRequest)
			return
		}
		log.Err(err).Msg("failed to delete role")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

/* ===== URL helper ===== */

func (handler *RequestHandler) roleIDFromURL(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := chi.URLParam(r, "roleId")
	id, err := uuid.FromString(raw)
	if err != nil {
		WriteError(w, r, "error.invalidRoleId", http.StatusBadRequest)
		return uuid.UUID{}, false
	}
	return id, true
}

func strPtr(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	v := s
	return &v
}
