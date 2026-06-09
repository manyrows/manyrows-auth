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

// updateAppOrganizationsEnabledRequest toggles per-app org mode from the admin
// panel. Pointer so a missing field is rejected, not silently treated as false.
type updateAppOrganizationsEnabledRequest struct {
	OrganizationsEnabled *bool `json:"organizationsEnabled"`
}

// adminAppScope runs the admin/workspace gate, parses the path ids, AND verifies
// the app belongs to the caller's workspace+project — failing safe (404) if not.
// resolvePathIDs alone only PARSES the ids; without this ownership check a
// workspace-A admin could reach an app in workspace B by supplying its id. Every
// org-management handler must go through this.
func (handler *RequestHandler) adminAppScope(w http.ResponseWriter, r *http.Request) (projectID, appID uuid.UUID, ok bool) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return uuid.Nil, uuid.Nil, false
	}
	projectID, appID, ok = handler.resolvePathIDs(w, r)
	if !ok {
		return uuid.Nil, uuid.Nil, false
	}
	if _, err := handler.repo.GetAppByIDForProject(r.Context(), ws.ID, projectID, appID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return uuid.Nil, uuid.Nil, false
		}
		log.Err(err).Msg("failed to load app for org admin scope")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return uuid.Nil, uuid.Nil, false
	}
	return projectID, appID, true
}

// HandleUpdateAppOrganizationsEnabled flips organizations_enabled for the whole
// project the addressed app belongs to. The flag is conceptually project-level
// but stored per-app (duplicated across the project's apps); this keeps every
// copy in sync. The endpoint is still addressed via one app's id (the admin UI
// lives on an app's Organizations page) and returns that app.
func (handler *RequestHandler) HandleUpdateAppOrganizationsEnabled(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	projectID, appID, ok := handler.resolvePathIDs(w, r)
	if !ok {
		return
	}

	var req updateAppOrganizationsEnabledRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode json")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if req.OrganizationsEnabled == nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Validate the addressed app belongs to this workspace+project before
	// mutating anything (404 otherwise) — so a bad app id can't trigger a
	// project-wide write.
	out, err := handler.repo.GetAppByIDForProject(r.Context(), ws.ID, projectID, appID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to load app for organizations flag update")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if err := handler.repo.SetProjectOrganizationsEnabled(r.Context(), ws.ID, projectID, *req.OrganizationsEnabled); err != nil {
		log.Err(err).Msg("failed to update project organizations flag")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Reflect the new value on the addressed app we return (every app in the
	// project now carries it).
	out.OrganizationsEnabled = *req.OrganizationsEnabled
	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, ws), http.StatusOK)
}

type setAppOrgMemberRolesRequest struct {
	RoleIDs []uuid.UUID `json:"roleIds"`
}

// HandleSetAppOrganizationMemberRoles replaces an org member's project-role
// assignment from the admin panel. App-scoped + ownership-checked via
// adminAppScope/adminOrgFromURL; the target must be a member of the org. Role
// ids are validated against the app's project catalog (a stray id -> 400).
// Replace semantics: the posted set becomes the membership's exact project
// roles, and an empty array clears them. Independent of the org tier
// (owner/admin/member), which this endpoint does not touch.
func (handler *RequestHandler) HandleSetAppOrganizationMemberRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	projectID, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	org, ok := handler.adminOrgFromURL(w, r, appID)
	if !ok {
		return
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}
	member, err := handler.repo.GetOrganizationMember(ctx, org.ID, userID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("HandleSetAppOrganizationMemberRoles: load member failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	var body setAppOrgMemberRolesRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	roleIDs := dedupeUUIDs(body.RoleIDs)
	if len(roleIDs) > 0 {
		n, err := handler.repo.CountRolesInProject(ctx, projectID, roleIDs)
		if err != nil {
			log.Err(err).Msg("HandleSetAppOrganizationMemberRoles: role validation failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if n != len(roleIDs) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest) // stray role id
			return
		}
	}
	if err := handler.repo.SetOrganizationMemberRoles(ctx, member.ID, roleIDs); err != nil {
		log.Err(err).Msg("HandleSetAppOrganizationMemberRoles: set roles failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// adminOrgListItem is one row of the admin org list.
type adminOrgListItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Status      string `json:"status"`
	MemberCount int    `json:"memberCount"`
	CreatedAt   string `json:"createdAt"`
}

type adminOrgListResponse struct {
	Organizations []adminOrgListItem `json:"organizations"`
}

// HandleListAppOrganizations lists every org in the app (active + archived) with
// active-member counts. App-scoped via the path appId.
func (handler *RequestHandler) HandleListAppOrganizations(w http.ResponseWriter, r *http.Request) {
	_, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	views, err := handler.repo.ListOrganizationsForApp(r.Context(), appID)
	if err != nil {
		log.Err(err).Msg("failed to list organizations for app")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	out := adminOrgListResponse{Organizations: make([]adminOrgListItem, 0, len(views))}
	for _, v := range views {
		out.Organizations = append(out.Organizations, adminOrgListItem{
			ID:          v.ID.String(),
			Name:        v.Name,
			Slug:        v.Slug,
			Status:      v.Status,
			MemberCount: v.MemberCount,
			CreatedAt:   v.CreatedAt.Format(time.RFC3339),
		})
	}
	utils.WriteJsonWithStatusCode(w, out, http.StatusOK)
}

// adminOrgFromURL loads {orgId} and enforces it belongs to appID, returning 404
// otherwise. Archived orgs pass (admin must view/rename/archive them); only
// cross-app access is denied. Caller has already run adminAndWorkspace +
// resolvePathIDs.
func (handler *RequestHandler) adminOrgFromURL(w http.ResponseWriter, r *http.Request, appID uuid.UUID) (*core.Organization, bool) {
	orgID, err := utils.GetPathUUID("orgId", r)
	if err != nil || orgID == uuid.Nil {
		WriteError(w, r, "error.organizationNotFound", http.StatusNotFound)
		return nil, false
	}
	org, err := handler.repo.GetOrganizationByID(r.Context(), orgID)
	if err != nil || org == nil || org.AppID != appID {
		WriteError(w, r, "error.organizationNotFound", http.StatusNotFound)
		return nil, false
	}
	return org, true
}

type adminOrgMembersResponse struct {
	Members []repo.OrganizationMemberView `json:"members"`
}

// HandleListAppOrganizationMembers returns an org's members (read-only).
func (handler *RequestHandler) HandleListAppOrganizationMembers(w http.ResponseWriter, r *http.Request) {
	_, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	org, ok := handler.adminOrgFromURL(w, r, appID)
	if !ok {
		return
	}
	members, err := handler.repo.ListOrganizationMembers(r.Context(), org.ID)
	if err != nil {
		log.Err(err).Msg("failed to list organization members")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if members == nil {
		members = []repo.OrganizationMemberView{}
	}
	utils.WriteJsonWithStatusCode(w, adminOrgMembersResponse{Members: members}, http.StatusOK)
}

type renameAppOrganizationRequest struct {
	Name string `json:"name"`
}

type adminOrgResponse struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Status string `json:"status"`
}

// HandleRenameAppOrganization renames an org (name only; slug is preserved so
// downstream mirrors keyed on id/slug don't drift).
func (handler *RequestHandler) HandleRenameAppOrganization(w http.ResponseWriter, r *http.Request) {
	_, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	org, ok := handler.adminOrgFromURL(w, r, appID)
	if !ok {
		return
	}
	var req renameAppOrganizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode json")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	updated, err := handler.repo.UpdateOrganization(r.Context(), org.ID, name, org.Slug)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.organizationNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to rename organization")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJsonWithStatusCode(w, adminOrgResponse{
		ID:     updated.ID.String(),
		Name:   updated.Name,
		Slug:   updated.Slug,
		Status: updated.Status,
	}, http.StatusOK)
}

// HandleArchiveAppOrganization archives an org (status='archived'). Idempotent:
// archiving an already-archived org still returns 204.
func (handler *RequestHandler) HandleArchiveAppOrganization(w http.ResponseWriter, r *http.Request) {
	_, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	org, ok := handler.adminOrgFromURL(w, r, appID)
	if !ok {
		return
	}
	if err := handler.repo.ArchiveOrganization(r.Context(), org.ID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			// Row physically gone — treat as already-archived (idempotent).
			// (Re-archiving an existing archived row returns nil, not ErrNotFound.)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		log.Err(err).Msg("failed to archive organization")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleRestoreAppOrganization restores an archived org (status='active').
// Idempotent for an already-active org. adminOrgFromURL has already loaded and
// ownership-checked the org, so the ErrNotFound->404 branch below is a defensive
// guard against a concurrent hard-delete between that load and the update
// (restoring a gone row is an error, unlike archive's idempotent-gone 204).
func (handler *RequestHandler) HandleRestoreAppOrganization(w http.ResponseWriter, r *http.Request) {
	_, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	org, ok := handler.adminOrgFromURL(w, r, appID)
	if !ok {
		return
	}
	if err := handler.repo.RestoreOrganization(r.Context(), org.ID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.organizationNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to restore organization")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleDeleteAppOrganization permanently hard-deletes an org. Gated to archived
// orgs: an active org returns 409 (must archive first). Members, member-roles and
// invites cascade; client_sessions.organization_id is set NULL. adminOrgFromURL has
// already loaded and ownership-checked the org, so the ErrNotFound->404 branch is a
// defensive guard against a concurrent delete.
func (handler *RequestHandler) HandleDeleteAppOrganization(w http.ResponseWriter, r *http.Request) {
	_, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	org, ok := handler.adminOrgFromURL(w, r, appID)
	if !ok {
		return
	}
	if org.Status != core.OrgStatusArchived {
		WriteError(w, r, "error.organizationNotArchived", http.StatusConflict)
		return
	}
	if err := handler.repo.DeleteOrganization(r.Context(), org.ID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.organizationNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to delete organization")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
