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

// requireOrgRole resolves the acting end-user (session auth), asserts orgs are
// enabled for the app, loads the {orgId} org (must belong to this app + be
// active) and the caller's active membership, and asserts caller.OrgRole is in
// `allowed`. Fail-closed: anything that would reveal an org the caller can't see
// (missing / cross-app / archived / not-an-active-member) -> 404; an active
// member whose tier is not allowed -> 403.
func (handler *RequestHandler) requireOrgRole(
	w http.ResponseWriter, r *http.Request, allowed ...string,
) (*core.App, *core.Organization, *core.OrganizationMember, bool) {
	ctx := r.Context()
	_, identity, _, app, _, ok := handler.requireActiveClientSessionApp(w, r)
	if !ok {
		return nil, nil, nil, false
	}
	if !app.OrganizationsEnabled {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return nil, nil, nil, false
	}
	orgID, err := uuid.FromString(chi.URLParam(r, "orgId"))
	if err != nil || orgID == uuid.Nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return nil, nil, nil, false
	}
	org, err := handler.repo.GetOrganizationByID(ctx, orgID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return nil, nil, nil, false
		}
		log.Err(err).Msg("requireOrgRole: load org failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return nil, nil, nil, false
	}
	if org.AppID != app.ID || org.Status != core.OrgStatusActive {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return nil, nil, nil, false
	}
	caller, err := handler.repo.GetOrganizationMember(ctx, orgID, identity.User.ID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return nil, nil, nil, false
		}
		log.Err(err).Msg("requireOrgRole: load membership failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return nil, nil, nil, false
	}
	if caller.Status != core.OrgMemberStatusActive {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return nil, nil, nil, false
	}
	for _, a := range allowed {
		if caller.OrgRole == a {
			return app, org, caller, true
		}
	}
	WriteError(w, r, "error.forbidden", http.StatusForbidden)
	return nil, nil, nil, false
}

// ClientListOrgMembers: GET /a/organizations/{orgId}/members -- any active member.
func (handler *RequestHandler) ClientListOrgMembers(w http.ResponseWriter, r *http.Request) {
	_, org, _, ok := handler.requireOrgRole(w, r, core.OrgRoleOwner, core.OrgRoleAdmin, core.OrgRoleMember)
	if !ok {
		return
	}
	members, err := handler.repo.ListOrganizationMembers(r.Context(), org.ID)
	if err != nil {
		log.Err(err).Msg("ClientListOrgMembers failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if members == nil {
		members = []repo.OrganizationMemberView{}
	}
	utils.WriteJson(w, map[string]any{"members": members})
}

// ClientListOrganizations: GET /a/organizations -- the caller's orgs in this app.
func (handler *RequestHandler) ClientListOrganizations(w http.ResponseWriter, r *http.Request) {
	_, identity, _, app, _, ok := handler.requireActiveClientSessionApp(w, r)
	if !ok {
		return
	}
	if !app.OrganizationsEnabled {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	orgs, err := handler.repo.ListOrganizationsForUserInApp(r.Context(), app.ID, identity.User.ID)
	if err != nil {
		log.Err(err).Msg("ClientListOrganizations failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if orgs == nil {
		orgs = []core.OrganizationMembershipView{}
	}
	utils.WriteJson(w, map[string]any{"organizations": orgs})
}

type clientUpdateOrgRequest struct {
	Name *string `json:"name"`
	Slug *string `json:"slug"`
}

// ClientRenameOrganization: PATCH /a/organizations/{orgId} -- owner/admin.
func (handler *RequestHandler) ClientRenameOrganization(w http.ResponseWriter, r *http.Request) {
	_, org, _, ok := handler.requireOrgRole(w, r, core.OrgRoleOwner, core.OrgRoleAdmin)
	if !ok {
		return
	}
	var body clientUpdateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if (body.Name != nil && len(strings.TrimSpace(*body.Name)) > maxOrgNameLen) ||
		(body.Slug != nil && len(strings.TrimSpace(*body.Slug)) > maxOrgNameLen) {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	name := org.Name
	if body.Name != nil && strings.TrimSpace(*body.Name) != "" {
		name = strings.TrimSpace(*body.Name)
	}
	baseSlug := org.Slug
	switch {
	case body.Slug != nil && strings.TrimSpace(*body.Slug) != "":
		baseSlug = strings.TrimSpace(*body.Slug)
	case body.Name != nil && strings.TrimSpace(*body.Name) != "":
		baseSlug = simpleSlug(name)
	}
	updated, err := handler.repo.UpdateOrganizationWithUniqueSlug(r.Context(), org.ID, name, baseSlug)
	if err != nil {
		log.Err(err).Msg("ClientRenameOrganization failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, toServerOrg(updated))
}

// ClientArchiveOrganization: DELETE /a/organizations/{orgId} -- owner-only,
// reversible (status=archived). Hard-delete/restore stay operator-side.
func (handler *RequestHandler) ClientArchiveOrganization(w http.ResponseWriter, r *http.Request) {
	_, org, _, ok := handler.requireOrgRole(w, r, core.OrgRoleOwner)
	if !ok {
		return
	}
	if err := handler.repo.ArchiveOrganization(r.Context(), org.ID); err != nil {
		log.Err(err).Msg("ClientArchiveOrganization failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type clientCreateOrgRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// ClientCreateOrganization: POST /a/organizations -- self-serve create, gated by
// org_creation_policy; the creator is seeded as owner.
func (handler *RequestHandler) ClientCreateOrganization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, identity, _, app, _, ok := handler.requireActiveClientSessionApp(w, r)
	if !ok {
		return
	}
	if !app.OrganizationsEnabled {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if app.OrgCreationPolicy != core.OrgCreationSelfServe {
		WriteError(w, r, "error.forbidden", http.StatusForbidden)
		return
	}
	var body clientCreateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(body.Name)
	if len(name) > maxOrgNameLen || len(strings.TrimSpace(body.Slug)) > maxOrgNameLen {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	slug := strings.TrimSpace(body.Slug)
	if slug == "" {
		slug = simpleSlug(name)
	}
	org, err := handler.repo.CreateOrganizationWithOwner(ctx, app.ID, name, slug, identity.User.ID)
	if err != nil {
		log.Err(err).Msg("ClientCreateOrganization failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJsonWithStatusCode(w, toServerOrg(org), http.StatusCreated)
}
