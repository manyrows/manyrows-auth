package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

type switchOrganizationRequest struct {
	OrganizationID string `json:"organizationId"`
}

// SwitchOrganization sets the session's active org and (on next token refresh)
// updates the access-token org claim. The end-user must be an active member of
// an active org under this app.
// POST /x/{workspaceSlug}/apps/{appId}/a/session/organization
func (handler *RequestHandler) SwitchOrganization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ses, identity, _, app, _, ok := handler.requireActiveClientSessionApp(w, r)
	if !ok {
		return
	}
	if !app.OrganizationsEnabled {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	var body switchOrganizationRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	orgID, err := uuid.FromString(body.OrganizationID)
	if err != nil || orgID == uuid.Nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Must be an active member of an active org under THIS app.
	org, err := handler.repo.GetOrganizationByID(ctx, orgID)
	if err != nil {
		if !errors.Is(err, repo.ErrNotFound) {
			log.Err(err).Msg("Could not load organization for switch")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		WriteError(w, r, "error.forbidden", http.StatusForbidden)
		return
	}
	if org.AppID != app.ID || org.Status != core.OrgStatusActive {
		WriteError(w, r, "error.forbidden", http.StatusForbidden)
		return
	}
	member, err := handler.repo.GetOrganizationMember(ctx, orgID, identity.User.ID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.forbidden", http.StatusForbidden)
			return
		}
		log.Err(err).Msg("Could not load org membership")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if member.Status != core.OrgMemberStatusActive {
		WriteError(w, r, "error.forbidden", http.StatusForbidden)
		return
	}

	if err := handler.repo.SetClientSessionOrganization(ctx, ses.ID, &orgID); err != nil {
		log.Err(err).Msg("Could not set session organization")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{
		"organization": core.OrganizationMembershipView{
			ID: org.ID, Name: org.Name, Slug: org.Slug, OrgRole: member.OrgRole,
		},
	})
}
