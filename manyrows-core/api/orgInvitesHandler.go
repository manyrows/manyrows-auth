package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/email"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

const orgInviteTTL = 7 * 24 * time.Hour

type createOrgInviteRequest struct {
	Email           string      `json:"email"`
	OrgRole         string      `json:"orgRole"`
	RoleIDs         []uuid.UUID `json:"roleIds"`
	InvitedByUserID *uuid.UUID  `json:"invitedByUserId"`
}

type orgInviteResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	OrgRole   string `json:"orgRole"`
	Status    string `json:"status"`
	CreatedAt string `json:"createdAt"`
	ExpiresAt string `json:"expiresAt"`
}

// ServerCreateOrgInvite: POST /v1/apps/{appId}/organizations/{orgId}/invites
func (handler *RequestHandler) ServerCreateOrgInvite(w http.ResponseWriter, r *http.Request) {
	app, org, ok := handler.serverOrgFromURL(w, r)
	if !ok {
		return
	}
	// Accept link needs an app URL.
	base := handler.AppBaseURL(app)
	if app.AppURL == nil || strings.TrimSpace(*app.AppURL) == "" {
		WriteError(w, r, "error.appUrlRequired", http.StatusBadRequest)
		return
	}
	var req createOrgInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	emailAddr := strings.TrimSpace(strings.ToLower(req.Email))
	if emailAddr == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	orgRole := strings.TrimSpace(req.OrgRole)
	if orgRole == "" {
		orgRole = core.OrgRoleAdmin
	}
	if !validOrgRole(orgRole) {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	// Defensive: if the email already resolves to an active member, 409.
	if existing, _ := handler.repo.GetUserByEmail(r.Context(), emailAddr, app); existing != nil {
		if m, _ := handler.repo.GetOrganizationMember(r.Context(), org.ID, existing.ID); m != nil && m.Status == core.OrgMemberStatusActive {
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		}
	}

	rawToken, tokenHash, err := handler.adminAuthService.NewMagicToken()
	if err != nil {
		log.Err(err).Msg("ServerCreateOrgInvite: NewMagicToken failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	inv, err := handler.repo.CreateOrganizationInvite(r.Context(), org.ID, emailAddr, orgRole, req.RoleIDs, req.InvitedByUserID, tokenHash, time.Now().UTC().Add(orgInviteTTL))
	if err != nil {
		if errors.Is(err, repo.ErrInvitePending) {
			WriteError(w, r, "error.invitePending", http.StatusConflict)
			return
		}
		log.Err(err).Msg("ServerCreateOrgInvite: create failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Build accept link + send email; roll back the invite on send failure.
	ws, _ := core.WorkspaceFromContext(r.Context())
	acceptLink := buildOrgInviteAcceptURL(base, ws.Slug, app.ID, rawToken)
	inviterLabel := app.DisplayName()
	msg := email.BuildOrgInviteEmail("en", emailAddr, email.WorkspaceFrom(app.DisplayName()), inviterLabel, org.Name, acceptLink)
	if sendErr := handler.sendWorkspaceEmail(r.Context(), app.WorkspaceID, msg); sendErr != nil {
		log.Err(sendErr).Msg("ServerCreateOrgInvite: email send failed; revoking invite")
		_ = handler.repo.RevokeOrganizationInvite(r.Context(), org.ID, inv.ID)
		WriteError(w, r, "error.inviteEmailFailed", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, orgInviteResponse{
		ID: inv.ID.String(), Email: inv.Email, OrgRole: inv.OrgRole, Status: inv.Status,
		CreatedAt: inv.CreatedAt.Format(time.RFC3339), ExpiresAt: inv.ExpiresAt.Format(time.RFC3339),
	}, http.StatusCreated)
}

type orgInvitesListResponse struct {
	Invites []orgInviteListItem `json:"invites"`
}
type orgInviteListItem struct {
	ID             string  `json:"id"`
	Email          string  `json:"email"`
	OrgRole        string  `json:"orgRole"`
	Status         string  `json:"status"`
	InvitedByEmail *string `json:"invitedByEmail,omitempty"`
	CreatedAt      string  `json:"createdAt"`
	ExpiresAt      string  `json:"expiresAt"`
}

// ServerListOrgInvites: GET …/invites (pending only)
func (handler *RequestHandler) ServerListOrgInvites(w http.ResponseWriter, r *http.Request) {
	_, org, ok := handler.serverOrgFromURL(w, r)
	if !ok {
		return
	}
	views, err := handler.repo.ListPendingOrgInvites(r.Context(), org.ID)
	if err != nil {
		log.Err(err).Msg("ServerListOrgInvites failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	out := orgInvitesListResponse{Invites: make([]orgInviteListItem, 0, len(views))}
	for _, v := range views {
		out.Invites = append(out.Invites, orgInviteListItem{
			ID: v.ID.String(), Email: v.Email, OrgRole: v.OrgRole, Status: v.Status,
			InvitedByEmail: v.InvitedByEmail, CreatedAt: v.CreatedAt.Format(time.RFC3339), ExpiresAt: v.ExpiresAt.Format(time.RFC3339),
		})
	}
	utils.WriteJsonWithStatusCode(w, out, http.StatusOK)
}

// ServerRevokeOrgInvite: DELETE …/invites/{inviteId}
func (handler *RequestHandler) ServerRevokeOrgInvite(w http.ResponseWriter, r *http.Request) {
	_, org, ok := handler.serverOrgFromURL(w, r)
	if !ok {
		return
	}
	inviteID, err := utils.GetPathUUID("inviteId", r)
	if err != nil || inviteID == uuid.Nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if err := handler.repo.RevokeOrganizationInvite(r.Context(), org.ID, inviteID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerRevokeOrgInvite failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// buildOrgInviteAcceptURL builds the public accept link (lands on the auth server).
func buildOrgInviteAcceptURL(baseURL, workspaceSlug string, appID uuid.UUID, token string) string {
	baseURL = strings.TrimRight(baseURL, "/")
	return baseURL + "/x/" + workspaceSlug + "/apps/" + appID.String() + "/auth/org-invite?token=" + token
}
