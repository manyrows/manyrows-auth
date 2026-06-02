package api

import (
	"net/http"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// HandleListTeamMembers returns workspace admin team members.
func (handler *RequestHandler) HandleListTeamMembers(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	members, err := handler.repo.GetWorkspaceAdmins(r.Context(), ws.ID)
	if err != nil {
		log.Err(err).Msg("GetWorkspaceAdmins failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	role, _ := core.WorkspaceRoleFromContext(r.Context())
	utils.WriteJson(w, map[string]any{
		"members":    members,
		"callerRole": role,
	})
}

// HandleAddTeamMember adds an existing account as an admin, or sends an invite if the account doesn't exist. Owner only.
func (handler *RequestHandler) HandleAddTeamMember(w http.ResponseWriter, r *http.Request) {
	acc, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	if !handler.requireOwner(w, r) {
		return
	}

	var req struct {
		Email string `json:"email"`
	}
	if ok := utils.ReadJson(w, r, &req); !ok {
		return
	}

	email := strings.TrimSpace(strings.ToLower(req.Email))
	if email == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	target, vr, err := handler.repo.GetAccountByEmail(r.Context(), email)
	if err != nil {
		log.Err(err).Msg("GetAccountByEmail failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !vr.Ok() {
		WriteValidationError(w, r, vr)
		return
	}

	if target != nil {
		// Account exists — add directly
		admin := core.WorkspaceAdmin{
			WorkspaceID: ws.ID,
			AccountID:   target.ID,
			Role:        "admin",
			AddedBy:     &acc.ID,
		}
		if err := handler.repo.AddWorkspaceAdmin(r.Context(), admin); err != nil {
			log.Err(err).Msg("AddWorkspaceAdmin failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		utils.WriteJson(w, map[string]any{"ok": true})
		return
	}

	// Account doesn't exist — create invite and send email
	already, err := handler.repo.HasPendingInvite(r.Context(), ws.ID, email)
	if err != nil {
		log.Err(err).Msg("HasPendingInvite failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if already {
		WriteError(w, r, "error.team.alreadyInvited", http.StatusConflict)
		return
	}

	invite := core.TeamInvite{
		ID:          utils.NewUUID(),
		WorkspaceID: ws.ID,
		Email:       email,
		InvitedBy:   acc.ID,
		Status:      "pending",
	}
	if err := handler.repo.CreateTeamInvite(r.Context(), invite); err != nil {
		log.Err(err).Msg("CreateTeamInvite failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Create a magic link for the invite (7-day expiry)
	rawToken, tokenHash, err := handler.adminAuthService.NewMagicToken()
	if err != nil {
		log.Err(err).Msg("NewMagicToken failed for team invite")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if err := handler.repo.CreateMagicLink(r.Context(), repo.CreateMagicLinkParams{
		Purpose:   "team_invite",
		Email:     email,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}); err != nil {
		log.Err(err).Msg("CreateMagicLink failed for team invite")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	link := handler.config.GetBaseURL() + "/admin/auth?token=" + rawToken

	lang := "en"
	if acc.Language != "" {
		lang = acc.Language
	}
	if err := handler.emailService.SendTeamInviteEmail(email, acc.Name, ws.Name, link, lang); err != nil {
		log.Err(err).Msg("SendTeamInviteEmail failed")
		// Invite is created, email just failed to send — don't fail the request
	}

	utils.WriteJson(w, map[string]any{"ok": true, "invited": true})
}

// HandleListTeamInvites returns pending team invites for a workspace.
func (handler *RequestHandler) HandleListTeamInvites(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	invites, err := handler.repo.GetPendingInvitesByWorkspace(r.Context(), ws.ID)
	if err != nil {
		log.Err(err).Msg("GetPendingInvitesByWorkspace failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{"invites": invites})
}

// HandleCancelTeamInvite cancels a pending team invite. Owner only.
func (handler *RequestHandler) HandleCancelTeamInvite(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	if !handler.requireOwner(w, r) {
		return
	}

	inviteID, err := utils.GetPathUUID("inviteId", r)
	if err != nil || inviteID == uuid.Nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	if err := handler.repo.DeleteTeamInvite(r.Context(), ws.ID, inviteID); err != nil {
		log.Err(err).Msg("DeleteTeamInvite failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{"ok": true})
}

// HandleRemoveTeamMember removes an admin from the workspace. Owner only.
func (handler *RequestHandler) HandleRemoveTeamMember(w http.ResponseWriter, r *http.Request) {
	acc, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	if !handler.requireOwner(w, r) {
		return
	}

	targetID, err := utils.GetPathUUID("accountId", r)
	if err != nil || targetID == uuid.Nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Cannot remove yourself
	if targetID == acc.ID {
		WriteError(w, r, "error.team.cannotRemoveSelf", http.StatusBadRequest)
		return
	}

	// Cannot remove last owner
	targetRole, found, err := handler.repo.GetWorkspaceAdminRole(r.Context(), ws.ID, targetID)
	if err != nil {
		log.Err(err).Msg("GetWorkspaceAdminRole failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !found {
		WriteError(w, r, "error.team.notFound", http.StatusNotFound)
		return
	}
	if targetRole == "owner" {
		count, err := handler.repo.CountWorkspaceOwners(r.Context(), ws.ID)
		if err != nil {
			log.Err(err).Msg("CountWorkspaceOwners failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if count <= 1 {
			WriteError(w, r, "error.team.cannotRemoveLastOwner", http.StatusBadRequest)
			return
		}
	}

	if err := handler.repo.RemoveWorkspaceAdmin(r.Context(), ws.ID, targetID); err != nil {
		log.Err(err).Msg("RemoveWorkspaceAdmin failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{"ok": true})
}
