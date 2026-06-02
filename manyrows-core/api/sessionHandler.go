package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

type WorkspaceSessionsResponse struct {
	Sessions []core.ClientSessionResource `json:"sessions"`
	Total    int                          `json:"total"`
}

// HandleGetWorkspaceSessions
// GET /admin/workspace/{workspaceId}/sessions?limit=25&offset=0&email=foo
//
// Lists ACTIVE client sessions for the workspace (JWT client sessions).
// Optional email filter (substring match).
func (handler *RequestHandler) HandleGetWorkspaceSessions(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	limit := 25
	offset := 0

	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		if n > 200 {
			n = 200
		}
		limit = n
	}

	if v := r.URL.Query().Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		offset = n
	}

	email := strings.TrimSpace(r.URL.Query().Get("email"))

	// Optional app filter
	var appID *uuid.UUID
	if v := strings.TrimSpace(r.URL.Query().Get("appId")); v != "" {
		if id, err := uuid.FromString(v); err == nil {
			appID = &id
		}
	}

	var (
		total    int
		sessions []core.ClientSessionResource
		err      error
	)

	if email != "" {
		total, err = handler.repo.CountActiveClientSessionsForWorkspaceByEmail(r.Context(), ws.ID, email)
		if err != nil {
			log.Err(err).Msg("Could not count workspace client sessions (email filter)")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}

		sessions, err = handler.repo.GetActiveClientSessionResourcesForWorkspaceByEmail(r.Context(), ws.ID, email, limit, offset)
		if err != nil {
			log.Err(err).Msg("Could not get workspace client sessions (email filter)")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
	} else {
		total, err = handler.repo.CountActiveClientSessionsForWorkspace(r.Context(), ws.ID)
		if err != nil {
			log.Err(err).Msg("Could not count workspace client sessions")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}

		sessions, err = handler.repo.GetActiveClientSessionResourcesForWorkspace(r.Context(), ws.ID, limit, offset)
		if err != nil {
			log.Err(err).Msg("Could not get workspace client sessions")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
	}

	// Filter by appId if provided
	if appID != nil {
		filtered := make([]core.ClientSessionResource, 0, len(sessions))
		for _, s := range sessions {
			if s.App != nil && s.App.ID == *appID {
				filtered = append(filtered, s)
			}
		}
		sessions = filtered
		total = len(filtered)
	}

	utils.WriteJson(w, WorkspaceSessionsResponse{
		Sessions: sessions,
		Total:    total,
	})
}

// HandleDeleteWorkspaceSession
// DELETE /admin/workspace/{workspaceId}/sessions/{sessionId}
//
// Revokes a client session by ID.
// Idempotent: if already gone, return 204.
// The session's app must belong to this workspace (validated via the app->project->workspace chain).
func (handler *RequestHandler) HandleDeleteWorkspaceSession(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	sessionID, err := utils.GetPathUUID("sessionId", r)
	if sessionID == uuid.Nil || err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Load the session to verify it belongs to this workspace (via app).
	ses, err := handler.repo.GetClientSessionByID(r.Context(), sessionID)
	if err != nil {
		if errors.Is(err, repo.ErrClientSessionNotFound) || errors.Is(err, repo.ErrClientSessionExpired) {
			// Idempotent delete
			w.WriteHeader(http.StatusNoContent)
			return
		}
		log.Err(err).Msg("Could not load client session for delete")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if ses == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Verify the session's app belongs to this workspace.
	// The admin middleware already validated workspace access, but we still verify
	// the session is within scope. If AppID is nil, allow deletion by the admin.
	if ses.AppID != nil {
		app, err := handler.repo.GetAppByID(r.Context(), *ses.AppID)
		if err != nil {
			log.Err(err).Msg("Could not load app for session workspace check")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if app.WorkspaceID != ws.ID {
			WriteError(w, r, "error.sessionNotFound", http.StatusNotFound)
			return
		}
	}

	// Revoke all refresh tokens for this session BEFORE deleting the
	// session row. If token revocation fails we MUST fail-closed: the
	// previous behaviour deleted the session while leaving live refresh
	// tokens behind, which depending on join semantics could let those
	// tokens still pass validation. The admin can retry the call.
	if err := handler.clientAuthService.RevokeAllSessionTokens(r.Context(), sessionID); err != nil {
		log.Err(err).Str("sessionId", sessionID.String()).Msg("Could not revoke refresh tokens for session — aborting session deletion to avoid leaving live tokens")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Delete the session
	if err := handler.clientAuthService.DeleteSession(r.Context(), sessionID); err != nil {
		log.Err(err).Msg("Could not revoke client session")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	subjectUserID := ses.UserID
	in := AuthLogInput{
		WorkspaceID:   ws.ID,
		AppID:         ses.AppID,
		Event:         core.AuthEventSessionRevoked,
		Outcome:       core.AuthOutcomeSuccess,
		SubjectUserID: &subjectUserID,
		ActorType:     core.AuthActorAdmin,
		Metadata:      core.SessionRevokedMetadata{TargetSessionID: sessionID},
	}
	if admin, ok := core.AdminAccountFromContext(r.Context()); ok && admin != nil {
		in.ActorAccountID = &admin.ID
		in.ActorLabel = admin.Email
	}
	handler.writeAuthLogFromRequest(r, in)

	w.WriteHeader(http.StatusNoContent)
}

// HandlePruneExpiredSessions
// POST /admin/workspace/{workspaceId}/sessions/prune
//
// Deletes all expired client sessions for the workspace.
// Returns JSON { "deleted": N }.
func (handler *RequestHandler) HandlePruneExpiredSessions(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	deleted, err := handler.repo.DeleteExpiredClientSessions(r.Context(), ws.ID)
	if err != nil {
		log.Err(err).Msg("Could not prune expired client sessions")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if deleted > 0 {
		in := AuthLogInput{
			WorkspaceID: ws.ID,
			Event:       core.AuthEventSessionsPruned,
			Outcome:     core.AuthOutcomeSuccess,
			ActorType:   core.AuthActorAdmin,
			Metadata:    core.SessionsPrunedMetadata{Count: int(deleted)},
		}
		if admin, ok := core.AdminAccountFromContext(r.Context()); ok && admin != nil {
			in.ActorAccountID = &admin.ID
			in.ActorLabel = admin.Email
		}
		handler.writeAuthLogFromRequest(r, in)
	}

	utils.WriteJson(w, map[string]int64{"deleted": deleted})
}

// HandleDeleteWorkspaceSessionsByAccount
// DELETE /admin/workspace/{workspaceId}/sessions?accountId=...&exclude=...
//
// Revokes all sessions for a specific user.
// Optional 'exclude' param to preserve a specific session (e.g., current session).
func (handler *RequestHandler) HandleDeleteWorkspaceSessionsByAccount(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	accountIDStr := strings.TrimSpace(r.URL.Query().Get("accountId"))
	if accountIDStr == "" {
		WriteError(w, r, "error.missingAccountId", http.StatusBadRequest)
		return
	}

	userID, err := uuid.FromString(accountIDStr)
	if err != nil || userID == uuid.Nil {
		WriteError(w, r, "error.invalidAccountId", http.StatusBadRequest)
		return
	}

	// Scope the target user to this workspace. Users carry no workspace_id, so
	// without this an admin could revoke any user's sessions across tenants.
	if _, ok := handler.requireUserInWorkspace(w, r, ws.ID, userID); !ok {
		return
	}

	// Optional: exclude a specific session from deletion
	var excludeSessionID *uuid.UUID
	if excludeStr := strings.TrimSpace(r.URL.Query().Get("exclude")); excludeStr != "" {
		if id, err := uuid.FromString(excludeStr); err == nil && id != uuid.Nil {
			excludeSessionID = &id
		}
	}

	_, err = handler.repo.DeleteClientSessionsByUser(r.Context(), userID, excludeSessionID)
	if err != nil {
		log.Err(err).Msg("Could not delete sessions by user")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	in := AuthLogInput{
		WorkspaceID:   ws.ID,
		Event:         core.AuthEventSessionRevoked,
		Outcome:       core.AuthOutcomeSuccess,
		SubjectUserID: &userID,
		ActorType:     core.AuthActorAdmin,
	}
	if admin, ok := core.AdminAccountFromContext(r.Context()); ok && admin != nil {
		in.ActorAccountID = &admin.ID
		in.ActorLabel = admin.Email
	}
	handler.writeAuthLogFromRequest(r, in)

	w.WriteHeader(http.StatusNoContent)
}
