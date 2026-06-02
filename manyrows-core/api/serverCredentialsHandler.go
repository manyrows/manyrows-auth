package api

import (
	"encoding/json"
	"net/http"
	"time"

	"manyrows-core/core"
	"manyrows-core/crypto/passwordhash"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

type ServerSetPasswordRequest struct {
	Password string `json:"password"`
}

// ServerSetUserPassword sets (or replaces) a member's password, enforcing the
// app's password policy. Existing sessions are left intact — call
// DELETE /users/{userId}/sessions to force re-login if you want that.
// PUT /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/password
func (handler *RequestHandler) ServerSetUserPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}
	if !handler.requireAppMember(w, r, app.ID, userID) {
		return
	}

	var req ServerSetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Load the user so the email can seed the strength check (zxcvbn scores
	// passwords lower when they echo the user's own address).
	user, err := handler.repo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		log.Err(err).Msg("ServerSetUserPassword: GetUserByID failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if pol := checkPasswordPolicy(app, req.Password, user.Email); !pol.OK {
		if pol.Issue == "too_short" {
			WriteErrorf(w, r, "error.passwordTooShort", http.StatusBadRequest, pol.MinLength)
		} else {
			WriteError(w, r, "error.passwordTooWeak", http.StatusBadRequest)
		}
		return
	}

	hash, err := passwordhash.Hash(req.Password)
	if err != nil {
		log.Err(err).Msg("ServerSetUserPassword: hash failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if err := handler.repo.UpdateUserPassword(ctx, userID, hash, time.Now().UTC()); err != nil {
		log.Err(err).Msg("ServerSetUserPassword: UpdateUserPassword failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ServerClearUserPassword removes a member's password. They can no longer sign
// in with email+password until a new one is set (OAuth/passkey still work).
// DELETE /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/password
func (handler *RequestHandler) ServerClearUserPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}
	if !handler.requireAppMember(w, r, app.ID, userID) {
		return
	}

	if err := handler.repo.ClearUserPassword(ctx, userID); err != nil {
		log.Err(err).Msg("ServerClearUserPassword: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type ServerSessionSummary struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	UserAgent  string    `json:"userAgent,omitempty"`
	IP         string    `json:"ip,omitempty"`
}

type ServerSessionsResponse struct {
	Sessions []ServerSessionSummary `json:"sessions"`
}

// ServerListUserSessions lists a member's active sessions for THIS app.
// GET /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/sessions
func (handler *RequestHandler) ServerListUserSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}
	if !handler.requireAppMember(w, r, app.ID, userID) {
		return
	}

	all, err := handler.repo.GetActiveClientSessionsByUserID(ctx, userID)
	if err != nil {
		log.Err(err).Msg("ServerListUserSessions: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	out := make([]ServerSessionSummary, 0, len(all))
	for _, s := range all {
		if s.AppID == nil || *s.AppID != app.ID {
			continue // only this app's sessions
		}
		out = append(out, ServerSessionSummary{
			ID:         s.ID.String(),
			CreatedAt:  s.CreatedAt,
			LastSeenAt: s.LastSeenAt,
			ExpiresAt:  s.ExpiresAt,
			UserAgent:  s.UserAgent,
			IP:         s.IP,
		})
	}

	utils.WriteJson(w, ServerSessionsResponse{Sessions: out})
}

// ServerRevokeUserSession revokes a single session of a member in this app.
// DELETE /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/sessions/{sessionId}
func (handler *RequestHandler) ServerRevokeUserSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}
	if !handler.requireAppMember(w, r, app.ID, userID) {
		return
	}

	sessionID, err := uuid.FromString(chi.URLParam(r, "sessionId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Confirm the session belongs to this user AND this app before deleting,
	// so a key can't revoke arbitrary sessions by guessing IDs.
	all, err := handler.repo.GetActiveClientSessionsByUserID(ctx, userID)
	if err != nil {
		log.Err(err).Msg("ServerRevokeUserSession: lookup failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	owned := false
	for _, s := range all {
		if s.ID == sessionID && s.AppID != nil && *s.AppID == app.ID {
			owned = true
			break
		}
	}
	if !owned {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	if _, err := handler.repo.DeleteClientSession(ctx, sessionID); err != nil {
		log.Err(err).Msg("ServerRevokeUserSession: delete failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
