package api

import (
	"encoding/json"
	"net/http"

	"manyrows-core/auth"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

type ServerSetUserEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

type ServerUserEnabledResponse struct {
	UserID  string `json:"userId"`
	Enabled bool   `json:"enabled"`
}

// ServerSetUserEnabled enables or disables a user's identity POOL-WIDE (the
// users.enabled flag) — distinct from the per-app suspend on PATCH /users/{id}.
// Disabling blocks sign-in to EVERY app sharing the pool and revokes all of the
// user's sessions, so it's a real cross-app blast radius; use it to ban a bad
// actor everywhere, not to gate a single app. Gated on membership of the
// calling app.
// PUT /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/enabled
func (handler *RequestHandler) ServerSetUserEnabled(w http.ResponseWriter, r *http.Request) {
	_, userID, ok := handler.resolveAppMember(w, r)
	if !ok {
		return
	}

	var req ServerSetUserEnabledRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	if err := handler.repo.SetUserEnabled(ctx, userID, req.Enabled); err != nil {
		log.Err(err).Msg("ServerSetUserEnabled: SetUserEnabled failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if !req.Enabled {
		// Disabling is pool-wide: revoke every session so existing tokens stop
		// working across all apps. Best-effort — the disable already committed.
		if _, err := handler.repo.DeleteClientSessionsByUser(ctx, userID, nil); err != nil {
			log.Err(err).Msg("ServerSetUserEnabled: revoke sessions failed")
		}
	}

	utils.WriteJson(w, ServerUserEnabledResponse{UserID: userID.String(), Enabled: req.Enabled})
}

type ServerChangeEmailRequest struct {
	Email string `json:"email"`
}

type ServerChangeEmailResponse struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
}

// ServerChangeUserEmail changes a member's email and marks it verified (the
// caller vouches for it — there's no re-verification round-trip). The new
// address must be unique within the pool (409 otherwise). Pool-level.
// PUT /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/email
func (handler *RequestHandler) ServerChangeUserEmail(w http.ResponseWriter, r *http.Request) {
	_, userID, ok := handler.resolveAppMember(w, r)
	if !ok {
		return
	}

	var req ServerChangeEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	email, vr := auth.ValidateEmail(req.Email)
	if !vr.Ok() {
		WriteValidationError(w, r, vr)
		return
	}

	if err := handler.repo.UpdateUserEmail(r.Context(), userID, email); err != nil {
		if repo.IsUniqueViolation(err) {
			WriteError(w, r, "error.emailTaken", http.StatusConflict)
			return
		}
		log.Err(err).Msg("ServerChangeUserEmail: UpdateUserEmail failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, ServerChangeEmailResponse{UserID: userID.String(), Email: email})
}
