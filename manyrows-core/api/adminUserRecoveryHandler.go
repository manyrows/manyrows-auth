package api

import (
	"net/http"

	"github.com/rs/zerolog/log"
)

// HandleAdminResetUserTOTP disables a user's TOTP/2FA from the admin panel —
// the support operation for a user who lost their authenticator. They re-enroll
// via the normal flow afterward. Mirrors the S2S ServerResetUserTOTP.
// DELETE /admin/workspace/{workspaceId}/projects/{projectId}/apps/{appId}/users/{userId}/totp
func (handler *RequestHandler) HandleAdminResetUserTOTP(w http.ResponseWriter, r *http.Request) {
	_, _, appID, ok := handler.parseAppContext(w, r)
	if !ok {
		return
	}
	user, ok := handler.loadUserScopedToApp(w, r, appID)
	if !ok {
		return
	}
	if err := handler.repo.DisableUserTOTP(r.Context(), user.ID); err != nil {
		log.Err(err).Msg("Could not reset user TOTP (admin)")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	handler.dispatchMFAEvent(whMFADisabled, appID, user.ID)
	w.WriteHeader(http.StatusNoContent)
}

// HandleAdminUnlockUser clears a failed-login lockout on a user from the admin
// panel, restoring sign-in immediately. Mirrors the S2S ServerUnlockUser.
// POST /admin/workspace/{workspaceId}/projects/{projectId}/apps/{appId}/users/{userId}/unlock
func (handler *RequestHandler) HandleAdminUnlockUser(w http.ResponseWriter, r *http.Request) {
	_, _, appID, ok := handler.parseAppContext(w, r)
	if !ok {
		return
	}
	user, ok := handler.loadUserScopedToApp(w, r, appID)
	if !ok {
		return
	}
	if err := handler.repo.ClearUserLockedUntil(r.Context(), user.ID); err != nil {
		log.Err(err).Msg("Could not unlock user (admin)")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
