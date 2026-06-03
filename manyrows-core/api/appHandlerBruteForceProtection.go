package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

// =====================
// Admin: Brute force protection config
// =====================
//
// Per-app toggle for credential-guessing defenses on workspace-user login
// (account lockout + login rate limit). Mirrors the QR sign-in config
// endpoint. Simple enable/disable boolean; on by default.

type updateAppBruteForceProtectionRequest struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// HandleUpdateAppBruteForceProtectionConfig is PUT
// /admin/.../projects/{pid}/apps/{appId}/brute-force-protection-config.
// Returns the standard adminAppResponse (bruteForceProtectionEnabled flows
// through the embedded core.App).
func (handler *RequestHandler) HandleUpdateAppBruteForceProtectionConfig(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	projectID, appID, ok := handler.resolvePathIDs(w, r)
	if !ok {
		return
	}

	var req updateAppBruteForceProtectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("HandleUpdateAppBruteForceProtectionConfig: decode failed")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if req.Enabled == nil {
		WriteError(w, r, "error.invalidRequest", http.StatusBadRequest)
		return
	}

	out, err := handler.repo.UpdateAppBruteForceProtectionConfig(r.Context(), ws.ID, projectID, appID, *req.Enabled)
	if err != nil {
		switch {
		case errors.Is(err, repo.ErrNotFound):
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		default:
			log.Err(err).Msg("HandleUpdateAppBruteForceProtectionConfig: update failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
	}

	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, ws), http.StatusOK)
}
