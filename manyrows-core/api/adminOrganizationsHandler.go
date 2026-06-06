package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

// updateAppOrganizationsEnabledRequest toggles per-app org mode from the admin
// panel. Pointer so a missing field is rejected, not silently treated as false.
type updateAppOrganizationsEnabledRequest struct {
	OrganizationsEnabled *bool `json:"organizationsEnabled"`
}

// HandleUpdateAppOrganizationsEnabled flips apps.organizations_enabled for one
// app, scoped to the caller's workspace+project, and returns the updated app.
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

	out, err := handler.repo.UpdateAppOrganizationsEnabled(r.Context(), ws.ID, projectID, appID, *req.OrganizationsEnabled)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to update app organizations flag")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, ws), http.StatusOK)
}
