package api

import (
	"net/http"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

// HandleAdminUserOrganizations returns the organizations a user belongs to
// in this app, for the admin user-detail view. Display-only; membership
// management stays in the org screens.
// GET /admin/workspace/{workspaceId}/projects/{projectId}/apps/{appId}/users/{userId}/organizations
func (handler *RequestHandler) HandleAdminUserOrganizations(w http.ResponseWriter, r *http.Request) {
	_, _, appID, ok := handler.parseAppContext(w, r)
	if !ok {
		return
	}
	user, ok := handler.loadUserScopedToApp(w, r, appID)
	if !ok {
		return
	}
	views, err := handler.repo.ListOrganizationsForUserInApp(r.Context(), appID, user.ID)
	if err != nil {
		log.Err(err).Msg("admin user organizations: list failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if views == nil {
		views = []core.OrganizationMembershipView{}
	}
	utils.WriteJsonWithStatusCode(w, map[string]any{"organizations": views}, http.StatusOK)
}
