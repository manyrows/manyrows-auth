package api

import (
	"net/http"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

type AdminAppData struct {
	Env     string `json:"env"`
	BaseURL string `json:"baseUrl"`
	// Version is the build version (config.BuildVersion). The admin
	// UI shows it in the account menu so operators / support can
	// confirm which release is running.
	Version    string               `json:"version,omitempty"`
	Account    core.AccountResource `json:"account"`
	Workspaces []WorkspaceResource  `json:"workspaces"`
}

func (handler *RequestHandler) GetAdminAppData(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acc, ok := core.AdminAccountFromContext(ctx)
	if !ok {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	// Prevent caching of auth bootstrap data
	w.Header().Set("Cache-Control", "no-store")

	// Get workspaces this account has access to (via workspace_admins)
	memberships, err := handler.repo.GetWorkspacesForAccount(ctx, acc.ID)
	if err != nil {
		log.Err(err).Msg("failed to get workspaces for admin app data")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	workspaces := make([]WorkspaceResource, 0, len(memberships))
	for _, m := range memberships {
		wrs := WorkspaceResource{
			ID:                        m.ID,
			Name:                      m.Name,
			Slug:                      m.Slug,
			Status:                    m.Status,
			CreatedAt:                 m.CreatedAt,
			Role:                      m.Role,
			SetupChecklistDismissedAt: m.SetupChecklistDismissedAt,
			SetupTestEmailSentAt:      m.SetupTestEmailSentAt,
		}

		products, err := handler.repo.GetProductsByWorkspaceID(ctx, m.ID)
		if err != nil {
			log.Err(err).Msg("failed to get products by workspace ID for admin app data")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		wrs.Products = products

		workspaces = append(workspaces, wrs)
	}

	accResource := core.ToAccountResource(acc)
	appData := AdminAppData{
		Account:    *accResource,
		Workspaces: workspaces,
		BaseURL:    handler.config.GetBaseURL(),
		Env:        handler.config.GetProfile(),
		Version:    handler.config.GetVersion(),
	}

	session, err := handler.adminAuthService.GetSession(r)
	if err != nil {
		log.Err(err).Msg("Could not get session")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if session != nil {
		_, err = handler.repo.TouchSessionLastSeen(ctx, session.ID)
		if err != nil {
			log.Err(err).Msg("Could not touch session last seen")
		}
	}

	utils.WriteJson(w, appData)
}
