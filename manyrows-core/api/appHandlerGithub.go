package api

import (
	"errors"
	"net/http"

	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

// GitHub sign-in: toggle + OAuth App credentials. GitHub doesn't have
// a tenant concept — verification + scoping happen via the user's
// own verified-email mechanism.
type updateAppGithubConfigRequest struct {
	AuthMethodGithub   *bool   `json:"authMethodGithub,omitempty"`
	GithubClientID     *string `json:"githubClientId,omitempty"`
	GithubClientSecret *string `json:"githubClientSecret,omitempty"`
}

// HandleUpdateAppGithubConfig sets the GitHub sign-in toggle and OAuth
// credentials together. Enabling requires both client ID and secret;
// disabling when the primary email mode is "none" and no other OAuth
// provider is on leaves the app unusable and is rejected.
func (handler *RequestHandler) HandleUpdateAppGithubConfig(w http.ResponseWriter, r *http.Request) {
	var req updateAppGithubConfigRequest
	c, ok := handler.beginOAuthConfigUpdate(w, r, "github", &req)
	if !ok {
		return
	}
	curApp := c.curApp

	clientID := mergeOptionalString(req.GithubClientID, curApp.GithubClientID)

	clientSecretEncrypted, postSaveHasSecret, ok := handler.encryptOptionalSecret(
		w, r, req.GithubClientSecret, curApp.GithubClientSecretEncrypted, "github_client_secret_encrypted", c.appID)
	if !ok {
		return
	}

	authMethodGithub := curApp.AuthMethodGithub
	if req.AuthMethodGithub != nil {
		authMethodGithub = *req.AuthMethodGithub
	}
	if authMethodGithub && (clientID == nil || *clientID == "" || !postSaveHasSecret) {
		WriteError(w, r, "error.githubConfigIncomplete", http.StatusBadRequest)
		return
	}
	if !handler.requireAtLeastOneSignInMethod(r.Context(), c.ws, c.acc.IsSuper(), curApp.PrimaryAuthMethod, curApp.AuthMethodGoogle, curApp.AuthMethodApple, curApp.AuthMethodMicrosoft, authMethodGithub, curApp.AuthMethodKakao, curApp.AuthMethodNaver) {
		WriteError(w, r, "error.noSignInMethodEnabled", http.StatusBadRequest)
		return
	}

	out, err := handler.repo.UpdateAppGithubConfig(r.Context(), c.ws.ID, c.productID, c.appID, repo.AppGithubConfigUpdate{
		AuthMethodGithub:      authMethodGithub,
		ClientID:              clientID,
		ClientSecretEncrypted: clientSecretEncrypted,
	})
	if err != nil {
		log.Err(err).Msg("failed to update github config")
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, c.ws), http.StatusOK)
}
