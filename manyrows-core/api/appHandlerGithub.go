package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"manyrows-core/core/repo"
	"manyrows-core/crypto"
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
	acc, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	if !handler.requireOwner(w, r) {
		return
	}
	productID, appID, ok := handler.resolvePathIDs(w, r)
	if !ok {
		return
	}

	var req updateAppGithubConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode json")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	curApp, curAppErr := handler.repo.GetAppByIDForProduct(r.Context(), ws.ID, productID, appID)
	if curAppErr != nil {
		if errors.Is(curAppErr, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		log.Err(curAppErr).Msg("failed to load app for github-config update")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	clientID := curApp.GithubClientID
	if req.GithubClientID != nil {
		trimmed := strings.TrimSpace(*req.GithubClientID)
		if trimmed == "" {
			clientID = nil
		} else {
			clientID = &trimmed
		}
	}

	// nil = keep existing; []byte{} = clear; non-empty = encrypt+set.
	var clientSecretEncrypted []byte
	postSaveHasSecret := len(curApp.GithubClientSecretEncrypted) > 0
	if req.GithubClientSecret != nil {
		trimmed := strings.TrimSpace(*req.GithubClientSecret)
		if trimmed == "" {
			clientSecretEncrypted = []byte{}
			postSaveHasSecret = false
		} else {
			encrypted, encErr := handler.encryptor.EncryptToBytesWithAAD(
				[]byte(trimmed),
				crypto.AAD("apps", "github_client_secret_encrypted", appID),
			)
			if encErr != nil {
				log.Err(encErr).Msg("failed to encrypt github client secret")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
			clientSecretEncrypted = encrypted
			postSaveHasSecret = true
		}
	}

	authMethodGithub := curApp.AuthMethodGithub
	if req.AuthMethodGithub != nil {
		authMethodGithub = *req.AuthMethodGithub
	}
	if authMethodGithub && (clientID == nil || *clientID == "" || !postSaveHasSecret) {
		WriteError(w, r, "error.githubConfigIncomplete", http.StatusBadRequest)
		return
	}
	if !handler.requireAtLeastOneSignInMethod(r.Context(), ws, acc.IsSuper(), curApp.PrimaryAuthMethod, curApp.AuthMethodGoogle, curApp.AuthMethodApple, curApp.AuthMethodMicrosoft, authMethodGithub) {
		WriteError(w, r, "error.noSignInMethodEnabled", http.StatusBadRequest)
		return
	}

	out, err := handler.repo.UpdateAppGithubConfig(r.Context(), ws.ID, productID, appID, repo.AppGithubConfigUpdate{
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

	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, ws), http.StatusOK)
}
