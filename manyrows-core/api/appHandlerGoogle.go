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

// Google sign-in: toggle + credentials in one call. Toggle and creds
// are validated together so it isn't possible to enable Google with no
// client_id (the broken state the previous split allowed).
type updateAppGoogleConfigRequest struct {
	AuthMethodGoogle        *bool   `json:"authMethodGoogle,omitempty"`
	GoogleOAuthClientID     *string `json:"googleOAuthClientId,omitempty"`
	GoogleOAuthClientSecret *string `json:"googleOAuthClientSecret,omitempty"`
}

// HandleUpdateAppGoogleConfig sets the Google sign-in toggle and
// credentials together. Enabling without a client ID is rejected;
// disabling Google when the primary email mode is "none" and no other
// OAuth provider is on leaves the app unusable and is rejected.
func (handler *RequestHandler) HandleUpdateAppGoogleConfig(w http.ResponseWriter, r *http.Request) {
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

	var req updateAppGoogleConfigRequest
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
		log.Err(curAppErr).Msg("failed to load app for google-config update")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	clientID := curApp.GoogleOAuthClientID
	if req.GoogleOAuthClientID != nil {
		trimmed := strings.TrimSpace(*req.GoogleOAuthClientID)
		if trimmed == "" {
			clientID = nil
		} else {
			clientID = &trimmed
		}
	}

	// nil = keep existing (COALESCE in SQL); []byte{} = clear; non-empty = set.
	var clientSecretEncrypted []byte
	if req.GoogleOAuthClientSecret != nil {
		trimmed := strings.TrimSpace(*req.GoogleOAuthClientSecret)
		if trimmed == "" {
			clientSecretEncrypted = []byte{}
		} else {
			encrypted, encErr := handler.encryptor.EncryptToBytesWithAAD(
				[]byte(trimmed),
				crypto.AAD("apps", "google_oauth_client_secret_encrypted", appID),
			)
			if encErr != nil {
				log.Err(encErr).Msg("failed to encrypt google oauth client secret")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
			clientSecretEncrypted = encrypted
		}
	}

	authMethodGoogle := curApp.AuthMethodGoogle
	if req.AuthMethodGoogle != nil {
		authMethodGoogle = *req.AuthMethodGoogle
	}
	// Enabling Google requires a client ID; otherwise the toggle would
	// flip to "on" with no usable credentials, which is the broken
	// state the previous endpoint split allowed.
	if authMethodGoogle && (clientID == nil || *clientID == "") {
		WriteError(w, r, "error.googleClientIdRequired", http.StatusBadRequest)
		return
	}
	// The OAuth Authorization Code flow needs the client secret for the
	// server-to-server token exchange, so the secret is required whenever
	// Google is enabled. Compute the secret state that will result after
	// this update — keep current if not in the request, set/cleared per
	// the encrypted bytes below.
	secretWillExist := len(curApp.GoogleOAuthClientSecretEncrypted) > 0
	if req.GoogleOAuthClientSecret != nil {
		secretWillExist = len(clientSecretEncrypted) > 0
	}
	if authMethodGoogle && !secretWillExist {
		WriteError(w, r, "error.googleClientSecretRequired", http.StatusBadRequest)
		return
	}
	if !handler.requireAtLeastOneSignInMethod(r.Context(), ws, acc.IsSuper(), curApp.PrimaryAuthMethod, authMethodGoogle, curApp.AuthMethodApple, curApp.AuthMethodMicrosoft, curApp.AuthMethodGithub, curApp.AuthMethodKakao, curApp.AuthMethodNaver) {
		WriteError(w, r, "error.noSignInMethodEnabled", http.StatusBadRequest)
		return
	}

	out, err := handler.repo.UpdateAppGoogleConfig(r.Context(), ws.ID, productID, appID, repo.AppGoogleConfigUpdate{
		AuthMethodGoogle:      authMethodGoogle,
		ClientID:              clientID,
		ClientSecretEncrypted: clientSecretEncrypted,
	})
	if err != nil {
		log.Err(err).Msg("failed to update google config")
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, ws), http.StatusOK)
}
