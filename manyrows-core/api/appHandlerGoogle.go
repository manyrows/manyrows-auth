package api

import (
	"errors"
	"net/http"

	"manyrows-core/core/repo"
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
	var req updateAppGoogleConfigRequest
	c, ok := handler.beginOAuthConfigUpdate(w, r, "google", &req)
	if !ok {
		return
	}
	curApp := c.curApp

	clientID := mergeOptionalString(req.GoogleOAuthClientID, curApp.GoogleOAuthClientID)

	clientSecretEncrypted, secretWillExist, ok := handler.encryptOptionalSecret(
		w, r, req.GoogleOAuthClientSecret, curApp.GoogleOAuthClientSecretEncrypted, "google_oauth_client_secret_encrypted", c.appID)
	if !ok {
		return
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
	// Google is enabled.
	if authMethodGoogle && !secretWillExist {
		WriteError(w, r, "error.googleClientSecretRequired", http.StatusBadRequest)
		return
	}
	if !handler.requireAtLeastOneSignInMethod(r.Context(), c.ws, c.acc.IsSuper(), curApp.PrimaryAuthMethod, authMethodGoogle, curApp.AuthMethodApple, curApp.AuthMethodMicrosoft, curApp.AuthMethodGithub, curApp.AuthMethodKakao, curApp.AuthMethodNaver) {
		WriteError(w, r, "error.noSignInMethodEnabled", http.StatusBadRequest)
		return
	}

	out, err := handler.repo.UpdateAppGoogleConfig(r.Context(), c.ws.ID, c.productID, c.appID, repo.AppGoogleConfigUpdate{
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

	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, c.ws), http.StatusOK)
}
