package api

import (
	"errors"
	"net/http"

	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

// Naver sign-in: toggle + OAuth credentials. Naver is OAuth2-only; both the
// client ID and secret are mandatory (Naver always requires a client secret,
// unlike Kakao's opt-in one).
type updateAppNaverConfigRequest struct {
	AuthMethodNaver   *bool   `json:"authMethodNaver,omitempty"`
	NaverClientID     *string `json:"naverClientId,omitempty"`
	NaverClientSecret *string `json:"naverClientSecret,omitempty"`
}

// HandleUpdateAppNaverConfig sets the Naver sign-in toggle and OAuth
// credentials together. Enabling requires both client ID and secret;
// disabling when the primary email mode is "none" and no other OAuth provider
// is on leaves the app unusable and is rejected.
func (handler *RequestHandler) HandleUpdateAppNaverConfig(w http.ResponseWriter, r *http.Request) {
	var req updateAppNaverConfigRequest
	c, ok := handler.beginOAuthConfigUpdate(w, r, "naver", &req)
	if !ok {
		return
	}
	curApp := c.curApp

	clientID := mergeOptionalString(req.NaverClientID, curApp.NaverClientID)

	clientSecretEncrypted, postSaveHasSecret, ok := handler.encryptOptionalSecret(
		w, r, req.NaverClientSecret, curApp.NaverClientSecretEncrypted, "naver_client_secret_encrypted", c.appID)
	if !ok {
		return
	}

	authMethodNaver := curApp.AuthMethodNaver
	if req.AuthMethodNaver != nil {
		authMethodNaver = *req.AuthMethodNaver
	}
	if authMethodNaver && (clientID == nil || *clientID == "" || !postSaveHasSecret) {
		WriteError(w, r, "error.naverConfigIncomplete", http.StatusBadRequest)
		return
	}
	if !handler.requireAtLeastOneSignInMethod(r.Context(), c.ws, c.acc.IsSuper(), curApp.PrimaryAuthMethod, curApp.AuthMethodGoogle, curApp.AuthMethodApple, curApp.AuthMethodMicrosoft, curApp.AuthMethodGithub, curApp.AuthMethodKakao, authMethodNaver) {
		WriteError(w, r, "error.noSignInMethodEnabled", http.StatusBadRequest)
		return
	}

	out, err := handler.repo.UpdateAppNaverConfig(r.Context(), c.ws.ID, c.productID, c.appID, repo.AppNaverConfigUpdate{
		AuthMethodNaver:       authMethodNaver,
		ClientID:              clientID,
		ClientSecretEncrypted: clientSecretEncrypted,
	})
	if err != nil {
		log.Err(err).Msg("failed to update naver config")
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, c.ws), http.StatusOK)
}
