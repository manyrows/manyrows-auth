package api

import (
	"errors"
	"net/http"

	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

// Kakao sign-in: toggle + OAuth credentials. The client ID is the Kakao
// app's REST API key; the client secret is Kakao's opt-in security feature
// (Security → Client Secret on the customer's Kakao app). Like the other
// bespoke providers, enabling Kakao requires both, so the customer must
// turn on Client Secret — documented as a prerequisite in the admin UI,
// alongside the account_email consent (Business verification) requirement.
type updateAppKakaoConfigRequest struct {
	AuthMethodKakao   *bool   `json:"authMethodKakao,omitempty"`
	KakaoClientID     *string `json:"kakaoClientId,omitempty"`
	KakaoClientSecret *string `json:"kakaoClientSecret,omitempty"`
}

// HandleUpdateAppKakaoConfig sets the Kakao sign-in toggle and OAuth
// credentials together. Enabling requires both client ID (REST API key) and
// secret; disabling when the primary email mode is "none" and no other OAuth
// provider is on leaves the app unusable and is rejected.
func (handler *RequestHandler) HandleUpdateAppKakaoConfig(w http.ResponseWriter, r *http.Request) {
	var req updateAppKakaoConfigRequest
	c, ok := handler.beginOAuthConfigUpdate(w, r, "kakao", &req)
	if !ok {
		return
	}
	curApp := c.curApp

	clientID := mergeOptionalString(req.KakaoClientID, curApp.KakaoClientID)

	clientSecretEncrypted, postSaveHasSecret, ok := handler.encryptOptionalSecret(
		w, r, req.KakaoClientSecret, curApp.KakaoClientSecretEncrypted, "kakao_client_secret_encrypted", c.appID)
	if !ok {
		return
	}

	authMethodKakao := curApp.AuthMethodKakao
	if req.AuthMethodKakao != nil {
		authMethodKakao = *req.AuthMethodKakao
	}
	if authMethodKakao && (clientID == nil || *clientID == "" || !postSaveHasSecret) {
		WriteError(w, r, "error.kakaoConfigIncomplete", http.StatusBadRequest)
		return
	}
	if !handler.requireAtLeastOneSignInMethod(r.Context(), c.ws, c.acc.IsSuper(), curApp.PrimaryAuthMethod, curApp.AuthMethodGoogle, curApp.AuthMethodApple, curApp.AuthMethodMicrosoft, curApp.AuthMethodGithub, authMethodKakao, curApp.AuthMethodNaver) {
		WriteError(w, r, "error.noSignInMethodEnabled", http.StatusBadRequest)
		return
	}

	out, err := handler.repo.UpdateAppKakaoConfig(r.Context(), c.ws.ID, c.projectID, c.appID, repo.AppKakaoConfigUpdate{
		AuthMethodKakao:       authMethodKakao,
		ClientID:              clientID,
		ClientSecretEncrypted: clientSecretEncrypted,
	})
	if err != nil {
		log.Err(err).Msg("failed to update kakao config")
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, c.ws), http.StatusOK)
}
