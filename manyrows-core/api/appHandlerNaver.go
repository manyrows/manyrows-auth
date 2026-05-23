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

	var req updateAppNaverConfigRequest
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
		log.Err(curAppErr).Msg("failed to load app for naver-config update")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	clientID := curApp.NaverClientID
	if req.NaverClientID != nil {
		trimmed := strings.TrimSpace(*req.NaverClientID)
		if trimmed == "" {
			clientID = nil
		} else {
			clientID = &trimmed
		}
	}

	// nil = keep existing; []byte{} = clear; non-empty = encrypt+set.
	var clientSecretEncrypted []byte
	postSaveHasSecret := len(curApp.NaverClientSecretEncrypted) > 0
	if req.NaverClientSecret != nil {
		trimmed := strings.TrimSpace(*req.NaverClientSecret)
		if trimmed == "" {
			clientSecretEncrypted = []byte{}
			postSaveHasSecret = false
		} else {
			encrypted, encErr := handler.encryptor.EncryptToBytesWithAAD(
				[]byte(trimmed),
				crypto.AAD("apps", "naver_client_secret_encrypted", appID),
			)
			if encErr != nil {
				log.Err(encErr).Msg("failed to encrypt naver client secret")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
			clientSecretEncrypted = encrypted
			postSaveHasSecret = true
		}
	}

	authMethodNaver := curApp.AuthMethodNaver
	if req.AuthMethodNaver != nil {
		authMethodNaver = *req.AuthMethodNaver
	}
	if authMethodNaver && (clientID == nil || *clientID == "" || !postSaveHasSecret) {
		WriteError(w, r, "error.naverConfigIncomplete", http.StatusBadRequest)
		return
	}
	if !handler.requireAtLeastOneSignInMethod(r.Context(), ws, acc.IsSuper(), curApp.PrimaryAuthMethod, curApp.AuthMethodGoogle, curApp.AuthMethodApple, curApp.AuthMethodMicrosoft, curApp.AuthMethodGithub, curApp.AuthMethodKakao, authMethodNaver) {
		WriteError(w, r, "error.noSignInMethodEnabled", http.StatusBadRequest)
		return
	}

	out, err := handler.repo.UpdateAppNaverConfig(r.Context(), ws.ID, productID, appID, repo.AppNaverConfigUpdate{
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

	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, ws), http.StatusOK)
}
