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

	var req updateAppKakaoConfigRequest
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
		log.Err(curAppErr).Msg("failed to load app for kakao-config update")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	clientID := curApp.KakaoClientID
	if req.KakaoClientID != nil {
		trimmed := strings.TrimSpace(*req.KakaoClientID)
		if trimmed == "" {
			clientID = nil
		} else {
			clientID = &trimmed
		}
	}

	// nil = keep existing; []byte{} = clear; non-empty = encrypt+set.
	var clientSecretEncrypted []byte
	postSaveHasSecret := len(curApp.KakaoClientSecretEncrypted) > 0
	if req.KakaoClientSecret != nil {
		trimmed := strings.TrimSpace(*req.KakaoClientSecret)
		if trimmed == "" {
			clientSecretEncrypted = []byte{}
			postSaveHasSecret = false
		} else {
			encrypted, encErr := handler.encryptor.EncryptToBytesWithAAD(
				[]byte(trimmed),
				crypto.AAD("apps", "kakao_client_secret_encrypted", appID),
			)
			if encErr != nil {
				log.Err(encErr).Msg("failed to encrypt kakao client secret")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
			clientSecretEncrypted = encrypted
			postSaveHasSecret = true
		}
	}

	authMethodKakao := curApp.AuthMethodKakao
	if req.AuthMethodKakao != nil {
		authMethodKakao = *req.AuthMethodKakao
	}
	if authMethodKakao && (clientID == nil || *clientID == "" || !postSaveHasSecret) {
		WriteError(w, r, "error.kakaoConfigIncomplete", http.StatusBadRequest)
		return
	}
	if !handler.requireAtLeastOneSignInMethod(r.Context(), ws, acc.IsSuper(), curApp.PrimaryAuthMethod, curApp.AuthMethodGoogle, curApp.AuthMethodApple, curApp.AuthMethodMicrosoft, curApp.AuthMethodGithub, authMethodKakao) {
		WriteError(w, r, "error.noSignInMethodEnabled", http.StatusBadRequest)
		return
	}

	out, err := handler.repo.UpdateAppKakaoConfig(r.Context(), ws.ID, productID, appID, repo.AppKakaoConfigUpdate{
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

	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, ws), http.StatusOK)
}
