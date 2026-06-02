package api

import (
	"errors"
	"net/http"
	"strings"

	"manyrows-core/auth/apple"
	"manyrows-core/core/repo"
	"manyrows-core/crypto"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

// Apple sign-in: toggle + credentials in one call. Same atomicity
// guarantee — enabling without the four required fields is rejected.
type updateAppAppleConfigRequest struct {
	AuthMethodApple *bool   `json:"authMethodApple,omitempty"`
	AppleServicesID *string `json:"appleServicesId,omitempty"`
	AppleTeamID     *string `json:"appleTeamId,omitempty"`
	AppleKeyID      *string `json:"appleKeyId,omitempty"`
	ApplePrivateKey *string `json:"applePrivateKey,omitempty"`
}

// HandleUpdateAppAppleConfig sets the Apple sign-in toggle and
// credentials together. Enabling requires all four fields (services
// ID, team ID, key ID, and a stored .p8). Disabling when the primary
// email mode is "none" and no other OAuth provider is on leaves the
// app unusable and is rejected.
func (handler *RequestHandler) HandleUpdateAppAppleConfig(w http.ResponseWriter, r *http.Request) {
	var req updateAppAppleConfigRequest
	c, ok := handler.beginOAuthConfigUpdate(w, r, "apple", &req)
	if !ok {
		return
	}
	curApp := c.curApp

	servicesID := mergeOptionalString(req.AppleServicesID, curApp.AppleServicesID)
	teamID := mergeOptionalString(req.AppleTeamID, curApp.AppleTeamID)
	keyID := mergeOptionalString(req.AppleKeyID, curApp.AppleKeyID)

	// The .p8 private key is its own merge: unlike the other providers the
	// inbound value is validated before encryption, so it stays inline here.
	// nil = keep existing (COALESCE); []byte{} = clear; non-empty = set.
	var privateKeyEncrypted []byte
	postSaveHasKey := len(curApp.ApplePrivateKeyEncrypted) > 0
	if req.ApplePrivateKey != nil {
		trimmed := strings.TrimSpace(*req.ApplePrivateKey)
		if trimmed == "" {
			privateKeyEncrypted = []byte{}
			postSaveHasKey = false
		} else {
			if err := apple.ValidatePrivateKey([]byte(trimmed)); err != nil {
				WriteError(w, r, "error.appleKeyInvalid", http.StatusBadRequest)
				return
			}
			encrypted, encErr := handler.encryptor.EncryptToBytesWithAAD(
				[]byte(trimmed),
				crypto.AAD("apps", "apple_private_key_encrypted", c.appID),
			)
			if encErr != nil {
				log.Err(encErr).Msg("failed to encrypt apple private key")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
			privateKeyEncrypted = encrypted
			postSaveHasKey = true
		}
	}

	authMethodApple := curApp.AuthMethodApple
	if req.AuthMethodApple != nil {
		authMethodApple = *req.AuthMethodApple
	}
	if authMethodApple {
		// Enabling Apple requires the full credential set.
		if servicesID == nil || *servicesID == "" ||
			teamID == nil || *teamID == "" ||
			keyID == nil || *keyID == "" ||
			!postSaveHasKey {
			WriteError(w, r, "error.appleConfigIncomplete", http.StatusBadRequest)
			return
		}
	}
	if !handler.requireAtLeastOneSignInMethod(r.Context(), c.ws, c.acc.IsSuper(), curApp.PrimaryAuthMethod, curApp.AuthMethodGoogle, authMethodApple, curApp.AuthMethodMicrosoft, curApp.AuthMethodGithub, curApp.AuthMethodKakao, curApp.AuthMethodNaver) {
		WriteError(w, r, "error.noSignInMethodEnabled", http.StatusBadRequest)
		return
	}

	out, err := handler.repo.UpdateAppAppleConfig(r.Context(), c.ws.ID, c.projectID, c.appID, repo.AppAppleConfigUpdate{
		AuthMethodApple:     authMethodApple,
		ServicesID:          servicesID,
		TeamID:              teamID,
		KeyID:               keyID,
		PrivateKeyEncrypted: privateKeyEncrypted,
	})
	if err != nil {
		log.Err(err).Msg("failed to update apple config")
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, c.ws), http.StatusOK)
}
