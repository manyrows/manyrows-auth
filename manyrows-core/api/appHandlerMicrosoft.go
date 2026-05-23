package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	microsoftauth "manyrows-core/auth/microsoft"
	"manyrows-core/core/repo"
	"manyrows-core/crypto"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

// Microsoft sign-in: toggle + Entra ID credentials + tenant scope.
// Tenant is one of 'common' / 'organizations' / 'consumers' / a
// specific tenant UUID; defaults to 'common' on app creation.
type updateAppMicrosoftConfigRequest struct {
	AuthMethodMicrosoft   *bool   `json:"authMethodMicrosoft,omitempty"`
	MicrosoftClientID     *string `json:"microsoftClientId,omitempty"`
	MicrosoftClientSecret *string `json:"microsoftClientSecret,omitempty"`
	MicrosoftTenant       *string `json:"microsoftTenant,omitempty"`
}

// HandleUpdateAppMicrosoftConfig sets the Microsoft sign-in toggle,
// Entra ID credentials, and tenant scope together. Enabling requires
// client ID + secret; disabling when the primary email mode is "none"
// and no other OAuth provider is on leaves the app unusable and is
// rejected. Tenant must be one of the four allowed values.
func (handler *RequestHandler) HandleUpdateAppMicrosoftConfig(w http.ResponseWriter, r *http.Request) {
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

	var req updateAppMicrosoftConfigRequest
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
		log.Err(curAppErr).Msg("failed to load app for microsoft-config update")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	clientID := curApp.MicrosoftClientID
	if req.MicrosoftClientID != nil {
		trimmed := strings.TrimSpace(*req.MicrosoftClientID)
		if trimmed == "" {
			clientID = nil
		} else {
			clientID = &trimmed
		}
	}

	// nil = keep existing; []byte{} = clear; non-empty = encrypt+set.
	var clientSecretEncrypted []byte
	postSaveHasSecret := len(curApp.MicrosoftClientSecretEncrypted) > 0
	if req.MicrosoftClientSecret != nil {
		trimmed := strings.TrimSpace(*req.MicrosoftClientSecret)
		if trimmed == "" {
			clientSecretEncrypted = []byte{}
			postSaveHasSecret = false
		} else {
			encrypted, encErr := handler.encryptor.EncryptToBytesWithAAD(
				[]byte(trimmed),
				crypto.AAD("apps", "microsoft_client_secret_encrypted", appID),
			)
			if encErr != nil {
				log.Err(encErr).Msg("failed to encrypt microsoft client secret")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
			clientSecretEncrypted = encrypted
			postSaveHasSecret = true
		}
	}

	tenant := curApp.MicrosoftTenant
	if tenant == "" {
		tenant = microsoftauth.TenantCommon
	}
	if req.MicrosoftTenant != nil {
		trimmed := strings.TrimSpace(*req.MicrosoftTenant)
		if trimmed == "" {
			tenant = microsoftauth.TenantCommon
		} else {
			tenant = trimmed
		}
	}
	if !microsoftauth.IsValidTenant(tenant) {
		WriteError(w, r, "error.microsoftTenantInvalid", http.StatusBadRequest)
		return
	}
	// Normalize tenant UUIDs to lowercase for consistent storage and
	// audit logging. The auth-side compare uses EqualFold so the
	// original case would still match Microsoft's lowercase tid, but
	// storing it canonically prevents two-rows-with-different-case
	// confusion in the admin UI.
	tenant = strings.ToLower(tenant)

	authMethodMicrosoft := curApp.AuthMethodMicrosoft
	if req.AuthMethodMicrosoft != nil {
		authMethodMicrosoft = *req.AuthMethodMicrosoft
	}
	// Enabling Microsoft requires both client ID and secret.
	if authMethodMicrosoft && (clientID == nil || *clientID == "" || !postSaveHasSecret) {
		WriteError(w, r, "error.microsoftConfigIncomplete", http.StatusBadRequest)
		return
	}
	if !handler.requireAtLeastOneSignInMethod(r.Context(), ws, acc.IsSuper(), curApp.PrimaryAuthMethod, curApp.AuthMethodGoogle, curApp.AuthMethodApple, authMethodMicrosoft, curApp.AuthMethodGithub, curApp.AuthMethodKakao) {
		WriteError(w, r, "error.noSignInMethodEnabled", http.StatusBadRequest)
		return
	}

	out, err := handler.repo.UpdateAppMicrosoftConfig(r.Context(), ws.ID, productID, appID, repo.AppMicrosoftConfigUpdate{
		AuthMethodMicrosoft:   authMethodMicrosoft,
		ClientID:              clientID,
		ClientSecretEncrypted: clientSecretEncrypted,
		Tenant:                tenant,
	})
	if err != nil {
		log.Err(err).Msg("failed to update microsoft config")
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, ws), http.StatusOK)
}
