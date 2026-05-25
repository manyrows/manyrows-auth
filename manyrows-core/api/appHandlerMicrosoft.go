package api

import (
	"errors"
	"net/http"
	"strings"

	microsoftauth "manyrows-core/auth/microsoft"
	"manyrows-core/core/repo"
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
	var req updateAppMicrosoftConfigRequest
	c, ok := handler.beginOAuthConfigUpdate(w, r, "microsoft", &req)
	if !ok {
		return
	}
	curApp := c.curApp

	clientID := mergeOptionalString(req.MicrosoftClientID, curApp.MicrosoftClientID)

	clientSecretEncrypted, postSaveHasSecret, ok := handler.encryptOptionalSecret(
		w, r, req.MicrosoftClientSecret, curApp.MicrosoftClientSecretEncrypted, "microsoft_client_secret_encrypted", c.appID)
	if !ok {
		return
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
	if !handler.requireAtLeastOneSignInMethod(r.Context(), c.ws, c.acc.IsSuper(), curApp.PrimaryAuthMethod, curApp.AuthMethodGoogle, curApp.AuthMethodApple, authMethodMicrosoft, curApp.AuthMethodGithub, curApp.AuthMethodKakao, curApp.AuthMethodNaver) {
		WriteError(w, r, "error.noSignInMethodEnabled", http.StatusBadRequest)
		return
	}

	out, err := handler.repo.UpdateAppMicrosoftConfig(r.Context(), c.ws.ID, c.productID, c.appID, repo.AppMicrosoftConfigUpdate{
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

	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, c.ws), http.StatusOK)
}
