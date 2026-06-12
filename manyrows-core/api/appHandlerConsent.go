package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

type updateAppConsentConfigRequest struct {
	TermsURL       *string `json:"termsUrl,omitempty"`
	PrivacyURL     *string `json:"privacyUrl,omitempty"`
	ConsentVersion *string `json:"consentVersion,omitempty"`
	RequireConsent *bool   `json:"requireConsent,omitempty"`
}

// HandleUpdateAppConsentConfig sets the per-app legal-consent settings.
// PUT /admin/.../projects/{pid}/apps/{appId}/consent-config
func (handler *RequestHandler) HandleUpdateAppConsentConfig(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	projectID, appID, ok := handler.resolvePathIDs(w, r)
	if !ok {
		return
	}

	var req updateAppConsentConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("HandleUpdateAppConsentConfig: decode failed")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	cur, curErr := handler.repo.GetAppByIDForProject(r.Context(), ws.ID, projectID, appID)
	if curErr != nil {
		if errors.Is(curErr, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		log.Err(curErr).Msg("HandleUpdateAppConsentConfig: fetch current app failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Keep-existing-if-nil pattern (mirrors HandleUpdateAppRegistration).
	termsURL, privacyURL, consentVersion, requireConsent := cur.TermsURL, cur.PrivacyURL, cur.ConsentVersion, cur.RequireConsent
	if req.TermsURL != nil {
		termsURL = *req.TermsURL
	}
	if req.PrivacyURL != nil {
		privacyURL = *req.PrivacyURL
	}
	if req.ConsentVersion != nil {
		consentVersion = *req.ConsentVersion
	}
	if req.RequireConsent != nil {
		requireConsent = *req.RequireConsent
	}

	out, err := handler.repo.UpdateAppConsentConfig(r.Context(), ws.ID, projectID, appID, termsURL, privacyURL, consentVersion, requireConsent)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("HandleUpdateAppConsentConfig: update failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, ws), http.StatusOK)
}
