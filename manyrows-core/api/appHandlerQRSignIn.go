package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

// =====================
// Admin: QR sign-in config
// =====================
//
// Per-app QR-sign-in toggle endpoint matching the per-provider
// (Google/Apple/Microsoft/GitHub) and OIDC patterns. One simple
// boolean today; the response surfaces the customer-facing URL
// pattern so the admin UI can show what to integrate.

// updateAppQRSignInConfigRequest is just an enable/disable toggle.
// More knobs could be added later (custom QR styling, allowed-
// device-types, etc.) — keep simple for v1.
type updateAppQRSignInConfigRequest struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// adminAppQRSignInResponse extends adminAppResponse with a
// computed URL pattern so the admin UI can render the integration
// snippet without having to know how to construct it itself.
type adminAppQRSignInResponse struct {
	adminAppResponse
	QRSignInEnabled bool   `json:"qrSignInEnabled"`
	QRSignInURL     string `json:"qrSignInUrl,omitempty"`
}

// HandleUpdateAppQRSignInConfig is PUT
// /admin/.../products/{pid}/apps/{appId}/qr-sign-in-config.
func (handler *RequestHandler) HandleUpdateAppQRSignInConfig(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	productID, appID, ok := handler.resolvePathIDs(w, r)
	if !ok {
		return
	}

	var req updateAppQRSignInConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("HandleUpdateAppQRSignInConfig: decode failed")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if req.Enabled == nil {
		WriteError(w, r, "error.invalidRequest", http.StatusBadRequest)
		return
	}

	out, err := handler.repo.UpdateAppQRSignInConfig(r.Context(), ws.ID, productID, appID, *req.Enabled)
	if err != nil {
		switch {
		case errors.Is(err, repo.ErrQRSignInRequiresAppURL):
			WriteError(w, r, "error.qrSignInRequiresAppURL", http.StatusBadRequest)
			return
		case errors.Is(err, repo.ErrNotFound):
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		default:
			log.Err(err).Msg("HandleUpdateAppQRSignInConfig: update failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
	}

	base := handler.AppBaseURL(&out)
	var qrURL string
	if base != "" && out.QRSignInEnabled {
		qrURL = base + "/x/" + ws.Slug + "/apps/" + out.ID.String() + "/qr-sign-in"
	}

	resp := adminAppQRSignInResponse{
		adminAppResponse: handler.toAdminAppResponse(out, ws),
		QRSignInEnabled:  out.QRSignInEnabled,
		QRSignInURL:      qrURL,
	}
	utils.WriteJsonWithStatusCode(w, resp, http.StatusOK)
}
