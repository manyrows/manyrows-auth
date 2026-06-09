package api

import "github.com/gofrs/uuid/v5"

// Session and MFA webhook event names.
const (
	whSessionRevoked = "session.revoked"
	whMFAEnabled     = "user.mfa_enabled"
	whMFADisabled    = "user.mfa_disabled"
)

// dispatchSessionRevoked fires session.revoked when a session is force-ended
// by an admin or a backend (distinct from a user-initiated logout). sessionID
// is nil for a bulk revoke-all (no single session to name).
func (h *RequestHandler) dispatchSessionRevoked(appID, userID uuid.UUID, sessionID *uuid.UUID) {
	if appID == uuid.Nil {
		return
	}
	payload := map[string]any{"appId": appID, "userId": userID}
	if sessionID != nil {
		payload["sessionId"] = *sessionID
	}
	h.dispatchWebhook(appID, whSessionRevoked, payload)
}

// dispatchMFAEvent fires user.mfa_enabled / user.mfa_disabled for an app user.
func (h *RequestHandler) dispatchMFAEvent(event string, appID, userID uuid.UUID) {
	if appID == uuid.Nil {
		return
	}
	h.dispatchWebhook(appID, event, map[string]any{"appId": appID, "userId": userID})
}
