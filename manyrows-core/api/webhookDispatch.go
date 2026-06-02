package api

import (
	"github.com/gofrs/uuid/v5"
)

// dispatchWebhook fires a webhook event for an app. Best-effort, non-blocking.
func (handler *RequestHandler) dispatchWebhook(appID uuid.UUID, event string, payload any) {
	if handler.webhookDispatcher == nil || appID == uuid.Nil {
		return
	}
	go handler.webhookDispatcher.Dispatch(appID, event, payload)
}
