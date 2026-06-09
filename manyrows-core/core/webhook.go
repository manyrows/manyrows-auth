package core

import (
	"encoding/json"
	"time"

	"github.com/gofrs/uuid/v5"
)

type Webhook struct {
	ID          uuid.UUID `json:"id" db:"id"`
	ProjectID   uuid.UUID `json:"-" db:"project_id"` // legacy, use AppID
	AppID       uuid.UUID `json:"appId" db:"app_id"`
	URL         string    `json:"url" db:"url"`
	// Secret is the plaintext signing secret. It is only ever populated
	// transiently: returned ONCE in the create/rotate API response, and
	// read from the legacy plaintext column for webhooks created before
	// secret_encrypted existed. New rows store '' here.
	Secret string `json:"secret,omitempty" db:"secret"`
	// SecretEncrypted is the at-rest AAD-bound GCM ciphertext of the signing
	// secret (AAD = webhooks:secret_encrypted:<id>). NULL/empty on legacy rows
	// that still carry their secret in the plaintext column. json:"-" keeps the
	// ciphertext out of every API response.
	SecretEncrypted []byte    `json:"-" db:"secret_encrypted"`
	Events          []string  `json:"events" db:"events"`
	Status          string    `json:"status" db:"status"`
	Description string    `json:"description" db:"description"`
	CreatedAt   time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt   time.Time `json:"updatedAt" db:"updated_at"`
	CreatedBy   uuid.UUID `json:"createdBy" db:"created_by"`
}

type WebhookDelivery struct {
	ID           uuid.UUID       `json:"id" db:"id"`
	WebhookID    uuid.UUID       `json:"webhookId" db:"webhook_id"`
	Event        string          `json:"event" db:"event"`
	Payload      json.RawMessage `json:"payload" db:"payload"`
	Status       string          `json:"status" db:"status"`
	StatusCode   *int            `json:"statusCode,omitempty" db:"status_code"`
	ResponseBody *string         `json:"responseBody,omitempty" db:"response_body"`
	Attempts     int             `json:"attempts" db:"attempts"`
	NextRetryAt  *time.Time      `json:"nextRetryAt,omitempty" db:"next_retry_at"`
	CreatedAt    time.Time       `json:"createdAt" db:"created_at"`
	CompletedAt  *time.Time      `json:"completedAt,omitempty" db:"completed_at"`
}

// ===== Health dashboard =====

// WebhookDeliveryFailure is the lightweight shape for the recent-failures
// list in the health dashboard. Trimmed payload/response so the response
// stays compact.
type WebhookDeliveryFailure struct {
	ID         string `json:"id"`
	WebhookID  string `json:"webhookId"`
	WebhookURL string `json:"webhookUrl"`
	Event      string `json:"event"`
	StatusCode *int   `json:"statusCode,omitempty"`
	Attempts   int    `json:"attempts"`
	CreatedAt  string `json:"createdAt"`
}

// WebhookHealth backs the stat-card row + recent-failures list on the
// app's Webhooks page. All counts are app-scoped via webhooks.app_id.
type WebhookHealth struct {
	TotalWebhooks  int                      `json:"totalWebhooks"`
	ActiveWebhooks int                      `json:"activeWebhooks"`
	Deliveries24h  int                      `json:"deliveries24h"`
	Successes24h   int                      `json:"successes24h"`
	Failures24h    int                      `json:"failures24h"`
	PendingRetries int                      `json:"pendingRetries"`
	RecentFailures []WebhookDeliveryFailure `json:"recentFailures"`
}
