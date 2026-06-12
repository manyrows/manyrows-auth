package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

// UserConsent is one append-only acceptance event (e.g. terms vX accepted at T).
type UserConsent struct {
	ID         uuid.UUID `json:"id"`
	UserID     uuid.UUID `json:"userId"`
	AppID      uuid.UUID `json:"appId"`
	Kind       string    `json:"kind"`
	Version    string    `json:"version"`
	IP         string    `json:"ip,omitempty"`
	UserAgent  string    `json:"userAgent,omitempty"`
	AcceptedAt time.Time `json:"acceptedAt"`
}
