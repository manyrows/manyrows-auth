package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

// ClientOTPCode is a short-lived email OTP for app-scoped client login.
// IMPORTANT: store ONLY CodeHash, never the raw code.
type ClientOTPCode struct {
	ID    uuid.UUID `json:"id"`
	AppID uuid.UUID `json:"appId"`

	EmailNorm string `json:"emailNorm"`
	CodeHash  string `json:"-"`

	RequestedIP        string `json:"requestedIp,omitempty"`
	RequestedUserAgent string `json:"requestedUserAgent,omitempty"`

	CreatedAt     time.Time  `json:"createdAt"`
	ExpiresAt     time.Time  `json:"expiresAt"`
	UsedAt        *time.Time `json:"usedAt,omitempty"`
	Attempts      int        `json:"attempts"`
	LastAttemptAt *time.Time `json:"lastAttemptAt,omitempty"`
}
