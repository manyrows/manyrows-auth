package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

type APIKey struct {
	ID          uuid.UUID  `json:"id"`
	WorkspaceID uuid.UUID  `json:"workspaceId"`
	AppID       *uuid.UUID `json:"appId,omitempty"`

	Name   string `json:"name"`
	Prefix string `json:"prefix"` // e.g. first 8 chars for UI display
	Hash   string `json:"-"`      // stored hash only, never exposed

	CreatedAt time.Time `json:"createdAt"`
	CreatedBy uuid.UUID `json:"createdBy"`

	// LastUsedAt is the approximate time the key was last presented to the
	// server API. Nil if it has never been used. Updated best-effort, so it
	// can lag slightly behind the most recent request.
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
}
