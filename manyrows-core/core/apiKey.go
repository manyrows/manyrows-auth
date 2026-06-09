package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

// APIKey scope levels. A read key may only perform GET/HEAD on the
// server API; a read_write key may perform any operation.
const (
	APIKeyScopeRead      = "read"
	APIKeyScopeReadWrite = "read_write"
)

// ValidAPIKeyScope reports whether s is a recognised scope.
func ValidAPIKeyScope(s string) bool {
	return s == APIKeyScopeRead || s == APIKeyScopeReadWrite
}

type APIKey struct {
	ID          uuid.UUID  `json:"id"`
	WorkspaceID uuid.UUID  `json:"workspaceId"`
	AppID       *uuid.UUID `json:"appId,omitempty"`

	Name   string `json:"name"`
	Prefix string `json:"prefix"` // e.g. first 8 chars for UI display
	Hash   string `json:"-"`      // stored hash only, never exposed

	// Scope is "read" or "read_write" (see the constants above). Controls
	// whether the key may perform mutating server-API calls.
	Scope string `json:"scope"`

	// ExpiresAt is an optional hard expiry. Nil means the key never
	// expires. A key past its expiry is rejected at authentication.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	CreatedBy uuid.UUID `json:"createdBy"`

	// LastUsedAt is the approximate time the key was last presented to the
	// server API. Nil if it has never been used. Updated best-effort, so it
	// can lag slightly behind the most recent request.
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
}

// IsExpired reports whether the key has a hard expiry that is in the past
// relative to now. Keys with no expiry never expire.
func (k *APIKey) IsExpired(now time.Time) bool {
	return k.ExpiresAt != nil && now.After(*k.ExpiresAt)
}

// AllowsWrite reports whether the key may perform mutating operations.
// Only the explicit "read" scope denies writes; anything else (the
// read_write default) retains full access.
func (k *APIKey) AllowsWrite() bool {
	return k.Scope != APIKeyScopeRead
}
