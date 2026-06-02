package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

// ClientRefreshToken represents a refresh token tied to a client session.
// Used for token rotation in the refresh token flow.
type ClientRefreshToken struct {
	ID        uuid.UUID `db:"id" json:"id"`
	SessionID uuid.UUID `db:"session_id" json:"sessionId"`

	// sha256 hash of the actual refresh token - never store raw
	TokenHash string `db:"token_hash" json:"-"`

	CreatedAt time.Time `db:"created_at" json:"createdAt"`
	ExpiresAt time.Time `db:"expires_at" json:"expiresAt"`

	// set when this token is used to issue a new token pair (rotation)
	RotatedAt *time.Time `db:"rotated_at" json:"rotatedAt,omitempty"`

	// set when explicitly revoked (logout, security event)
	RevokedAt *time.Time `db:"revoked_at" json:"revokedAt,omitempty"`

	// the token that replaced this one (for detecting reuse attacks)
	ReplacedByID *uuid.UUID `db:"replaced_by_id" json:"-"`

	UserAgent string `db:"user_agent" json:"userAgent,omitempty"`
	IP        string `db:"ip" json:"ip,omitempty"`

	// JWK SHA-256 thumbprint (RFC 7638) of the keypair this refresh token is
	// bound to. Empty when the session was created without DPoP — a Bearer-
	// only refresh token. When non-empty, the refresh handler MUST require a
	// valid DPoP proof from the matching keypair on every rotation.
	DPopJKT string `db:"dpop_jkt" json:"-"`
}

// IsActive returns true if the token can be used for refresh.
func (t *ClientRefreshToken) IsActive(now time.Time) bool {
	if t.ID == uuid.Nil || t.SessionID == uuid.Nil {
		return false
	}
	if t.RevokedAt != nil && !t.RevokedAt.IsZero() {
		return false
	}
	if t.RotatedAt != nil && !t.RotatedAt.IsZero() {
		return false
	}
	if !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt) {
		return false
	}
	return true
}
