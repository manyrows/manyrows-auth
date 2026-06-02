package core

import (
	"encoding/json"
	"time"

	"github.com/gofrs/uuid/v5"
)

// WorkspaceEncryptionKey is the single active public key for a workspace.
// The corresponding private key is generated in the customer's browser and
// must NEVER be sent to ManyRows.
//
// We store only:
// - PublicKeyJWK: the ECDH public key (JWK JSON) used by browsers to encrypt secrets client-side
// - Fingerprint: SHA-256 hex of a canonical representation of the public JWK (display + sanity check)
//
// Rotation model (v1):
// - exactly one row per workspace (workspace_id UNIQUE in DB)
// - POSTing again overwrites the active key
type WorkspaceEncryptionKey struct {
	ID uuid.UUID `json:"id"`

	WorkspaceID uuid.UUID `json:"workspaceId"`

	// PublicKeyJWK stores the public key as JWK JSON bytes (jsonb in Postgres).
	// Example JWK fields for ECDH P-256: kty, crv, x, y (+ optional ext, key_ops).
	PublicKeyJWK json.RawMessage `json:"publicKeyJwk"`

	// Fingerprint is a SHA-256 hex digest (string) of the canonicalized public JWK.
	Fingerprint string `json:"fingerprint"`

	CreatedAt time.Time  `json:"createdAt"`
	CreatedBy *uuid.UUID `json:"createdBy"`
}
