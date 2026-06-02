package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

// UserPasskey is a registered WebAuthn credential bound to a single (app, user)
// pair. CredentialID and PublicKey are stored as the raw bytes the WebAuthn
// library produced — we deliberately do not interpret them outside the library.
type UserPasskey struct {
	ID             uuid.UUID
	AppID          uuid.UUID
	UserID         uuid.UUID
	CredentialID   []byte
	PublicKey      []byte
	SignCount      uint32
	Transports     []string
	AAGUID         *uuid.UUID
	BackupEligible bool
	BackupState    bool
	Name           *string
	CreatedAt      time.Time
	LastUsedAt     *time.Time
}
