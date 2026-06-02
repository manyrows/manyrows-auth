package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

type WorkspaceSMTPConfig struct {
	WorkspaceID       uuid.UUID `json:"workspaceId"`
	Enabled           bool      `json:"enabled"`
	Host              string    `json:"host"`
	Port              int       `json:"port"`
	Username          string    `json:"username"`
	PasswordEncrypted []byte    `json:"-"` // never returned to client
	FromEmail         string    `json:"fromEmail"`
	FromName          string    `json:"fromName"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}
