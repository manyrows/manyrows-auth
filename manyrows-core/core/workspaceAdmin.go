package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

// WorkspaceAdmin represents a row in workspace_admins.
type WorkspaceAdmin struct {
	ID          uuid.UUID  `json:"id"`
	WorkspaceID uuid.UUID  `json:"workspaceId"`
	AccountID   uuid.UUID  `json:"accountId"`
	Role        string     `json:"role"` // "owner" or "admin"
	AddedBy     *uuid.UUID `json:"addedBy,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
}

// WorkspaceAdminResource is the API-facing representation (includes account info).
type WorkspaceAdminResource struct {
	ID        uuid.UUID `json:"id"`
	AccountID uuid.UUID `json:"accountId"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"createdAt"`
}
