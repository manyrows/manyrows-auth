package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

// TeamInvite represents a pending invitation for someone to join a workspace as an admin.
type TeamInvite struct {
	ID          uuid.UUID  `json:"id"`
	WorkspaceID uuid.UUID  `json:"workspaceId"`
	Email       string     `json:"email"`
	InvitedBy   uuid.UUID  `json:"invitedBy"`
	Status      string     `json:"status"` // "pending" or "accepted"
	CreatedAt   time.Time  `json:"createdAt"`
	AcceptedAt  *time.Time `json:"acceptedAt,omitempty"`
}

// TeamInviteResource is the API-facing representation (includes inviter info).
type TeamInviteResource struct {
	ID            uuid.UUID `json:"id"`
	Email         string    `json:"email"`
	InvitedByName string    `json:"invitedByName"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"createdAt"`
}
