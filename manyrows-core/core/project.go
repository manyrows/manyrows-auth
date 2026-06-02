package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

type Project struct {
	ID          uuid.UUID `json:"id"`
	WorkspaceID uuid.UUID `json:"workspaceId"`
	Name        string    `json:"name"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	CreatedBy   uuid.UUID `json:"-"`
}
