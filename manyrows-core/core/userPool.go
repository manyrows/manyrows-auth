package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

// UserPool is the identity boundary. Apps point at a pool; apps that
// share a pool share users. Default behavior: one pool per app,
// auto-created at app creation time. Sharing is opt-in (an admin
// points a new app at an existing pool, or merges two).
type UserPool struct {
	ID          uuid.UUID `json:"id"`
	WorkspaceID uuid.UUID `json:"workspaceId"`
	Name        string    `json:"name"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}
