package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

// Permission is a project-scoped capability.
// Slug is the stable identifier used in auth checks (e.g. "orders:read").
// Name is display metadata for admin UI. Group is derived from slug prefix.
type Permission struct {
	ID        uuid.UUID `json:"id"`
	ProjectID uuid.UUID `json:"projectId"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type Role struct {
	ID          uuid.UUID    `json:"id"`
	ProjectID   uuid.UUID    `json:"projectId"`
	Name        string       `json:"name"`
	Slug        string       `json:"slug"`
	Permissions []Permission `json:"permissions"`
	CreatedAt   time.Time    `json:"createdAt"`
	UpdatedAt   time.Time    `json:"updatedAt"`
}

// UserRole links a user to a role within a specific app.
// Maps to the user_roles table. The project a row belongs to is reachable
// via apps.project_id (joined on read where the project is needed).
type UserRole struct {
	ID        uuid.UUID `json:"id"`
	AppID     uuid.UUID `json:"appId"`
	UserID    uuid.UUID `json:"userId"`
	RoleID    uuid.UUID `json:"roleId"`
	CreatedAt time.Time `json:"createdAt"`
}
