package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

type FeatureFlagScope string

const (
	FeatureFlagScopeServer FeatureFlagScope = "server"
	FeatureFlagScopeClient FeatureFlagScope = "client"
)

type FeatureFlag struct {
	ID        uuid.UUID `json:"id"`
	ProjectID uuid.UUID `json:"projectId"`

	// Stable identifier used in SDKs
	Key string `json:"key"` // e.g. "new_checkout"

	Description *string `json:"description,omitempty"`

	// Who can receive this flag via delivery endpoints.
	// - "server": never delivered to browsers/clients (backend only)
	// - "client": can be delivered to browsers/clients (NOT secure)
	Scope FeatureFlagScope `json:"scope"`

	// Default behavior if no env override exists
	DefaultEnabled bool `json:"defaultEnabled"`

	Status string `json:"status"` // "active", "archived"

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	CreatedBy uuid.UUID `json:"createdBy"`
}

type FeatureFlagOverride struct {
	ID uuid.UUID `json:"id"`

	ProjectID     uuid.UUID `json:"projectId"`
	AppID         uuid.UUID `json:"appId"`
	FeatureFlagID uuid.UUID `json:"featureFlagId"`

	Enabled bool `json:"enabled"`

	// RoleIDs restricts this flag to users with one of these roles.
	// Empty/nil = applies to everyone.
	RoleIDs []uuid.UUID `json:"roleIds,omitempty"`

	Status string `json:"status"` // "active", "disabled"

	UpdatedAt time.Time `json:"updatedAt"`
	UpdatedBy uuid.UUID `json:"updatedBy"`
}

// EvaluatedFeatureFlag just useful when returning flags to clients.
type EvaluatedFeatureFlag struct {
	Key     string      `json:"key"`
	Enabled bool        `json:"enabled"`
	RoleIDs []uuid.UUID `json:"-"` // internal use — for role-based filtering before delivery
}
