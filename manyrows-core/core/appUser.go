package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

// AppUserStatus values for per-app membership state.
type AppUserStatus string

const (
	AppUserStatusActive   AppUserStatus = "active"
	AppUserStatusDisabled AppUserStatus = "disabled"
)

// AppUser is the explicit (app, user) membership row. Membership is
// no longer derived from "user has at least one role" - a member can
// have zero roles and still sign in. Authorization is the customer
// backend's job once they hold a token.
type AppUser struct {
	AppID       uuid.UUID     `json:"appId"`
	UserID      uuid.UUID     `json:"userId"`
	Status      AppUserStatus `json:"status"`
	Source      UserSource    `json:"source"`
	JoinedAt    time.Time     `json:"joinedAt"`
	LastLoginAt *time.Time    `json:"lastLoginAt,omitempty"`
}

// IsActive returns true when the membership row allows sign-in.
func (m *AppUser) IsActive() bool {
	return m.Status == AppUserStatusActive
}
