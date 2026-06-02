package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

type MemberResource struct {
	UserID          uuid.UUID  `json:"userId"`
	Email           string     `json:"email"`
	Name            string     `json:"name"`
	Enabled         bool       `json:"enabled"`
	EmailVerifiedAt *time.Time `json:"emailVerifiedAt,omitempty"`
	PasswordSetAt   *time.Time `json:"passwordSetAt,omitempty"`
	LastLoginAt     *time.Time `json:"lastLoginAt,omitempty"`
	Source          string     `json:"source"`
	AddedAt         time.Time  `json:"addedAt"`

	// Per-app activity stats. Populated only when the handler can resolve
	// an app context (e.g. the AppUsers admin page). Zero when unknown.
	ActiveSessions  int `json:"activeSessions,omitempty"`
	LoginFailures7d int `json:"loginFailures7d,omitempty"`

	// Free-form tags (e.g. "vip", "internal"). Same per-app scoping as
	// activity stats. Empty slice when unknown / app context missing.
	Tags []string `json:"tags,omitempty"`
}
