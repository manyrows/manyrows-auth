package core

import (
	"context"
	"time"

	"github.com/gofrs/uuid/v5"
)

// ClientSession is an app-scoped session used by external client apps.
// Auth is via JWT Bearer tokens (no cookies).
// Sessions are linked to users and scoped to an app.
type ClientSession struct {
	ID     uuid.UUID `db:"id" json:"id"`
	UserID uuid.UUID `db:"user_id" json:"userId"`

	// AppID is the app this session is scoped to.
	AppID *uuid.UUID `db:"app_id" json:"appId,omitempty"`

	CreatedAt  time.Time `db:"created_at" json:"createdAt"`
	ExpiresAt  time.Time `db:"expires_at" json:"expiresAt"`
	LastSeenAt time.Time `db:"last_seen_at" json:"lastSeenAt"`

	UserAgent string `db:"user_agent" json:"userAgent,omitempty"`
	IP        string `db:"ip" json:"ip,omitempty"`

	// RememberMe toggles a longer (30-day) refresh-token TTL on this session
	// — set at login from the AppKit "Keep me signed in" checkbox and
	// honored on refresh so the long lifetime doesn't shrink back to the
	// app's default after the first rotation.
	RememberMe bool `db:"remember_me" json:"-"`
}

// IsActive returns true if the session is not expired.
func (s ClientSession) IsActive(now time.Time) bool {
	if s.ID == uuid.Nil || s.UserID == uuid.Nil {
		return false
	}
	if !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt) {
		return false
	}
	return true
}

// ClientSessionResource is safe to return to client apps (no secrets).
type ClientSessionResource struct {
	ID     uuid.UUID `json:"id"`
	UserID uuid.UUID `json:"userId"`

	CreatedAt  time.Time `json:"createdAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`

	UserAgent string `json:"userAgent,omitempty"`
	IP        string `json:"ip,omitempty"`

	// User info (populated by join)
	User *ClientSessionUser `json:"user,omitempty"`

	// App this session belongs to (populated by join)
	App *ClientSessionApp `json:"app,omitempty"`
}

// ClientSessionApp is the app info embedded in session responses.
type ClientSessionApp struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// ClientSessionUser is the user info embedded in session responses.
type ClientSessionUser struct {
	ID    uuid.UUID `json:"id"`
	Email string    `json:"email"`
}

var clientSessionKey = &ctxKey{"clientSession"}

func WithClientSessionContext(ctx context.Context, s *ClientSession) context.Context {
	key := clientSessionKey
	return context.WithValue(ctx, key, s)
}

func ClientSessionFromContext(ctx context.Context) (*ClientSession, bool) {
	s, ok := ctx.Value(clientSessionKey).(*ClientSession)
	return s, ok
}
