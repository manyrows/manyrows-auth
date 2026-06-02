package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

type WorkspaceStatus int16

const (
	WorkspaceStatusActive WorkspaceStatus = 1
)

type Workspace struct {
	ID                  uuid.UUID       `json:"id"`
	Name                string          `json:"name"`
	Slug                string          `json:"slug"`
	Status              WorkspaceStatus `json:"status"`
	CreatedAt           time.Time       `json:"createdAt"`
	CreatedBy           *uuid.UUID      `json:"-"`
	GoogleOAuthClientID *string         `json:"googleOAuthClientId,omitempty"`

	// CookieDomain controls the Domain attribute on session cookies
	// set for any app in this workspace. Typically a parent-domain
	// form like ".acme.com" so the cookie is shared across subdomains.
	// Nil / empty = no Domain attribute set; the browser scopes the
	// cookie to the exact host that set it.
	CookieDomain *string `json:"cookieDomain,omitempty"`

	// First-boot setup checklist state. The UI renders a Stripe-style
	// "complete your setup" card on the workspace home until either
	// dismissed or all items complete. Both nil = not done yet.
	SetupChecklistDismissedAt *time.Time `json:"setupChecklistDismissedAt,omitempty"`
	SetupTestEmailSentAt      *time.Time `json:"setupTestEmailSentAt,omitempty"`
}

type CorsOrigin struct {
	ID        uuid.UUID `json:"id"`
	AppID     uuid.UUID `json:"appId"`
	Origin    string    `json:"origin"`
	CreatedAt time.Time `json:"createdAt"`
}

type IPAllowlistEntry struct {
	ID          uuid.UUID `json:"id"`
	AppID       uuid.UUID `json:"appId"`
	IPRange     string    `json:"ipRange"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}
