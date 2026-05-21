package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

// UserSource indicates how the user was created.
type UserSource string

const (
	UserSourceInvited    UserSource = "invited"
	UserSourceRegistered UserSource = "registered"
	UserSourceGoogle     UserSource = "google"
	UserSourceApple      UserSource = "apple"
	UserSourceMicrosoft  UserSource = "microsoft"
	UserSourceGithub     UserSource = "github"
	// UserSourceExternalIDP is the coarse origin for any user who signed
	// in through a generic configured external IdP (both OIDC and OAuth2
	// modes). The precise per-IdP link lives in user_identities.provider
	// as "idp:<config-uuid>" (see ExternalIDPProviderKey); user.source
	// stays coarse so it remains a small, predictable set.
	UserSourceExternalIDP UserSource = "external"
)

// User is an identity keyed by (email, user_pool). A pool is the
// identity boundary; apps that share a pool share users (SSO across
// related apps). Per-app membership lives in app_users, and roles
// remain in user_roles, both orthogonal to identity.
type User struct {
	ID    uuid.UUID `json:"id"`
	Email string    `json:"email"`

	// UserPoolID is the identity boundary. Always set.
	UserPoolID uuid.UUID `json:"userPoolId"`

	// Enabled controls whether the user can log in.
	Enabled bool `json:"enabled"`

	// Password auth (optional, never expose the hash)
	PasswordSetAt *time.Time `json:"passwordSetAt,omitempty"`

	Source UserSource `json:"source"`

	EmailVerifiedAt *time.Time `json:"emailVerifiedAt,omitempty"`

	// TOTP 2FA (never expose secrets)
	TOTPSecretEncrypted      []byte     `json:"-"`
	TOTPEnabledAt            *time.Time `json:"-"`
	TOTPBackupCodesEncrypted []byte     `json:"-"`

	// Lockout: set when user is temporarily locked due to failed login attempts
	LockedUntil *time.Time `json:"-"`

	// LastLoginAt is the most recent successful login timestamp.
	LastLoginAt *time.Time `json:"lastLoginAt,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// IsEmailVerified returns true if the user's email has been verified.
func (u *User) IsEmailVerified() bool {
	return u.EmailVerifiedAt != nil
}

// HasPassword returns true if the user has a password set.
func (u *User) HasPassword() bool {
	return u.PasswordSetAt != nil
}

// HasTOTP returns true if TOTP 2FA is enabled for this user.
func (u *User) HasTOTP() bool {
	return u.TOTPEnabledAt != nil
}

// IsDisabled returns true if the user has been disabled by an admin.
func (u *User) IsDisabled() bool {
	return !u.Enabled
}

// UserResource is safe to return in API responses.
type UserResource struct {
	ID              uuid.UUID  `json:"id"`
	Email           string     `json:"email"`
	Enabled         bool       `json:"enabled"`
	EmailVerifiedAt *time.Time `json:"emailVerifiedAt,omitempty"`
	PasswordSetAt   *time.Time `json:"passwordSetAt,omitempty"`
	TOTPEnabled     bool       `json:"totpEnabled"`
	Source          UserSource `json:"source"`
}

func ToUserResource(u *User) *UserResource {
	if u == nil {
		return nil
	}
	return &UserResource{
		ID:              u.ID,
		Email:           u.Email,
		Enabled:         u.Enabled,
		EmailVerifiedAt: u.EmailVerifiedAt,
		PasswordSetAt:   u.PasswordSetAt,
		TOTPEnabled:     u.HasTOTP(),
		Source:          u.Source,
	}
}

