package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

// WorkspaceAccountSource indicates how the account was created.
type WorkspaceAccountSource string

const (
	WorkspaceAccountSourceInvited    WorkspaceAccountSource = "invited"
	WorkspaceAccountSourceRegistered WorkspaceAccountSource = "registered"
	WorkspaceAccountSourceGoogle     WorkspaceAccountSource = "google"
)

const (
	WorkspaceAccountStatusActive   = "active"
	WorkspaceAccountStatusDisabled = "disabled"
)

// WorkspaceAccount represents a workspace-scoped account for regular members.
// Unlike global Account (for workspace admins), WorkspaceAccount is specific to
// a single workspace and allows users to have different identities per org.
type WorkspaceAccount struct {
	ID          uuid.UUID `json:"id"`
	WorkspaceID uuid.UUID `json:"workspaceId"`

	Email       string `json:"email"`
	DisplayName string `json:"displayName"`

	EmailVerifiedAt *time.Time `json:"emailVerifiedAt,omitempty"`

	// Password auth (optional, never expose the hash)
	PasswordSetAt *time.Time `json:"passwordSetAt,omitempty"`

	// Source indicates how this account was created (invited by owner or self-registered)
	Source WorkspaceAccountSource `json:"source"`

	// Status is the account status: "active" or "disabled".
	Status string `json:"status"`

	// TOTP 2FA (never expose secrets)
	TOTPSecretEncrypted      []byte     `json:"-"`
	TOTPEnabledAt            *time.Time `json:"-"`
	TOTPBackupCodesEncrypted []byte     `json:"-"`

	// Lockout: set when account is temporarily locked due to failed login attempts
	LockedUntil *time.Time `json:"-"`

	// LastLoginAt is the most recent successful login timestamp.
	LastLoginAt *time.Time `json:"lastLoginAt,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// IsEmailVerified returns true if the workspace account's email has been verified.
func (wa *WorkspaceAccount) IsEmailVerified() bool {
	return wa.EmailVerifiedAt != nil
}

// HasPassword returns true if the workspace account has a password set.
func (wa *WorkspaceAccount) HasPassword() bool {
	return wa.PasswordSetAt != nil
}

// HasTOTP returns true if TOTP 2FA is enabled for this workspace account.
func (wa *WorkspaceAccount) HasTOTP() bool {
	return wa.TOTPEnabledAt != nil
}

// IsDisabled returns true if the workspace account has been administratively disabled.
func (wa *WorkspaceAccount) IsDisabled() bool {
	return wa.Status == WorkspaceAccountStatusDisabled
}

// WorkspaceAccountResource is a safe shape for frontend responses.
type WorkspaceAccountResource struct {
	ID              uuid.UUID              `json:"id"`
	Email           string                 `json:"email"`
	DisplayName     string                 `json:"displayName"`
	EmailVerifiedAt *time.Time             `json:"emailVerifiedAt,omitempty"`
	PasswordSetAt   *time.Time             `json:"passwordSetAt,omitempty"`
	TOTPEnabled     bool                   `json:"totpEnabled"`
	Source          WorkspaceAccountSource `json:"source"`
	Status          string                 `json:"status"`
}
