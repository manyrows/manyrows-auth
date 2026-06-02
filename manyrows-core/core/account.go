package core

import (
	"context"
	"errors"
	"time"

	"github.com/gofrs/uuid/v5"
)

type Account struct {
	ID    uuid.UUID `json:"id"`
	Email string    `json:"email"`
	Name  string    `json:"name"`

	ValidatedAt *time.Time `json:"validatedAt,omitempty"`

	// Password auth (never expose the hash)
	PasswordSetAt *time.Time `json:"passwordSetAt,omitempty"`

	// Language preference for i18n (default: "en")
	Language string `json:"language"`

	// Lockout: set when account is temporarily locked due to failed login attempts
	LockedUntil *time.Time `json:"-"`

	// TOTP 2FA
	TOTPSecretEncrypted      []byte     `json:"-"`
	TOTPEnabledAt            *time.Time `json:"-"`
	TOTPBackupCodesEncrypted []byte     `json:"-"`

	CreatedAt time.Time `json:"createdAt"`
}

var superAdminEmail string

func SetSuperAdminEmail(email string) {
	superAdminEmail = email
}

func GetSuperAdminEmail() string {
	return superAdminEmail
}

func (a *Account) IsSuper() bool {
	return superAdminEmail != "" && a.Email == superAdminEmail
}

func (a *Account) HasTOTP() bool {
	return a.TOTPEnabledAt != nil
}

var ErrAccountNotFound = errors.New("account not found")

// ---- context key (unique, unexported, collision-proof) ----

// NOTE: ctxKey is defined in your other core file:
// type ctxKey struct{ name string }
var adminAccountKey = &ctxKey{"adminAccount"}

func WithAdminAccount(ctx context.Context, acc *Account) context.Context {
	return context.WithValue(ctx, adminAccountKey, acc)
}

// AdminAccountFromContext usage: acc, ok := AdminAccountFromContext(r.Context())
func AdminAccountFromContext(ctx context.Context) (*Account, bool) {
	acc, ok := ctx.Value(adminAccountKey).(*Account)
	return acc, ok
}

// AccountResource is a safe shape for frontend.
type AccountResource struct {
	ID          uuid.UUID  `json:"id"`
	Email       string     `json:"email"`
	Name        string     `json:"name"`
	ValidatedAt *time.Time `json:"validatedAt,omitempty"`
	Language    string     `json:"language"`
	TOTPEnabled bool       `json:"totpEnabled"`
	IsSuper     bool       `json:"isSuper"`
}

func ToAccountResource(acc *Account) *AccountResource {
	if acc == nil {
		return nil
	}
	return &AccountResource{
		ID:          acc.ID,
		Email:       acc.Email,
		Name:        acc.Name,
		ValidatedAt: acc.ValidatedAt,
		Language:    acc.Language,
		TOTPEnabled: acc.HasTOTP(),
		IsSuper:     acc.IsSuper(),
	}
}
