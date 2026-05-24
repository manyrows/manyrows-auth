package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

// UserIdentity is one external identity (Google, Apple, Microsoft,
// GitHub) linked to a pool user. A user can have at most one identity
// per provider; the (provider, provider_subject) pair is the IdP's
// stable id and is what OAuth sign-in matches against first, falling
// back to verified email when no identity row exists yet.
type UserIdentity struct {
	ID              uuid.UUID  `json:"id"`
	UserID          uuid.UUID  `json:"userId"`
	UserPoolID      uuid.UUID  `json:"userPoolId"`
	Provider        UserSource `json:"provider"`
	ProviderSubject string     `json:"providerSubject"`
	ProviderEmail   string     `json:"providerEmail,omitempty"`
	CreatedAt       time.Time  `json:"createdAt"`
	LastLoginAt     time.Time  `json:"lastLoginAt"`
}

// UserIdentityResource is safe to return in API responses. The raw
// provider subject is excluded — it's an internal correlator, not
// something the client needs.
type UserIdentityResource struct {
	Provider      UserSource `json:"provider"`
	ProviderEmail string     `json:"providerEmail,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	LastLoginAt   time.Time  `json:"lastLoginAt"`
}

func ToUserIdentityResource(i *UserIdentity) *UserIdentityResource {
	if i == nil {
		return nil
	}
	return &UserIdentityResource{
		Provider:      i.Provider,
		ProviderEmail: i.ProviderEmail,
		CreatedAt:     i.CreatedAt,
		LastLoginAt:   i.LastLoginAt,
	}
}
