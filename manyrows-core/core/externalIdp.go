package core

import (
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
)

// ExternalIDPMode distinguishes how a configured external provider
// authenticates a user.
type ExternalIDPMode string

const (
	// ExternalIDPModeOIDC discovers endpoints from the issuer's
	// /.well-known/openid-configuration and verifies a signed id_token
	// against the provider's JWKS. Generalizes Google/Microsoft/Apple.
	ExternalIDPModeOIDC ExternalIDPMode = "oidc"
	// ExternalIDPModeOAuth2 uses explicit endpoints and reads identity
	// from the userinfo endpoint (no id_token). Generalizes GitHub.
	ExternalIDPModeOAuth2 ExternalIDPMode = "oauth2"
)

// ExternalIDPProviderKey is the value written to user_identities.provider
// for an identity that signed in through this external IdP. It is keyed
// by the config's UUID, not its slug: identities are matched POOL-wide
// (FindUserByIdentity keys on user_pool_id), but slugs are unique only
// per-app — so two apps sharing a pool could both use slug "okta" for
// DIFFERENT issuers, and since a `sub` is unique only per-issuer, a
// slug-based key could collide two distinct people. The config UUID is
// pool-global and stable for the provider's lifetime. The "idp:" prefix
// is mode-neutral and can't collide with the bespoke keys ("google", …
// — no colon).
func ExternalIDPProviderKey(id uuid.UUID) string {
	return "idp:" + id.String()
}

// IsExternalIDPProviderKey reports whether a user_identities.provider
// value belongs to a generic external IdP (vs a bespoke provider like
// "google"). Used to allow disconnecting these identities.
func IsExternalIDPProviderKey(provider string) bool {
	return strings.HasPrefix(provider, "idp:")
}

// ExternalIDP is one external identity provider configured for an app —
// the OAuth/OIDC *client* side (ManyRows consuming someone else's IdP),
// distinct from the OIDC *provider* surface where ManyRows is the IdP.
//
// Optional URL/field columns are NULL in the DB when unset; the repo
// COALESCEs them to "" on read and stores "" back as NULL, so consumers
// treat empty as absent. The client secret is never plaintext here — it
// stays in ClientSecretEncrypted until the callback decrypts it at
// token-exchange time.
type ExternalIDP struct {
	ID    uuid.UUID `db:"id" json:"id"`
	AppID uuid.UUID `db:"app_id" json:"appId"`

	Slug        string          `db:"slug" json:"slug"`
	DisplayName string          `db:"display_name" json:"displayName"`
	Enabled     bool            `db:"enabled" json:"enabled"`
	Mode        ExternalIDPMode `db:"mode" json:"mode"`

	IssuerURL    string `db:"issuer_url" json:"issuerUrl,omitempty"`
	AuthorizeURL string `db:"authorize_url" json:"authorizeUrl,omitempty"`
	TokenURL     string `db:"token_url" json:"tokenUrl,omitempty"`
	UserinfoURL  string `db:"userinfo_url" json:"userinfoUrl,omitempty"`
	JWKSURL      string `db:"jwks_url" json:"jwksUrl,omitempty"`

	ClientID              string `db:"client_id" json:"clientId"`
	ClientSecretEncrypted []byte `db:"client_secret_encrypted" json:"-"`

	Scopes string `db:"scopes" json:"scopes"`

	SubjectField       string `db:"subject_field" json:"subjectField"`
	EmailField         string `db:"email_field" json:"emailField"`
	EmailVerifiedField string `db:"email_verified_field" json:"emailVerifiedField,omitempty"`
	NameField          string `db:"name_field" json:"nameField,omitempty"`

	ButtonIcon string `db:"button_icon" json:"buttonIcon,omitempty"`

	// TrustUnverifiedEmail opts INTO accepting this IdP's email even when
	// it isn't marked verified. Default false = require verified (safe);
	// only set true for an IdP whose emails are trustworthy but which
	// omits the email_verified claim. See the callback's verified gate.
	TrustUnverifiedEmail bool `db:"trust_unverified_email" json:"trustUnverifiedEmail"`

	CreatedAt time.Time `db:"created_at" json:"createdAt"`
	UpdatedAt time.Time `db:"updated_at" json:"updatedAt"`
}

// ProviderKey returns the user_identities.provider value for this IdP.
func (e *ExternalIDP) ProviderKey() string {
	return ExternalIDPProviderKey(e.ID)
}
