package core

import (
	"encoding/json"
	"time"

	"github.com/gofrs/uuid/v5"
)

// =====================
// OIDC provider types
// =====================
//
// ManyRows acts as an OpenID Connect provider for downstream customer
// apps. Each app is its own OIDC issuer (per-app AuthDomain or workspace
// base URL); the discovery document lives at the per-app well-known
// path and the standard endpoints sit under /oidc/. None of this
// replaces the existing AppKit SDK path — OIDC is a parallel option
// for customers whose stack speaks standard OIDC natively (next-auth,
// passport-openidconnect, Spring Security, etc.).

// OIDC scope constants. We only recognise the standard set today; any
// other scope value in an /authorize request is ignored on the way in
// and dropped from the granted scope echoed back at /token, matching
// OIDC §5.4 "scope values that the OP does not recognise SHOULD be
// ignored."
const (
	OIDCScopeOpenID        = "openid"
	OIDCScopeEmail         = "email"
	OIDCScopeProfile       = "profile"
	OIDCScopeOfflineAccess = "offline_access"
)

// Auth-code-flow constants. Only the values we actually support are
// listed; the discovery document advertises this exact set.
const (
	OIDCResponseTypeCode             = "code"
	OIDCGrantTypeAuthorizationCode   = "authorization_code"
	OIDCGrantTypeRefreshToken        = "refresh_token"
	OIDCCodeChallengeMethodS256      = "S256"
	OIDCTokenEndpointAuthBasic       = "client_secret_basic"
	OIDCTokenEndpointAuthPost        = "client_secret_post"
	OIDCTokenEndpointAuthNone        = "none"
	OIDCSubjectTypePublic            = "public"
	OIDCIDTokenSigningAlgValueES256  = "ES256"
)

// OIDCAuthCode is a single-use authorization-code grant. Persisted by
// /oidc/authorize and consumed atomically by /oidc/token. Code values
// themselves are never stored — only the SHA-256 hash of the raw code
// (matches the magic_links / client_otp_codes pattern).
type OIDCAuthCode struct {
	CodeHash            string
	AppID               uuid.UUID
	UserID              uuid.UUID
	SessionID           *uuid.UUID
	Nonce               string
	RedirectURI         string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	UsedAt              *time.Time
}

// OIDCAuthorizeParams is the exact set of /authorize query parameters
// that survive the AppKit-sign-in round-trip. Stored as a typed JSON
// blob on oidc_pending_authorize so the resume handler reconstructs the
// original request without re-parsing the URL.
type OIDCAuthorizeParams struct {
	ResponseType        string `json:"response_type"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// OIDCPendingAuthorize is the short-lived row holding an /authorize
// request while the user signs in via AppKit. ID is the opaque token
// in the return-to URL; the row is single-consume so a leaked return
// link can't be reused.
type OIDCPendingAuthorize struct {
	ID            uuid.UUID
	AppID         uuid.UUID
	RequestParams json.RawMessage
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ConsumedAt    *time.Time
}

// OIDCAppConfig is the per-app OIDC provider configuration. Fetched
// once per /oidc/* request; nil when the app exists but OIDC is not
// enabled (handlers return 404 in that case so the surface is
// indistinguishable from "app has no OIDC at all").
type OIDCAppConfig struct {
	Enabled                bool
	ClientSecretHash       *string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
}

// HasClientSecret reports whether this app is configured as a
// confidential client. Public clients (PKCE-only) leave the hash
// nullable; the token endpoint requires either valid client credentials
// (confidential) or no client_secret at all (public + PKCE).
func (c *OIDCAppConfig) HasClientSecret() bool {
	return c != nil && c.ClientSecretHash != nil && *c.ClientSecretHash != ""
}
