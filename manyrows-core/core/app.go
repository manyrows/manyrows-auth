package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

// PrimaryAuthMethod values — the email-form mode for an app's sign-in
// screen. password, code, and magicLink are mutually exclusive; "none"
// hides the email form entirely (OAuth-only).
const (
	PrimaryAuthMethodPassword  = "password"
	PrimaryAuthMethodCode      = "code"
	PrimaryAuthMethodMagicLink = "magicLink"
	PrimaryAuthMethodNone      = "none"
)

// TransportMode values — how the session token is delivered to the
// user's browser. Returned in the AppKit boot/me response so the SDK
// can configure itself without a separate prop.
//   - local : JWT in localStorage / Bearer header. Default.
//   - cookie: first-party HttpOnly cookie set by ManyRows directly
//     (custom domain or same-host deploy).
const (
	TransportModeLocal  = "local"
	TransportModeCookie = "cookie"
)

// SessionCookieSameSite values — the SameSite attribute used when
// issuing the mr_at / mr_rt cookies. Default "lax" works for every
// auth flow including magic links and OAuth redirects. "strict" is
// only safe when no inbound cross-site GET ever needs to carry the
// session (no magic links, no OAuth, no link-based reset/verify) —
// the handler that flips this enforces those preconditions.
const (
	SessionCookieSameSiteLax    = "lax"
	SessionCookieSameSiteStrict = "strict"
)

// SessionTTL returns the configured absolute session TTL, or 0 when
// unset (callers fall back to the auth-service default — 7 days).
func (a *App) SessionTTL() time.Duration {
	if a.SessionTTLMinutes != nil && *a.SessionTTLMinutes > 0 {
		return time.Duration(*a.SessionTTLMinutes) * time.Minute
	}
	return 0
}

// IdleTimeout returns the configured idle-timeout duration, or 0 when
// unset (no idle enforcement — session lives until SessionTTL).
// Enforcement happens at refresh time: a session whose LastSeenAt is
// older than this is refused at refresh, ending the session naturally
// once the current access token expires.
func (a *App) IdleTimeout() time.Duration {
	if a.IdleTimeoutMinutes != nil && *a.IdleTimeoutMinutes > 0 {
		return time.Duration(*a.IdleTimeoutMinutes) * time.Minute
	}
	return 0
}

// RememberMeTTL returns the configured remember-me session lifetime,
// or 0 when unset (callers fall back to the auth-service default —
// 30 days). Applied when the user opted into "Keep me signed in" at
// login.
func (a *App) RememberMeTTL() time.Duration {
	if a.RememberMeTTLMinutes != nil && *a.RememberMeTTLMinutes > 0 {
		return time.Duration(*a.RememberMeTTLMinutes) * time.Minute
	}
	return 0
}

// AccessTokenTTL returns the configured access-token lifetime, or 0
// when unset (callers fall back to the auth-service default — 15
// minutes). Shorter values trade JWT-replay window for more frequent
// refresh-call traffic; longer values reduce refresh chatter but
// widen the window an exfiltrated token stays valid.
func (a *App) AccessTokenTTL() time.Duration {
	if a.AccessTokenTTLMinutes != nil && *a.AccessTokenTTLMinutes > 0 {
		return time.Duration(*a.AccessTokenTTLMinutes) * time.Minute
	}
	return 0
}

// MaxSessions returns the configured max active sessions per user+app
// pair, or 0 when unset (callers fall back to the auth-service default
// — 5). A login that would exceed this prunes the oldest by
// last_seen_at before inserting the new session.
func (a *App) MaxSessions() int {
	if a.MaxSessionsPerUser != nil && *a.MaxSessionsPerUser > 0 {
		return *a.MaxSessionsPerUser
	}
	return 0
}

// AppDisplayName composes the user-visible app label from a product
// name + env type. Single source of truth; (*App).DisplayName() and
// the repo-side row formatter both call this so any tweak to the
// convention ("Drum Kingdom (Staging)" etc.) lands in one place.
func AppDisplayName(productName, envType string) string {
	if productName == "" {
		return "(unnamed app)"
	}
	switch envType {
	case "prod":
		return productName
	case "staging":
		return productName + " (Staging)"
	case "dev":
		return productName + " (Dev)"
	}
	return productName
}

// DisplayName is the user-visible app label. Delegates to
// AppDisplayName so the composition logic lives in one place.
func (a *App) DisplayName() string {
	return AppDisplayName(a.ProductName, a.Type)
}

type App struct {
	ID          uuid.UUID `json:"id"`
	WorkspaceID uuid.UUID `json:"workspaceId"`
	ProductID   uuid.UUID `json:"productId"`
	// UserPoolID is the identity pool this app draws from. Two apps
	// pointing at the same pool share users.
	UserPoolID uuid.UUID `json:"userPoolId"`
	// UserPoolName is the pool's display name, populated by repo
	// JOIN/subquery on read. Transient (not stored on apps); the
	// admin UI uses it for the per-app "User pool: X" surface so the
	// table doesn't need a second round-trip to /userPools.
	UserPoolName string `json:"userPoolName"`
	Type         string `json:"type"`
	// ProductName is the parent product's name, populated by repo
	// JOIN/subquery on read. Not persisted on the apps table - the
	// display name is computed from product + env type.
	ProductName string    `json:"productName"`
	Description *string   `json:"description,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	Enabled     bool      `json:"enabled"`

	// Registration settings
	AllowRegistration   bool       `json:"allowRegistration"`
	DefaultRoleID       *uuid.UUID `json:"defaultRoleId,omitempty"`
	AllowedEmailDomains []string   `json:"allowedEmailDomains,omitempty"` // e.g., ["acme.com", "example.org"]

	// AllowAccountDeletion gates the "Delete my account" button in
	// AppKit's profile dialog. Default true preserves the existing
	// behaviour for every app already in the wild. The server-side
	// DeleteMyAccount handler enforces this independently of the UI.
	AllowAccountDeletion bool `json:"allowAccountDeletion"`

	// AllowEmailChange gates the "Change email" flow in AppKit's
	// profile dialog. Same enforcement model as AllowAccountDeletion —
	// the server-side ClientRequestEmailChange / ClientVerifyEmailChange
	// handlers reject when this flag is false, regardless of UI state.
	AllowEmailChange bool `json:"allowEmailChange"`

	// Email-form mode for the sign-in screen: "password" (default),
	// "code" (email-OTP), or "none" (OAuth-only). password and code
	// are mutually exclusive — see core.PrimaryAuthMethod* constants.
	PrimaryAuthMethod                string  `json:"primaryAuthMethod"`
	AuthMethodGoogle                 bool    `json:"authMethodGoogle"`
	GoogleOAuthClientID              *string `json:"googleOAuthClientId,omitempty"`
	GoogleOAuthClientSecretEncrypted []byte  `json:"-"` // encrypted at rest, never serialized

	AuthMethodApple          bool    `json:"authMethodApple"`
	AppleServicesID          *string `json:"appleServicesId,omitempty"`
	AppleTeamID              *string `json:"appleTeamId,omitempty"`
	AppleKeyID               *string `json:"appleKeyId,omitempty"`
	ApplePrivateKeyEncrypted []byte  `json:"-"` // encrypted at rest, never serialized

	AuthMethodMicrosoft            bool    `json:"authMethodMicrosoft"`
	MicrosoftClientID              *string `json:"microsoftClientId,omitempty"`
	MicrosoftClientSecretEncrypted []byte  `json:"-"`               // encrypted at rest, never serialized
	MicrosoftTenant                string  `json:"microsoftTenant"` // 'common' | 'organizations' | 'consumers' | UUID

	AuthMethodGithub            bool    `json:"authMethodGithub"`
	GithubClientID              *string `json:"githubClientId,omitempty"`
	GithubClientSecretEncrypted []byte  `json:"-"` // encrypted at rest, never serialized

	// Kakao (kauth.kakao.com) — OIDC, verified against Kakao's JWKS like
	// Microsoft. KakaoClientID is the app's REST API key (Kakao's term for
	// the OAuth client_id).
	AuthMethodKakao            bool    `json:"authMethodKakao"`
	KakaoClientID              *string `json:"kakaoClientId,omitempty"`
	KakaoClientSecretEncrypted []byte  `json:"-"` // encrypted at rest, never serialized

	// 2FA
	Require2FA bool `json:"require2fa"`

	// Optional app URL (e.g. https://myapp.com)
	AppURL *string `json:"appUrl,omitempty"`

	// AuthDomain is the per-app custom auth hostname (e.g. "auth.drumkingdom.com").
	// Stored as bare hostname; https:// is implied. When set, this is the host
	// used to build OAuth redirect URIs (sent to Google/Apple/etc. and shown in
	// the admin UI). NULL falls back to MANYROWS_BASE_URL. This lets one
	// ManyRows install serve multiple apps each with their own customer-branded
	// auth host without forcing the install itself onto any one of them.
	AuthDomain *string `json:"authDomain,omitempty"`

	// QRSignInEnabled gates the cross-device QR sign-in surface
	// (/auth/pair/* + /qr-sign-in + /pair). Off-by-default so existing
	// installs don't suddenly expose the feature on every app.
	// Enabling requires AppURL to be set on the app (the QR flow
	// hands tokens to the customer via a same-origin fragment redirect
	// and the AppURL host is the allowlisted target).
	QRSignInEnabled bool `json:"qrSignInEnabled"`

	// Session TTL in minutes (nil = default 7 days). Absolute lifetime
	// — the session dies at CreatedAt + this regardless of activity.
	SessionTTLMinutes *int `json:"sessionTtlMinutes,omitempty"`

	// Idle timeout in minutes (nil/0 = no idle enforcement). Refresh
	// is refused when (now - LastSeenAt) exceeds this, so the session
	// dies once the current access token expires. Combine with
	// SessionTTLMinutes to get the banking-style absolute + idle pair
	// (e.g. SessionTTL=480 min / IdleTimeout=15 min).
	IdleTimeoutMinutes *int `json:"idleTimeoutMinutes,omitempty"`

	// Remember-me session TTL in minutes (nil = default 30 days).
	// Applied when the user opted into "Keep me signed in" at login.
	// Overrides the global RememberMeTTL constant per-app — useful
	// when one workspace runs both a consumer app (90-day remember)
	// and an internal tool (7-day remember).
	RememberMeTTLMinutes *int `json:"rememberMeTtlMinutes,omitempty"`

	// Access-token TTL in minutes (nil = default 15 min). Trades the
	// JWT-replay window against refresh-call frequency. Don't go
	// below ~5 min unless your SDK can handle refresh storms.
	AccessTokenTTLMinutes *int `json:"accessTokenTtlMinutes,omitempty"`

	// Max active sessions per user for this app (nil = default 5).
	// Logging in beyond this prunes the oldest session by
	// last_seen_at — banking-style apps set 1 (single device),
	// productivity tools commonly set 10–20.
	MaxSessionsPerUser *int `json:"maxSessionsPerUser,omitempty"`

	// Password strength policy (per-app). Length is the hard floor;
	// MinZxcvbnScore is the 0..4 threshold from the zxcvbn library
	// (anything below "safe-ish" is rejected). Defaults are 8 / 2;
	// admins can tighten or loosen on the Security → Passwords tab.
	PasswordMinLength      int `json:"passwordMinLength"`
	PasswordMinZxcvbnScore int `json:"passwordMinZxcvbnScore"`

	// CookieDomain overrides the workspace-level cookie domain for
	// this specific app. Non-nil = use this value verbatim; nil =
	// inherit Workspace.CookieDomain. Useful when one ManyRows
	// install hosts multiple apps on different parent domains.
	CookieDomain *string `json:"cookieDomain,omitempty"`

	// TransportMode is the explicit selector for how the session token
	// is delivered (see TransportMode* constants). Default "local".
	// The /a/app/me response surfaces this so AppKit picks the right
	// behaviour automatically.
	TransportMode string `json:"transportMode"`

	// SessionCookieSameSite is the SameSite attribute applied to the
	// mr_at / mr_rt cookies in cookie-mode (see SessionCookieSameSite*
	// constants). Default "lax" — Strict is opt-in and only valid when
	// no inbound cross-site GET ever needs to carry the session.
	SessionCookieSameSite string `json:"sessionCookieSameSite"`
}
