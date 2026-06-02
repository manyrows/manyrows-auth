package client

import (
	"context"
	"errors"
	"manyrows-core/auth/jwks"
	"manyrows-core/config"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/crypto"
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

const (
	// AccessTokenTTL is the TTL for short-lived access tokens.
	AccessTokenTTL = 15 * time.Minute

	// RefreshTokenTTL is the TTL for long-lived refresh tokens.
	RefreshTokenTTL = 7 * 24 * time.Hour

	// refreshGraceWindow is how long after a refresh token is rotated
	// we still treat re-presentations as "duplicate concurrent
	// request" rather than "reuse attack." Two-tab races and SDK
	// retry-on-timeout commonly land within a few seconds; 30s gives
	// generous headroom while keeping the security window small —
	// after this, a re-presented token revokes the session.
	refreshGraceWindow = 30 * time.Second
)

var (
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrSessionExpired      = errors.New("session expired")

	// ErrDPoPRequired is returned when a refresh request omits a DPoP proof
	// for a session that was created with DPoP binding. The client cannot
	// downgrade a bound session to Bearer; they must present a valid proof
	// from the bound keypair, or re-authenticate.
	ErrDPoPRequired = errors.New("dpop proof required for this session")

	// ErrDPoPBindingMismatch is returned when the presented DPoP proof's jkt
	// does not match the thumbprint the session was bound to. Indicates the
	// proof was signed by a different keypair (legitimate user lost their key
	// → re-authenticate; or attacker presenting their own key with a stolen
	// refresh token → reject).
	ErrDPoPBindingMismatch = errors.New("dpop proof does not match bound key")
)

// TokenPair represents the response from login/refresh operations.
// ExpiresAt/ExpiresIn describe the access token's lifetime;
// RefreshExpiresIn describes the refresh token's lifetime in seconds
// (callers use this to set the refresh-cookie Max-Age so it stays in
// lockstep with the server-side refresh token, especially for
// remember-me sessions on the refresh path where the cookie issuer
// doesn't otherwise know the chosen TTL).
type TokenPair struct {
	AccessToken      string    `json:"accessToken"`
	RefreshToken     string    `json:"refreshToken"`
	ExpiresAt        time.Time `json:"expiresAt"`
	ExpiresIn        int       `json:"expiresIn"`
	RefreshExpiresIn int       `json:"refreshExpiresIn"`
}

// AuthService is JWT-only auth for external client apps.
// Sessions are stored in DB (client_sessions) and scoped to a user + app.
type AuthService struct {
	repo *repo.Repo

	// jwtKeyStore is the storage surface for the install's JWT signing
	// keypair. In prod it's a system_secrets wrapper that encrypts the
	// PEM at rest under the install's encryption_key; tests can use a
	// plaintext fake. Held here so RotateSigningKey + Retire... read
	// and write through the same wrapper LoadOrGenerateSet did.
	jwtKeyStore jwks.MutableSecretsStore

	// ES256 signing keys for JWT bearer tokens. Loaded from
	// system_secrets at boot, generated on first run. Public halves
	// are published at /.well-known/jwks.json so consumers verify
	// locally without a shared secret. Current is always non-nil
	// after construction; Previous is populated only during a
	// rotation overlap window. Atomic so RotateSigningKey can swap
	// the pointer without locking every read.
	jwtKeys atomic.Pointer[jwks.KeySet]

	// cfg is held so jwt iss can be resolved at issue/verify time
	// rather than baked in at constructor time. Lets first-boot
	// installs come up with BASE_URL still empty (it's pinned by
	// the first-admin registration flow); end-user JWT issuance
	// fails until BASE_URL exists, but admin login (cookie-based)
	// works fine in the meantime.
	cfg *config.Config

	// session TTL (defaults to 30d if zero)
	sessionTTL time.Duration
}

// JWKSDocument returns the JWKS payload for /.well-known/jwks.json.
// Stable bytes; safe for the HTTP layer to cache or hand directly to
// the response writer. Includes the previous key when a rotation
// overlap window is open.
func (a *AuthService) JWKSDocument() ([]byte, error) {
	return a.jwtKeys.Load().Document()
}

// SigningKeyInfo is the operator-facing description of a single
// signing key — returned by GetSigningKeyStatus so the admin UI can
// show what's currently published.
type SigningKeyInfo struct {
	KID string `json:"kid"`
}

// SigningKeyStatus describes the live signing keyset. Returned by
// the admin status endpoint so the operator can see what's active
// before triggering a rotation or retirement.
type SigningKeyStatus struct {
	Current  SigningKeyInfo  `json:"current"`
	Previous *SigningKeyInfo `json:"previous,omitempty"`
}

// GetSigningKeyStatus returns the live keyset's current + optional
// previous kid. No private material exposed.
func (a *AuthService) GetSigningKeyStatus() SigningKeyStatus {
	set := a.jwtKeys.Load()
	out := SigningKeyStatus{Current: SigningKeyInfo{KID: set.Current.KID}}
	if set.Previous != nil {
		out.Previous = &SigningKeyInfo{KID: set.Previous.KID}
	}
	return out
}

// RotateSigningKey generates a fresh signing key, moves the prior
// current key into the previous slot, persists both rows, and atomically
// swaps the in-process keyset. Subsequent token issuance signs with the
// new key; both keys are published in JWKS so tokens already in flight
// continue to verify until they reach natural expiry.
//
// Multi-instance caveat: only the replica that handles the request
// reloads its in-memory keyset. Other replicas continue issuing under
// the old kid until they restart. Tokens cross-verify correctly during
// the overlap (both replicas serve both keys in JWKS via the DB), so
// users don't notice — but operators should be aware that "rotation
// complete" means the originating replica only.
func (a *AuthService) RotateSigningKey(ctx context.Context) (SigningKeyStatus, error) {
	cur := a.jwtKeys.Load()
	rotated, err := cur.Rotate(ctx, a.jwtKeyStore)
	if err != nil {
		return SigningKeyStatus{}, err
	}
	a.jwtKeys.Store(rotated)
	log.Info().
		Str("new_kid", rotated.Current.KID).
		Str("prev_kid", rotated.Previous.KID).
		Msg("signing key rotated")
	return a.GetSigningKeyStatus(), nil
}

// RetirePreviousSigningKey drops the previous-key slot from both the
// DB and the in-process keyset. Call this once enough time has elapsed
// since RotateSigningKey that no JWT signed with the previous key can
// still be in use (≥ the longest live refresh-token TTL — 7d by
// default, up to 30d remember-me, or per-app override).
func (a *AuthService) RetirePreviousSigningKey(ctx context.Context) (SigningKeyStatus, error) {
	cur := a.jwtKeys.Load()
	retired, err := cur.RetirePrevious(ctx, a.repo)
	if err != nil {
		return SigningKeyStatus{}, err
	}
	a.jwtKeys.Store(retired)
	log.Info().
		Str("current_kid", retired.Current.KID).
		Msg("previous signing key retired")
	return a.GetSigningKeyStatus(), nil
}

// issuer resolves the JWT iss claim from the live config. Called at
// every issue/verify so a BASE_URL that gets pinned mid-process (the
// first-admin flow does this via os.Setenv) takes effect for the
// next minted token without a restart.
func (a *AuthService) issuer() string {
	if a.cfg == nil {
		return ""
	}
	return strings.TrimRight(strings.TrimSpace(a.cfg.GetBaseURL()), "/")
}

// IssuerForApp returns the JWT iss claim to use for tokens minted for
// this app. Per-app AuthDomain wins when set so customer backends
// verifying against "https://auth.<their>.com" succeed; falls back to
// the install-wide base URL when the app has no custom auth host.
func (a *AuthService) IssuerForApp(app *core.App) string {
	if app != nil && app.AuthDomain != nil {
		if d := strings.TrimSpace(*app.AuthDomain); d != "" {
			return "https://" + strings.TrimRight(d, "/")
		}
	}
	return a.issuer()
}

// NewAuthService constructs the client-side auth service. jwtKeyStore
// is the wrapper used to read and write the install's JWT signing PEM
// rows in system_secrets — in prod it's the encrypting wrapper so the
// PEM is at-rest encrypted.
//
// Passing nil for jwtKeyStore is supported as a convenience: the
// constructor builds a fresh encrypting wrapper from the config's
// encryption_key. That keeps existing tests from having to thread
// the wrapper through, and means any DB with already-encrypted JWT
// key rows decrypts cleanly. If the encryption_key isn't configured
// (e.g. tests that only exercise login flows pre-bootstrap), the
// fallback is the raw repo — works for clean test DBs where the
// PEM is still plaintext.
func NewAuthService(c *config.Config, repo *repo.Repo, jwtKeyStore jwks.MutableSecretsStore) (*AuthService, error) {
	if jwtKeyStore == nil {
		// Try to build the encrypting wrapper from cfg; if the
		// encryption key isn't available, fall back to raw repo.
		if _, err := c.GetEncryptionKey(); err == nil {
			jwtKeyStore = crypto.NewEncryptingSystemSecretsStore(repo, crypto.NewMySecretEncryptor(c))
		} else {
			jwtKeyStore = repo
		}
	}

	// ES256 keyset: load current + optional previous from
	// system_secrets; generate current on first boot. Public halves
	// ship at /.well-known/jwks.json so SDKs verify locally — no
	// shared secret to distribute or rotate. Previous key is
	// present only during a rotation overlap window.
	set, err := jwks.LoadOrGenerateSet(context.Background(), jwtKeyStore)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(c.GetBaseURL()) == "" {
		// Don't fail boot — BASE_URL is empty on a fresh self-hosted
		// install until the first admin registers (which pins it from
		// their request host). End-user JWT issuance returns an error
		// until then; admin login uses cookie sessions and is fine.
		log.Warn().Msg("client auth: MANYROWS_BASE_URL not set yet; end-user JWT issuance will fail until first /admin/register pins it")
	}

	svc := &AuthService{
		repo:        repo,
		jwtKeyStore: jwtKeyStore,
		cfg:         c,
		sessionTTL:  30 * 24 * time.Hour,
	}
	svc.jwtKeys.Store(set)
	return svc, nil
}

// =====================
// JWT claims + issuance
// =====================

// We keep claims minimal and DB-backed.
//   - iss: deployment base URL (RegisteredClaims.Issuer) — verified on
//     parse as defence-in-depth against cross-deployment token replay.
//   - aud: app ID (RegisteredClaims.Audience) — formalises the
//     existing custom AppID check; the strict "ses.AppID == claims.AppID"
//     comparison downstream stays in place as the authoritative
//     per-request check.
//   - sid: client_sessions.id
//   - app: client_sessions.app_id (kept for back-compat with the
//     downstream strict-equality check; mirrors aud)
//   - sub: user_id (for debugging/auditing)
type mrClientJWTClaims struct {
	SessionID string `json:"sid"`
	AppID     string `json:"app,omitempty"`
	jwt.RegisteredClaims
}
