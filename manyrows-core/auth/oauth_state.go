// Package-level OAuth state token primitives, used by all four social
// providers (Google, Apple, Microsoft, GitHub). State is signed with HMAC
// for tamper detection AND persisted in Postgres so single-use is
// enforced atomically across all backend instances.
//
// Token layout (raw bytes, base64url-encoded for transport):
//
//	[appID 16][jti 16][expiresAt 8 BE-uint64][hmac 32]  = 72 bytes
//
// The jti is a per-request nonce; replays land on the same DB row, which
// can only be consumed once via ConsumeOAuthState's atomic UPDATE.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"

	"github.com/gofrs/uuid/v5"
)

var (
	ErrOAuthStateExpired = errors.New("oauth state expired")
	ErrOAuthStateInvalid = errors.New("oauth state invalid")
	ErrOAuthStateReused  = errors.New("oauth state already consumed")
)

// OAuthStateStore is the slice of *repo.Repo this package needs. Defined
// as an interface here so the auth package doesn't import repo (avoids
// circular deps) and so tests can stub it out. The error returned by
// ConsumeOAuthState when a row is missing or already consumed is matched
// by string equality against repo.ErrOAuthStateNotFoundOrConsumed —
// callers in api translate that to ErrOAuthStateReused.
type OAuthStateStore interface {
	InsertOAuthState(ctx context.Context, jti, appID uuid.UUID, provider string, openerOrigin string, preloginSessionID *uuid.UUID, expiresAt time.Time) error
	ConsumeOAuthState(ctx context.Context, jti uuid.UUID) (uuid.UUID, string, string, *uuid.UUID, error)
	PeekOAuthStateOpenerOrigin(ctx context.Context, jti uuid.UUID) (string, error)
}

// errOAuthStateNotFoundOrConsumed mirrors repo.ErrOAuthStateNotFoundOrConsumed
// by string. We can't import repo here (circular dep), so we match by
// Error() text — a small price to keep the package boundary clean.
var errOAuthStateNotFoundOrConsumed = errors.New("oauth state not found or already consumed")

const stateTokenLen = 16 + 16 + 8 + 32 // 72 bytes

// SignOAuthState issues a fresh state token for the given (app, provider)
// pair. A new jti is generated and persisted via store before the token
// is returned, so by the time the URL leaves this server the row exists
// and ConsumeOAuthState can atomically claim it later.
//
// openerOrigin is the popup-flow opener-origin captured at /authorize
// (Apple/Microsoft/GitHub use it to scope postMessage at callback). Pass
// "" for non-popup flows like Google's POST callback.
//
// preloginSessionID is the client-session already active for this app
// when /authorize ran (nil = unauthenticated start). It is persisted on
// the DB row only — deliberately NOT folded into the signed token
// payload: it's set server-side from a server-resolved session, keyed by
// the server-generated jti (which IS signed), and only ever read
// server-side at consume time. The client never supplies it, so there's
// nothing to tamper; keeping it off the token leaves the 72-byte layout
// and HMAC untouched.
func SignOAuthState(
	ctx context.Context,
	store OAuthStateStore,
	key []byte,
	appID uuid.UUID,
	provider string,
	openerOrigin string,
	preloginSessionID *uuid.UUID,
	ttl time.Duration,
) (string, error) {
	jti, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	expiresAt := time.Now().UTC().Add(ttl)

	if err := store.InsertOAuthState(ctx, jti, appID, provider, openerOrigin, preloginSessionID, expiresAt); err != nil {
		return "", err
	}

	payload := make([]byte, 40)
	copy(payload[0:16], appID.Bytes())
	copy(payload[16:32], jti.Bytes())
	binary.BigEndian.PutUint64(payload[32:40], uint64(expiresAt.Unix()))

	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	sig := mac.Sum(nil)

	token := append(payload, sig...)
	return base64.RawURLEncoding.EncodeToString(token), nil
}

// VerifyOAuthState validates a state token's signature, expiry, and
// single-use status. The DB-side claim ensures replays fail across all
// instances. Returns the app ID, the recorded openerOrigin ("" if none
// was set at sign time), and the prelogin client-session id (nil if the
// flow began unauthenticated) on success.
//
// expectedProvider must match the provider recorded at sign time —
// guards against an attacker swapping a Google state into the GitHub
// callback (or vice versa) on a multi-provider app.
func VerifyOAuthState(
	ctx context.Context,
	store OAuthStateStore,
	key []byte,
	token string,
	expectedProvider string,
) (uuid.UUID, string, *uuid.UUID, error) {
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return uuid.Nil, "", nil, ErrOAuthStateInvalid
	}
	if len(data) != stateTokenLen {
		return uuid.Nil, "", nil, ErrOAuthStateInvalid
	}

	payload := data[:40]
	sig := data[40:]

	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return uuid.Nil, "", nil, ErrOAuthStateInvalid
	}

	expiresUnix := binary.BigEndian.Uint64(payload[32:40])
	if time.Now().UTC().Unix() > int64(expiresUnix) {
		return uuid.Nil, "", nil, ErrOAuthStateExpired
	}

	appID, err := uuid.FromBytes(payload[0:16])
	if err != nil {
		return uuid.Nil, "", nil, ErrOAuthStateInvalid
	}
	jti, err := uuid.FromBytes(payload[16:32])
	if err != nil {
		return uuid.Nil, "", nil, ErrOAuthStateInvalid
	}

	// Atomic single-use claim. If the row doesn't exist, has already been
	// consumed, or has expired between our local check and the DB write,
	// the store returns its "not found or consumed" sentinel. We translate
	// that to ErrOAuthStateReused so callers don't have to know about
	// repo's sentinel.
	storedAppID, storedProvider, openerOrigin, preloginSessionID, err := store.ConsumeOAuthState(ctx, jti)
	if err != nil {
		if err.Error() == errOAuthStateNotFoundOrConsumed.Error() {
			return uuid.Nil, "", nil, ErrOAuthStateReused
		}
		return uuid.Nil, "", nil, err
	}

	// Defence in depth: the signed token's app_id must match the row, and
	// the row's provider must match the expected provider. Either mismatch
	// means a tampered/cross-provider token landed here.
	if storedAppID != appID || storedProvider != expectedProvider {
		return uuid.Nil, "", nil, ErrOAuthStateInvalid
	}

	return appID, openerOrigin, preloginSessionID, nil
}

// PeekOAuthStateOpenerOrigin returns the opener_origin recorded at sign
// time WITHOUT consuming the state row. Used by popup-flow callback
// handlers that need to scope the postMessage targetOrigin in the HTML
// wrapper BEFORE running the inner processor (which atomically consumes
// the row via VerifyOAuthState).
//
// Returns "" if the token is malformed, the signature/expiry check
// fails, the row is missing, the row is already consumed, or no
// origin was recorded.
func PeekOAuthStateOpenerOrigin(
	ctx context.Context,
	store OAuthStateStore,
	key []byte,
	token string,
) string {
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(data) != stateTokenLen {
		return ""
	}

	payload := data[:40]
	sig := data[40:]

	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return ""
	}

	jti, err := uuid.FromBytes(payload[16:32])
	if err != nil {
		return ""
	}

	origin, err := store.PeekOAuthStateOpenerOrigin(ctx, jti)
	if err != nil {
		return ""
	}
	return origin
}
