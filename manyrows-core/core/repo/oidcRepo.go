package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// ErrOIDCRequiresCookieTransport is returned by UpdateAppOIDCConfig
// when an admin tries to enable OIDC on an app whose transport_mode is
// not "cookie". OIDC's /authorize → AppKit-sign-in → /authorize/resume
// round-trip relies on a same-origin session cookie to identify the
// signed-in user at the resume step; local-mode apps don't set one.
// Surfaced as a typed error so the admin handler can render a
// targeted "switch transport mode first" message.
var ErrOIDCRequiresCookieTransport = errors.New("OIDC requires cookie transport mode")

// OIDC-provider repo. Backs the auth-code flow plus the per-app
// provider config. Codes are hashed (SHA-256) before storage; raw code
// values never touch the DB. Consume is a single atomic UPDATE so a
// replayed code reliably hits the "already used" branch even under
// concurrent /token calls (no SELECT-then-UPDATE TOCTOU window).
//
// TTL policy lives here, not in the schema, so it can move without
// a migration:
//   - Auth codes: 60s. Plenty of headroom for the customer's redirect
//     + their backend's token call; below this you start losing real
//     users on slow networks.
//   - Pending /authorize: 10 min. Covers a user landing on the AppKit
//     sign-in page and taking their time with email verification.
const (
	OIDCAuthCodeTTL          = 60 * time.Second
	OIDCPendingAuthorizeTTL  = 10 * time.Minute
	oidcPendingConsumedGrace = 1 * time.Hour
	oidcCodeUsedGrace        = 1 * time.Hour
)

// =====================
// oidc_auth_codes
// =====================

// CreateOIDCAuthCodeParams is the full set of fields needed at mint
// time. CodeHash is the SHA-256 hex of the raw code; the raw code goes
// straight into the redirect URL and is never persisted.
type CreateOIDCAuthCodeParams struct {
	CodeHash            string
	AppID               uuid.UUID
	UserID              uuid.UUID
	SessionID           *uuid.UUID
	Nonce               string
	RedirectURI         string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

// CreateOIDCAuthCode persists a freshly minted authorization code.
// Caller is responsible for setting ExpiresAt = now + OIDCAuthCodeTTL.
func (r *Repo) CreateOIDCAuthCode(ctx context.Context, p CreateOIDCAuthCodeParams) error {
	_, err := r.db.Pool().Exec(ctx, `
		insert into oidc_auth_codes (
			code_hash, app_id, user_id, session_id, nonce,
			redirect_uri, scope, code_challenge, code_challenge_method,
			expires_at
		)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`,
		p.CodeHash, p.AppID, p.UserID, p.SessionID, p.Nonce,
		p.RedirectURI, p.Scope, p.CodeChallenge, p.CodeChallengeMethod,
		p.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("CreateOIDCAuthCode: %w", err)
	}
	return nil
}

// ConsumeOIDCAuthCode atomically marks the code as used and returns
// it. Single-statement UPDATE...WHERE used_at IS NULL...RETURNING so
// concurrent /token calls reliably resolve to "consumed by one,
// rejected as already-used by the other" with no race window.
//
// Returns (nil, false, nil) when the code doesn't exist, is expired,
// or was already used. The caller cannot distinguish those — that's
// intentional and matches OIDC §3.1.3.2 "the authorization server
// MUST ensure that ... the authorization code is otherwise still
// valid" with no guidance to leak why it isn't.
func (r *Repo) ConsumeOIDCAuthCode(ctx context.Context, codeHash string) (*core.OIDCAuthCode, bool, error) {
	const q = `
		update oidc_auth_codes
		set used_at = now()
		where code_hash = $1
		  and used_at is null
		  and expires_at > now()
		returning
			code_hash, app_id, user_id, session_id, nonce,
			redirect_uri, scope, code_challenge, code_challenge_method,
			created_at, expires_at, used_at
	`
	var c core.OIDCAuthCode
	err := r.db.Pool().QueryRow(ctx, q, codeHash).Scan(
		&c.CodeHash, &c.AppID, &c.UserID, &c.SessionID, &c.Nonce,
		&c.RedirectURI, &c.Scope, &c.CodeChallenge, &c.CodeChallengeMethod,
		&c.CreatedAt, &c.ExpiresAt, &c.UsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("ConsumeOIDCAuthCode: %w", err)
	}
	return &c, true, nil
}

// RevokeOIDCAuthCodeUserSession revokes every session/refresh-token
// chain rooted at the auth code identified by code_hash. Called when
// a code is presented twice at /token — the second presentation is
// either replay or a genuine attack, and we cannot tell which. Per
// OIDC §3.1.3.2, the safe response is to revoke the original session
// + refresh chain so an attacker who stole the code can't keep using
// the tokens already issued from it.
//
// Looks up the user_id from the (already-used) code row and asks the
// caller to revoke. Returns (uuid.Nil, false, nil) if the code_hash
// is unknown (in which case there's nothing to revoke).
func (r *Repo) LookupUsedOIDCAuthCodeUser(ctx context.Context, codeHash string) (uuid.UUID, *uuid.UUID, bool, error) {
	const q = `
		select user_id, session_id
		from oidc_auth_codes
		where code_hash = $1
		  and used_at is not null
	`
	var userID uuid.UUID
	var sessionID *uuid.UUID
	if err := r.db.Pool().QueryRow(ctx, q, codeHash).Scan(&userID, &sessionID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, nil, false, nil
		}
		return uuid.Nil, nil, false, fmt.Errorf("LookupUsedOIDCAuthCodeUser: %w", err)
	}
	return userID, sessionID, true, nil
}

// SweepExpiredOIDCAuthCodes deletes codes that have either expired or
// been used+aged-out. Driven by the janitor; safe to call concurrently
// with /token because consumed rows linger for oidcCodeUsedGrace so a
// replay attempt still finds the row and triggers the revoke path.
func (r *Repo) SweepExpiredOIDCAuthCodes(ctx context.Context) (int64, error) {
	ct, err := r.db.Pool().Exec(ctx, `
		delete from oidc_auth_codes
		where expires_at < now()
		   or (used_at is not null and used_at < now() - $1::interval)
	`, fmt.Sprintf("%d seconds", int(oidcCodeUsedGrace.Seconds())))
	if err != nil {
		return 0, fmt.Errorf("SweepExpiredOIDCAuthCodes: %w", err)
	}
	return ct.RowsAffected(), nil
}

// =====================
// oidc_pending_authorize
// =====================

// CreateOIDCPendingAuthorize stashes the original /authorize params
// for retrieval after AppKit sign-in completes. Returns the row's id
// for use as the return-to nonce.
func (r *Repo) CreateOIDCPendingAuthorize(ctx context.Context, appID uuid.UUID, params core.OIDCAuthorizeParams) (uuid.UUID, error) {
	id := utils.NewUUID()
	blob, err := json.Marshal(params)
	if err != nil {
		return uuid.Nil, fmt.Errorf("CreateOIDCPendingAuthorize marshal: %w", err)
	}
	_, err = r.db.Pool().Exec(ctx, `
		insert into oidc_pending_authorize (id, app_id, request_params, expires_at)
		values ($1, $2, $3, $4)
	`, id, appID, blob, time.Now().UTC().Add(OIDCPendingAuthorizeTTL))
	if err != nil {
		return uuid.Nil, fmt.Errorf("CreateOIDCPendingAuthorize insert: %w", err)
	}
	return id, nil
}

// ConsumeOIDCPendingAuthorize atomically claims a pending /authorize
// row, returning its stored request params. Single-use: a second call
// with the same id returns (nil, false, nil).
func (r *Repo) ConsumeOIDCPendingAuthorize(ctx context.Context, id uuid.UUID) (*core.OIDCPendingAuthorize, *core.OIDCAuthorizeParams, bool, error) {
	const q = `
		update oidc_pending_authorize
		set consumed_at = now()
		where id = $1
		  and consumed_at is null
		  and expires_at > now()
		returning id, app_id, request_params, created_at, expires_at, consumed_at
	`
	var p core.OIDCPendingAuthorize
	err := r.db.Pool().QueryRow(ctx, q, id).Scan(
		&p.ID, &p.AppID, &p.RequestParams, &p.CreatedAt, &p.ExpiresAt, &p.ConsumedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, false, nil
		}
		return nil, nil, false, fmt.Errorf("ConsumeOIDCPendingAuthorize: %w", err)
	}
	var params core.OIDCAuthorizeParams
	if err := json.Unmarshal(p.RequestParams, &params); err != nil {
		return nil, nil, false, fmt.Errorf("ConsumeOIDCPendingAuthorize unmarshal: %w", err)
	}
	return &p, &params, true, nil
}

// SweepExpiredOIDCPendingAuthorize is the janitor counterpart for
// pending /authorize rows. Same shape as SweepExpiredOIDCAuthCodes.
func (r *Repo) SweepExpiredOIDCPendingAuthorize(ctx context.Context) (int64, error) {
	ct, err := r.db.Pool().Exec(ctx, `
		delete from oidc_pending_authorize
		where expires_at < now()
		   or (consumed_at is not null and consumed_at < now() - $1::interval)
	`, fmt.Sprintf("%d seconds", int(oidcPendingConsumedGrace.Seconds())))
	if err != nil {
		return 0, fmt.Errorf("SweepExpiredOIDCPendingAuthorize: %w", err)
	}
	return ct.RowsAffected(), nil
}

// =====================
// apps OIDC config
// =====================

// GetAppOIDCConfig fetches the per-app OIDC provider configuration
// (separate from the App row to keep the existing appRepo SELECTs
// stable). Returns a populated *OIDCAppConfig regardless of whether
// OIDC is enabled — handlers check Enabled to decide whether to
// serve the OIDC surface at all.
func (r *Repo) GetAppOIDCConfig(ctx context.Context, appID uuid.UUID) (*core.OIDCAppConfig, error) {
	const q = `
		select oidc_enabled, oidc_client_secret_hash,
		       oidc_redirect_uris, oidc_post_logout_redirect_uris
		from apps
		where id = $1
	`
	var c core.OIDCAppConfig
	err := r.db.Pool().QueryRow(ctx, q, appID).Scan(
		&c.Enabled, &c.ClientSecretHash, &c.RedirectURIs, &c.PostLogoutRedirectURIs,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("GetAppOIDCConfig: %w", err)
	}
	return &c, nil
}

// UpdateAppOIDCConfigParams is the whole-config update shape. Whole-
// config replace (rather than per-field PATCH) keeps the admin handler
// simple and matches how the per-provider OAuth configs are set today.
type UpdateAppOIDCConfigParams struct {
	Enabled                bool
	ClientSecretHash       *string  // pass nil to leave the existing hash unchanged; pass a non-nil empty string to clear it (public client)
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
}

// UpdateAppOIDCConfig writes the four OIDC columns. ClientSecretHash
// uses tri-state nil-sentinel semantics — nil means "leave as-is" so
// admins can toggle redirect URIs without re-pasting the secret hash;
// an explicit empty string clears it (downgrade to public client).
//
// Nil slices are coerced to empty (`{}`) so a caller passing
// PostLogoutRedirectURIs: nil writes the spec-correct "empty allowlist"
// rather than tripping the NOT-NULL DEFAULT '{}' constraint via pgx.
//
// Refuses to enable OIDC on an app whose transport_mode is not
// "cookie" — returns ErrOIDCRequiresCookieTransport. OIDC sign-in
// flow needs a same-origin session cookie at /oidc/authorize/resume;
// local-mode apps don't set one. Lookup-before-update accepts the
// extra round-trip — admin config writes are rare.
func (r *Repo) UpdateAppOIDCConfig(ctx context.Context, appID uuid.UUID, p UpdateAppOIDCConfigParams) error {
	if p.Enabled {
		var transportMode string
		err := r.db.Pool().QueryRow(ctx, `select transport_mode from apps where id = $1`, appID).Scan(&transportMode)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("UpdateAppOIDCConfig: transport_mode lookup: %w", err)
		}
		if transportMode != core.TransportModeCookie {
			return ErrOIDCRequiresCookieTransport
		}
	}

	redirects := p.RedirectURIs
	if redirects == nil {
		redirects = []string{}
	}
	postLogout := p.PostLogoutRedirectURIs
	if postLogout == nil {
		postLogout = []string{}
	}

	if p.ClientSecretHash == nil {
		ct, err := r.db.Pool().Exec(ctx, `
			update apps
			set oidc_enabled = $2,
			    oidc_redirect_uris = $3,
			    oidc_post_logout_redirect_uris = $4,
			    updated_at = now()
			where id = $1
		`, appID, p.Enabled, redirects, postLogout)
		if err != nil {
			return fmt.Errorf("UpdateAppOIDCConfig: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	}

	// ClientSecretHash explicitly set (possibly empty to clear).
	var secret *string
	if *p.ClientSecretHash != "" {
		secret = p.ClientSecretHash
	}
	ct, err := r.db.Pool().Exec(ctx, `
		update apps
		set oidc_enabled = $2,
		    oidc_client_secret_hash = $3,
		    oidc_redirect_uris = $4,
		    oidc_post_logout_redirect_uris = $5,
		    updated_at = now()
		where id = $1
	`, appID, p.Enabled, secret, redirects, postLogout)
	if err != nil {
		return fmt.Errorf("UpdateAppOIDCConfig: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
