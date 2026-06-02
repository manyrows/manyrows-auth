package repo

import (
	"context"
	"errors"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// ErrOAuthStateNotFoundOrConsumed is returned by ConsumeOAuthState when the
// row either doesn't exist (forged jti, expired and cleaned, or never
// inserted) or has already been consumed (replay). Callers SHOULD NOT
// distinguish the two — both indicate "do not authorize this callback".
var ErrOAuthStateNotFoundOrConsumed = errors.New("oauth state not found or already consumed")

// InsertOAuthState persists a fresh OAuth state row keyed by jti. Used at
// /authorize time to make the token globally trackable. The jti is a
// per-request nonce embedded in the signed state token.
//
// openerOrigin is the AppKit popup-opener origin captured at authorize
// time (used by popup-flow providers Apple/Microsoft/GitHub to scope
// their postMessage targetOrigin at callback). Pass "" for non-popup
// flows (e.g. Google's POST callback).
//
// preloginSessionID is the client-session that was already active for
// this app when /authorize ran (nil = flow began unauthenticated).
// Carried across the provider round-trip so the callback can honor /
// guard against an existing session — see the column comment in
// migration 00008.
func (r *Repo) InsertOAuthState(ctx context.Context, jti, appID uuid.UUID, provider string, openerOrigin string, preloginSessionID *uuid.UUID, expiresAt time.Time) error {
	const q = `
insert into oauth_states (jti, app_id, provider, opener_origin, prelogin_session_id, expires_at)
values ($1, $2, $3, nullif($4, ''), $5, $6);
`
	_, err := r.db.Pool().Exec(ctx, q, jti, appID, provider, openerOrigin, preloginSessionID, expiresAt.UTC())
	return err
}

// ConsumeOAuthState atomically marks an OAuth state row as consumed and
// returns (app_id, provider, opener_origin, prelogin_session_id).
// Single-use is enforced by the "consumed_at IS NULL" predicate
// combined with the primary-key on jti — concurrent callers can't both
// succeed regardless of how many backend instances are running.
//
// opener_origin is "" when the row has no recorded origin (Google's
// non-popup flow, or any future provider that doesn't use AppKit's
// popup bridge). prelogin_session_id is nil when the flow began
// unauthenticated.
//
// Expired rows (expires_at < now()) are also rejected so a slow attacker
// can't exploit a long-tail replay.
func (r *Repo) ConsumeOAuthState(ctx context.Context, jti uuid.UUID) (uuid.UUID, string, string, *uuid.UUID, error) {
	const q = `
update oauth_states
   set consumed_at = now()
 where jti = $1
   and consumed_at is null
   and expires_at > now()
returning app_id, provider, coalesce(opener_origin, ''), prelogin_session_id;
`
	var (
		appID        uuid.UUID
		provider     string
		openerOrigin string
		preloginSes  *uuid.UUID
	)
	err := r.db.Pool().QueryRow(ctx, q, jti).Scan(&appID, &provider, &openerOrigin, &preloginSes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, "", "", nil, ErrOAuthStateNotFoundOrConsumed
		}
		return uuid.Nil, "", "", nil, err
	}
	return appID, provider, openerOrigin, preloginSes, nil
}

// PeekOAuthStateOpenerOrigin reads opener_origin without consuming the
// row. Used by popup-flow callback handlers that need the origin BEFORE
// running the inner processor (which atomically consumes the state via
// ConsumeOAuthState). Returns "" if the row is missing, already
// consumed, expired, or never had an origin set.
func (r *Repo) PeekOAuthStateOpenerOrigin(ctx context.Context, jti uuid.UUID) (string, error) {
	const q = `
select coalesce(opener_origin, '')
from oauth_states
where jti = $1
  and consumed_at is null
  and expires_at > now();
`
	var origin string
	err := r.db.Pool().QueryRow(ctx, q, jti).Scan(&origin)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrOAuthStateNotFoundOrConsumed
		}
		return "", err
	}
	return origin, nil
}

// DeleteExpiredOAuthStates is intended to be called periodically (e.g. from
// a cron-style worker) to keep the table bounded. Rows past their TTL are
// already rejected by ConsumeOAuthState, so this is purely housekeeping.
// Returns the number of rows deleted.
func (r *Repo) DeleteExpiredOAuthStates(ctx context.Context, olderThan time.Duration) (int64, error) {
	const q = `delete from oauth_states where expires_at < now() - $1::interval;`
	ct, err := r.db.Pool().Exec(ctx, q, olderThan.String())
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}
