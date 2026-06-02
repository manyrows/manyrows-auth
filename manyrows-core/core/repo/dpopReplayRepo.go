package repo

import (
	"context"
	"errors"
	"time"
)

// RecordDPopProofIfNew atomically inserts a (jkt, jti) pair into the replay
// cache. Returns true if the proof is novel (the row was inserted), false if
// it has already been recorded — indicating a replayed DPoP proof.
//
// The expiry is enforced by the row's expires_at column plus the periodic
// cleanup goroutine; we never accept a "newly fresh" jti just because the
// previous record expired, because reusing the same jti at all is not
// something a correct client should do (RFC 9449 §4.1).
func (r *Repo) RecordDPopProofIfNew(ctx context.Context, jkt, jti string, expiresAt time.Time) (bool, error) {
	if jkt == "" || jti == "" {
		return false, errors.New("RecordDPopProofIfNew: jkt and jti must be non-empty")
	}
	const q = `
insert into dpop_replay (jkt, jti, expires_at)
values ($1, $2, $3)
on conflict (jkt, jti) do nothing;
`
	tag, err := r.db.Pool().Exec(ctx, q, jkt, jti, expiresAt)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// DeleteExpiredDPopReplay removes all replay-cache rows whose expires_at is
// in the past. Intended to be called from a periodic background goroutine to
// keep the table tidy. Returns the number of rows removed.
func (r *Repo) DeleteExpiredDPopReplay(ctx context.Context, now time.Time) (int64, error) {
	const q = `delete from dpop_replay where expires_at < $1;`
	tag, err := r.db.Pool().Exec(ctx, q, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
