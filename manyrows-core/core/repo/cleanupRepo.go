package repo

import (
	"context"
	"time"
)

// janitorLockKey is the Postgres advisory-lock key used to leader-elect
// the janitor across replicas. Arbitrary prime — must stay stable across
// versions so different replicas pick the same key. No other code in
// this codebase takes advisory locks; the keyspace is uncontested.
const janitorLockKey int64 = 7919

// TryClaimJanitorLock acquires a session-level Postgres advisory lock on
// the janitor's key. Returns (release, true, nil) if this replica is now
// the sweep leader; the caller MUST defer release() to free the lock
// and return the underlying connection to the pool. Returns
// (nil, false, nil) when another replica already holds the lock — the
// caller should skip its tick.
//
// Session-level (not transaction-scoped) so the lock survives across
// the independent DELETE queries in a sweep. If the holding replica
// crashes, Postgres releases the lock automatically when the TCP
// connection drops — no stale-lock recovery needed.
func (r *Repo) TryClaimJanitorLock(ctx context.Context) (release func(), got bool, err error) {
	conn, err := r.db.Pool().Acquire(ctx)
	if err != nil {
		return nil, false, err
	}

	var locked bool
	if err := conn.QueryRow(ctx, "select pg_try_advisory_lock($1)", janitorLockKey).Scan(&locked); err != nil {
		conn.Release()
		return nil, false, err
	}
	if !locked {
		conn.Release()
		return nil, false, nil
	}

	return func() {
		// Use a fresh context so a cancelled tick still cleans the
		// lock up. Best-effort: on error the lock releases when the
		// connection closes anyway.
		_, _ = conn.Exec(context.Background(), "select pg_advisory_unlock($1)", janitorLockKey)
		conn.Release()
	}, true, nil
}

// Cleanup methods consumed by the janitor goroutine. Each one is a single
// bounded DELETE against a transient table; expired/event rows aren't load-
// bearing once their natural TTL has passed (or, for event logs, once the
// configured retention window has). Keeping the methods here avoids
// scattering one-line cleanup helpers across every transient-data repo.

// DeleteOldAttempts removes rate-limit log rows older than olderThan.
// Attempts have no natural expiry — they grow on every login attempt and
// only matter for the rate-limit windowing query which looks at the last
// few minutes. Anything beyond that is dead weight.
func (r *Repo) DeleteOldAttempts(ctx context.Context, olderThan time.Duration) (int64, error) {
	const q = `delete from attempts where created_at < now() - $1::interval;`
	tag, err := r.db.Pool().Exec(ctx, q, olderThan.String())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteOldAuthLogs removes audit-log rows older than olderThan. Operators
// who need long-term retention bump MANYROWS_AUTH_LOG_RETENTION_DAYS.
func (r *Repo) DeleteOldAuthLogs(ctx context.Context, olderThan time.Duration) (int64, error) {
	const q = `delete from auth_logs where created_at < now() - $1::interval;`
	tag, err := r.db.Pool().Exec(ctx, q, olderThan.String())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteExpiredMagicLinks removes consumed or naturally-expired magic-link
// rows. Tokens are single-use so used_at != NULL also makes the row dead
// weight even before expires_at lands.
func (r *Repo) DeleteExpiredMagicLinks(ctx context.Context, now time.Time) (int64, error) {
	const q = `delete from magic_links where expires_at < $1 or used_at is not null;`
	tag, err := r.db.Pool().Exec(ctx, q, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteExpiredClientRefreshTokens removes refresh-token rows whose
// natural TTL has passed. Rotated / revoked rows that haven't yet expired
// are kept around so the reuse-detection grace window still has something
// to compare against.
func (r *Repo) DeleteExpiredClientRefreshTokens(ctx context.Context, now time.Time) (int64, error) {
	const q = `delete from client_refresh_tokens where expires_at < $1;`
	tag, err := r.db.Pool().Exec(ctx, q, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteExpiredClientOTPCodes removes end-user OTP codes past their TTL or
// already used.
func (r *Repo) DeleteExpiredClientOTPCodes(ctx context.Context, now time.Time) (int64, error) {
	const q = `delete from client_otp_codes where expires_at < $1 or used_at is not null;`
	tag, err := r.db.Pool().Exec(ctx, q, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteExpiredAccountEmailOTPs removes admin email-verification OTP rows
// past their TTL or already used.
func (r *Repo) DeleteExpiredAccountEmailOTPs(ctx context.Context, now time.Time) (int64, error) {
	const q = `delete from account_email_otps where expires_at < $1 or used_at is not null;`
	tag, err := r.db.Pool().Exec(ctx, q, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteExpiredAccountPasswordResetOTPs removes admin password-reset OTP
// rows past their TTL or already used.
func (r *Repo) DeleteExpiredAccountPasswordResetOTPs(ctx context.Context, now time.Time) (int64, error) {
	const q = `delete from account_password_reset_otps where expires_at < $1 or used_at is not null;`
	tag, err := r.db.Pool().Exec(ctx, q, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteExpiredAccountEmailChangeOTPs removes admin email-change OTP rows
// past their TTL or already used.
func (r *Repo) DeleteExpiredAccountEmailChangeOTPs(ctx context.Context, now time.Time) (int64, error) {
	const q = `delete from account_email_change_otps where expires_at < $1 or used_at is not null;`
	tag, err := r.db.Pool().Exec(ctx, q, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteExpiredEmailChangeRequests removes end-user email-change request
// rows past their TTL.
func (r *Repo) DeleteExpiredEmailChangeRequests(ctx context.Context, now time.Time) (int64, error) {
	const q = `delete from email_change_requests where expires_at < $1;`
	tag, err := r.db.Pool().Exec(ctx, q, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteExpiredAdminSessions removes admin session rows past their TTL.
func (r *Repo) DeleteExpiredAdminSessions(ctx context.Context, now time.Time) (int64, error) {
	const q = `delete from sessions where expires_at < $1;`
	tag, err := r.db.Pool().Exec(ctx, q, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteAllExpiredClientSessions removes end-user session rows past their
// TTL across every workspace. The existing DeleteExpiredClientSessions is
// workspace-scoped (used by the per-workspace housekeeping endpoint); this
// variant is for the global janitor sweep.
func (r *Repo) DeleteAllExpiredClientSessions(ctx context.Context, now time.Time) (int64, error) {
	const q = `delete from client_sessions where expires_at < $1;`
	tag, err := r.db.Pool().Exec(ctx, q, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
