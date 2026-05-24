package repo

import (
	"context"
	"errors"
	"time"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// Sentinel errors (follow your existing pattern)
var (
	ErrClientOTPNotFound       = errors.New("client otp not found")
	ErrClientOTPAttemptsCapHit = errors.New("client otp attempts cap reached")
)

// DeleteUnusedClientOTPs deletes any unused OTP rows for (app, email).
func (r *Repo) DeleteUnusedClientOTPs(ctx context.Context, appID uuid.UUID, emailNorm string) error {
	const q = `
delete from client_otp_codes
where app_id = $1
  and email_norm = $2
  and used_at is null;
`
	_, err := r.db.Pool().Exec(ctx, q, appID, emailNorm)
	return err
}

func (r *Repo) InsertClientOTP(ctx context.Context, otp core.ClientOTPCode) error {
	const q = `
insert into client_otp_codes (
  id,
  app_id,
  email_norm,
  code_hash,
  requested_ip,
  requested_user_agent,
  created_at,
  expires_at,
  used_at,
  attempts,
  last_attempt_at
) values (
  $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
);
`
	_, err := r.db.Pool().Exec(
		ctx,
		q,
		otp.ID,
		otp.AppID,
		otp.EmailNorm,
		otp.CodeHash,
		otp.RequestedIP,
		otp.RequestedUserAgent,
		otp.CreatedAt,
		otp.ExpiresAt,
		otp.UsedAt,
		otp.Attempts,
		otp.LastAttemptAt,
	)
	return err
}

// GetLatestUnusedClientOTP returns the most recent unused OTP for (app, email).
func (r *Repo) GetLatestUnusedClientOTP(ctx context.Context, appID uuid.UUID, emailNorm string) (*core.ClientOTPCode, error) {
	const q = `
select
  id,
  app_id,
  email_norm,
  code_hash,
  requested_ip,
  requested_user_agent,
  created_at,
  expires_at,
  used_at,
  attempts,
  last_attempt_at
from client_otp_codes
where app_id = $1
  and email_norm = $2
  and used_at is null
  and expires_at > now()
order by created_at desc
limit 1;
`

	var otp core.ClientOTPCode
	var usedAt *time.Time
	var lastAttemptAt *time.Time

	err := r.db.Pool().QueryRow(ctx, q, appID, emailNorm).Scan(
		&otp.ID,
		&otp.AppID,
		&otp.EmailNorm,
		&otp.CodeHash,
		&otp.RequestedIP,
		&otp.RequestedUserAgent,
		&otp.CreatedAt,
		&otp.ExpiresAt,
		&usedAt,
		&otp.Attempts,
		&lastAttemptAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrClientOTPNotFound
		}
		return nil, err
	}

	otp.UsedAt = usedAt
	otp.LastAttemptAt = lastAttemptAt
	return &otp, nil
}

// IncrementClientOTPAttempts increments attempts and sets last_attempt_at=now().
func (r *Repo) IncrementClientOTPAttempts(ctx context.Context, otpID uuid.UUID) error {
	const q = `
update client_otp_codes
set
  attempts = attempts + 1,
  last_attempt_at = now()
where id = $1;
`
	tag, err := r.db.Pool().Exec(ctx, q, otpID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrClientOTPNotFound
	}
	return nil
}

// ClaimClientOTPAttempt atomically increments attempts in one query
// AND enforces the cap. Returns the new attempts value on success.
// Returns ErrClientOTPAttemptsCapHit when the row exists but the
// pre-increment attempts value already met or exceeded `cap`. Returns
// ErrClientOTPNotFound when the row is missing or already used.
//
// This replaces the read-modify-write pattern (read attempts via
// GetLatestUnusedClientOTP, compare against cap in Go, then call
// IncrementClientOTPAttempts on hash miss) which had a TOCTOU race
// under concurrent verifies — N parallel requests could all observe
// attempts < cap, all hash-compare, all increment past the cap. The
// HTTP rate limit kept worst-case attempt counts bounded but the
// per-code cap was effectively lifted by concurrency. This single
// query closes that gap.
func (r *Repo) ClaimClientOTPAttempt(ctx context.Context, otpID uuid.UUID, cap int) (int, error) {
	const q = `
update client_otp_codes
set
  attempts = attempts + 1,
  last_attempt_at = now()
where id = $1
  and used_at is null
  and attempts < $2
returning attempts;
`
	var attempts int
	err := r.db.Pool().QueryRow(ctx, q, otpID, cap).Scan(&attempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Either the row doesn't exist / was used, OR it's at the
			// attempts cap. Disambiguate with one more read.
			var attemptsRead int
			var usedAt *time.Time
			readErr := r.db.Pool().QueryRow(ctx,
				`select attempts, used_at from client_otp_codes where id = $1`,
				otpID,
			).Scan(&attemptsRead, &usedAt)
			if readErr != nil {
				if errors.Is(readErr, pgx.ErrNoRows) {
					return 0, ErrClientOTPNotFound
				}
				return 0, readErr
			}
			if usedAt != nil {
				return 0, ErrClientOTPNotFound
			}
			return attemptsRead, ErrClientOTPAttemptsCapHit
		}
		return 0, err
	}
	return attempts, nil
}

// MarkClientOTPUsed sets used_at (one-time use). Only succeeds if not already used.
func (r *Repo) MarkClientOTPUsed(ctx context.Context, otpID uuid.UUID, usedAt time.Time) error {
	const q = `
update client_otp_codes
set used_at = $2
where id = $1
  and used_at is null;
`
	tag, err := r.db.Pool().Exec(ctx, q, otpID, usedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrClientOTPNotFound
	}
	return nil
}
