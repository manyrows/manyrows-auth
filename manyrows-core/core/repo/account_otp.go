package repo

import (
	"context"
	"errors"
	"time"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// Sentinel errors
var (
	ErrAccountEmailOTPNotFound       = errors.New("account email otp not found")
	ErrAccountEmailOTPAttemptsCapHit = errors.New("account email otp attempts cap reached")
)

/* -------------------------------------------------------------------------- */
/* Delete                                                                      */
/* -------------------------------------------------------------------------- */

// DeleteUnusedAccountEmailOTPs deletes any unused OTP rows for an account.
// This enforces "one active OTP" without a partial unique index.
func (r *Repo) DeleteUnusedAccountEmailOTPs(ctx context.Context, accountID uuid.UUID) error {
	const q = `
delete from account_email_otps
where account_id = $1
  and used_at is null;
`
	_, err := r.db.Pool().Exec(ctx, q, accountID)
	return err
}

/* -------------------------------------------------------------------------- */
/* Insert                                                                      */
/* -------------------------------------------------------------------------- */

func (r *Repo) InsertAccountEmailOTP(ctx context.Context, otp core.AccountEmailOTP) error {
	const q = `
insert into account_email_otps (
  id,
  account_id,
  code_hash,
  expires_at,
  used_at,
  created_at
) values (
  $1, $2, $3, $4, $5, $6
);
`
	_, err := r.db.Pool().Exec(
		ctx,
		q,
		otp.ID,
		otp.AccountID,
		otp.CodeHash,
		otp.ExpiresAt,
		otp.UsedAt,
		otp.CreatedAt,
	)
	return err
}

/* -------------------------------------------------------------------------- */
/* Lookups                                                                     */
/* -------------------------------------------------------------------------- */

// GetLatestAccountEmailOTP returns the latest OTP (used/expired included).
// Typically you want GetLatestActiveAccountEmailOTP instead.
func (r *Repo) GetLatestAccountEmailOTP(ctx context.Context, accountID uuid.UUID) (*core.AccountEmailOTP, error) {
	const q = `
select
  id,
  account_id,
  code_hash,
  expires_at,
  used_at,
  attempts,
  created_at
from account_email_otps
where account_id = $1
order by created_at desc
limit 1;
`

	var otp core.AccountEmailOTP
	var usedAt *time.Time

	err := r.db.Pool().QueryRow(ctx, q, accountID).Scan(
		&otp.ID,
		&otp.AccountID,
		&otp.CodeHash,
		&otp.ExpiresAt,
		&usedAt,
		&otp.Attempts,
		&otp.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAccountEmailOTPNotFound
		}
		return nil, err
	}

	otp.UsedAt = usedAt
	return &otp, nil
}

// GetLatestActiveAccountEmailOTP returns the most recent unused + unexpired OTP for an account.
func (r *Repo) GetLatestActiveAccountEmailOTP(ctx context.Context, accountID uuid.UUID) (*core.AccountEmailOTP, error) {
	const q = `
select
  id,
  account_id,
  code_hash,
  expires_at,
  used_at,
  attempts,
  created_at
from account_email_otps
where account_id = $1
  and used_at is null
  and expires_at > now()
order by created_at desc
limit 1;
`

	var otp core.AccountEmailOTP
	var usedAt *time.Time

	err := r.db.Pool().QueryRow(ctx, q, accountID).Scan(
		&otp.ID,
		&otp.AccountID,
		&otp.CodeHash,
		&otp.ExpiresAt,
		&usedAt,
		&otp.Attempts,
		&otp.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAccountEmailOTPNotFound
		}
		return nil, err
	}

	otp.UsedAt = usedAt

	// Defensive: query already filters, but this keeps behaviour stable if SQL changes.
	if !otp.IsActive(time.Now().UTC()) {
		return nil, ErrAccountEmailOTPNotFound
	}

	return &otp, nil
}

/* -------------------------------------------------------------------------- */
/* Update                                                                      */
/* -------------------------------------------------------------------------- */

// MarkAccountEmailOTPUsed sets used_at (one-time use). Only succeeds if not already used.
func (r *Repo) MarkAccountEmailOTPUsed(ctx context.Context, otpID uuid.UUID, usedAt time.Time) error {
	const q = `
update account_email_otps
set used_at = $2
where id = $1
  and used_at is null;
`
	tag, err := r.db.Pool().Exec(ctx, q, otpID, usedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAccountEmailOTPNotFound
	}
	return nil
}

/* -------------------------------------------------------------------------- */
/* Transaction-safe verification helpers                                       */
/* -------------------------------------------------------------------------- */

// GetLatestActiveAccountEmailOTPForUpdate locks the selected row.
// Use this inside a tx to avoid race conditions during verification.
func (r *Repo) GetLatestActiveAccountEmailOTPForUpdate(ctx context.Context, tx pgx.Tx, accountID uuid.UUID) (*core.AccountEmailOTP, error) {
	const q = `
select
  id,
  account_id,
  code_hash,
  expires_at,
  used_at,
  attempts,
  created_at
from account_email_otps
where account_id = $1
  and used_at is null
  and expires_at > now()
order by created_at desc
limit 1
for update;
`

	var otp core.AccountEmailOTP
	var usedAt *time.Time

	err := tx.QueryRow(ctx, q, accountID).Scan(
		&otp.ID,
		&otp.AccountID,
		&otp.CodeHash,
		&otp.ExpiresAt,
		&usedAt,
		&otp.Attempts,
		&otp.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAccountEmailOTPNotFound
		}
		return nil, err
	}

	otp.UsedAt = usedAt

	// Defensive (same as above)
	if !otp.IsActive(time.Now().UTC()) {
		return nil, ErrAccountEmailOTPNotFound
	}

	return &otp, nil
}

// IncrementAccountEmailOTPAttemptsTx bumps the per-OTP wrong-guess
// counter inside a tx and returns the new value. Caller decides
// whether the new count crosses the burn threshold.
func (r *Repo) IncrementAccountEmailOTPAttemptsTx(ctx context.Context, tx pgx.Tx, otpID uuid.UUID) (int, error) {
	const q = `
update account_email_otps
set attempts = attempts + 1
where id = $1
returning attempts;
`
	var attempts int
	err := tx.QueryRow(ctx, q, otpID).Scan(&attempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrAccountEmailOTPNotFound
		}
		return 0, err
	}
	return attempts, nil
}

// ClaimAccountEmailOTPAttemptTx atomically increments attempts in one
// query AND enforces the cap. Tx-scoped counterpart of
// ClaimClientOTPAttempt. Returns the new attempts value on success;
// ErrAccountEmailOTPAttemptsCapHit if the row exists but attempts
// already met or exceeded `cap`; ErrAccountEmailOTPNotFound if the
// row is missing or already used.
//
// Replaces the read-modify-write pattern (read attempts via
// GetLatestActiveAccountEmailOTP, compare cap in Go, then call
// IncrementAccountEmailOTPAttemptsTx on hash miss) which had a
// TOCTOU race under concurrent verifies — N parallel requests could
// all observe attempts < cap and all pass before any of them
// incremented.
func (r *Repo) ClaimAccountEmailOTPAttemptTx(ctx context.Context, tx pgx.Tx, otpID uuid.UUID, cap int) (int, error) {
	const q = `
update account_email_otps
set attempts = attempts + 1
where id = $1
  and used_at is null
  and attempts < $2
returning attempts;
`
	var attempts int
	err := tx.QueryRow(ctx, q, otpID, cap).Scan(&attempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Disambiguate "missing/used" vs "cap reached" with one more read.
			var attemptsRead int
			var usedAt *time.Time
			readErr := tx.QueryRow(ctx,
				`select attempts, used_at from account_email_otps where id = $1`,
				otpID,
			).Scan(&attemptsRead, &usedAt)
			if readErr != nil {
				if errors.Is(readErr, pgx.ErrNoRows) {
					return 0, ErrAccountEmailOTPNotFound
				}
				return 0, readErr
			}
			if usedAt != nil {
				return 0, ErrAccountEmailOTPNotFound
			}
			return attemptsRead, ErrAccountEmailOTPAttemptsCapHit
		}
		return 0, err
	}
	return attempts, nil
}

// MarkAccountEmailOTPUsedTx marks used_at inside a tx (preferred for verify flows).
func (r *Repo) MarkAccountEmailOTPUsedTx(ctx context.Context, tx pgx.Tx, otpID uuid.UUID, usedAt time.Time) error {
	const q = `
update account_email_otps
set used_at = $2
where id = $1
  and used_at is null;
`
	tag, err := tx.Exec(ctx, q, otpID, usedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAccountEmailOTPNotFound
	}
	return nil
}
