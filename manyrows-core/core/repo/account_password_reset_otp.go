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
	ErrAccountPasswordResetOTPNotFound       = errors.New("account password reset otp not found")
	ErrAccountPasswordResetOTPAttemptsCapHit = errors.New("account password reset otp attempts cap reached")
)

/* -------------------------------------------------------------------------- */
/* Delete                                                                      */
/* -------------------------------------------------------------------------- */

func (r *Repo) DeleteUnusedAccountPasswordResetOTPs(ctx context.Context, accountID uuid.UUID) error {
	const q = `
delete from account_password_reset_otps
where account_id = $1
  and used_at is null;
`
	_, err := r.db.Pool().Exec(ctx, q, accountID)
	return err
}

/* -------------------------------------------------------------------------- */
/* Insert                                                                      */
/* -------------------------------------------------------------------------- */

func (r *Repo) InsertAccountPasswordResetOTP(ctx context.Context, otp core.AccountPasswordResetOTP) error {
	const q = `
insert into account_password_reset_otps (
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

func (r *Repo) GetLatestActiveAccountPasswordResetOTP(ctx context.Context, accountID uuid.UUID) (*core.AccountPasswordResetOTP, error) {
	const q = `
select
  id,
  account_id,
  code_hash,
  expires_at,
  used_at,
  attempts,
  created_at
from account_password_reset_otps
where account_id = $1
  and used_at is null
  and expires_at > now()
order by created_at desc
limit 1;
`

	var otp core.AccountPasswordResetOTP
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
			return nil, ErrAccountPasswordResetOTPNotFound
		}
		return nil, err
	}

	otp.UsedAt = usedAt
	if !otp.IsActive(time.Now().UTC()) {
		return nil, ErrAccountPasswordResetOTPNotFound
	}
	return &otp, nil
}

/* -------------------------------------------------------------------------- */
/* Tx-safe helpers                                                             */
/* -------------------------------------------------------------------------- */

func (r *Repo) GetLatestActiveAccountPasswordResetOTPForUpdate(ctx context.Context, tx pgx.Tx, accountID uuid.UUID) (*core.AccountPasswordResetOTP, error) {
	const q = `
select
  id,
  account_id,
  code_hash,
  expires_at,
  used_at,
  attempts,
  created_at
from account_password_reset_otps
where account_id = $1
  and used_at is null
  and expires_at > now()
order by created_at desc
limit 1
for update;
`

	var otp core.AccountPasswordResetOTP
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
			return nil, ErrAccountPasswordResetOTPNotFound
		}
		return nil, err
	}

	otp.UsedAt = usedAt
	if !otp.IsActive(time.Now().UTC()) {
		return nil, ErrAccountPasswordResetOTPNotFound
	}
	return &otp, nil
}

// ClaimAccountPasswordResetOTPAttemptTx atomically increments
// attempts in one query AND enforces the cap. Tx-scoped counterpart
// of ClaimClientOTPAttempt. Returns the new attempts value on
// success; ErrAccountPasswordResetOTPAttemptsCapHit if the row
// exists but attempts already met or exceeded `cap`;
// ErrAccountPasswordResetOTPNotFound if the row is missing or
// already used. Closes the TOCTOU race that the read-then-increment
// pattern had under concurrent verifies.
func (r *Repo) ClaimAccountPasswordResetOTPAttemptTx(ctx context.Context, tx pgx.Tx, otpID uuid.UUID, cap int) (int, error) {
	const q = `
update account_password_reset_otps
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
			var attemptsRead int
			var usedAt *time.Time
			readErr := tx.QueryRow(ctx,
				`select attempts, used_at from account_password_reset_otps where id = $1`,
				otpID,
			).Scan(&attemptsRead, &usedAt)
			if readErr != nil {
				if errors.Is(readErr, pgx.ErrNoRows) {
					return 0, ErrAccountPasswordResetOTPNotFound
				}
				return 0, readErr
			}
			if usedAt != nil {
				return 0, ErrAccountPasswordResetOTPNotFound
			}
			return attemptsRead, ErrAccountPasswordResetOTPAttemptsCapHit
		}
		return 0, err
	}
	return attempts, nil
}

// IncrementAccountPasswordResetOTPAttemptsTx bumps the per-OTP
// wrong-guess counter inside a tx and returns the new value.
func (r *Repo) IncrementAccountPasswordResetOTPAttemptsTx(ctx context.Context, tx pgx.Tx, otpID uuid.UUID) (int, error) {
	const q = `
update account_password_reset_otps
set attempts = attempts + 1
where id = $1
returning attempts;
`
	var attempts int
	err := tx.QueryRow(ctx, q, otpID).Scan(&attempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrAccountPasswordResetOTPNotFound
		}
		return 0, err
	}
	return attempts, nil
}

func (r *Repo) MarkAccountPasswordResetOTPUsedTx(ctx context.Context, tx pgx.Tx, otpID uuid.UUID, usedAt time.Time) error {
	const q = `
update account_password_reset_otps
set used_at = $2
where id = $1
  and used_at is null;
`
	tag, err := tx.Exec(ctx, q, otpID, usedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAccountPasswordResetOTPNotFound
	}
	return nil
}
