package repo

import (
	"context"
	"errors"
	"time"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

var (
	ErrAccountEmailChangeOTPNotFound       = errors.New("account email change otp not found")
	ErrAccountEmailChangeOTPAttemptsCapHit = errors.New("account email change otp attempts cap reached")
)

/* -------------------------------------------------------------------------- */
/* Delete                                                                      */
/* -------------------------------------------------------------------------- */

// DeleteUnusedAccountEmailChangeOTPs deletes any unused OTP rows for an account.
func (r *Repo) DeleteUnusedAccountEmailChangeOTPs(ctx context.Context, accountID uuid.UUID) error {
	const q = `
delete from account_email_change_otps
where account_id = $1
  and used_at is null;
`
	_, err := r.db.Pool().Exec(ctx, q, accountID)
	return err
}

/* -------------------------------------------------------------------------- */
/* Insert                                                                      */
/* -------------------------------------------------------------------------- */

func (r *Repo) InsertAccountEmailChangeOTP(ctx context.Context, otp core.AccountEmailChangeOTP) error {
	const q = `
insert into account_email_change_otps (
  id,
  account_id,
  new_email,
  code_hash,
  expires_at,
  used_at,
  created_at
) values (
  $1, $2, $3, $4, $5, $6, $7
);
`
	_, err := r.db.Pool().Exec(
		ctx,
		q,
		otp.ID,
		otp.AccountID,
		otp.NewEmail,
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

// GetLatestActiveAccountEmailChangeOTP returns the most recent unused + unexpired OTP for an account.
func (r *Repo) GetLatestActiveAccountEmailChangeOTP(ctx context.Context, accountID uuid.UUID) (*core.AccountEmailChangeOTP, error) {
	const q = `
select
  id,
  account_id,
  new_email,
  code_hash,
  expires_at,
  used_at,
  attempts,
  created_at
from account_email_change_otps
where account_id = $1
  and used_at is null
  and expires_at > now()
order by created_at desc
limit 1;
`

	var otp core.AccountEmailChangeOTP
	var usedAt *time.Time

	err := r.db.Pool().QueryRow(ctx, q, accountID).Scan(
		&otp.ID,
		&otp.AccountID,
		&otp.NewEmail,
		&otp.CodeHash,
		&otp.ExpiresAt,
		&usedAt,
		&otp.Attempts,
		&otp.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAccountEmailChangeOTPNotFound
		}
		return nil, err
	}

	otp.UsedAt = usedAt

	if !otp.IsActive(time.Now().UTC()) {
		return nil, ErrAccountEmailChangeOTPNotFound
	}

	return &otp, nil
}

/* -------------------------------------------------------------------------- */
/* Transaction-safe verification helpers                                       */
/* -------------------------------------------------------------------------- */

// GetLatestActiveAccountEmailChangeOTPForUpdate locks the selected row.
func (r *Repo) GetLatestActiveAccountEmailChangeOTPForUpdate(ctx context.Context, tx pgx.Tx, accountID uuid.UUID) (*core.AccountEmailChangeOTP, error) {
	const q = `
select
  id,
  account_id,
  new_email,
  code_hash,
  expires_at,
  used_at,
  attempts,
  created_at
from account_email_change_otps
where account_id = $1
  and used_at is null
  and expires_at > now()
order by created_at desc
limit 1
for update;
`

	var otp core.AccountEmailChangeOTP
	var usedAt *time.Time

	err := tx.QueryRow(ctx, q, accountID).Scan(
		&otp.ID,
		&otp.AccountID,
		&otp.NewEmail,
		&otp.CodeHash,
		&otp.ExpiresAt,
		&usedAt,
		&otp.Attempts,
		&otp.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAccountEmailChangeOTPNotFound
		}
		return nil, err
	}

	otp.UsedAt = usedAt

	if !otp.IsActive(time.Now().UTC()) {
		return nil, ErrAccountEmailChangeOTPNotFound
	}

	return &otp, nil
}

// IncrementAccountEmailChangeOTPAttemptsTx bumps the per-OTP wrong-guess
// counter and returns the new value. Caller decides whether the new
// count crosses the burn threshold and, if so, should follow up with
// MarkAccountEmailChangeOTPUsedTx in the same transaction.
//
// Prefer ClaimAccountEmailChangeOTPAttemptTx for new code — that
// version closes the TOCTOU race on the cap check.

// ClaimAccountEmailChangeOTPAttemptTx atomically increments attempts
// AND enforces the cap in one query. Tx-scoped counterpart of
// ClaimClientOTPAttempt. Returns ErrAccountEmailChangeOTPAttemptsCapHit
// when the row is at or beyond `cap`, ErrAccountEmailChangeOTPNotFound
// when the row is missing or already used.
func (r *Repo) ClaimAccountEmailChangeOTPAttemptTx(ctx context.Context, tx pgx.Tx, otpID uuid.UUID, cap int) (int, error) {
	const q = `
update account_email_change_otps
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
				`select attempts, used_at from account_email_change_otps where id = $1`,
				otpID,
			).Scan(&attemptsRead, &usedAt)
			if readErr != nil {
				if errors.Is(readErr, pgx.ErrNoRows) {
					return 0, ErrAccountEmailChangeOTPNotFound
				}
				return 0, readErr
			}
			if usedAt != nil {
				return 0, ErrAccountEmailChangeOTPNotFound
			}
			return attemptsRead, ErrAccountEmailChangeOTPAttemptsCapHit
		}
		return 0, err
	}
	return attempts, nil
}

func (r *Repo) IncrementAccountEmailChangeOTPAttemptsTx(ctx context.Context, tx pgx.Tx, otpID uuid.UUID) (int, error) {
	const q = `
update account_email_change_otps
set attempts = attempts + 1
where id = $1
returning attempts;
`
	var attempts int
	err := tx.QueryRow(ctx, q, otpID).Scan(&attempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrAccountEmailChangeOTPNotFound
		}
		return 0, err
	}
	return attempts, nil
}

// MarkAccountEmailChangeOTPUsedTx marks used_at inside a tx.
func (r *Repo) MarkAccountEmailChangeOTPUsedTx(ctx context.Context, tx pgx.Tx, otpID uuid.UUID, usedAt time.Time) error {
	const q = `
update account_email_change_otps
set used_at = $2
where id = $1
  and used_at is null;
`
	tag, err := tx.Exec(ctx, q, otpID, usedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAccountEmailChangeOTPNotFound
	}
	return nil
}

// UpdateAccountEmailTx updates the account's email address within a transaction.
func (r *Repo) UpdateAccountEmailTx(ctx context.Context, tx pgx.Tx, accountID uuid.UUID, newEmail string) error {
	const q = `
update accounts
set email = $2
where id = $1;
`
	tag, err := tx.Exec(ctx, q, accountID, newEmail)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.ErrAccountNotFound
	}
	return nil
}

// IsEmailTaken checks if an email is already used by another account.
func (r *Repo) IsEmailTaken(ctx context.Context, email string, excludeAccountID uuid.UUID) (bool, error) {
	const q = `
select exists(
  select 1 from accounts
  where lower(email) = lower($1)
    and id != $2
);
`
	var exists bool
	err := r.db.Pool().QueryRow(ctx, q, email, excludeAccountID).Scan(&exists)
	return exists, err
}

// IsEmailPendingChange checks if another account has a pending (unused, unexpired) email change to this email.
func (r *Repo) IsEmailPendingChange(ctx context.Context, email string, excludeAccountID uuid.UUID) (bool, error) {
	const q = `
select exists(
  select 1 from account_email_change_otps
  where lower(new_email) = lower($1)
    and account_id != $2
    and used_at is null
    and expires_at > now()
);
`
	var exists bool
	err := r.db.Pool().QueryRow(ctx, q, email, excludeAccountID).Scan(&exists)
	return exists, err
}
