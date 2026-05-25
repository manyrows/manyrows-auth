package repo

import (
	"context"
	"errors"
	"manyrows-core/core"
	"manyrows-core/core/validation"
	"net/http"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

func (r *Repo) GetAccountWithPasswordByEmail(
	ctx context.Context,
	email string,
) (*core.Account, string, *validation.Result, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil, "", validation.NewIssue("email", "required", "email is required"), nil
	}

	const q = `
select
  id,
  email,
  name,
  password_hash,
  validated_at,
  language,
  locked_until,
  totp_secret_encrypted,
  totp_enabled_at,
  totp_backup_codes_encrypted,
  created_at
from accounts
where email = $1
limit 1;
`

	var acc core.Account
	var passwordHash *string
	var validatedAt *time.Time
	var language *string

	err := r.db.Pool().QueryRow(ctx, q, email).Scan(
		&acc.ID,
		&acc.Email,
		&acc.Name,
		&passwordHash,
		&validatedAt,
		&language,
		&acc.LockedUntil,
		&acc.TOTPSecretEncrypted,
		&acc.TOTPEnabledAt,
		&acc.TOTPBackupCodesEncrypted,
		&acc.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", &validation.Result{}, nil
		}
		return nil, "", &validation.Result{}, err
	}

	acc.ValidatedAt = validatedAt
	if language != nil {
		acc.Language = *language
	} else {
		acc.Language = "en"
	}

	if passwordHash == nil {
		return &acc, "", &validation.Result{}, nil
	}
	return &acc, *passwordHash, &validation.Result{}, nil
}

func (r *Repo) InsertAccountWithPassword(
	ctx context.Context,
	tx pgx.Tx,
	acc *core.Account,
	passwordHash string,
	passwordSetAt time.Time,
) (*validation.Result, error) {
	// New accounts are NOT validated by default: validated_at = NULL
	const q = `
insert into accounts (
  id,
  email,
  name,
  password_hash,
  password_set_at,
  validated_at,
  language,
  created_at
)
values ($1, $2, $3, $4, $5, null, $6, $7);
`
	lang := acc.Language
	if lang == "" {
		lang = "en"
	}
	_, err := tx.Exec(
		ctx,
		q,
		acc.ID,
		strings.TrimSpace(strings.ToLower(acc.Email)),
		acc.Name,
		passwordHash,
		passwordSetAt,
		lang,
		acc.CreatedAt,
	)
	if err != nil {
		if IsUniqueViolation(err) {
			vr := validation.NewIssue("email", "duplicate", "account already registered")
			vr.Status = http.StatusConflict
			return vr, nil
		}
		return &validation.Result{}, err
	}

	return &validation.Result{}, nil
}

/* -------------------------------------------------------------------------- */
/* Account validation                                                          */
/* -------------------------------------------------------------------------- */

func (r *Repo) SetAccountValidatedAt(ctx context.Context, tx pgx.Tx, accountID uuid.UUID, validatedAt time.Time) error {
	const q = `
update accounts
set validated_at = $2
where id = $1;
`
	ct, err := tx.Exec(ctx, q, accountID, validatedAt)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return core.ErrAccountNotFound
	}
	return nil
}

func (r *Repo) ClearAccountValidatedAt(ctx context.Context, tx pgx.Tx, accountID uuid.UUID) error {
	const q = `
update accounts
set validated_at = null
where id = $1;
`
	ct, err := tx.Exec(ctx, q, accountID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return core.ErrAccountNotFound
	}
	return nil
}

/* -------------------------------------------------------------------------- */
/* Insert                                                                      */
/* -------------------------------------------------------------------------- */

func (r *Repo) InsertAccount(ctx context.Context, tx pgx.Tx, acc *core.Account) (*validation.Result, error) {
	const q = `
insert into accounts (
  id,
  email,
  name,
  validated_at,
  language,
  created_at
)
values ($1, $2, $3, null, $4, $5);
`
	lang := acc.Language
	if lang == "" {
		lang = "en"
	}
	_, err := tx.Exec(
		ctx,
		q,
		acc.ID,
		strings.TrimSpace(strings.ToLower(acc.Email)),
		acc.Name,
		lang,
		acc.CreatedAt,
	)
	if err != nil {
		if IsUniqueViolation(err) {
			vr := validation.NewIssue("email", "duplicate", "email already registered")
			vr.Status = http.StatusConflict
			return vr, nil
		}
		return &validation.Result{}, err
	}

	return &validation.Result{}, nil
}

/* -------------------------------------------------------------------------- */
/* Lookups                                                                     */
/* -------------------------------------------------------------------------- */

// GetAccountByEmail returns (account, validationResult, err).
// If the account is not found, account is nil and result is ok.
func (r *Repo) GetAccountByEmail(ctx context.Context, email string) (*core.Account, *validation.Result, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil, validation.NewIssue("email", "required", "email is required"), nil
	}

	const q = `
select
  id,
  email,
  name,
  validated_at,
  language,
  locked_until,
  totp_secret_encrypted,
  totp_enabled_at,
  totp_backup_codes_encrypted,
  created_at
from accounts
where email = $1
limit 1;
`

	var acc core.Account
	var validatedAt *time.Time
	var language *string
	err := r.db.Pool().QueryRow(ctx, q, email).Scan(
		&acc.ID,
		&acc.Email,
		&acc.Name,
		&validatedAt,
		&language,
		&acc.LockedUntil,
		&acc.TOTPSecretEncrypted,
		&acc.TOTPEnabledAt,
		&acc.TOTPBackupCodesEncrypted,
		&acc.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &validation.Result{}, nil
		}
		return nil, &validation.Result{}, err
	}

	acc.ValidatedAt = validatedAt
	if language != nil {
		acc.Language = *language
	} else {
		acc.Language = "en"
	}
	return &acc, &validation.Result{}, nil
}

func (r *Repo) GetAccountByID(ctx context.Context, id uuid.UUID) (*core.Account, error) {
	const q = `
select
  id,
  email,
  name,
  validated_at,
  language,
  locked_until,
  totp_secret_encrypted,
  totp_enabled_at,
  totp_backup_codes_encrypted,
  created_at
from accounts
where id = $1
limit 1;
`

	var acc core.Account
	var validatedAt *time.Time
	var language *string
	err := r.db.Pool().QueryRow(ctx, q, id).Scan(
		&acc.ID,
		&acc.Email,
		&acc.Name,
		&validatedAt,
		&language,
		&acc.LockedUntil,
		&acc.TOTPSecretEncrypted,
		&acc.TOTPEnabledAt,
		&acc.TOTPBackupCodesEncrypted,
		&acc.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, core.ErrAccountNotFound
		}
		return nil, err
	}

	acc.ValidatedAt = validatedAt
	if language != nil {
		acc.Language = *language
	} else {
		acc.Language = "en"
	}
	return &acc, nil
}

func (r *Repo) UpdateName(ctx context.Context, id uuid.UUID, name string) error {
	const q = `
update accounts
set name = $2
where id = $1;
`
	return r.execAffectingOne(ctx, core.ErrAccountNotFound, q, id, name)
}

func (r *Repo) UpdateAccountLanguage(ctx context.Context, id uuid.UUID, language string) error {
	const q = `
update accounts
set language = $2
where id = $1;
`
	return r.execAffectingOne(ctx, core.ErrAccountNotFound, q, id, language)
}

/* -------------------------------------------------------------------------- */
/* TOTP 2FA                                                                    */
/* -------------------------------------------------------------------------- */

func (r *Repo) SetTOTPSecret(ctx context.Context, accountID uuid.UUID, encryptedSecret []byte) error {
	const q = `
update accounts
set totp_secret_encrypted = $2
where id = $1;
`
	return r.execAffectingOne(ctx, core.ErrAccountNotFound, q, accountID, encryptedSecret)
}

func (r *Repo) EnableTOTP(ctx context.Context, accountID uuid.UUID, enabledAt time.Time, encryptedBackupCodes []byte) error {
	const q = `
update accounts
set totp_enabled_at = $2,
    totp_backup_codes_encrypted = $3
where id = $1;
`
	return r.execAffectingOne(ctx, core.ErrAccountNotFound, q, accountID, enabledAt, encryptedBackupCodes)
}

func (r *Repo) DisableTOTP(ctx context.Context, accountID uuid.UUID) error {
	const q = `
update accounts
set totp_secret_encrypted = null,
    totp_enabled_at = null,
    totp_backup_codes_encrypted = null
where id = $1;
`
	return r.execAffectingOne(ctx, core.ErrAccountNotFound, q, accountID)
}

func (r *Repo) UpdateTOTPBackupCodes(ctx context.Context, accountID uuid.UUID, encryptedBackupCodes []byte) error {
	const q = `
update accounts
set totp_backup_codes_encrypted = $2
where id = $1;
`
	return r.execAffectingOne(ctx, core.ErrAccountNotFound, q, accountID, encryptedBackupCodes)
}

// AdvanceAccountTOTPStep atomically writes the supplied step number iff
// it's strictly greater than the currently-stored value. Returns true on
// success (the step was advanced — the code can be accepted). Returns
// false when the step is not greater than last_totp_step, which means
// the code has already been used inside its own window — replay
// rejected.
//
// Companion to AdvanceUserTOTPStep, but for admin accounts.
func (r *Repo) AdvanceAccountTOTPStep(ctx context.Context, accountID uuid.UUID, step int64) (bool, error) {
	const q = `
update accounts
set last_totp_step = $2
where id = $1
  and last_totp_step < $2;
`
	ct, err := r.db.Pool().Exec(ctx, q, accountID, step)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}
