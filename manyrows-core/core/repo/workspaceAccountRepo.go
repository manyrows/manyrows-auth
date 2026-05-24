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

/* -------------------------------------------------------------------------- */
/* Insert                                                                      */
/* -------------------------------------------------------------------------- */

// InsertWorkspaceAccount creates a new workspace-scoped account.
func (r *Repo) InsertWorkspaceAccount(
	ctx context.Context,
	tx pgx.Tx,
	wa *core.WorkspaceAccount,
) (*validation.Result, error) {
	// Default source to "invited" if not set
	source := wa.Source
	if source == "" {
		source = core.WorkspaceAccountSourceInvited
	}

	const q = `
insert into workspace_accounts (
  id,
  workspace_id,
  email,
  display_name,
  email_verified_at,
  source,
  created_at,
  updated_at
)
values ($1, $2, $3, $4, $5, $6, $7, $8);
`
	_, err := tx.Exec(
		ctx,
		q,
		wa.ID,
		wa.WorkspaceID,
		strings.TrimSpace(strings.ToLower(wa.Email)),
		wa.DisplayName,
		wa.EmailVerifiedAt,
		source,
		wa.CreatedAt,
		wa.UpdatedAt,
	)
	if err != nil {
		if IsUniqueViolation(err) {
			vr := validation.NewIssue("email", "duplicate", "email already registered in this workspace")
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

// GetWorkspaceAccountByID returns a workspace account by ID.
func (r *Repo) GetWorkspaceAccountByID(
	ctx context.Context,
	id uuid.UUID,
) (*core.WorkspaceAccount, error) {
	const q = `
select
  id,
  workspace_id,
  email,
  display_name,
  email_verified_at,
  password_set_at,
  source,
  locked_until,
  totp_enabled_at,
  last_login_at,
  status,
  created_at,
  updated_at
from workspace_accounts
where id = $1
limit 1;
`

	var wa core.WorkspaceAccount
	var source *string
	err := r.db.Pool().QueryRow(ctx, q, id).Scan(
		&wa.ID,
		&wa.WorkspaceID,
		&wa.Email,
		&wa.DisplayName,
		&wa.EmailVerifiedAt,
		&wa.PasswordSetAt,
		&source,
		&wa.LockedUntil,
		&wa.TOTPEnabledAt,
		&wa.LastLoginAt,
		&wa.Status,
		&wa.CreatedAt,
		&wa.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Default to "invited" for existing accounts without source
	if source != nil {
		wa.Source = core.WorkspaceAccountSource(*source)
	} else {
		wa.Source = core.WorkspaceAccountSourceInvited
	}

	return &wa, nil
}

// GetWorkspaceAccountByEmail returns a workspace account by workspace ID and email.
// If not found, account is nil and result is ok.
func (r *Repo) GetWorkspaceAccountByEmail(
	ctx context.Context,
	workspaceID uuid.UUID,
	email string,
) (*core.WorkspaceAccount, *validation.Result, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil, validation.NewIssue("email", "required", "email is required"), nil
	}

	const q = `
select
  id,
  workspace_id,
  email,
  display_name,
  email_verified_at,
  password_set_at,
  source,
  locked_until,
  status,
  created_at,
  updated_at
from workspace_accounts
where workspace_id = $1
  and lower(email) = $2
limit 1;
`

	var wa core.WorkspaceAccount
	var source *string
	err := r.db.Pool().QueryRow(ctx, q, workspaceID, email).Scan(
		&wa.ID,
		&wa.WorkspaceID,
		&wa.Email,
		&wa.DisplayName,
		&wa.EmailVerifiedAt,
		&wa.PasswordSetAt,
		&source,
		&wa.LockedUntil,
		&wa.Status,
		&wa.CreatedAt,
		&wa.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &validation.Result{}, nil
		}
		return nil, &validation.Result{}, err
	}

	// Default to "invited" for existing accounts without source
	if source != nil {
		wa.Source = core.WorkspaceAccountSource(*source)
	} else {
		wa.Source = core.WorkspaceAccountSourceInvited
	}

	return &wa, &validation.Result{}, nil
}

// GetOrCreateWorkspaceAccountByEmail finds or creates a workspace account.
// If the account doesn't exist, it creates one with unverified email.
// Returns (account, created, error).
func (r *Repo) GetOrCreateWorkspaceAccountByEmail(
	ctx context.Context,
	workspaceID uuid.UUID,
	email string,
	displayName string,
) (*core.WorkspaceAccount, bool, error) {
	return r.GetOrCreateWorkspaceAccountByEmailWithSource(ctx, workspaceID, email, displayName, core.WorkspaceAccountSourceInvited)
}

// GetOrCreateWorkspaceAccountByEmailWithSource finds or creates a workspace account with a specific source.
// If the account doesn't exist, it creates one with unverified email.
// Returns (account, created, error).
func (r *Repo) GetOrCreateWorkspaceAccountByEmailWithSource(
	ctx context.Context,
	workspaceID uuid.UUID,
	email string,
	displayName string,
	source core.WorkspaceAccountSource,
) (*core.WorkspaceAccount, bool, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil, false, errors.New("email is required")
	}

	// Check if account exists
	existing, vr, err := r.GetWorkspaceAccountByEmail(ctx, workspaceID, email)
	if err != nil {
		return nil, false, err
	}
	if !vr.Ok() {
		return nil, false, errors.New(vr.Issues[0].Message)
	}
	if existing != nil {
		return existing, false, nil
	}

	// Create new account
	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)

	now := time.Now().UTC()
	wa := &core.WorkspaceAccount{
		ID:              uuid.Must(uuid.NewV4()),
		WorkspaceID:     workspaceID,
		Email:           email,
		DisplayName:     displayName,
		EmailVerifiedAt: nil, // Not verified yet
		Source:          source,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	vr2, err := r.InsertWorkspaceAccount(ctx, tx, wa)
	if err != nil {
		return nil, false, err
	}
	if !vr2.Ok() {
		// Unique violation - account was created concurrently
		// Re-fetch and return
		existing, _, err := r.GetWorkspaceAccountByEmail(ctx, workspaceID, email)
		if err != nil {
			return nil, false, err
		}
		if existing != nil {
			return existing, false, nil
		}
		return nil, false, errors.New(vr2.Issues[0].Message)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}

	return wa, true, nil
}

/* -------------------------------------------------------------------------- */
/* Updates                                                                     */
/* -------------------------------------------------------------------------- */

// SetWorkspaceAccountEmailVerified marks the workspace account's email as verified.
func (r *Repo) SetWorkspaceAccountEmailVerified(
	ctx context.Context,
	id uuid.UUID,
	verifiedAt time.Time,
) error {
	const q = `
update workspace_accounts
set email_verified_at = $2,
    updated_at = $3
where id = $1;
`
	ct, err := r.db.Pool().Exec(ctx, q, id, verifiedAt, time.Now().UTC())
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateWorkspaceAccountLastLogin sets the last_login_at timestamp.
func (r *Repo) UpdateWorkspaceAccountLastLogin(
	ctx context.Context,
	id uuid.UUID,
	loginAt time.Time,
) error {
	const q = `
update workspace_accounts
set last_login_at = $2
where id = $1;
`
	_, err := r.db.Pool().Exec(ctx, q, id, loginAt)
	return err
}

// UpdateWorkspaceAccountDisplayName updates the display name.
func (r *Repo) UpdateWorkspaceAccountDisplayName(
	ctx context.Context,
	id uuid.UUID,
	displayName string,
) error {
	const q = `
update workspace_accounts
set display_name = $2,
    updated_at = $3
where id = $1;
`
	ct, err := r.db.Pool().Exec(ctx, q, id, displayName, time.Now().UTC())
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateWorkspaceAccountEmail updates the email and resets verification status.
func (r *Repo) UpdateWorkspaceAccountEmail(
	ctx context.Context,
	workspaceID uuid.UUID,
	id uuid.UUID,
	newEmail string,
) (*validation.Result, error) {
	newEmail = strings.TrimSpace(strings.ToLower(newEmail))
	if newEmail == "" {
		return validation.NewIssue("email", "required", "email is required"), nil
	}

	const q = `
update workspace_accounts
set email = $3,
    email_verified_at = null,
    updated_at = $4
where id = $1 and workspace_id = $2;
`
	ct, err := r.db.Pool().Exec(ctx, q, id, workspaceID, newEmail, time.Now().UTC())
	if err != nil {
		if IsUniqueViolation(err) {
			vr := validation.NewIssue("email", "duplicate", "email already registered in this workspace")
			vr.Status = http.StatusConflict
			return vr, nil
		}
		return &validation.Result{}, err
	}
	if ct.RowsAffected() == 0 {
		vr := validation.NewIssue("id", "not_found", "workspace account not found")
		vr.Status = http.StatusNotFound
		return vr, nil
	}
	return &validation.Result{}, nil
}

/* -------------------------------------------------------------------------- */
/* Listing                                                                     */
/* -------------------------------------------------------------------------- */

// GetWorkspaceAccountsByWorkspaceID lists all accounts in a workspace.
func (r *Repo) GetWorkspaceAccountsByWorkspaceID(
	ctx context.Context,
	workspaceID uuid.UUID,
) ([]core.WorkspaceAccount, error) {
	const q = `
select
  id,
  workspace_id,
  email,
  display_name,
  email_verified_at,
  password_set_at,
  source,
  locked_until,
  last_login_at,
  status,
  created_at,
  updated_at
from workspace_accounts
where workspace_id = $1
order by created_at desc;
`

	rows, err := r.db.Pool().Query(ctx, q, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []core.WorkspaceAccount
	for rows.Next() {
		var wa core.WorkspaceAccount
		var source *string
		if err := rows.Scan(
			&wa.ID,
			&wa.WorkspaceID,
			&wa.Email,
			&wa.DisplayName,
			&wa.EmailVerifiedAt,
			&wa.PasswordSetAt,
			&source,
			&wa.LockedUntil,
			&wa.LastLoginAt,
			&wa.Status,
			&wa.CreatedAt,
			&wa.UpdatedAt,
		); err != nil {
			return nil, err
		}
		// Default to "invited" for existing accounts without source
		if source != nil {
			wa.Source = core.WorkspaceAccountSource(*source)
		} else {
			wa.Source = core.WorkspaceAccountSourceInvited
		}
		accounts = append(accounts, wa)
	}

	return accounts, rows.Err()
}

// CountWorkspaceAccounts returns the number of workspace accounts in a workspace.
func (r *Repo) CountWorkspaceAccounts(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	const q = `
select count(*)
from workspace_accounts
where workspace_id = $1;
`
	var n int
	if err := r.db.Pool().QueryRow(ctx, q, workspaceID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// CountInvitedMembers returns the number of admin-invited workspace accounts.
func (r *Repo) CountInvitedMembers(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	const q = `
select count(*)
from workspace_accounts
where workspace_id = $1
  and (source = 'invited' or source is null);
`
	var n int
	if err := r.db.Pool().QueryRow(ctx, q, workspaceID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// CountRegisteredUsers returns the number of self-registered workspace accounts (registered + google).
func (r *Repo) CountRegisteredUsers(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	const q = `
select count(*)
from workspace_accounts
where workspace_id = $1
  and source in ('registered', 'google');
`
	var n int
	if err := r.db.Pool().QueryRow(ctx, q, workspaceID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// ListWorkspaceAccountsParams defines parameters for listing workspace accounts.
type ListWorkspaceAccountsParams struct {
	WorkspaceID uuid.UUID
	Page        int
	PageSize    int
	Email       string // optional filter (substring match)
}

// ListWorkspaceAccountsResult contains the result of listing workspace accounts.
type ListWorkspaceAccountsResult struct {
	Accounts []core.WorkspaceAccount
	Total    int
	Page     int
	PageSize int
}

// ListWorkspaceAccounts returns a paginated list of workspace accounts.
func (r *Repo) ListWorkspaceAccounts(
	ctx context.Context,
	params ListWorkspaceAccountsParams,
) (ListWorkspaceAccountsResult, error) {
	// Defaults
	if params.Page < 0 {
		params.Page = 0
	}
	if params.PageSize <= 0 {
		params.PageSize = 50
	}
	if params.PageSize > 200 {
		params.PageSize = 200
	}

	email := strings.TrimSpace(strings.ToLower(params.Email))
	offset := params.Page * params.PageSize

	emailPattern := email
	if email != "" {
		emailPattern = "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(email) + "%"
	}

	// Count query
	const qCount = `
select count(*)
from workspace_accounts
where workspace_id = $1
  and ($2 = '' or lower(email) like $2 escape '\');
`
	var total int
	if err := r.db.Pool().QueryRow(ctx, qCount, params.WorkspaceID, emailPattern).Scan(&total); err != nil {
		return ListWorkspaceAccountsResult{}, err
	}

	// Data query
	const q = `
select
  id,
  workspace_id,
  email,
  display_name,
  email_verified_at,
  password_set_at,
  source,
  locked_until,
  last_login_at,
  status,
  created_at,
  updated_at
from workspace_accounts
where workspace_id = $1
  and ($2 = '' or lower(email) like $2 escape '\')
order by created_at desc
limit $3 offset $4;
`

	rows, err := r.db.Pool().Query(ctx, q, params.WorkspaceID, emailPattern, params.PageSize, offset)
	if err != nil {
		return ListWorkspaceAccountsResult{}, err
	}
	defer rows.Close()

	accounts := make([]core.WorkspaceAccount, 0, params.PageSize)
	for rows.Next() {
		var wa core.WorkspaceAccount
		var source *string
		if err := rows.Scan(
			&wa.ID,
			&wa.WorkspaceID,
			&wa.Email,
			&wa.DisplayName,
			&wa.EmailVerifiedAt,
			&wa.PasswordSetAt,
			&source,
			&wa.LockedUntil,
			&wa.LastLoginAt,
			&wa.Status,
			&wa.CreatedAt,
			&wa.UpdatedAt,
		); err != nil {
			return ListWorkspaceAccountsResult{}, err
		}
		// Default to "invited" for existing accounts without source
		if source != nil {
			wa.Source = core.WorkspaceAccountSource(*source)
		} else {
			wa.Source = core.WorkspaceAccountSourceInvited
		}
		accounts = append(accounts, wa)
	}

	if err := rows.Err(); err != nil {
		return ListWorkspaceAccountsResult{}, err
	}

	return ListWorkspaceAccountsResult{
		Accounts: accounts,
		Total:    total,
		Page:     params.Page,
		PageSize: params.PageSize,
	}, nil
}

/* -------------------------------------------------------------------------- */
/* Delete                                                                      */
/* -------------------------------------------------------------------------- */

// DeleteWorkspaceAccount deletes a workspace account by ID.
func (r *Repo) DeleteWorkspaceAccount(
	ctx context.Context,
	workspaceID uuid.UUID,
	id uuid.UUID,
) error {
	const q = `
delete from workspace_accounts
where id = $1 and workspace_id = $2;
`
	ct, err := r.db.Pool().Exec(ctx, q, id, workspaceID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

/* -------------------------------------------------------------------------- */
/* Status                                                                      */
/* -------------------------------------------------------------------------- */

// UpdateWorkspaceAccountStatus sets the status of a workspace account to "active" or "disabled".
func (r *Repo) UpdateWorkspaceAccountStatus(
	ctx context.Context,
	workspaceID uuid.UUID,
	id uuid.UUID,
	status string,
) (*core.WorkspaceAccount, error) {
	const q = `
update workspace_accounts
set status = $3, updated_at = now()
where workspace_id = $1 and id = $2
returning
  id, workspace_id, email, display_name, email_verified_at,
  password_set_at, source, locked_until,
  last_login_at, status, created_at, updated_at;
`
	var wa core.WorkspaceAccount
	var source *string
	err := r.db.Pool().QueryRow(ctx, q, workspaceID, id, status).Scan(
		&wa.ID,
		&wa.WorkspaceID,
		&wa.Email,
		&wa.DisplayName,
		&wa.EmailVerifiedAt,
		&wa.PasswordSetAt,
		&source,
		&wa.LockedUntil,
		&wa.LastLoginAt,
		&wa.Status,
		&wa.CreatedAt,
		&wa.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if source != nil {
		wa.Source = core.WorkspaceAccountSource(*source)
	} else {
		wa.Source = core.WorkspaceAccountSourceInvited
	}
	return &wa, nil
}

/* -------------------------------------------------------------------------- */
/* Password Authentication                                                     */
/* -------------------------------------------------------------------------- */

// GetWorkspaceAccountWithPasswordByEmail returns a workspace account and its password hash.
// Used for password login verification.
// If the account exists but has no password, passwordHash will be empty string.
// If not found, account is nil and result is ok.
func (r *Repo) GetWorkspaceAccountWithPasswordByEmail(
	ctx context.Context,
	workspaceID uuid.UUID,
	email string,
) (*core.WorkspaceAccount, string, *validation.Result, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil, "", validation.NewIssue("email", "required", "email is required"), nil
	}

	const q = `
select
  id,
  workspace_id,
  email,
  display_name,
  email_verified_at,
  password_hash,
  password_set_at,
  source,
  locked_until,
  totp_secret_encrypted,
  totp_enabled_at,
  totp_backup_codes_encrypted,
  status,
  created_at,
  updated_at
from workspace_accounts
where workspace_id = $1
  and lower(email) = $2
limit 1;
`

	var wa core.WorkspaceAccount
	var passwordHash *string
	var source *string
	err := r.db.Pool().QueryRow(ctx, q, workspaceID, email).Scan(
		&wa.ID,
		&wa.WorkspaceID,
		&wa.Email,
		&wa.DisplayName,
		&wa.EmailVerifiedAt,
		&passwordHash,
		&wa.PasswordSetAt,
		&source,
		&wa.LockedUntil,
		&wa.TOTPSecretEncrypted,
		&wa.TOTPEnabledAt,
		&wa.TOTPBackupCodesEncrypted,
		&wa.Status,
		&wa.CreatedAt,
		&wa.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", &validation.Result{}, nil
		}
		return nil, "", &validation.Result{}, err
	}

	hash := ""
	if passwordHash != nil {
		hash = *passwordHash
	}

	// Default to "invited" for existing accounts without source
	if source != nil {
		wa.Source = core.WorkspaceAccountSource(*source)
	} else {
		wa.Source = core.WorkspaceAccountSourceInvited
	}

	return &wa, hash, &validation.Result{}, nil
}

// UpdateWorkspaceAccountPassword sets or updates the password for a workspace account.
func (r *Repo) UpdateWorkspaceAccountPassword(
	ctx context.Context,
	workspaceID uuid.UUID,
	accountID uuid.UUID,
	passwordHash string,
	passwordSetAt time.Time,
) error {
	const q = `
update workspace_accounts
set password_hash = $3,
    password_set_at = $4,
    updated_at = $5
where id = $1 and workspace_id = $2;
`
	ct, err := r.db.Pool().Exec(ctx, q, accountID, workspaceID, passwordHash, passwordSetAt, time.Now().UTC())
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateWorkspaceAccountPasswordTx sets or updates the password for a workspace account within a transaction.
func (r *Repo) UpdateWorkspaceAccountPasswordTx(
	ctx context.Context,
	tx pgx.Tx,
	accountID uuid.UUID,
	passwordHash string,
	passwordSetAt time.Time,
) error {
	const q = `
update workspace_accounts
set password_hash = $2,
    password_set_at = $3,
    updated_at = $4
where id = $1;
`
	ct, err := tx.Exec(ctx, q, accountID, passwordHash, passwordSetAt, time.Now().UTC())
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

/* -------------------------------------------------------------------------- */
/* TOTP 2FA                                                                    */
/* -------------------------------------------------------------------------- */

// SetWorkspaceAccountTOTPSecret stores an encrypted TOTP secret (pre-enable).
func (r *Repo) SetWorkspaceAccountTOTPSecret(ctx context.Context, id uuid.UUID, encryptedSecret []byte) error {
	const q = `
UPDATE workspace_accounts
SET totp_secret_encrypted = $2, updated_at = now()
WHERE id = $1;
`
	ct, err := r.db.Pool().Exec(ctx, q, id, encryptedSecret)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// EnableWorkspaceAccountTOTP marks TOTP as enabled and stores encrypted backup codes.
func (r *Repo) EnableWorkspaceAccountTOTP(ctx context.Context, id uuid.UUID, enabledAt time.Time, encryptedBackupCodes []byte) error {
	const q = `
UPDATE workspace_accounts
SET totp_enabled_at = $2,
    totp_backup_codes_encrypted = $3,
    updated_at = now()
WHERE id = $1;
`
	ct, err := r.db.Pool().Exec(ctx, q, id, enabledAt, encryptedBackupCodes)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DisableWorkspaceAccountTOTP clears all TOTP columns.
func (r *Repo) DisableWorkspaceAccountTOTP(ctx context.Context, id uuid.UUID) error {
	const q = `
UPDATE workspace_accounts
SET totp_secret_encrypted = NULL,
    totp_enabled_at = NULL,
    totp_backup_codes_encrypted = NULL,
    updated_at = now()
WHERE id = $1;
`
	ct, err := r.db.Pool().Exec(ctx, q, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateWorkspaceAccountTOTPBackupCodes replaces the encrypted backup codes.
func (r *Repo) UpdateWorkspaceAccountTOTPBackupCodes(ctx context.Context, id uuid.UUID, encryptedCodes []byte) error {
	const q = `
UPDATE workspace_accounts
SET totp_backup_codes_encrypted = $2, updated_at = now()
WHERE id = $1;
`
	ct, err := r.db.Pool().Exec(ctx, q, id, encryptedCodes)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetWorkspaceAccountByIDWithTOTP returns a workspace account including TOTP columns.
func (r *Repo) GetWorkspaceAccountByIDWithTOTP(ctx context.Context, id uuid.UUID) (*core.WorkspaceAccount, error) {
	const q = `
SELECT
  id, workspace_id, email, display_name, email_verified_at,
  password_set_at, source, locked_until,
  totp_secret_encrypted, totp_enabled_at, totp_backup_codes_encrypted,
  status, created_at, updated_at
FROM workspace_accounts
WHERE id = $1
LIMIT 1;
`
	var wa core.WorkspaceAccount
	var source *string
	err := r.db.Pool().QueryRow(ctx, q, id).Scan(
		&wa.ID,
		&wa.WorkspaceID,
		&wa.Email,
		&wa.DisplayName,
		&wa.EmailVerifiedAt,
		&wa.PasswordSetAt,
		&source,
		&wa.LockedUntil,
		&wa.TOTPSecretEncrypted,
		&wa.TOTPEnabledAt,
		&wa.TOTPBackupCodesEncrypted,
		&wa.Status,
		&wa.CreatedAt,
		&wa.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if source != nil {
		wa.Source = core.WorkspaceAccountSource(*source)
	} else {
		wa.Source = core.WorkspaceAccountSourceInvited
	}
	return &wa, nil
}
