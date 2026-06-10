package repo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

/* -------------------------------------------------------------------------- */
/* Scan helper                                                                 */
/* -------------------------------------------------------------------------- */

// All identifiers are u.-qualified so userCols composes safely with
// joins (notably user_identities) that share id / user_pool_id column
// names. Non-aliased callers must select FROM users u.
const userCols = `
  u.id, u.email, u.enabled,
  u.email_verified_at, u.password_set_at, u.source,
  u.locked_until, u.last_login_at,
  u.user_pool_id,
  u.created_at, u.updated_at
`

// scanUser scans a user row from the standard column set (userCols).
// TOTP columns and password_hash are NOT included.
func scanUser(scanner interface{ Scan(...any) error }) (*core.User, error) {
	var u core.User
	var source *string
	err := scanner.Scan(
		&u.ID, &u.Email, &u.Enabled,
		&u.EmailVerifiedAt, &u.PasswordSetAt, &source,
		&u.LockedUntil, &u.LastLoginAt,
		&u.UserPoolID,
		&u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if source != nil {
		u.Source = core.UserSource(*source)
	} else {
		u.Source = core.UserSourceInvited
	}
	return &u, nil
}

/* -------------------------------------------------------------------------- */
/* Lookups                                                                     */
/* -------------------------------------------------------------------------- */

// GetUserByID returns a user by ID.
func (r *Repo) GetUserByID(ctx context.Context, id uuid.UUID) (*core.User, error) {
	q := `SELECT` + userCols + `FROM users u WHERE u.id = $1 LIMIT 1;`
	u, err := scanUser(r.db.Pool().QueryRow(ctx, q, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return u, nil
}

// GetUserByEmail returns a user by email within an app's user pool.
// Membership in the specific app is NOT checked here; callers that
// need that gate the result against an app_users row.
// Returns nil,nil if not found.
func (r *Repo) GetUserByEmail(ctx context.Context, email string, app *core.App) (*core.User, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil, errors.New("email is required")
	}

	q := `SELECT` + userCols + `FROM users u WHERE LOWER(u.email) = $1 AND u.user_pool_id = $2 LIMIT 1`

	u, err := scanUser(r.db.Pool().QueryRow(ctx, q, email, app.UserPoolID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return u, nil
}

// GetUsersByEmails returns app members matching any of the normalized emails in
// one query. Only users with an app_users membership row for the given app are
// returned — pool users who never joined this app are absent (they appear in
// the caller's "missing" list). This mirrors the single-user path in
// respondServerUser → requireAppMember → GetAppUser.
// Missing emails are simply absent from the result.
// The caller is responsible for normalizing (lower-casing / trimming) the
// input before passing it here.
func (r *Repo) GetUsersByEmails(ctx context.Context, app *core.App, emails []string) ([]*core.User, error) {
	if len(emails) == 0 {
		return nil, nil
	}
	q := `SELECT` + userCols + `FROM users u
JOIN app_users au ON au.user_id = u.id AND au.app_id = $2
WHERE u.user_pool_id = $1 AND LOWER(u.email) = ANY($3)`
	rows, err := r.db.Pool().Query(ctx, q, app.UserPoolID, app.ID, emails)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*core.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// GetUserByEmailInPool returns a user by email in a pool (no app needed).
// Returns nil,nil if not found.
func (r *Repo) GetUserByEmailInPool(ctx context.Context, email string, poolID uuid.UUID) (*core.User, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil, errors.New("email is required")
	}

	q := `SELECT` + userCols + `FROM users u WHERE LOWER(u.email) = $1 AND u.user_pool_id = $2 LIMIT 1`

	u, err := scanUser(r.db.Pool().QueryRow(ctx, q, email, poolID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return u, nil
}

// GetUserByEmailGlobal returns any user with this email (no app scope).
// Used for password reset and similar flows where app context is not needed.
func (r *Repo) GetUserByEmailGlobal(ctx context.Context, email string) (*core.User, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil, errors.New("email is required")
	}
	q := `SELECT` + userCols + `FROM users u WHERE LOWER(u.email) = $1 LIMIT 1;`
	u, err := scanUser(r.db.Pool().QueryRow(ctx, q, email))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return u, nil
}

// GetOrCreateUser finds a user by (email, pool) or creates one.
// Returns (user, created, error). "created" means a new user row was inserted.
// Callers that also need per-app membership must call EnsureAppMember
// after this; the user row alone is identity, not membership.
//
// The (lower(email), user_pool_id) unique index catches the race where
// two concurrent calls both pass the existence check.
func (r *Repo) GetOrCreateUser(
	ctx context.Context,
	email string,
	app *core.App,
	source core.UserSource,
) (*core.User, bool, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil, false, errors.New("email is required")
	}

	existing, err := r.GetUserByEmail(ctx, email, app)
	if err != nil {
		return nil, false, err
	}
	if existing != nil {
		return existing, false, nil
	}

	now := time.Now().UTC()
	u := &core.User{
		ID:         uuid.Must(uuid.NewV4()),
		Email:      email,
		Enabled:    true,
		Source:     source,
		UserPoolID: app.UserPoolID,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	const q = `
INSERT INTO users (id, email, enabled, source, user_pool_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);
`
	if _, err := r.db.Pool().Exec(ctx, q,
		u.ID, u.Email, u.Enabled, u.Source, u.UserPoolID, u.CreatedAt, u.UpdatedAt,
	); err != nil {
		// Lost a concurrent-create race: another call inserted the same
		// (email, pool) between our existence check and this insert. The
		// unique index rejects us with 23505 — re-read and return the now-
		// existing row idempotently rather than surfacing a 500.
		if IsUniqueViolation(err) {
			existing, gerr := r.GetUserByEmail(ctx, email, app)
			if gerr != nil {
				return nil, false, gerr
			}
			if existing != nil {
				return existing, false, nil
			}
		}
		return nil, false, err
	}
	return u, true, nil
}

/* -------------------------------------------------------------------------- */
/* Password                                                                    */
/* -------------------------------------------------------------------------- */

// GetUserWithPasswordByEmailAndApp returns a user including password_hash
// for password sign-in. The user must (a) exist in the app's user pool
// and (b) have an active app_users membership row for this specific app.
// "Not in pool" and "in pool but not a member of this app" both collapse
// to the same nil,"",nil result - the handler turns that into the same
// invalidCredentials 401 to avoid leaking which condition failed.
func (r *Repo) GetUserWithPasswordByEmailAndApp(
	ctx context.Context,
	email string,
	app *core.App,
) (*core.User, string, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil, "", errors.New("email is required")
	}

	q := `SELECT u.id, u.email, u.enabled,
            u.email_verified_at, u.password_hash, u.password_set_at, u.source,
            u.locked_until,
            u.user_pool_id,
            u.totp_secret_encrypted, u.totp_enabled_at, u.totp_backup_codes_encrypted,
            u.created_at, u.updated_at
          FROM users u
          JOIN app_users au ON au.user_id = u.id AND au.app_id = $3
          WHERE LOWER(u.email) = $1 AND u.user_pool_id = $2
            AND au.status = 'active'
          LIMIT 1`

	var u core.User
	var passwordHash *string
	var source *string
	err := r.db.Pool().QueryRow(ctx, q, email, app.UserPoolID, app.ID).Scan(
		&u.ID, &u.Email, &u.Enabled,
		&u.EmailVerifiedAt, &passwordHash, &u.PasswordSetAt, &source,
		&u.LockedUntil,
		&u.UserPoolID,
		&u.TOTPSecretEncrypted, &u.TOTPEnabledAt, &u.TOTPBackupCodesEncrypted,
		&u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", nil
		}
		return nil, "", err
	}

	hash := ""
	if passwordHash != nil {
		hash = *passwordHash
	}
	if source != nil {
		u.Source = core.UserSource(*source)
	} else {
		u.Source = core.UserSourceInvited
	}
	return &u, hash, nil
}

// UpdateUserPassword sets or updates the password for a user.
func (r *Repo) UpdateUserPassword(
	ctx context.Context,
	userID uuid.UUID,
	passwordHash string,
	passwordSetAt time.Time,
) error {
	const q = `
UPDATE users
SET password_hash = $2, password_set_at = $3, updated_at = $4
WHERE id = $1;
`
	return r.execAffectingOne(ctx, ErrNotFound, q, userID, passwordHash, passwordSetAt, time.Now().UTC())
}

// ClearUserPassword unsets the user's password — sets password_hash and
// password_set_at to NULL. Used by admin "clear password" tooling. The
// user can no longer sign in via email+password until they go through
// the forgot-password flow (or the in-profile set-password flow) to set
// a new one. OAuth + passkey sign-in still work.
func (r *Repo) ClearUserPassword(ctx context.Context, userID uuid.UUID) error {
	const q = `
UPDATE users
SET password_hash = NULL, password_set_at = NULL, updated_at = $2
WHERE id = $1;
`
	return r.execAffectingOne(ctx, ErrNotFound, q, userID, time.Now().UTC())
}

/* -------------------------------------------------------------------------- */
/* Email verification                                                          */
/* -------------------------------------------------------------------------- */

// SetUserEmailVerified marks the user's email as verified.
func (r *Repo) SetUserEmailVerified(ctx context.Context, id uuid.UUID, verifiedAt time.Time) error {
	const q = `
UPDATE users SET email_verified_at = $2, updated_at = $3 WHERE id = $1;
`
	return r.execAffectingOne(ctx, ErrNotFound, q, id, verifiedAt, time.Now().UTC())
}

// ClearUserEmailVerified marks the user's email as unverified (NULLs the
// verified-at timestamp).
func (r *Repo) ClearUserEmailVerified(ctx context.Context, id uuid.UUID) error {
	const q = `
UPDATE users SET email_verified_at = NULL, updated_at = $2 WHERE id = $1;
`
	return r.execAffectingOne(ctx, ErrNotFound, q, id, time.Now().UTC())
}

/* -------------------------------------------------------------------------- */
/* Login tracking                                                              */
/* -------------------------------------------------------------------------- */

// UpdateUserLastLogin sets the last_login_at timestamp.
func (r *Repo) UpdateUserLastLogin(ctx context.Context, id uuid.UUID, loginAt time.Time) error {
	const q = `UPDATE users SET last_login_at = $2 WHERE id = $1;`
	_, err := r.db.Pool().Exec(ctx, q, id, loginAt)
	return err
}

/* -------------------------------------------------------------------------- */
/* TOTP 2FA                                                                    */
/* -------------------------------------------------------------------------- */

// SetUserTOTPSecret stores an encrypted TOTP secret (pre-enable).
func (r *Repo) SetUserTOTPSecret(ctx context.Context, id uuid.UUID, encryptedSecret []byte) error {
	const q = `UPDATE users SET totp_secret_encrypted = $2, updated_at = now() WHERE id = $1;`
	return r.execAffectingOne(ctx, ErrNotFound, q, id, encryptedSecret)
}

// EnableUserTOTP marks TOTP as enabled and stores encrypted backup codes.
func (r *Repo) EnableUserTOTP(ctx context.Context, id uuid.UUID, enabledAt time.Time, encryptedBackupCodes []byte) error {
	const q = `
UPDATE users
SET totp_enabled_at = $2, totp_backup_codes_encrypted = $3, updated_at = now()
WHERE id = $1;
`
	return r.execAffectingOne(ctx, ErrNotFound, q, id, enabledAt, encryptedBackupCodes)
}

// DisableUserTOTP clears all TOTP columns.
func (r *Repo) DisableUserTOTP(ctx context.Context, id uuid.UUID) error {
	const q = `
UPDATE users
SET totp_secret_encrypted = NULL, totp_enabled_at = NULL, totp_backup_codes_encrypted = NULL, updated_at = now()
WHERE id = $1;
`
	return r.execAffectingOne(ctx, ErrNotFound, q, id)
}

// UpdateUserTOTPBackupCodes replaces the encrypted backup codes.
func (r *Repo) UpdateUserTOTPBackupCodes(ctx context.Context, id uuid.UUID, encryptedCodes []byte) error {
	const q = `UPDATE users SET totp_backup_codes_encrypted = $2, updated_at = now() WHERE id = $1;`
	return r.execAffectingOne(ctx, ErrNotFound, q, id, encryptedCodes)
}

// AdvanceUserTOTPStep atomically writes the supplied step number iff it's
// strictly greater than the currently-stored value. Returns true on
// success (the step was advanced — the code can be accepted). Returns
// false when the step is not greater than last_totp_step, which means
// the code has already been used inside its own window — replay
// rejected.
//
// This is the M1 fix: pquerna/otp's totp.Validate doesn't track which
// step it accepted, so without this gate the same 30-second TOTP code
// would be replayable.
func (r *Repo) AdvanceUserTOTPStep(ctx context.Context, id uuid.UUID, step int64) (bool, error) {
	const q = `
UPDATE users
   SET last_totp_step = $2, updated_at = now()
 WHERE id = $1
   AND last_totp_step < $2;
`
	ct, err := r.db.Pool().Exec(ctx, q, id, step)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

// GetUserByIDWithTOTP returns a user including TOTP columns.
func (r *Repo) GetUserByIDWithTOTP(ctx context.Context, id uuid.UUID) (*core.User, error) {
	const q = `
SELECT
  id, email, enabled,
  email_verified_at, password_set_at, source,
  locked_until,
  totp_secret_encrypted, totp_enabled_at, totp_backup_codes_encrypted,
  created_at, updated_at
FROM users
WHERE id = $1
LIMIT 1;
`
	var u core.User
	var source *string
	err := r.db.Pool().QueryRow(ctx, q, id).Scan(
		&u.ID, &u.Email, &u.Enabled,
		&u.EmailVerifiedAt, &u.PasswordSetAt, &source,
		&u.LockedUntil,
		&u.TOTPSecretEncrypted, &u.TOTPEnabledAt, &u.TOTPBackupCodesEncrypted,
		&u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if source != nil {
		u.Source = core.UserSource(*source)
	} else {
		u.Source = core.UserSourceInvited
	}
	return &u, nil
}

/* -------------------------------------------------------------------------- */
/* Enabled                                                                     */
/* -------------------------------------------------------------------------- */

// SetUserEnabled enables or disables a user.
func (r *Repo) SetUserEnabled(ctx context.Context, userID uuid.UUID, enabled bool) error {
	const q = `UPDATE users SET enabled = $2, updated_at = now() WHERE id = $1;`
	return r.execAffectingOne(ctx, ErrNotFound, q, userID, enabled)
}

/* -------------------------------------------------------------------------- */
/* Listing                                                                     */
/* -------------------------------------------------------------------------- */

// ListUsersByApp returns all users with an app_users membership row for
// the app, ordered by created_at DESC. Includes members with zero roles.
func (r *Repo) ListUsersByApp(ctx context.Context, appID uuid.UUID) ([]core.User, error) {
	q := `SELECT` + userCols + `FROM users u
JOIN app_users au ON au.user_id = u.id
WHERE au.app_id = $1
ORDER BY u.created_at DESC;`
	rows, err := r.db.Pool().Query(ctx, q, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []core.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	return users, rows.Err()
}

// CountUsersByWorkspace returns the total number of users in pools
// belonging to a workspace.
func (r *Repo) CountUsersByWorkspace(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	const q = `
SELECT COUNT(*)
FROM users u
WHERE u.user_pool_id IN (SELECT id FROM user_pools WHERE workspace_id = $1);
`
	return r.scalarCount(ctx, q, workspaceID)
}

// CountRegisteredUsersByWorkspace counts self-registered users (registered + google) in a workspace.
func (r *Repo) CountRegisteredUsersByWorkspace(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	const q = `
SELECT COUNT(*)
FROM users u
WHERE u.source IN ('registered', 'google')
  AND u.user_pool_id IN (SELECT id FROM user_pools WHERE workspace_id = $1);
`
	return r.scalarCount(ctx, q, workspaceID)
}

// emailILIKEArg builds the bound argument for a case-insensitive email
// substring filter, escaping ILIKE wildcards so emails containing a
// literal '%' or '_' (both valid per RFC 5321) match exactly rather
// than expanding. Pair with: `email ILIKE $n ESCAPE '\'`.
func emailILIKEArg(emailQuery string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(emailQuery) + "%"
}

// ListUsersInPool returns users whose pool matches poolID, ordered by
// email. emailQuery is an optional case-insensitive substring filter
// (used by the admin "add user" autocomplete and the pool Users tab);
// empty matches all. A non-positive limit means "no cap"; offset is
// applied only when > 0 (server-side pagination).
func (r *Repo) ListUsersInPool(ctx context.Context, poolID uuid.UUID, emailQuery string, limit, offset int) ([]core.User, error) {
	q := `SELECT` + userCols + `FROM users u WHERE u.user_pool_id = $1`
	args := []any{poolID}
	if emailQuery != "" {
		q += ` AND u.email ILIKE $2 ESCAPE '\'`
		args = append(args, emailILIKEArg(emailQuery))
	}
	q += ` ORDER BY u.email ASC, u.id ASC` // u.id tiebreaker = stable pagination
	if limit > 0 {
		args = append(args, limit)
		q += fmt.Sprintf(` LIMIT $%d`, len(args)) // only the placeholder index is formatted, never data
	}
	if offset > 0 {
		args = append(args, offset)
		q += fmt.Sprintf(` OFFSET $%d`, len(args))
	}

	rows, err := r.db.Pool().Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []core.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	return users, rows.Err()
}

// CountUsersInPool counts users in poolID, honoring the same optional
// email substring filter as ListUsersInPool. Used to drive paginated
// totals.
func (r *Repo) CountUsersInPool(ctx context.Context, poolID uuid.UUID, emailQuery string) (int, error) {
	q := `SELECT COUNT(*) FROM users u WHERE u.user_pool_id = $1`
	args := []any{poolID}
	if emailQuery != "" {
		q += ` AND u.email ILIKE $2 ESCAPE '\'`
		args = append(args, emailILIKEArg(emailQuery))
	}
	return r.scalarCount(ctx, q, args...)
}

// ListUsersInWorkspace returns users in pools belonging to the
// workspace, ordered by email. emailQuery is an optional
// case-insensitive substring filter; limit/offset drive server-side
// pagination (non-positive limit = no cap, offset applied only when > 0).
func (r *Repo) ListUsersInWorkspace(ctx context.Context, workspaceID uuid.UUID, emailQuery string, limit, offset int) ([]core.User, error) {
	q := `SELECT` + userCols + `FROM users u
WHERE u.user_pool_id IN (SELECT id FROM user_pools WHERE workspace_id = $1)`
	args := []any{workspaceID}
	if emailQuery != "" {
		q += ` AND u.email ILIKE $2 ESCAPE '\'`
		args = append(args, emailILIKEArg(emailQuery))
	}
	q += ` ORDER BY u.email ASC, u.id ASC` // u.id tiebreaker = stable pagination
	if limit > 0 {
		args = append(args, limit)
		q += fmt.Sprintf(` LIMIT $%d`, len(args)) // only the placeholder index is formatted, never data
	}
	if offset > 0 {
		args = append(args, offset)
		q += fmt.Sprintf(` OFFSET $%d`, len(args))
	}

	rows, err := r.db.Pool().Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []core.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	return users, rows.Err()
}

// CountUsersInWorkspace counts users in the workspace's pools, honoring
// the same optional email filter as ListUsersInWorkspace.
func (r *Repo) CountUsersInWorkspace(ctx context.Context, workspaceID uuid.UUID, emailQuery string) (int, error) {
	q := `SELECT COUNT(*) FROM users u
WHERE u.user_pool_id IN (SELECT id FROM user_pools WHERE workspace_id = $1)`
	args := []any{workspaceID}
	if emailQuery != "" {
		q += ` AND u.email ILIKE $2 ESCAPE '\'`
		args = append(args, emailILIKEArg(emailQuery))
	}
	return r.scalarCount(ctx, q, args...)
}

// ListUsersInProject returns all users who are members of any app in
// the project, deduplicated.
func (r *Repo) ListUsersInProject(ctx context.Context, projectID, workspaceID uuid.UUID, emailQuery string, limit, offset int) ([]core.User, error) {
	_ = workspaceID
	q := `SELECT DISTINCT ` + userCols + `FROM users u
JOIN app_users au ON au.user_id = u.id
JOIN apps a ON a.id = au.app_id
WHERE a.project_id = $1`
	args := []any{projectID}
	if emailQuery != "" {
		q += ` AND u.email ILIKE $2 ESCAPE '\'`
		args = append(args, emailILIKEArg(emailQuery))
	}
	q += ` ORDER BY u.email ASC, u.id ASC` // u.id tiebreaker = stable pagination
	if limit > 0 {
		args = append(args, limit)
		q += fmt.Sprintf(` LIMIT $%d`, len(args)) // only the placeholder index is formatted, never data
	}
	if offset > 0 {
		args = append(args, offset)
		q += fmt.Sprintf(` OFFSET $%d`, len(args))
	}

	rows, err := r.db.Pool().Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []core.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	return users, rows.Err()
}

// CountUsersInProject counts distinct users who are members of any app
// in the project, honoring the same optional email filter as
// ListUsersInProject.
func (r *Repo) CountUsersInProject(ctx context.Context, projectID, workspaceID uuid.UUID, emailQuery string) (int, error) {
	_ = workspaceID
	q := `SELECT COUNT(DISTINCT u.id) FROM users u
JOIN app_users au ON au.user_id = u.id
JOIN apps a ON a.id = au.app_id
WHERE a.project_id = $1`
	args := []any{projectID}
	if emailQuery != "" {
		q += ` AND u.email ILIKE $2 ESCAPE '\'`
		args = append(args, emailILIKEArg(emailQuery))
	}
	return r.scalarCount(ctx, q, args...)
}

/* -------------------------------------------------------------------------- */
/* App access                                                                  */
/* -------------------------------------------------------------------------- */

// UserAppAccess describes which apps a user can access in a workspace.
// AppName is composed in Go from project + env type at scan time so
// the SQL doesn't have to know the display convention.
type UserAppAccess struct {
	UserID    uuid.UUID
	AppID     uuid.UUID
	AppName   string
	ProjectID uuid.UUID
}

// GetUserAppAccessForWorkspace returns the apps each user is a member
// of within a workspace. Reads app_users so roleless members appear
// too - "is a member" is the app_users row, not the presence of roles.
func (r *Repo) GetUserAppAccessForWorkspace(ctx context.Context, workspaceID uuid.UUID) (map[uuid.UUID][]UserAppAccess, error) {
	const q = `
SELECT au.user_id, a.id, p.name, a.type, a.project_id
FROM app_users au
JOIN apps a ON a.id = au.app_id
JOIN projects p ON p.id = a.project_id
WHERE p.workspace_id = $1
ORDER BY p.name ASC, a.type ASC;
`
	rows, err := r.db.Pool().Query(ctx, q, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[uuid.UUID][]UserAppAccess)
	for rows.Next() {
		var ua UserAppAccess
		var projectName, envType string
		if err := rows.Scan(&ua.UserID, &ua.AppID, &projectName, &envType, &ua.ProjectID); err != nil {
			return nil, err
		}
		// One source of truth lives in core.AppDisplayName; call it
		// here so chips here, the App struct's DisplayName(), and
		// the UI helper all stay in lock-step.
		ua.AppName = core.AppDisplayName(projectName, envType)
		result[ua.UserID] = append(result[ua.UserID], ua)
	}
	return result, rows.Err()
}

/* -------------------------------------------------------------------------- */
/* Delete                                                                      */
/* -------------------------------------------------------------------------- */

// DeleteUser deletes a user by ID.
func (r *Repo) DeleteUser(ctx context.Context, id uuid.UUID) error {
	const q = `DELETE FROM users WHERE id = $1;`
	return r.execAffectingOne(ctx, ErrNotFound, q, id)
}

// DeleteOrphanPoolUsers deletes every user in the pool that belongs to
// no app (no app_users row). The no-app guard is enforced in SQL so it
// can never catch an app member. Cascades roles / permission overrides
// / OAuth identities / sessions / field values; auth_log links are
// nulled. Returns the number deleted.
func (r *Repo) DeleteOrphanPoolUsers(ctx context.Context, poolID uuid.UUID) (int64, error) {
	const q = `
DELETE FROM users u
WHERE u.user_pool_id = $1
  AND NOT EXISTS (SELECT 1 FROM app_users au WHERE au.user_id = u.id);`
	ct, err := r.db.Pool().Exec(ctx, q, poolID)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

// DeleteUserIfOrphanInPool atomically deletes the user only if they
// belong to poolID AND have no app memberships — the guard lives in
// the DELETE predicate itself, closing the count→delete race in the
// single pool-user delete path (a concurrent login / admin-add could
// attach a membership between a separate count and the delete).
// Reports whether a row was actually deleted.
func (r *Repo) DeleteUserIfOrphanInPool(ctx context.Context, userID, poolID uuid.UUID) (bool, error) {
	const q = `
DELETE FROM users
WHERE id = $1
  AND user_pool_id = $2
  AND NOT EXISTS (SELECT 1 FROM app_users au WHERE au.user_id = $1);`
	ct, err := r.db.Pool().Exec(ctx, q, userID, poolID)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}
