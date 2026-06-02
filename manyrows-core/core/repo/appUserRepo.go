package repo

import (
	"context"
	"errors"
	"time"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// EnsureAppMember upserts an app_users row. If a row already exists,
// status is preserved (idempotent for repeat sign-ins) and source is
// not overwritten - the original "how this membership was created"
// stays. last_login_at is only touched by UpdateAppUserLastLogin.
func (r *Repo) EnsureAppMember(
	ctx context.Context,
	appID, userID uuid.UUID,
	source core.UserSource,
) (*core.AppUser, bool, error) {
	const q = `
INSERT INTO app_users (app_id, user_id, status, source, joined_at)
VALUES ($1, $2, 'active', $3, now())
ON CONFLICT (app_id, user_id) DO NOTHING
RETURNING app_id, user_id, status, source, joined_at, last_login_at;
`
	m, err := scanAppUser(r.db.Pool().QueryRow(ctx, q, appID, userID, string(source)))
	if err == nil {
		return m, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}
	// Row already existed; read it back.
	existing, getErr := r.GetAppUser(ctx, appID, userID)
	if getErr != nil {
		return nil, false, getErr
	}
	return existing, false, nil
}

// GetAppUser returns the membership row or nil,nil if not a member.
func (r *Repo) GetAppUser(ctx context.Context, appID, userID uuid.UUID) (*core.AppUser, error) {
	const q = `
SELECT app_id, user_id, status, source, joined_at, last_login_at
FROM app_users
WHERE app_id = $1 AND user_id = $2
LIMIT 1;
`
	m, err := scanAppUser(r.db.Pool().QueryRow(ctx, q, appID, userID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return m, nil
}

// UpdateAppUserLastLogin sets last_login_at on the membership row.
// Silent no-op if the row doesn't exist (caller should have created
// it via EnsureAppMember before issuing a session).
func (r *Repo) UpdateAppUserLastLogin(ctx context.Context, appID, userID uuid.UUID, t time.Time) error {
	const q = `UPDATE app_users SET last_login_at = $3 WHERE app_id = $1 AND user_id = $2;`
	_, err := r.db.Pool().Exec(ctx, q, appID, userID, t)
	return err
}

// SetAppUserStatus changes the membership status (active/pending/disabled).
func (r *Repo) SetAppUserStatus(ctx context.Context, appID, userID uuid.UUID, status core.AppUserStatus) error {
	const q = `UPDATE app_users SET status = $3 WHERE app_id = $1 AND user_id = $2;`
	return r.execAffectingOne(ctx, ErrNotFound, q, appID, userID, string(status))
}

// DeleteAppMember removes the membership row. The underlying user row
// (in the pool) is untouched.
func (r *Repo) DeleteAppMember(ctx context.Context, appID, userID uuid.UUID) error {
	const q = `DELETE FROM app_users WHERE app_id = $1 AND user_id = $2;`
	return r.execAffectingOne(ctx, ErrNotFound, q, appID, userID)
}

// CountAppMembershipsByUser returns how many app memberships the user
// has. A user belongs to exactly one pool and app_users only links
// apps in that pool, so this doubles as the pool-scoped count. Used to
// gate pool-user deletion: a user is only deletable from a pool once
// they belong to no apps.
func (r *Repo) CountAppMembershipsByUser(ctx context.Context, userID uuid.UUID) (int, error) {
	var n int
	if err := r.db.Pool().QueryRow(ctx, `SELECT count(*) FROM app_users WHERE user_id = $1`, userID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func scanAppUser(scanner interface{ Scan(...any) error }) (*core.AppUser, error) {
	var m core.AppUser
	var status, source string
	if err := scanner.Scan(&m.AppID, &m.UserID, &status, &source, &m.JoinedAt, &m.LastLoginAt); err != nil {
		return nil, err
	}
	m.Status = core.AppUserStatus(status)
	m.Source = core.UserSource(source)
	return &m, nil
}
