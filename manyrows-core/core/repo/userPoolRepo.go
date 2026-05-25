package repo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// CreateUserPool inserts a new pool and returns the persisted row.
// The caller-supplied name is taken as-is; collisions surface as a
// unique-violation error (callers that need collision-tolerant naming
// use CreateUserPoolWithUniqueName).
func (r *Repo) CreateUserPool(ctx context.Context, workspaceID uuid.UUID, name string) (*core.UserPool, error) {
	name = strings.TrimSpace(name)
	if workspaceID == uuid.Nil || name == "" {
		return nil, errors.New("invalid user pool")
	}
	id := utils.NewUUID()
	const q = `
INSERT INTO user_pools (id, workspace_id, name, created_at, updated_at)
VALUES ($1, $2, $3, $4, $4)
RETURNING id, workspace_id, name, created_at, updated_at;
`
	now := time.Now().UTC()
	var p core.UserPool
	if err := r.db.Pool().QueryRow(ctx, q, id, workspaceID, name, now).Scan(
		&p.ID, &p.WorkspaceID, &p.Name, &p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &p, nil
}

// CreateUserPoolWithUniqueName creates a pool, appending " (2)", " (3)"
// etc. on collision. Used by the auto-create-on-app-create path where
// the caller doesn't care about the exact name, just that one exists.
func (r *Repo) CreateUserPoolWithUniqueName(ctx context.Context, workspaceID uuid.UUID, baseName string) (*core.UserPool, error) {
	baseName = strings.TrimSpace(baseName)
	if baseName == "" {
		baseName = "pool"
	}
	name := baseName
	for attempt := 2; attempt < 100; attempt++ {
		p, err := r.CreateUserPool(ctx, workspaceID, name)
		if err == nil {
			return p, nil
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
			return nil, err
		}
		name = fmt.Sprintf("%s (%d)", baseName, attempt)
	}
	return nil, errors.New("could not allocate unique pool name")
}

// GetUserPoolByID returns a pool by ID, or ErrNotFound.
func (r *Repo) GetUserPoolByID(ctx context.Context, id uuid.UUID) (*core.UserPool, error) {
	const q = `SELECT id, workspace_id, name, created_at, updated_at FROM user_pools WHERE id = $1 LIMIT 1;`
	var p core.UserPool
	if err := r.db.Pool().QueryRow(ctx, q, id).Scan(
		&p.ID, &p.WorkspaceID, &p.Name, &p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

// ListUserPoolsByWorkspace returns all pools in a workspace.
func (r *Repo) ListUserPoolsByWorkspace(ctx context.Context, workspaceID uuid.UUID) ([]core.UserPool, error) {
	const q = `SELECT id, workspace_id, name, created_at, updated_at FROM user_pools WHERE workspace_id = $1 ORDER BY name ASC;`
	rows, err := r.db.Pool().Query(ctx, q, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.UserPool
	for rows.Next() {
		var p core.UserPool
		if err := rows.Scan(&p.ID, &p.WorkspaceID, &p.Name, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UserPoolWithStats annotates a pool with the counts the admin UI
// needs to render the list (apps using this pool, identities in it).
type UserPoolWithStats struct {
	core.UserPool
	AppCount  int `json:"appCount"`
	UserCount int `json:"userCount"`
}

// PoolApp is the shape returned by ListAppsByUserPool. Minimal:
// just what the admin drill-down dialog needs to render a row +
// route to the app's detail page.
type PoolApp struct {
	ID          uuid.UUID `json:"id"`
	ProductID   uuid.UUID `json:"productId"`
	ProductName string    `json:"productName"`
	Type        string    `json:"type"`
	Enabled     bool      `json:"enabled"`
	// DisplayName is composed server-side so the UI doesn't have to
	// duplicate the convention.
	DisplayName string `json:"displayName"`
	// MemberCount: number of app_users rows for this app. Surfaced so
	// the drill-down can show "App X · 42 members" without a second
	// round trip per app.
	MemberCount int `json:"memberCount"`
}

// ListAppsByUserPool returns every app pointing at the pool, with
// product context and member counts. The admin drill-down dialog
// renders this list under the pool details.
func (r *Repo) ListAppsByUserPool(ctx context.Context, poolID uuid.UUID) ([]PoolApp, error) {
	const q = `
SELECT a.id,
       a.product_id,
       p.name           AS product_name,
       a.type,
       a.enabled,
       coalesce(m.cnt, 0)::int AS member_count
FROM apps a
JOIN products p ON p.id = a.product_id
LEFT JOIN (
  SELECT app_id, count(*) AS cnt
  FROM app_users
  GROUP BY app_id
) m ON m.app_id = a.id
WHERE a.user_pool_id = $1
ORDER BY p.name ASC, a.type ASC;
`
	rows, err := r.db.Pool().Query(ctx, q, poolID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PoolApp
	for rows.Next() {
		var pa PoolApp
		if err := rows.Scan(&pa.ID, &pa.ProductID, &pa.ProductName, &pa.Type, &pa.Enabled, &pa.MemberCount); err != nil {
			return nil, err
		}
		pa.DisplayName = core.AppDisplayName(pa.ProductName, pa.Type)
		out = append(out, pa)
	}
	return out, rows.Err()
}

// ListUserPoolsByWorkspaceWithStats returns workspace pools annotated
// with app/user counts. The two scalars are computed via LEFT JOIN
// + COUNT DISTINCT so empty pools still appear with zeros.
func (r *Repo) ListUserPoolsByWorkspaceWithStats(ctx context.Context, workspaceID uuid.UUID) ([]UserPoolWithStats, error) {
	const q = `
SELECT p.id, p.workspace_id, p.name, p.created_at, p.updated_at,
       coalesce(a.cnt, 0)::int AS app_count,
       coalesce(u.cnt, 0)::int AS user_count
FROM user_pools p
LEFT JOIN (
  SELECT user_pool_id, count(*) AS cnt
  FROM apps
  GROUP BY user_pool_id
) a ON a.user_pool_id = p.id
LEFT JOIN (
  SELECT user_pool_id, count(*) AS cnt
  FROM users
  GROUP BY user_pool_id
) u ON u.user_pool_id = p.id
WHERE p.workspace_id = $1
ORDER BY p.name ASC;
`
	rows, err := r.db.Pool().Query(ctx, q, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserPoolWithStats
	for rows.Next() {
		var s UserPoolWithStats
		if err := rows.Scan(
			&s.ID, &s.WorkspaceID, &s.Name, &s.CreatedAt, &s.UpdatedAt,
			&s.AppCount, &s.UserCount,
		); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// RenameUserPool updates the pool's display name. Returns ErrNotFound
// if the pool doesn't exist in the workspace. Surfaces a unique-violation
// error if another pool in the same workspace already has the name.
func (r *Repo) RenameUserPool(ctx context.Context, workspaceID, id uuid.UUID, name string) (*core.UserPool, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("name is required")
	}
	const q = `
UPDATE user_pools
   SET name = $3, updated_at = now()
 WHERE id = $1 AND workspace_id = $2
RETURNING id, workspace_id, name, created_at, updated_at;
`
	var p core.UserPool
	if err := r.db.Pool().QueryRow(ctx, q, id, workspaceID, name).Scan(
		&p.ID, &p.WorkspaceID, &p.Name, &p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

// DeleteUserPool removes a pool. Refuses (returns ErrPoolInUse) when
// any app still references the pool, so we never leave apps pointing
// at a dangling reference. The cascade on user_pools -> users is left
// to do its job once the caller has confirmed the empty-pool case.
//
// The FK from apps.user_pool_id is ON DELETE RESTRICT, so a race
// where another admin attaches an app between the count check and
// the DELETE surfaces as a 23503 from the database. Translated back
// to ErrPoolInUse here so callers get one error type either way.
func (r *Repo) DeleteUserPool(ctx context.Context, workspaceID, id uuid.UUID) error {
	// Pool existence check must be workspace-scoped and run first.
	// Counting apps before scoping would leak pool existence across
	// workspaces (foreign pool with apps → 409 instead of 404).
	var exists bool
	if err := r.db.Pool().QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM user_pools WHERE id = $1 AND workspace_id = $2);`,
		id, workspaceID,
	).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	count, err := r.CountAppsByUserPool(ctx, id)
	if err != nil {
		return err
	}
	if count > 0 {
		return ErrPoolInUse
	}
	const q = `DELETE FROM user_pools WHERE id = $1 AND workspace_id = $2;`
	ct, err := r.db.Pool().Exec(ctx, q, id, workspaceID)
	if err != nil {
		if IsForeignKeyViolation(err) {
			return ErrPoolInUse
		}
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CountAppsByUserPool returns the number of apps pointing at this pool.
// Used both as a delete-safety check and to drive the admin UI's
// "<n> apps" column.
func (r *Repo) CountAppsByUserPool(ctx context.Context, poolID uuid.UUID) (int, error) {
	const q = `SELECT count(*) FROM apps WHERE user_pool_id = $1;`
	return r.scalarCount(ctx, q, poolID)
}

// CountAppMembers returns the number of app_users rows for an app.
// The repoint-app-to-different-pool flow uses this to refuse when the
// app has any members - moving the app would orphan them since their
// user rows live in the old pool.
func (r *Repo) CountAppMembers(ctx context.Context, appID uuid.UUID) (int, error) {
	const q = `SELECT count(*) FROM app_users WHERE app_id = $1;`
	return r.scalarCount(ctx, q, appID)
}

// UpdateAppUserPool repoints an app at a different pool. Caller is
// expected to have run CountAppMembers first and bailed if non-zero;
// this method does not enforce that, so it stays usable for migrations
// and the (future) merge wizard. Returns ErrNotFound when the app
// doesn't exist in the workspace.
func (r *Repo) UpdateAppUserPool(ctx context.Context, workspaceID, appID, newPoolID uuid.UUID) error {
	const q = `
UPDATE apps
   SET user_pool_id = $3, updated_at = now()
 WHERE id = $1 AND workspace_id = $2;
`
	return r.execAffectingOne(ctx, ErrNotFound, q, appID, workspaceID, newPoolID)
}
