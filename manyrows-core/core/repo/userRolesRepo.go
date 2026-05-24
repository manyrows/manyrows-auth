package repo

import (
	"context"
	"errors"
	"time"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// GetUserRolesByProductID returns all role assignments for a project.
// user_roles no longer carries product_id directly; the project filter
// is applied via apps.
func (r *Repo) GetUserRolesByProductID(ctx context.Context, productID uuid.UUID) ([]core.UserRole, error) {
	const q = `
		select
			ur.id,
			ur.app_id,
			ur.user_id,
			ur.role_id,
			ur.created_at
		from user_roles ur
		join apps a on a.id = ur.app_id
		where a.product_id = $1
		order by ur.created_at asc
	`

	rows, err := r.db.Pool().Query(ctx, q, productID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]core.UserRole, 0)
	for rows.Next() {
		var ur core.UserRole
		if err := rows.Scan(
			&ur.ID,
			&ur.AppID,
			&ur.UserID,
			&ur.RoleID,
			&ur.CreatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, ur)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

// GetUserRolesByUserID returns role assignments for a user within a project.
func (r *Repo) GetUserRolesByUserID(ctx context.Context, productID, userID uuid.UUID) ([]core.UserRole, error) {
	const q = `
		select
			ur.id,
			ur.app_id,
			ur.user_id,
			ur.role_id,
			ur.created_at
		from user_roles ur
		join apps a on a.id = ur.app_id
		where a.product_id = $1
		  and ur.user_id = $2
		order by ur.created_at asc
	`

	rows, err := r.db.Pool().Query(ctx, q, productID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]core.UserRole, 0)
	for rows.Next() {
		var ur core.UserRole
		if err := rows.Scan(
			&ur.ID,
			&ur.AppID,
			&ur.UserID,
			&ur.RoleID,
			&ur.CreatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, ur)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

// GetRoleSlugsAndPermissionSlugsForRoleIDs returns unique role slugs and permission slugs
// for the given role IDs (scoped to project).
func (r *Repo) GetRoleSlugsAndPermissionSlugsForRoleIDs(
	ctx context.Context,
	productID uuid.UUID,
	roleIDs []uuid.UUID,
) ([]string, []string, error) {
	roleIDs = uniqueUUIDs(roleIDs)
	if len(roleIDs) == 0 {
		return []string{}, []string{}, nil
	}

	// 1) Role slugs
	const qRoles = `
		select distinct r.slug
		from roles r
		where r.product_id = $1
		  and r.id = any($2::uuid[])
		order by r.slug asc
	`

	roleRows, err := r.db.Pool().Query(ctx, qRoles, productID, roleIDs)
	if err != nil {
		return nil, nil, err
	}
	defer roleRows.Close()

	roles := make([]string, 0, len(roleIDs))
	for roleRows.Next() {
		var slug string
		if err := roleRows.Scan(&slug); err != nil {
			return nil, nil, err
		}
		roles = append(roles, slug)
	}
	if err := roleRows.Err(); err != nil {
		return nil, nil, err
	}

	// 2) Permission slugs (permissions granted by these roles)
	const qPerms = `
		select distinct p.slug
		from role_permissions rp
		join permissions p on p.id = rp.permission_id
		where rp.role_id = any($2::uuid[])
		  and p.product_id = $1
		order by p.slug asc
	`

	permRows, err := r.db.Pool().Query(ctx, qPerms, productID, roleIDs)
	if err != nil {
		return nil, nil, err
	}
	defer permRows.Close()

	perms := make([]string, 0, 16)
	for permRows.Next() {
		var slug string
		if err := permRows.Scan(&slug); err != nil {
			return nil, nil, err
		}
		perms = append(perms, slug)
	}
	if err := permRows.Err(); err != nil {
		return nil, nil, err
	}

	return roles, perms, nil
}

// GetUserRolesByUserAndAppID returns the user's roles in a specific app.
// productID parameter is kept for API stability but no longer needed for
// the query — app_id implies the project (apps.product_id).
func (r *Repo) GetUserRolesByUserAndAppID(
	ctx context.Context,
	productID, userID uuid.UUID,
	appID uuid.UUID,
) ([]core.UserRole, error) {
	_ = productID
	const q = `
		select
			id,
			app_id,
			user_id,
			role_id,
			created_at
		from user_roles
		where app_id = $1
		  and user_id = $2
		order by created_at asc
	`

	rows, err := r.db.Pool().Query(ctx, q, appID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]core.UserRole, 0)
	for rows.Next() {
		var ur core.UserRole
		if err := rows.Scan(
			&ur.ID,
			&ur.AppID,
			&ur.UserID,
			&ur.RoleID,
			&ur.CreatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, ur)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type ReplaceUserRolesParams struct {
	ProductID uuid.UUID // used to validate roles belong to this project
	UserID    uuid.UUID
	AppID     uuid.UUID // required — project-wide grants no longer exist
	RoleIDs   []uuid.UUID
	Now       time.Time
}

// ReplaceUserRoles replaces role assignments for (user, app) with RoleIDs.
// Validates that AppID belongs to ProductID and that all RoleIDs belong
// to ProductID — both checks guard against an admin in project A
// accidentally writing into project B.
func (r *Repo) ReplaceUserRoles(ctx context.Context, p ReplaceUserRolesParams) error {
	if p.AppID == uuid.Nil {
		return ErrBadRequest
	}

	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// Validate app belongs to project.
	{
		const q = `
			select 1
			from apps
			where id = $1
			  and product_id = $2
		`
		var one int
		if err := tx.QueryRow(ctx, q, p.AppID, p.ProductID).Scan(&one); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrBadRequest
			}
			return err
		}
	}

	// Validate roles all belong to this project
	if len(p.RoleIDs) > 0 {
		roleIDs := uniqueUUIDs(p.RoleIDs)

		const q = `
			select count(*)
			from roles
			where product_id = $1
			  and id = any($2::uuid[])
		`
		var cnt int
		if err := tx.QueryRow(ctx, q, p.ProductID, roleIDs).Scan(&cnt); err != nil {
			return err
		}
		if cnt != len(roleIDs) {
			return ErrBadRequest
		}
	}

	// Replace set for the given app + user scope. AppID is required after
	// 00010 — project-wide grants no longer exist.
	{
		const del = `
			delete from user_roles
			where app_id = $1
			  and user_id = $2
		`
		if _, err := tx.Exec(ctx, del, p.AppID, p.UserID); err != nil {
			return err
		}

		roleIDs := uniqueUUIDs(p.RoleIDs)
		if len(roleIDs) > 0 {
			const ins = `
				insert into user_roles (app_id, user_id, role_id, created_at, id)
				select $1, $2, x, $3, gen_random_uuid()
				from unnest($4::uuid[]) as x
				on conflict do nothing
			`
			if _, err := tx.Exec(ctx, ins, p.AppID, p.UserID, p.Now, roleIDs); err != nil {
				return err
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

// AddUserRole grants a single role to a user in an app. Idempotent — granting
// a role the user already has is a no-op. The caller is responsible for
// ensuring roleID belongs to the app's product (resolveRoleSlugs does this).
func (r *Repo) AddUserRole(ctx context.Context, appID, userID, roleID uuid.UUID) error {
	const q = `
		insert into user_roles (app_id, user_id, role_id, created_at, id)
		values ($1, $2, $3, $4, gen_random_uuid())
		on conflict do nothing;
	`
	_, err := r.db.Pool().Exec(ctx, q, appID, userID, roleID, time.Now().UTC())
	return err
}

// RemoveUserRole revokes a single role from a user in an app. Idempotent.
func (r *Repo) RemoveUserRole(ctx context.Context, appID, userID, roleID uuid.UUID) error {
	const q = `delete from user_roles where app_id = $1 and user_id = $2 and role_id = $3;`
	_, err := r.db.Pool().Exec(ctx, q, appID, userID, roleID)
	return err
}

// Optional helper: check if a project exists (useful if you want ErrNotFound when project is invalid).
func (r *Repo) ProductExists(ctx context.Context, productID uuid.UUID) (bool, error) {
	const q = `select 1 from products where id = $1`
	var one int
	err := r.db.Pool().QueryRow(ctx, q, productID).Scan(&one)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// IsWorkspaceOwner checks if account created this workspace.
func (r *Repo) IsWorkspaceOwner(ctx context.Context, workspaceID, accountID uuid.UUID) (bool, error) {
	const q = `select 1 from workspaces where id = $1 and created_by = $2`
	var one int
	err := r.db.Pool().QueryRow(ctx, q, workspaceID, accountID).Scan(&one)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// GetValidAppIDs returns the subset of appIDs that exist in the given project.
func (r *Repo) GetValidAppIDs(ctx context.Context, productID uuid.UUID, appIDs []uuid.UUID) ([]uuid.UUID, error) {
	if len(appIDs) == 0 {
		return []uuid.UUID{}, nil
	}
	const q = `
		select id
		from apps
		where product_id = $1
		  and id = any($2::uuid[])
	`
	rows, err := r.db.Pool().Query(ctx, q, productID, appIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]uuid.UUID, 0, len(appIDs))
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// GetValidRoleIDs returns the subset of roleIDs that exist in the given project.
func (r *Repo) GetValidRoleIDs(ctx context.Context, productID uuid.UUID, roleIDs []uuid.UUID) ([]uuid.UUID, error) {
	if len(roleIDs) == 0 {
		return []uuid.UUID{}, nil
	}
	const q = `
		select id
		from roles
		where product_id = $1
		  and id = any($2::uuid[])
	`
	rows, err := r.db.Pool().Query(ctx, q, productID, roleIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]uuid.UUID, 0, len(roleIDs))
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// GetRoleNames returns the names of roles by their IDs (preserving order).
func (r *Repo) GetRoleNames(ctx context.Context, productID uuid.UUID, roleIDs []uuid.UUID) ([]string, error) {
	if len(roleIDs) == 0 {
		return []string{}, nil
	}
	const q = `
		select id, name
		from roles
		where product_id = $1
		  and id = any($2::uuid[])
	`
	rows, err := r.db.Pool().Query(ctx, q, productID, roleIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Map IDs to names
	nameMap := make(map[uuid.UUID]string)
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		nameMap[id] = name
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Preserve original order
	out := make([]string, 0, len(roleIDs))
	for _, id := range roleIDs {
		if name, ok := nameMap[id]; ok {
			out = append(out, name)
		}
	}
	return out, nil
}

// =====================
// Direct User Permissions
// =====================

// GetDirectPermissionSlugs returns permission slugs directly assigned to a
// user for an app (not via roles). productID kept for API stability — the
// query no longer needs it since app_id implies the project.
func (r *Repo) GetDirectPermissionSlugs(ctx context.Context, productID, userID, appID uuid.UUID) ([]string, error) {
	_ = productID
	const q = `
		SELECT DISTINCT p.slug
		FROM user_permissions up
		JOIN permissions p ON p.id = up.permission_id
		WHERE up.app_id = $1
		  AND up.user_id = $2
		ORDER BY p.slug ASC
	`
	rows, err := r.db.Pool().Query(ctx, q, appID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var slug string
		if err := rows.Scan(&slug); err != nil {
			return nil, err
		}
		out = append(out, slug)
	}
	return out, rows.Err()
}

// GetDirectPermissionIDs returns permission IDs directly assigned to a user for an app.
func (r *Repo) GetDirectPermissionIDs(ctx context.Context, productID, userID, appID uuid.UUID) ([]uuid.UUID, error) {
	_ = productID
	const q = `
		SELECT permission_id
		FROM user_permissions
		WHERE app_id = $1 AND user_id = $2
	`
	rows, err := r.db.Pool().Query(ctx, q, appID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SetDirectPermissions replaces all direct permissions for a user in an app.
func (r *Repo) SetDirectPermissions(ctx context.Context, productID, userID, appID uuid.UUID, permissionIDs []uuid.UUID) error {
	if appID == uuid.Nil {
		return ErrBadRequest
	}
	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Validate app belongs to project (guards an admin in project A from writing
	// grants scoped to project B — mirrors ReplaceUserRoles).
	{
		var one int
		if err := tx.QueryRow(ctx, `select 1 from apps where id = $1 and product_id = $2`, appID, productID).Scan(&one); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrBadRequest
			}
			return err
		}
	}

	// Validate all permissions belong to this project.
	if len(permissionIDs) > 0 {
		permIDs := uniqueUUIDs(permissionIDs)
		var cnt int
		if err := tx.QueryRow(ctx, `select count(*) from permissions where product_id = $1 and id = any($2::uuid[])`, productID, permIDs).Scan(&cnt); err != nil {
			return err
		}
		if cnt != len(permIDs) {
			return ErrBadRequest
		}
	}

	// Delete existing
	_, err = tx.Exec(ctx,
		`DELETE FROM user_permissions WHERE app_id = $1 AND user_id = $2`,
		appID, userID)
	if err != nil {
		return err
	}

	// Insert new
	for _, permID := range permissionIDs {
		_, err = tx.Exec(ctx,
			`INSERT INTO user_permissions (id, app_id, user_id, permission_id) VALUES ($1, $2, $3, $4)`,
			utils.NewUUID(), appID, userID, permID)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}
