package repo

import (
	"context"
	"errors"
	"manyrows-core/utils"
	"sort"
	"strings"
	"time"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// GetRolesByProductID returns all roles for a project, each with Permissions loaded.
func (r *Repo) GetRolesByProductID(ctx context.Context, productID uuid.UUID) ([]core.Role, error) {
	// 1) Load roles
	const qRoles = `
		select
			id,
			product_id,
			name,
			slug,
			created_at,
			updated_at
		from roles
		where product_id = $1
		order by created_at desc
	`

	rows, err := r.db.Pool().Query(ctx, qRoles, productID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := make([]core.Role, 0)
	roleIDs := make([]uuid.UUID, 0)

	for rows.Next() {
		var role core.Role
		if err := rows.Scan(
			&role.ID,
			&role.ProductID,
			&role.Name,
			&role.Slug,
			&role.CreatedAt,
			&role.UpdatedAt,
		); err != nil {
			return nil, err
		}
		// IMPORTANT: keep permissions non-nil for stable JSON
		role.Permissions = []core.Permission{}
		roles = append(roles, role)
		roleIDs = append(roleIDs, role.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(roles) == 0 {
		return roles, nil
	}

	// 2) Load permissions for all roles in one go
	// (we ensure project scoping via permissions.product_id = $1)
	const qPerms = `
		select
			rp.role_id,

			p.id,
			p.product_id,
			p.name,
			p.slug,
			p.created_at,
			p.updated_at
		from role_permissions rp
		join permissions p on p.id = rp.permission_id
		where rp.role_id = any($2::uuid[])
		  and p.product_id = $1
		order by rp.role_id, p.slug, p.name
	`

	rows2, err := r.db.Pool().Query(ctx, qPerms, productID, roleIDs)
	if err != nil {
		return nil, err
	}
	defer rows2.Close()

	permsByRole := make(map[uuid.UUID][]core.Permission, len(roles))
	for rows2.Next() {
		var roleID uuid.UUID
		var p core.Permission

		if err := rows2.Scan(
			&roleID,
			&p.ID,
			&p.ProductID,
			&p.Name,
			&p.Slug,
			&p.CreatedAt,
			&p.UpdatedAt,
		); err != nil {
			return nil, err
		}
		permsByRole[roleID] = append(permsByRole[roleID], p)
	}
	if err := rows2.Err(); err != nil {
		return nil, err
	}

	// 3) Attach to roles (IMPORTANT: don't overwrite with nil)
	for i := range roles {
		if perms, ok := permsByRole[roles[i].ID]; ok {
			roles[i].Permissions = perms
		} else {
			roles[i].Permissions = []core.Permission{}
		}
	}

	return roles, nil
}

// GetRoleByID loads a single role with its permissions.
func (r *Repo) GetRoleByID(ctx context.Context, productID, roleID uuid.UUID) (core.Role, error) {
	const q = `
		select
			id,
			product_id,
			name,
			slug,
			created_at,
			updated_at
		from roles
		where product_id = $1 and id = $2
	`

	var role core.Role
	err := r.db.Pool().QueryRow(ctx, q, productID, roleID).Scan(
		&role.ID,
		&role.ProductID,
		&role.Name,
		&role.Slug,
		&role.CreatedAt,
		&role.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.Role{}, ErrNotFound
		}
		return core.Role{}, err
	}

	const qPerms = `
		select
			p.id,
			p.product_id,
			p.name,
			p.slug,
			p.created_at,
			p.updated_at
		from role_permissions rp
		join permissions p on p.id = rp.permission_id
		where rp.role_id = $2
		  and p.product_id = $1
		order by p.slug, p.name
	`

	rows, err := r.db.Pool().Query(ctx, qPerms, productID, roleID)
	if err != nil {
		return core.Role{}, err
	}
	defer rows.Close()

	role.Permissions = make([]core.Permission, 0)
	for rows.Next() {
		var p core.Permission
		if err := rows.Scan(
			&p.ID,
			&p.ProductID,
			&p.Name,
			&p.Slug,
			&p.CreatedAt,
			&p.UpdatedAt,
		); err != nil {
			return core.Role{}, err
		}
		role.Permissions = append(role.Permissions, p)
	}
	if err := rows.Err(); err != nil {
		return core.Role{}, err
	}

	// Defensive sort (in case DB ordering changes) - order by slug prefix (derived group), then name
	sort.Slice(role.Permissions, func(i, j int) bool {
		if role.Permissions[i].Slug != role.Permissions[j].Slug {
			return role.Permissions[i].Slug < role.Permissions[j].Slug
		}
		return role.Permissions[i].Name < role.Permissions[j].Name
	})

	return role, nil
}

type CreateRoleParams struct {
	ProductID uuid.UUID
	Name      string
	Slug      string
	Now       time.Time
}

func (r *Repo) CreateRole(ctx context.Context, p CreateRoleParams) (core.Role, error) {
	name := strings.TrimSpace(p.Name)
	slug := strings.TrimSpace(p.Slug)
	if name == "" || slug == "" {
		return core.Role{}, ErrBadRequest
	}

	const q = `
		insert into roles (product_id, name, slug, created_at, updated_at, id)
		values ($1, $2, $3, $4, $4, $5)
		returning
			id,
			product_id,
			name,
			slug,
			created_at,
			updated_at
	`

	var role core.Role
	err := r.db.Pool().QueryRow(ctx, q, p.ProductID, name, slug, p.Now, utils.NewUUID()).Scan(
		&role.ID,
		&role.ProductID,
		&role.Name,
		&role.Slug,
		&role.CreatedAt,
		&role.UpdatedAt,
	)
	if err != nil {
		if IsUniqueViolation(err) {
			return core.Role{}, ErrConflict
		}
		return core.Role{}, err
	}

	// IMPORTANT: stable JSON (permissions is [] not null)
	role.Permissions = []core.Permission{}

	return role, nil
}

type UpdateRoleParams struct {
	ProductID uuid.UUID
	RoleID    uuid.UUID
	Name      *string
	Slug      *string
	Now       time.Time
}

func (r *Repo) UpdateRole(ctx context.Context, p UpdateRoleParams) (core.Role, error) {
	// allow patching one or both
	var (
		setName = p.Name != nil
		setSlug = p.Slug != nil
	)

	if !setName && !setSlug {
		// nothing to do — but still return current row if it exists
		return r.GetRoleByID(ctx, p.ProductID, p.RoleID)
	}

	var (
		nameVal *string
		slugVal *string
	)

	if setName {
		v := strings.TrimSpace(*p.Name)
		if v == "" {
			return core.Role{}, ErrBadRequest
		}
		nameVal = &v
	}
	if setSlug {
		v := strings.TrimSpace(*p.Slug)
		if v == "" {
			return core.Role{}, ErrBadRequest
		}
		slugVal = &v
	}

	const q = `
		update roles
		set
			name = coalesce($3, name),
			slug = coalesce($4, slug),
			updated_at = $5
		where product_id = $1 and id = $2
		returning
			id,
			product_id,
			name,
			slug,
			created_at,
			updated_at
	`

	var role core.Role
	err := r.db.Pool().QueryRow(ctx, q, p.ProductID, p.RoleID, nameVal, slugVal, p.Now).Scan(
		&role.ID,
		&role.ProductID,
		&role.Name,
		&role.Slug,
		&role.CreatedAt,
		&role.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.Role{}, ErrNotFound
		}
		if IsUniqueViolation(err) {
			return core.Role{}, ErrConflict
		}
		return core.Role{}, err
	}

	// IMPORTANT: stable JSON (permissions is [] not null) unless you load them
	role.Permissions = []core.Permission{}

	return role, nil
}

// ---- Role Permissions (replace-all) ----

type ReplaceRolePermissionsParams struct {
	ProductID     uuid.UUID
	RoleID        uuid.UUID
	PermissionIDs []uuid.UUID
	Now           time.Time
}

// ReplaceRolePermissions atomically replaces the set of permissions on a role.
// Validates that:
// - role belongs to project
// - all permission IDs belong to same project
func (r *Repo) ReplaceRolePermissions(ctx context.Context, p ReplaceRolePermissionsParams) error {
	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// Ensure role exists + belongs to project
	{
		const q = `select 1 from roles where product_id = $1 and id = $2`
		var one int
		if err := tx.QueryRow(ctx, q, p.ProductID, p.RoleID).Scan(&one); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
	}

	// Validate permissions all belong to this project
	if len(p.PermissionIDs) > 0 {
		const q = `
			select count(*)
			from permissions
			where product_id = $1
			  and id = any($2::uuid[])
		`
		var cnt int
		if err := tx.QueryRow(ctx, q, p.ProductID, uniqueUUIDs(p.PermissionIDs)).Scan(&cnt); err != nil {
			return err
		}
		if cnt != len(uniqueUUIDs(p.PermissionIDs)) {
			return ErrBadRequest
		}
	}

	// Replace set
	{
		const del = `delete from role_permissions where role_id = $1`
		if _, err := tx.Exec(ctx, del, p.RoleID); err != nil {
			return err
		}

		ids := uniqueUUIDs(p.PermissionIDs)
		if len(ids) > 0 {
			const ins = `
				insert into role_permissions (role_id, permission_id, created_at, id)
				select $1, x, $2, gen_random_uuid()
				from unnest($3::uuid[]) as x
				on conflict (role_id, permission_id) do nothing
			`
			if _, err := tx.Exec(ctx, ins, p.RoleID, p.Now, ids); err != nil {
				return err
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

func uniqueUUIDs(in []uuid.UUID) []uuid.UUID {
	if len(in) <= 1 {
		return in
	}
	seen := make(map[uuid.UUID]struct{}, len(in))
	out := make([]uuid.UUID, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// DeleteRole deletes a role in a project.
//
// Behavior:
//   - Ensures the role belongs to the given project (project-scoped).
//   - Best-effort cleanup of role_permissions is handled by FK cascade if you have it;
//     otherwise we explicitly delete role_permissions first.
//   - If the role is referenced elsewhere (e.g. member_roles), Postgres will raise a FK violation.
//     In that case we return ErrConflict so the handler can respond 409 "role is in use".
func (r *Repo) DeleteRole(ctx context.Context, productID, roleID uuid.UUID) error {
	if productID == uuid.Nil || roleID == uuid.Nil {
		return ErrBadRequest
	}

	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// (Optional) ensure exists first so we can return ErrNotFound cleanly.
	{
		const q = `select 1 from roles where product_id = $1 and id = $2`
		var one int
		if err := tx.QueryRow(ctx, q, productID, roleID).Scan(&one); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
	}

	// Remove role permissions (if you DON'T have ON DELETE CASCADE on role_permissions.role_id).
	// Safe even if you do have cascade.
	{
		const q = `delete from role_permissions where role_id = $1`
		if _, err := tx.Exec(ctx, q, roleID); err != nil {
			return err
		}
	}

	// Delete the role (project-scoped)
	{
		const q = `delete from roles where product_id = $1 and id = $2`
		ct, err := tx.Exec(ctx, q, productID, roleID)
		if err != nil {
			// FK violation => role is referenced (e.g. member_roles). Surface as conflict.
			// Uses your helper that checks *pgconn.PgError and Code "23505" for unique;
			// for FK violations we can check the SQLSTATE directly.
			//
			// If you already have a helper for this, swap it in.
			var pgErr interface{ SQLState() string }
			if errors.As(err, &pgErr) && pgErr.SQLState() == "23503" { // foreign_key_violation
				return ErrConflict
			}
			return err
		}
		if ct.RowsAffected() == 0 {
			// In case it disappeared between existence check and delete.
			return ErrNotFound
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

// CountRolesByProductID returns the number of roles in a project.
func (r *Repo) CountRolesByProductID(ctx context.Context, productID uuid.UUID) (int, error) {
	const q = `SELECT COUNT(*) FROM roles WHERE product_id = $1`
	return r.scalarCount(ctx, q, productID)
}
