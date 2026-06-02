package repo

import (
	"context"
	"fmt"
	"manyrows-core/core"
	"manyrows-core/utils"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// GetPermissionsByProjectID returns all permissions for a project, ordered by slug.
func (r *Repo) GetPermissionsByProjectID(ctx context.Context, projectId uuid.UUID) ([]core.Permission, error) {
	const q = `
		select
			id,
			project_id,
			name,
			slug,
			created_at,
			updated_at
		from permissions
		where project_id = $1
		order by slug asc
	`

	rows, err := r.db.Pool().Query(ctx, q, projectId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []core.Permission{}
	for rows.Next() {
		var p core.Permission
		if err := rows.Scan(
			&p.ID,
			&p.ProjectID,
			&p.Name,
			&p.Slug,
			&p.CreatedAt,
			&p.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, p)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// GetPermission returns a permission by id scoped to a project.
// Returns (nil, nil) if not found.
func (r *Repo) GetPermission(ctx context.Context, permissionId uuid.UUID, projectId uuid.UUID) (*core.Permission, error) {
	const q = `
		select
			id,
			project_id,
			name,
			slug,
			created_at,
			updated_at
		from permissions
		where id = $1 and project_id = $2
		limit 1
	`

	row := r.db.Pool().QueryRow(ctx, q, permissionId, projectId)

	var p core.Permission
	if err := row.Scan(
		&p.ID,
		&p.ProjectID,
		&p.Name,
		&p.Slug,
		&p.CreatedAt,
		&p.UpdatedAt,
	); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &p, nil
}

// CreatePermission inserts a new permission. If ID is missing, it generates one.
func (r *Repo) CreatePermission(ctx context.Context, perm core.Permission) error {
	if perm.ID == uuid.Nil {
		perm.ID = utils.NewUUID()
	}

	perm.Name = strings.TrimSpace(perm.Name)
	perm.Slug = strings.TrimSpace(perm.Slug)

	if perm.Name == "" || perm.Slug == "" {
		return fmt.Errorf("permission requires name and slug")
	}

	const q = `
		insert into permissions (
			id,
			project_id,
			name,
			slug,
			created_at,
			updated_at
		) values (
			$1, $2, $3, $4, now(), now()
		)
	`

	_, err := r.db.Pool().Exec(ctx, q,
		perm.ID,
		perm.ProjectID,
		perm.Name,
		perm.Slug,
	)
	return err
}

// UpdatePermission updates the mutable fields for a permission scoped to a project.
// Expects perm.ID and perm.ProjectID set.
func (r *Repo) UpdatePermission(ctx context.Context, perm core.Permission) error {
	perm.Name = strings.TrimSpace(perm.Name)
	perm.Slug = strings.TrimSpace(perm.Slug)

	if perm.Name == "" || perm.Slug == "" {
		return fmt.Errorf("permission requires name and slug")
	}

	const q = `
		update permissions
		set
			name = $1,
			slug = $2,
			updated_at = now()
		where id = $3 and project_id = $4
	`

	ct, err := r.db.Pool().Exec(ctx, q,
		perm.Name,
		perm.Slug,
		perm.ID,
		perm.ProjectID,
	)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("permission not found (id=%s project_id=%s)", perm.ID, perm.ProjectID)
	}
	return nil
}

// DeletePermission deletes a permission by id scoped to a project.
func (r *Repo) DeletePermission(ctx context.Context, permissionId uuid.UUID, projectId uuid.UUID) error {
	const q = `
		delete from permissions
		where id = $1 and project_id = $2
	`

	ct, err := r.db.Pool().Exec(ctx, q, permissionId, projectId)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("permission not found (id=%s project_id=%s)", permissionId, projectId)
	}
	return nil
}

// CountPermissionsByProjectID returns the number of permissions in a project.
func (r *Repo) CountPermissionsByProjectID(ctx context.Context, projectID uuid.UUID) (int, error) {
	const q = `SELECT COUNT(*) FROM permissions WHERE project_id = $1`
	return r.scalarCount(ctx, q, projectID)
}
