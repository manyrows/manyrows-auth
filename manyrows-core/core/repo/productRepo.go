package repo

import (
	"context"
	"errors"
	"fmt"
	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// projectColumns is the canonical SELECT list — kept single-sourced so
// new columns don't need updating across three near-identical queries.
const projectColumns = `
	id,
	workspace_id,
	name,
	created_at,
	updated_at,
	created_by_account_id
`

func scanProduct(row pgx.Row) (*core.Product, error) {
	var p core.Product
	var createdBy *uuid.UUID
	if err := row.Scan(
		&p.ID,
		&p.WorkspaceID,
		&p.Name,
		&p.CreatedAt,
		&p.UpdatedAt,
		&createdBy,
	); err != nil {
		return nil, err
	}
	if createdBy != nil {
		p.CreatedBy = *createdBy
	} else {
		p.CreatedBy = uuid.Nil
	}
	return &p, nil
}

// GetProductsByWorkspaceID returns all products for a workspace (org), ordered by created_at desc.
func (r *Repo) GetProductsByWorkspaceID(ctx context.Context, workspaceId uuid.UUID) ([]core.Product, error) {
	q := `select` + projectColumns + `from products where workspace_id = $1 order by created_at desc`

	rows, err := r.db.Pool().Query(ctx, q, workspaceId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.Product
	for rows.Next() {
		p, err := scanProduct(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// GetProduct returns the project by id within a workspace.
// Returns (nil, nil) if the project is not found.
func (r *Repo) GetProduct(ctx context.Context, id uuid.UUID, workspaceId uuid.UUID) (*core.Product, error) {
	q := `select` + projectColumns + `from products where id = $1 and workspace_id = $2 limit 1`

	p, err := scanProduct(r.db.Pool().QueryRow(ctx, q, id, workspaceId))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return p, nil
}

// InsertProduct inserts a new project.
func (r *Repo) InsertProduct(ctx context.Context, project core.Product) error {
	if project.ID == uuid.Nil {
		project.ID = utils.NewUUID()
	}

	var createdBy any
	if project.CreatedBy == uuid.Nil {
		createdBy = nil
	} else {
		createdBy = project.CreatedBy
	}

	const q = `
		insert into products (
			id,
			workspace_id,
			name,
			created_at,
			updated_at,
			created_by_account_id
		) values (
			$1, $2, $3, now(), now(), $4
		)
	`

	_, err := r.db.Pool().Exec(ctx, q,
		project.ID,
		project.WorkspaceID,
		project.Name,
		createdBy,
	)
	return err
}

// UpdateProduct updates the mutable fields.
func (r *Repo) UpdateProduct(ctx context.Context, project *core.Product) error {
	const q = `
		update products
		set
			name = $1,
			updated_at = now()
		where id = $2 and workspace_id = $3
	`

	ct, err := r.db.Pool().Exec(ctx, q,
		project.Name,
		project.ID,
		project.WorkspaceID,
	)
	if err != nil {
		return err
	}

	if ct.RowsAffected() == 0 {
		return fmt.Errorf("project not found (id=%s workspace_id=%s)", project.ID, project.WorkspaceID)
	}

	return nil
}

// DeleteProduct deletes a project by id within a workspace.
func (r *Repo) DeleteProduct(ctx context.Context, id uuid.UUID, workspaceId uuid.UUID) error {
	const q = `
		delete from products
		where id = $1 and workspace_id = $2
	`

	ct, err := r.db.Pool().Exec(ctx, q, id, workspaceId)
	if err != nil {
		return err
	}

	if ct.RowsAffected() == 0 {
		return fmt.Errorf("project not found (id=%s workspace_id=%s)", id, workspaceId)
	}

	return nil
}

// CountProductsByWorkspaceID returns the number of products in a workspace.
func (r *Repo) CountProductsByWorkspaceID(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	const q = `
SELECT COUNT(*)
FROM products
WHERE workspace_id = $1
`
	return r.scalarCount(ctx, q, workspaceID)
}
