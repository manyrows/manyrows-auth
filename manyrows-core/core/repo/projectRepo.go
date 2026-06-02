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

func scanProject(row pgx.Row) (*core.Project, error) {
	var p core.Project
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

// GetProjectsByWorkspaceID returns all projects for a workspace (org), ordered by created_at desc.
func (r *Repo) GetProjectsByWorkspaceID(ctx context.Context, workspaceId uuid.UUID) ([]core.Project, error) {
	q := `select` + projectColumns + `from projects where workspace_id = $1 order by created_at desc`

	rows, err := r.db.Pool().Query(ctx, q, workspaceId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.Project
	for rows.Next() {
		p, err := scanProject(rows)
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

// GetProject returns the project by id within a workspace.
// Returns (nil, nil) if the project is not found.
func (r *Repo) GetProject(ctx context.Context, id uuid.UUID, workspaceId uuid.UUID) (*core.Project, error) {
	q := `select` + projectColumns + `from projects where id = $1 and workspace_id = $2 limit 1`

	p, err := scanProject(r.db.Pool().QueryRow(ctx, q, id, workspaceId))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return p, nil
}

// InsertProject inserts a new project.
func (r *Repo) InsertProject(ctx context.Context, project core.Project) error {
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
		insert into projects (
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

// UpdateProject updates the mutable fields.
func (r *Repo) UpdateProject(ctx context.Context, project *core.Project) error {
	const q = `
		update projects
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

// DeleteProject deletes a project by id within a workspace.
func (r *Repo) DeleteProject(ctx context.Context, id uuid.UUID, workspaceId uuid.UUID) error {
	const q = `
		delete from projects
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

// CountProjectsByWorkspaceID returns the number of projects in a workspace.
func (r *Repo) CountProjectsByWorkspaceID(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	const q = `
SELECT COUNT(*)
FROM projects
WHERE workspace_id = $1
`
	return r.scalarCount(ctx, q, workspaceID)
}
