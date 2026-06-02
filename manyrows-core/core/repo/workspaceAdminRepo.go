package repo

import (
	"context"
	"errors"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// WorkspaceMembership is a workspace plus the current user's role in it.
type WorkspaceMembership struct {
	core.Workspace
	Role string
}

// GetWorkspaceAdmins returns all admin-UI members for a workspace (joined with accounts).
func (r *Repo) GetWorkspaceAdmins(ctx context.Context, workspaceID uuid.UUID) ([]core.WorkspaceAdminResource, error) {
	const q = `
SELECT wa.id, wa.account_id, a.email, a.name, wa.role, wa.created_at
FROM workspace_admins wa
JOIN accounts a ON a.id = wa.account_id
WHERE wa.workspace_id = $1
ORDER BY wa.created_at
`
	rows, err := r.db.Pool().Query(ctx, q, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []core.WorkspaceAdminResource
	for rows.Next() {
		var m core.WorkspaceAdminResource
		if err := rows.Scan(&m.ID, &m.AccountID, &m.Email, &m.Name, &m.Role, &m.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

// GetWorkspaceAdminRole returns the role for an account in a workspace, or found=false.
func (r *Repo) GetWorkspaceAdminRole(ctx context.Context, workspaceID, accountID uuid.UUID) (string, bool, error) {
	const q = `SELECT role FROM workspace_admins WHERE workspace_id = $1 AND account_id = $2`
	var role string
	err := r.db.Pool().QueryRow(ctx, q, workspaceID, accountID).Scan(&role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	return role, true, nil
}

// AddWorkspaceAdmin inserts a workspace admin. Does nothing on conflict.
func (r *Repo) AddWorkspaceAdmin(ctx context.Context, admin core.WorkspaceAdmin) error {
	const q = `
INSERT INTO workspace_admins (workspace_id, account_id, role, added_by)
VALUES ($1, $2, $3, $4)
ON CONFLICT (workspace_id, account_id) DO NOTHING
`
	_, err := r.db.Pool().Exec(ctx, q, admin.WorkspaceID, admin.AccountID, admin.Role, admin.AddedBy)
	return err
}

// RemoveWorkspaceAdmin removes an admin from a workspace.
func (r *Repo) RemoveWorkspaceAdmin(ctx context.Context, workspaceID, accountID uuid.UUID) error {
	const q = `DELETE FROM workspace_admins WHERE workspace_id = $1 AND account_id = $2`
	_, err := r.db.Pool().Exec(ctx, q, workspaceID, accountID)
	return err
}

// CountWorkspaceOwners returns the number of owners for a workspace.
func (r *Repo) CountWorkspaceOwners(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	const q = `SELECT count(*) FROM workspace_admins WHERE workspace_id = $1 AND role = 'owner'`
	var count int
	err := r.db.Pool().QueryRow(ctx, q, workspaceID).Scan(&count)
	return count, err
}

// GetWorkspacesForAccount returns all workspaces the account has access to (via workspace_admins).
func (r *Repo) GetWorkspacesForAccount(ctx context.Context, accountID uuid.UUID) ([]WorkspaceMembership, error) {
	const q = `
SELECT w.id, w.name, w.slug, w.status, w.created_at, w.created_by, w.google_oauth_client_id,
       w.setup_checklist_dismissed_at, w.setup_test_email_sent_at, wa.role
FROM workspace_admins wa
JOIN workspaces w ON w.id = wa.workspace_id
WHERE wa.account_id = $1
ORDER BY w.created_at DESC
`
	rows, err := r.db.Pool().Query(ctx, q, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []WorkspaceMembership
	for rows.Next() {
		var m WorkspaceMembership
		if err := rows.Scan(
			&m.ID, &m.Name, &m.Slug, &m.Status, &m.CreatedAt, &m.CreatedBy, &m.GoogleOAuthClientID,
			&m.SetupChecklistDismissedAt, &m.SetupTestEmailSentAt, &m.Role,
		); err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, rows.Err()
}
