package repo

import (
	"context"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
)

// CreateTeamInvite inserts a pending team invite. Does nothing on conflict (already invited).
func (r *Repo) CreateTeamInvite(ctx context.Context, invite core.TeamInvite) error {
	const q = `
INSERT INTO team_invites (id, workspace_id, email, invited_by, status)
VALUES ($1, $2, lower($3), $4, 'pending')
ON CONFLICT DO NOTHING
`
	_, err := r.db.Pool().Exec(ctx, q, invite.ID, invite.WorkspaceID, invite.Email, invite.InvitedBy)
	return err
}

// GetPendingInvitesByWorkspace returns all pending invites for a workspace.
func (r *Repo) GetPendingInvitesByWorkspace(ctx context.Context, workspaceID uuid.UUID) ([]core.TeamInviteResource, error) {
	const q = `
SELECT ti.id, ti.email, a.name, ti.status, ti.created_at
FROM team_invites ti
JOIN accounts a ON a.id = ti.invited_by
WHERE ti.workspace_id = $1 AND ti.status = 'pending'
ORDER BY ti.created_at DESC
`
	rows, err := r.db.Pool().Query(ctx, q, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []core.TeamInviteResource
	for rows.Next() {
		var inv core.TeamInviteResource
		if err := rows.Scan(&inv.ID, &inv.Email, &inv.InvitedByName, &inv.Status, &inv.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, inv)
	}
	return result, rows.Err()
}

// AcceptTeamInvites marks all pending invites for an email as accepted.
// Returns the workspace IDs that were accepted.
func (r *Repo) AcceptTeamInvites(ctx context.Context, email string) ([]uuid.UUID, error) {
	const q = `
UPDATE team_invites
SET status = 'accepted', accepted_at = now()
WHERE lower(email) = lower($1) AND status = 'pending'
RETURNING workspace_id
`
	rows, err := r.db.Pool().Query(ctx, q, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var workspaceIDs []uuid.UUID
	for rows.Next() {
		var wsID uuid.UUID
		if err := rows.Scan(&wsID); err != nil {
			return nil, err
		}
		workspaceIDs = append(workspaceIDs, wsID)
	}
	return workspaceIDs, rows.Err()
}

// DeleteTeamInvite deletes a pending invite by ID and workspace.
func (r *Repo) DeleteTeamInvite(ctx context.Context, workspaceID, inviteID uuid.UUID) error {
	const q = `DELETE FROM team_invites WHERE id = $1 AND workspace_id = $2 AND status = 'pending'`
	_, err := r.db.Pool().Exec(ctx, q, inviteID, workspaceID)
	return err
}

// HasPendingInvite checks if an email already has a pending invite for a workspace.
func (r *Repo) HasPendingInvite(ctx context.Context, workspaceID uuid.UUID, email string) (bool, error) {
	const q = `SELECT EXISTS(SELECT 1 FROM team_invites WHERE workspace_id = $1 AND lower(email) = lower($2) AND status = 'pending')`
	var exists bool
	err := r.db.Pool().QueryRow(ctx, q, workspaceID, email).Scan(&exists)
	return exists, err
}
