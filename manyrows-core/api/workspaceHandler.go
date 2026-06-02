package api

import (
	"context"
	"manyrows-core/core"
	"time"

	"github.com/gofrs/uuid/v5"
)

type WorkspaceResource struct {
	// Workspace metadata
	ID        uuid.UUID            `json:"id"`
	Name      string               `json:"name"`
	Slug      string               `json:"slug"`
	Status    core.WorkspaceStatus `json:"status"`
	CreatedAt time.Time            `json:"createdAt"`

	// The current user's role in this workspace ("owner" or "admin")
	Role string `json:"role"`

	Projects []core.Project `json:"projects"`

	// First-boot setup checklist state — surfaced to the UI so the
	// home page can render the "Complete your setup" card and tick
	// items off as the operator progresses.
	SetupChecklistDismissedAt *time.Time `json:"setupChecklistDismissedAt,omitempty"`
	SetupTestEmailSentAt      *time.Time `json:"setupTestEmailSentAt,omitempty"`
}

// GetProjectAsAdmin returns a project if the admin has access to the workspace.
// Relies on middleware having already validated workspace ownership.
func (handler *RequestHandler) GetProjectAsAdmin(
	ctx context.Context,
	id uuid.UUID,
	workspaceID uuid.UUID,
	acc *core.Account,
) (*core.Project, bool, error) {
	ws, ok, err := handler.GetWorkspaceAsAdmin(ctx, workspaceID, acc)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, nil
	}
	project, err := handler.repo.GetProject(ctx, id, ws.ID)
	if err != nil {
		return nil, false, err
	}
	if project == nil {
		return nil, false, nil
	}
	return project, true, nil
}

// GetWorkspaceAsAdmin returns a workspace if the admin has access (via workspace_admins).
// Prefers using workspace from context (set by middleware).
func (handler *RequestHandler) GetWorkspaceAsAdmin(
	ctx context.Context,
	id uuid.UUID,
	acc *core.Account,
) (*core.Workspace, bool, error) {
	// Try middleware context first (already validated by adminWorkspaceMiddleware)
	ws, ok := core.WorkspaceFromContext(ctx)
	if ok && ws.ID == id {
		return ws, true, nil
	}

	// Fallback: fetch and verify membership
	if acc == nil || acc.ID == uuid.Nil {
		return nil, false, nil
	}

	ws, found, err := handler.repo.GetWorkspaceByID(ctx, id)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	}

	// Check membership via workspace_admins
	_, isMember, err := handler.repo.GetWorkspaceAdminRole(ctx, id, acc.ID)
	if err != nil {
		return nil, false, err
	}
	if !isMember {
		return nil, false, nil
	}

	return ws, true, nil
}
