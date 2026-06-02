package repo

import (
	"context"
	"errors"
	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

type rowScanner interface {
	Scan(dest ...any) error
}

// Central mapping: columns must match the select list order.
func scanWorkspace(s rowScanner) (*core.Workspace, error) {
	var ws core.Workspace
	var status int16

	if err := s.Scan(
		&ws.ID,
		&ws.Name,
		&ws.Slug,
		&status,
		&ws.CreatedAt,
		&ws.CreatedBy,
		&ws.GoogleOAuthClientID,
		&ws.CookieDomain,
		&ws.SetupChecklistDismissedAt,
		&ws.SetupTestEmailSentAt,
	); err != nil {
		return nil, err
	}

	ws.Status = core.WorkspaceStatus(status)
	return &ws, nil
}

func (r *Repo) WorkspaceSlugAvailable(ctx context.Context, slug string) (bool, error) {
	const q = `select 1 from workspaces where slug = $1 limit 1;`

	var one int
	err := r.db.Pool().QueryRow(ctx, q, slug).Scan(&one)
	if err == nil {
		return false, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	return false, err
}

func (r *Repo) GetWorkspaceByID(ctx context.Context, id uuid.UUID) (*core.Workspace, bool, error) {
	const q = `
select
  id,
  name,
  slug,
  status,
  created_at,
  created_by,
  google_oauth_client_id,
  cookie_domain,
  setup_checklist_dismissed_at,
  setup_test_email_sent_at
from workspaces
where id = $1
limit 1;
`

	ws, err := scanWorkspace(r.db.Pool().QueryRow(ctx, q, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}

	return ws, true, nil
}

func (r *Repo) GetWorkspaceBySlug(ctx context.Context, slug string) (*core.Workspace, bool, error) {
	const q = `
select
  id,
  name,
  slug,
  status,
  created_at,
  created_by,
  google_oauth_client_id,
  cookie_domain,
  setup_checklist_dismissed_at,
  setup_test_email_sent_at
from workspaces
where slug = $1
limit 1;
`

	ws, err := scanWorkspace(r.db.Pool().QueryRow(ctx, q, slug))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}

	return ws, true, nil
}

func (r *Repo) InsertWorkspace(ctx context.Context, ws *core.Workspace, tx pgx.Tx) error {
	const q = `
insert into workspaces (id, name, slug, created_by, google_oauth_client_id)
values ($1, $2, $3, $4, $5);
`
	_, err := tx.Exec(ctx, q, ws.ID, ws.Name, ws.Slug, ws.CreatedBy, ws.GoogleOAuthClientID)
	return err
}

func (r *Repo) UpdateWorkspace(ctx context.Context, ws *core.Workspace) error {
	const q = `update workspaces set name=$1, slug=$2, google_oauth_client_id=$3 where id=$4`
	_, err := r.db.Pool().Exec(ctx, q, ws.Name, ws.Slug, ws.GoogleOAuthClientID, ws.ID)
	return err
}

// MarkWorkspaceSetupChecklistDismissed records that the operator
// dismissed the first-boot setup checklist on the workspace home.
// Idempotent: re-dismissing leaves the original timestamp intact so we
// can show "you dismissed this on X" later if we ever want to.
func (r *Repo) MarkWorkspaceSetupChecklistDismissed(ctx context.Context, workspaceID uuid.UUID) error {
	const q = `
update workspaces
set setup_checklist_dismissed_at = coalesce(setup_checklist_dismissed_at, now())
where id = $1
`
	_, err := r.db.Pool().Exec(ctx, q, workspaceID)
	return err
}

// MarkWorkspaceTestEmailSent records that a test email through the
// workspace SMTP path completed without error. Same idempotency
// pattern — first success wins.
func (r *Repo) MarkWorkspaceTestEmailSent(ctx context.Context, workspaceID uuid.UUID) error {
	const q = `
update workspaces
set setup_test_email_sent_at = coalesce(setup_test_email_sent_at, now())
where id = $1
`
	_, err := r.db.Pool().Exec(ctx, q, workspaceID)
	return err
}

// UpdateWorkspaceCookieDomain sets the workspace-level session-cookie
// Domain attribute. Pass nil to clear (browser then scopes the
// cookie to the exact host that set it). Format / public-suffix
// validation is the caller's job.
func (r *Repo) UpdateWorkspaceCookieDomain(ctx context.Context, workspaceID uuid.UUID, cookieDomain *string) (*core.Workspace, error) {
	const q = `update workspaces set cookie_domain=$1 where id=$2`
	if _, err := r.db.Pool().Exec(ctx, q, cookieDomain, workspaceID); err != nil {
		return nil, err
	}
	ws, ok, err := r.GetWorkspaceByID(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotFound
	}
	return ws, nil
}

// GetWorkspacesByOwner returns all workspaces owned by the given account.
func (r *Repo) GetWorkspacesByOwner(ctx context.Context, ownerID uuid.UUID) ([]core.Workspace, error) {
	const q = `
select
  id,
  name,
  slug,
  status,
  created_at,
  created_by,
  google_oauth_client_id,
  cookie_domain,
  setup_checklist_dismissed_at,
  setup_test_email_sent_at
from workspaces
where created_by = $1
order by created_at desc;
`

	rows, err := r.db.Pool().Query(ctx, q, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	workspaces := make([]core.Workspace, 0)
	for rows.Next() {
		ws, err := scanWorkspace(rows)
		if err != nil {
			return nil, err
		}
		workspaces = append(workspaces, *ws)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return workspaces, nil
}
