package repo

import (
	"context"
	"errors"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------
// Workspace SMTP Config
// ---------------------------------------------

func (r *Repo) UpsertWorkspaceSMTPConfig(ctx context.Context, cfg core.WorkspaceSMTPConfig) error {
	const q = `
INSERT INTO workspace_smtp_config (
  workspace_id, enabled, host, port, username, password_encrypted,
  from_email, from_name, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now(), now())
ON CONFLICT (workspace_id) DO UPDATE SET
  enabled            = excluded.enabled,
  host               = excluded.host,
  port               = excluded.port,
  username           = excluded.username,
  password_encrypted = COALESCE(excluded.password_encrypted, workspace_smtp_config.password_encrypted),
  from_email         = excluded.from_email,
  from_name          = excluded.from_name,
  updated_at         = now()
`
	_, err := r.db.Pool().Exec(ctx, q,
		cfg.WorkspaceID,
		cfg.Enabled,
		cfg.Host,
		cfg.Port,
		cfg.Username,
		cfg.PasswordEncrypted, // nil means keep existing
		cfg.FromEmail,
		cfg.FromName,
	)
	return err
}

func (r *Repo) GetWorkspaceSMTPConfig(ctx context.Context, workspaceID uuid.UUID) (*core.WorkspaceSMTPConfig, bool, error) {
	const q = `
SELECT workspace_id, enabled, host, port, username, password_encrypted,
       from_email, from_name, created_at, updated_at
FROM workspace_smtp_config
WHERE workspace_id = $1
`
	row := r.db.Pool().QueryRow(ctx, q, workspaceID)

	var cfg core.WorkspaceSMTPConfig
	err := row.Scan(
		&cfg.WorkspaceID,
		&cfg.Enabled,
		&cfg.Host,
		&cfg.Port,
		&cfg.Username,
		&cfg.PasswordEncrypted,
		&cfg.FromEmail,
		&cfg.FromName,
		&cfg.CreatedAt,
		&cfg.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return &cfg, true, nil
}

func (r *Repo) DeleteWorkspaceSMTPConfig(ctx context.Context, workspaceID uuid.UUID) error {
	const q = `DELETE FROM workspace_smtp_config WHERE workspace_id = $1`
	_, err := r.db.Pool().Exec(ctx, q, workspaceID)
	return err
}
