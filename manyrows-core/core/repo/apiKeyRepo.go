package repo

import (
	"context"
	"errors"
	"fmt"
	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

func (r *Repo) InsertAPIKey(ctx context.Context, key *core.APIKey) error {
	const q = `
		insert into api_keys (
			id,
			workspace_id,
			app_id,
			name,
			prefix,
			hash,
			created_at,
			created_by
		) values (
			$1, $2, $3, $4, $5, $6, $7, $8
		)
	`

	_, err := r.db.Pool().Exec(
		ctx,
		q,
		key.ID,
		key.WorkspaceID,
		key.AppID,
		key.Name,
		key.Prefix,
		key.Hash,
		key.CreatedAt,
		key.CreatedBy,
	)

	return err
}

func (r *Repo) UpdateAPIKeyName(ctx context.Context, workspaceID, keyID uuid.UUID, name string) error {
	const q = `
		update api_keys set name = $1
		where id = $2
		  and workspace_id = $3
	`

	_, err := r.db.Pool().Exec(ctx, q, name, keyID, workspaceID)
	return err
}

func (r *Repo) DeleteAPIKey(
	ctx context.Context,
	workspaceID uuid.UUID,
	keyID uuid.UUID,
) error {
	const q = `
		delete from api_keys
		where id = $1
		  and workspace_id = $2
	`

	_, err := r.db.Pool().Exec(ctx, q, keyID, workspaceID)
	return err
}

func (r *Repo) GetAPIKey(
	ctx context.Context,
	workspaceID uuid.UUID,
	keyID uuid.UUID,
) (*core.APIKey, error) {
	const q = `
		select
			id,
			workspace_id,
			app_id,
			name,
			prefix,
			hash,
			created_at,
			created_by,
			last_used_at
		from api_keys
		where id = $1
		  and workspace_id = $2
	`

	row := r.db.Pool().QueryRow(ctx, q, keyID, workspaceID)

	var key core.APIKey
	if err := scanAPIKey(row, &key); err != nil {
		return nil, err
	}

	return &key, nil
}

func (r *Repo) GetAPIKeys(
	ctx context.Context,
	workspaceID uuid.UUID,
) ([]core.APIKey, error) {
	const q = `
		select
			id,
			workspace_id,
			app_id,
			name,
			prefix,
			hash,
			created_at,
			created_by,
			last_used_at
		from api_keys
		where workspace_id = $1
		order by created_at desc
	`

	rows, err := r.db.Pool().Query(ctx, q, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]core.APIKey, 0)
	for rows.Next() {
		var key core.APIKey
		if err := scanAPIKey(rows, &key); err != nil {
			return nil, err
		}
		out = append(out, key)
	}

	return out, rows.Err()
}

func (r *Repo) GetAPIKeysForApp(
	ctx context.Context,
	workspaceID uuid.UUID,
	appID uuid.UUID,
) ([]core.APIKey, error) {
	const q = `
		select
			id,
			workspace_id,
			app_id,
			name,
			prefix,
			hash,
			created_at,
			created_by,
			last_used_at
		from api_keys
		where workspace_id = $1
		  and app_id = $2
		order by created_at desc
	`

	rows, err := r.db.Pool().Query(ctx, q, workspaceID, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]core.APIKey, 0)
	for rows.Next() {
		var key core.APIKey
		if err := scanAPIKey(rows, &key); err != nil {
			return nil, err
		}
		out = append(out, key)
	}

	return out, rows.Err()
}

func (r *Repo) CountAPIKeysForApp(ctx context.Context, workspaceID, appID uuid.UUID) (int, error) {
	const q = `
		select count(*)
		from api_keys
		where workspace_id = $1
		  and app_id = $2
	`

	var count int
	if err := r.db.Pool().QueryRow(ctx, q, workspaceID, appID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count api keys for app: %w", err)
	}

	return count, nil
}

// ---- helpers ----

type apiKeyScanner interface {
	Scan(dest ...any) error
}

func scanAPIKey(s apiKeyScanner, key *core.APIKey) error {
	return s.Scan(
		&key.ID,
		&key.WorkspaceID,
		&key.AppID,
		&key.Name,
		&key.Prefix,
		&key.Hash,
		&key.CreatedAt,
		&key.CreatedBy,
		&key.LastUsedAt,
	)
}

func (r *Repo) CountAPIKeysForWorkspace(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	const q = `
		select count(*)
		from api_keys
		where workspace_id = $1
	`

	var count int
	if err := r.db.Pool().QueryRow(ctx, q, workspaceID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count api keys: %w", err)
	}

	return count, nil
}

func (r *Repo) GetAPIKeyByPrefix(
	ctx context.Context,
	workspaceID uuid.UUID,
	prefix string,
) (*core.APIKey, bool, error) {
	const q = `
    select
      id,
      workspace_id,
      app_id,
      name,
      prefix,
      hash,
      created_at,
      created_by,
      last_used_at
    from api_keys
    where workspace_id = $1
      and prefix = $2
    limit 1
  `

	row := r.db.Pool().QueryRow(ctx, q, workspaceID, prefix)

	var key core.APIKey
	if err := scanAPIKey(row, &key); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("get api key by prefix: %w", err)
	}

	return &key, true, nil
}

// TouchAPIKeyLastUsed records that a key was just used. The WHERE clause
// throttles writes to at most once per minute per key, so a hot key under
// heavy traffic doesn't generate a row update on every request. Best-effort:
// callers should log and ignore errors rather than failing the request.
func (r *Repo) TouchAPIKeyLastUsed(ctx context.Context, keyID uuid.UUID) error {
	const q = `
		update api_keys
		set last_used_at = now()
		where id = $1
		  and (last_used_at is null or last_used_at < now() - interval '1 minute')
	`

	_, err := r.db.Pool().Exec(ctx, q, keyID)
	return err
}
