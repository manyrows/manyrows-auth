package repo

import (
	"context"
	"encoding/json"
	"errors"
	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
)

func (r *Repo) GetWorkspaceEncryptionKey(ctx context.Context, workspaceID uuid.UUID) (*core.WorkspaceEncryptionKey, error) {
	const q = `
select
  id,
  workspace_id,
  public_key_jwk,
  fingerprint,
  created_at,
  created_by
from workspace_encryption_keys
where workspace_id = $1
limit 1
`

	row := r.db.Pool().QueryRow(ctx, q, workspaceID)

	var key core.WorkspaceEncryptionKey
	var publicJWK json.RawMessage

	if err := row.Scan(
		&key.ID,
		&key.WorkspaceID,
		&publicJWK,
		&key.Fingerprint,
		&key.CreatedAt,
		&key.CreatedBy,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Ensure we preserve the exact JSON bytes as stored.
	key.PublicKeyJWK = publicJWK

	return &key, nil
}

func (r *Repo) UpsertWorkspaceEncryptionKey(ctx context.Context, key core.WorkspaceEncryptionKey) error {
	// We overwrite on conflict so "rotation" is just calling this again.
	// Important: created_at/by reflect the most recent set/rotation.
	const q = `
insert into workspace_encryption_keys (
  id,
  workspace_id,
  public_key_jwk,
  fingerprint,
  created_at,
  created_by
) values (
  $1, $2, $3, $4, $5, $6
)
on conflict (workspace_id) do update set
  id = excluded.id,
  public_key_jwk = excluded.public_key_jwk,
  fingerprint = excluded.fingerprint,
  created_at = excluded.created_at,
  created_by = excluded.created_by
`

	_, err := r.db.Pool().Exec(ctx, q,
		key.ID,
		key.WorkspaceID,
		key.PublicKeyJWK,
		key.Fingerprint,
		key.CreatedAt,
		key.CreatedBy,
	)
	if err != nil {
		log.Error().
			Err(err).
			Str("workspaceId", key.WorkspaceID.String()).
			Msg("repo: upsert workspace encryption key failed")
		return err
	}

	return nil
}
