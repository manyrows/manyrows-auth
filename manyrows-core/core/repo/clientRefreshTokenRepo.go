package repo

import (
	"context"
	"errors"
	"manyrows-core/core"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

var (
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
)

// InsertClientRefreshToken inserts a new refresh token row.
func (r *Repo) InsertClientRefreshToken(ctx context.Context, rt *core.ClientRefreshToken) error {
	if rt == nil {
		return errors.New("refresh token is nil")
	}
	if rt.ID == uuid.Nil {
		return errors.New("refresh token ID must be set")
	}
	if rt.SessionID == uuid.Nil {
		return errors.New("session_id must be set")
	}
	if rt.TokenHash == "" {
		return errors.New("token_hash must be set")
	}

	const q = `
insert into client_refresh_tokens (
  id,
  session_id,
  token_hash,
  created_at,
  expires_at,
  user_agent,
  ip,
  dpop_jkt
) values ($1,$2,$3,$4,$5,$6,$7, nullif($8, ''));
`
	_, err := r.db.Pool().Exec(
		ctx,
		q,
		rt.ID,
		rt.SessionID,
		rt.TokenHash,
		rt.CreatedAt,
		rt.ExpiresAt,
		rt.UserAgent,
		rt.IP,
		rt.DPopJKT,
	)
	return err
}

// GetClientRefreshTokenByHash loads a refresh token by its hash.
func (r *Repo) GetClientRefreshTokenByHash(ctx context.Context, tokenHash string) (*core.ClientRefreshToken, error) {
	if tokenHash == "" {
		return nil, ErrRefreshTokenNotFound
	}

	const q = `
select
  id,
  session_id,
  token_hash,
  created_at,
  expires_at,
  rotated_at,
  revoked_at,
  replaced_by_id,
  user_agent,
  ip,
  coalesce(dpop_jkt, '')
from client_refresh_tokens
where token_hash = $1
limit 1;
`

	var rt core.ClientRefreshToken
	err := r.db.Pool().QueryRow(ctx, q, tokenHash).Scan(
		&rt.ID,
		&rt.SessionID,
		&rt.TokenHash,
		&rt.CreatedAt,
		&rt.ExpiresAt,
		&rt.RotatedAt,
		&rt.RevokedAt,
		&rt.ReplacedByID,
		&rt.UserAgent,
		&rt.IP,
		&rt.DPopJKT,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, err
	}

	return &rt, nil
}

// RotateRefreshToken marks a refresh token as rotated and sets its replacement.
func (r *Repo) RotateRefreshToken(ctx context.Context, oldID, newID uuid.UUID, rotatedAt time.Time) error {
	if oldID == uuid.Nil || newID == uuid.Nil {
		return errors.New("both oldID and newID must be set")
	}

	const q = `
update client_refresh_tokens
set rotated_at = $2, replaced_by_id = $3
where id = $1 and rotated_at is null and revoked_at is null;
`
	ct, err := r.db.Pool().Exec(ctx, q, oldID, rotatedAt, newID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errors.New("token already rotated or revoked")
	}
	return nil
}

// MarkRefreshTokenRotated marks a token as rotated without specifying a replacement yet.
// Used to atomically claim the token before issuing new tokens (prevents race conditions).
func (r *Repo) MarkRefreshTokenRotated(ctx context.Context, tokenID uuid.UUID, rotatedAt time.Time) error {
	const q = `
update client_refresh_tokens
set rotated_at = $2
where id = $1 and rotated_at is null and revoked_at is null;
`
	ct, err := r.db.Pool().Exec(ctx, q, tokenID, rotatedAt)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errors.New("token already rotated or revoked")
	}
	return nil
}

// UpdateRotatedRefreshTokenReplacement sets the replaced_by_id on an already-rotated token.
func (r *Repo) UpdateRotatedRefreshTokenReplacement(ctx context.Context, oldID, newID uuid.UUID) error {
	const q = `update client_refresh_tokens set replaced_by_id = $2 where id = $1;`
	_, err := r.db.Pool().Exec(ctx, q, oldID, newID)
	return err
}

// RevokeClientRefreshToken marks a refresh token as revoked by hash.
func (r *Repo) RevokeClientRefreshToken(ctx context.Context, tokenHash string, revokedAt time.Time) error {
	if tokenHash == "" {
		return nil
	}

	const q = `
update client_refresh_tokens
set revoked_at = $2
where token_hash = $1 and revoked_at is null;
`
	_, err := r.db.Pool().Exec(ctx, q, tokenHash, revokedAt)
	return err
}

// RevokeAllRefreshTokensForSession revokes all refresh tokens for a session.
func (r *Repo) RevokeAllRefreshTokensForSession(ctx context.Context, sessionID uuid.UUID, revokedAt time.Time) error {
	if sessionID == uuid.Nil {
		return nil
	}

	const q = `
update client_refresh_tokens
set revoked_at = $2
where session_id = $1 and revoked_at is null;
`
	_, err := r.db.Pool().Exec(ctx, q, sessionID, revokedAt)
	return err
}

// DeleteClientRefreshToken hard-deletes a refresh token by ID.
func (r *Repo) DeleteClientRefreshToken(ctx context.Context, id uuid.UUID) error {
	if id == uuid.Nil {
		return nil
	}
	const q = `delete from client_refresh_tokens where id = $1;`
	_, err := r.db.Pool().Exec(ctx, q, id)
	return err
}
