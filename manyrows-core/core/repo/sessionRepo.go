package repo

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"manyrows-core/core"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

func (r *Repo) InsertSession(ctx context.Context, s *core.Session) error {
	if s.ID == uuid.Nil {
		return errors.New("session ID must be set")
	}
	const q = `
insert into sessions (
  id,
  account_id,
  created_at,
  expires_at,
  last_seen_at,
  token_id,
  token_secret_hash,
  token_prefix,
  user_agent,
  ip
) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10);
`

	_, err := r.db.Pool().Exec(
		ctx,
		q,
		s.ID,
		s.AccountID,
		s.CreatedAt,
		s.ExpiresAt,
		s.LastSeenAt,
		s.TokenID,
		s.TokenSecretHash,
		s.TokenPrefix,
		s.UserAgent,
		s.IP,
	)
	return err
}

func (r *Repo) DeleteSessionByToken(ctx context.Context, tokenId uuid.UUID) error {
	const q = `delete from sessions where token_id = $1;`
	if _, err := r.db.Pool().Exec(ctx, q, tokenId); err != nil {
		return err
	}
	return nil
}

// DeleteSessionsByAccount removes every admin session for the given account.
// Used after security-sensitive events (password reset, etc.) to evict any
// concurrent sessions that may have been hijacked.
// Returns the number of sessions deleted.
func (r *Repo) DeleteSessionsByAccount(ctx context.Context, accountID uuid.UUID) (int64, error) {
	const q = `delete from sessions where account_id = $1;`
	ct, err := r.db.Pool().Exec(ctx, q, accountID)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

func (r *Repo) GetSessionByToken(ctx context.Context, tok core.TokenClaims) (*core.Session, error) {
	const q = `
select
  id,
  account_id,
  created_at,
  expires_at,
  last_seen_at,
  token_id,
  token_secret_hash,
  token_prefix,
  user_agent,
  ip
from sessions
where token_id = $1
limit 1;
`

	var s core.Session
	err := r.db.Pool().QueryRow(ctx, q, tok.TokenID).Scan(
		&s.ID,
		&s.AccountID,
		&s.CreatedAt,
		&s.ExpiresAt,
		&s.LastSeenAt,
		&s.TokenID,
		&s.TokenSecretHash,
		&s.TokenPrefix,
		&s.UserAgent,
		&s.IP,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, core.ErrSessionNotFound
		}
		return nil, err
	}

	now := time.Now()
	if !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt) {
		return nil, core.ErrSessionExpired
	}

	if len(tok.Secret) == 0 || len(s.TokenSecretHash) == 0 {
		return nil, core.ErrSessionInvalid
	}
	sum := sha256.Sum256(tok.Secret)
	if subtle.ConstantTimeCompare(sum[:], s.TokenSecretHash) != 1 {
		return nil, core.ErrSessionInvalid
	}
	return &s, nil
}

// TouchSessionLastSeen updates a session's last_seen_at to now().
// Returns (ok=false, nil) if the session doesn't exist.
func (r *Repo) TouchSessionLastSeen(ctx context.Context, sessionID uuid.UUID) (bool, error) {
	const q = `
update sessions
set last_seen_at = now()
where id = $1;
`
	ct, err := r.db.Pool().Exec(ctx, q, sessionID)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

// TouchSessionLastSeenByToken updates last_seen_at to now() by token_id.
// Useful if you only have claims.TokenID at middleware time.
// Returns (ok=false, nil) if no session matches that token.
func (r *Repo) TouchSessionLastSeenByToken(ctx context.Context, tokenID uuid.UUID) (bool, error) {
	const q = `
update sessions
set last_seen_at = now()
where token_id = $1;
`
	ct, err := r.db.Pool().Exec(ctx, q, tokenID)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}
