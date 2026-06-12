package repo

import (
	"context"
	"errors"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// ErrAccountDeleteRequestNotFound is returned when no pending delete
// request exists for the user.
var ErrAccountDeleteRequestNotFound = errors.New("account delete request not found")

// AccountDeleteRequest is a pending passwordless-deletion confirmation.
type AccountDeleteRequest struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	AppID     uuid.UUID
	CodeHash  string
	Attempts  int
	ExpiresAt time.Time
	CreatedAt time.Time
}

func (r *AccountDeleteRequest) IsActive(now time.Time) bool {
	return now.Before(r.ExpiresAt)
}

// UpsertAccountDeleteRequest creates or replaces the pending request for a
// user. One pending request per user; a re-request rotates id + hash so old
// codes stop matching.
func (r *Repo) UpsertAccountDeleteRequest(
	ctx context.Context,
	id, userID, appID uuid.UUID,
	codeHash string,
	expiresAt time.Time,
) error {
	const q = `
INSERT INTO account_delete_requests (id, user_id, app_id, code_hash, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, now())
ON CONFLICT (user_id) DO UPDATE SET
  id = EXCLUDED.id,
  app_id = EXCLUDED.app_id,
  code_hash = EXCLUDED.code_hash,
  attempts = 0,
  expires_at = EXCLUDED.expires_at,
  created_at = now();
`
	_, err := r.db.Pool().Exec(ctx, q, id, userID, appID, codeHash, expiresAt)
	return err
}

// GetAccountDeleteRequest returns the pending request for a user, or
// ErrAccountDeleteRequestNotFound.
func (r *Repo) GetAccountDeleteRequest(ctx context.Context, userID uuid.UUID) (*AccountDeleteRequest, error) {
	const q = `
SELECT id, user_id, app_id, code_hash, attempts, expires_at, created_at
FROM account_delete_requests
WHERE user_id = $1
LIMIT 1;
`
	var req AccountDeleteRequest
	err := r.db.Pool().QueryRow(ctx, q, userID).Scan(
		&req.ID, &req.UserID, &req.AppID, &req.CodeHash, &req.Attempts, &req.ExpiresAt, &req.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAccountDeleteRequestNotFound
		}
		return nil, err
	}
	return &req, nil
}

// IncrementAccountDeleteRequestAttempts bumps the attempt counter and
// returns the new count.
func (r *Repo) IncrementAccountDeleteRequestAttempts(ctx context.Context, userID uuid.UUID) (int, error) {
	const q = `
UPDATE account_delete_requests
SET attempts = attempts + 1
WHERE user_id = $1
RETURNING attempts;
`
	var attempts int
	err := r.db.Pool().QueryRow(ctx, q, userID).Scan(&attempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrAccountDeleteRequestNotFound
		}
		return 0, err
	}
	return attempts, nil
}

// DeleteAccountDeleteRequest removes the pending request for a user.
func (r *Repo) DeleteAccountDeleteRequest(ctx context.Context, userID uuid.UUID) error {
	const q = `DELETE FROM account_delete_requests WHERE user_id = $1;`
	_, err := r.db.Pool().Exec(ctx, q, userID)
	return err
}

// ConsumeAccountDeleteRequest atomically deletes the request iff (user_id,id)
// match. Reports whether a row was consumed (single-use guard).
func (r *Repo) ConsumeAccountDeleteRequest(ctx context.Context, userID, requestID uuid.UUID) (bool, error) {
	const q = `DELETE FROM account_delete_requests WHERE user_id = $1 AND id = $2;`
	tag, err := r.db.Pool().Exec(ctx, q, userID, requestID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}