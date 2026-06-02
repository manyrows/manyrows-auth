package repo

import (
	"context"
	"errors"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

var ErrEmailChangeRequestNotFound = errors.New("email change request not found")

// EmailChangeRequest represents a pending email change for an app user.
type EmailChangeRequest struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	AppID     uuid.UUID
	NewEmail  string
	CodeHash  string
	ExpiresAt time.Time
	Attempts  int
	CreatedAt time.Time
}

// IsActive returns true if the request has not expired.
func (r *EmailChangeRequest) IsActive(now time.Time) bool {
	return now.Before(r.ExpiresAt)
}

// UpsertEmailChangeRequest creates or replaces the pending email change request for a user.
func (r *Repo) UpsertEmailChangeRequest(
	ctx context.Context,
	id, userID, appID uuid.UUID,
	newEmail, codeHash string,
	expiresAt time.Time,
) error {
	const q = `
INSERT INTO email_change_requests (id, user_id, app_id, new_email, code_hash, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, now())
ON CONFLICT (user_id) DO UPDATE SET
  id = EXCLUDED.id,
  app_id = EXCLUDED.app_id,
  new_email = EXCLUDED.new_email,
  code_hash = EXCLUDED.code_hash,
  expires_at = EXCLUDED.expires_at,
  created_at = now();
`
	_, err := r.db.Pool().Exec(ctx, q, id, userID, appID, newEmail, codeHash, expiresAt)
	return err
}

// GetEmailChangeRequest returns the pending email change request for a user.
func (r *Repo) GetEmailChangeRequest(ctx context.Context, userID uuid.UUID) (*EmailChangeRequest, error) {
	const q = `
SELECT id, user_id, app_id, new_email, code_hash, expires_at, attempts, created_at
FROM email_change_requests
WHERE user_id = $1
LIMIT 1;
`
	var req EmailChangeRequest
	err := r.db.Pool().QueryRow(ctx, q, userID).Scan(
		&req.ID, &req.UserID, &req.AppID,
		&req.NewEmail, &req.CodeHash, &req.ExpiresAt, &req.Attempts, &req.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrEmailChangeRequestNotFound
		}
		return nil, err
	}
	return &req, nil
}

// IncrementEmailChangeRequestAttempts bumps the per-request wrong-guess
// counter and returns the new value. Returns ErrEmailChangeRequestNotFound
// if the row was already deleted (e.g. expired sweep).
func (r *Repo) IncrementEmailChangeRequestAttempts(ctx context.Context, userID uuid.UUID) (int, error) {
	const q = `
UPDATE email_change_requests
SET attempts = attempts + 1
WHERE user_id = $1
RETURNING attempts;
`
	var attempts int
	err := r.db.Pool().QueryRow(ctx, q, userID).Scan(&attempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrEmailChangeRequestNotFound
		}
		return 0, err
	}
	return attempts, nil
}

// DeleteEmailChangeRequest removes the pending email change request for a user.
func (r *Repo) DeleteEmailChangeRequest(ctx context.Context, userID uuid.UUID) error {
	const q = `DELETE FROM email_change_requests WHERE user_id = $1;`
	_, err := r.db.Pool().Exec(ctx, q, userID)
	return err
}

// ConsumeEmailChangeRequest atomically deletes the request matching
// (user_id, id), reporting whether a row was deleted. Used by the
// verify handler to claim the OTP atomically: if two concurrent
// verifies pass the hash compare, only one wins this delete and
// proceeds with the email update; the other gets ok=false and
// surfaces an invalidCode error to the caller.
func (r *Repo) ConsumeEmailChangeRequest(ctx context.Context, userID, requestID uuid.UUID) (bool, error) {
	const q = `DELETE FROM email_change_requests WHERE user_id = $1 AND id = $2;`
	tag, err := r.db.Pool().Exec(ctx, q, userID, requestID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// UpdateUserEmail updates the user's email AND marks it as verified —
// only called from ClientVerifyEmailChange, which already proved the
// user controls the new address by confirming an OTP sent to it. The
// previous behaviour cleared email_verified_at to NULL, which left
// the user unable to log in afterwards ("email not verified") even
// though they'd literally just verified the new address.
func (r *Repo) UpdateUserEmail(ctx context.Context, userID uuid.UUID, newEmail string) error {
	const q = `UPDATE users SET email = $1, email_verified_at = now(), updated_at = now() WHERE id = $2`
	_, err := r.db.Pool().Exec(ctx, q, newEmail, userID)
	return err
}
