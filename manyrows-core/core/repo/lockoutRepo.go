package repo

import (
	"context"
	"time"

	"github.com/gofrs/uuid/v5"
)

func (r *Repo) SetAccountLockedUntil(ctx context.Context, accountID uuid.UUID, lockedUntil time.Time) error {
	const q = `UPDATE accounts SET locked_until = $2 WHERE id = $1;`
	return r.execAffectingOne(ctx, ErrNotFound, q, accountID, lockedUntil)
}

func (r *Repo) ClearAccountLockedUntil(ctx context.Context, accountID uuid.UUID) error {
	const q = `UPDATE accounts SET locked_until = NULL WHERE id = $1;`
	return r.execAffectingOne(ctx, ErrNotFound, q, accountID)
}

func (r *Repo) SetUserLockedUntil(ctx context.Context, userID uuid.UUID, lockedUntil time.Time) error {
	const q = `UPDATE users SET locked_until = $2 WHERE id = $1;`
	return r.execAffectingOne(ctx, ErrNotFound, q, userID, lockedUntil)
}

func (r *Repo) ClearUserLockedUntil(ctx context.Context, userID uuid.UUID) error {
	const q = `UPDATE users SET locked_until = NULL WHERE id = $1;`
	return r.execAffectingOne(ctx, ErrNotFound, q, userID)
}
