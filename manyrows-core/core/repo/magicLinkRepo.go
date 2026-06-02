package repo

import (
	"context"
	"errors"
	"fmt"
	"manyrows-core/core"
	"manyrows-core/utils"
	"time"

	"github.com/jackc/pgx/v5"
)

type CreateMagicLinkParams struct {
	Purpose   string
	Email     string
	TokenHash string
	ExpiresAt time.Time
}

func (r *Repo) CreateMagicLink(ctx context.Context, p CreateMagicLinkParams) error {
	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("CreateMagicLink begin: %w", err)
	}
	defer tx.Rollback(ctx)

	// Optional cleanup: remove old unused links for same email+purpose
	_, err = tx.Exec(ctx, `
		delete from magic_links
		where purpose = $1
		  and lower(email) = lower($2)
	`, p.Purpose, p.Email)
	if err != nil {
		return fmt.Errorf("CreateMagicLink cleanup: %w", err)
	}

	_, err = tx.Exec(ctx, `
		insert into magic_links (purpose, email, token_hash, expires_at, id)
		values ($1, $2, $3, $4, $5)
	`, p.Purpose, p.Email, p.TokenHash, p.ExpiresAt, utils.NewUUID())
	if err != nil {
		return fmt.Errorf("CreateMagicLink insert: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("CreateMagicLink commit: %w", err)
	}
	return nil
}

// ConsumeMagicLink atomically selects a valid magic link and marks it as used
// within a single transaction, preventing TOCTOU race conditions.
func (r *Repo) ConsumeMagicLink(ctx context.Context, tokenHash string) (*core.MagicLink, bool, error) {
	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("ConsumeMagicLink begin: %w", err)
	}
	defer tx.Rollback(ctx)

	const selectQ = `
		select id, purpose, email, expires_at, used_at
		from magic_links
		where token_hash = $1
		  and used_at is null
		  and expires_at > now()
		for update
	`
	var ml core.MagicLink
	var usedAt *time.Time
	if err := tx.QueryRow(ctx, selectQ, tokenHash).Scan(&ml.ID, &ml.Purpose, &ml.Email, &ml.ExpiresAt, &usedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("ConsumeMagicLink select: %w", err)
	}
	ml.UsedAt = usedAt

	const updateQ = `update magic_links set used_at = now() where id = $1 and used_at is null`
	ct, err := tx.Exec(ctx, updateQ, ml.ID)
	if err != nil {
		return nil, false, fmt.Errorf("ConsumeMagicLink update: %w", err)
	}
	if ct.RowsAffected() == 0 {
		// Race: already consumed between SELECT and UPDATE (shouldn't happen with FOR UPDATE, but be safe)
		return nil, false, nil
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("ConsumeMagicLink commit: %w", err)
	}
	return &ml, true, nil
}

// LatestUnusedMagicLink returns the most recent unused, unexpired
// magic link for the given purpose+email — the caller uses it to apply
// a "resend cooldown" so a user mashing the request button doesn't
// generate N emails. Returns (nil, zero time, nil) when no matching
// row exists. Mirrors GetLatestUnusedClientOTP for the OTP flow.
func (r *Repo) LatestUnusedMagicLink(ctx context.Context, purpose, email string) (*core.MagicLink, time.Time, error) {
	const q = `
		select id, purpose, email, expires_at, used_at, created_at
		from magic_links
		where purpose = $1
		  and lower(email) = lower($2)
		  and used_at is null
		  and expires_at > now()
		order by created_at desc
		limit 1
	`
	var ml core.MagicLink
	var usedAt *time.Time
	var createdAt time.Time
	err := r.db.Pool().QueryRow(ctx, q, purpose, email).Scan(&ml.ID, &ml.Purpose, &ml.Email, &ml.ExpiresAt, &usedAt, &createdAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, time.Time{}, nil
		}
		return nil, time.Time{}, err
	}
	ml.UsedAt = usedAt
	return &ml, createdAt, nil
}
