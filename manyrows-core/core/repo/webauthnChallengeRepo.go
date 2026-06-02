package repo

import (
	"context"
	"errors"
	"fmt"
	"manyrows-core/core"
	"manyrows-core/utils"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// InsertWebAuthnChallenge persists the in-flight ceremony state returned
// from a /begin call so the matching /finish call can verify the assertion.
// Caller sets ExpiresAt — typically now()+5min, since real users complete
// a passkey ceremony in seconds.
func (r *Repo) InsertWebAuthnChallenge(ctx context.Context, c core.WebAuthnChallenge) (core.WebAuthnChallenge, error) {
	if c.ID == uuid.Nil {
		c.ID = utils.NewUUID()
	}
	if c.AppID == uuid.Nil || len(c.Challenge) == 0 || len(c.SessionData) == 0 {
		return core.WebAuthnChallenge{}, errors.New("InsertWebAuthnChallenge: missing required field")
	}
	if c.Purpose != core.WebAuthnChallengePurposeRegister && c.Purpose != core.WebAuthnChallengePurposeLogin {
		return core.WebAuthnChallenge{}, errors.New("InsertWebAuthnChallenge: invalid purpose")
	}
	if c.ExpiresAt.IsZero() {
		return core.WebAuthnChallenge{}, errors.New("InsertWebAuthnChallenge: ExpiresAt required")
	}

	const q = `
		INSERT INTO webauthn_challenges (id, app_id, user_id, purpose, challenge, session_data, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now())
		RETURNING id, created_at
	`
	if err := r.db.Pool().QueryRow(ctx, q,
		c.ID, c.AppID, c.UserID, string(c.Purpose), c.Challenge, c.SessionData, c.ExpiresAt,
	).Scan(&c.ID, &c.CreatedAt); err != nil {
		return core.WebAuthnChallenge{}, fmt.Errorf("InsertWebAuthnChallenge: %w", err)
	}
	return c, nil
}

// ConsumeWebAuthnChallenge atomically deletes and returns a challenge by id.
// Returns (challenge, true, nil) on hit; (zero, false, nil) if missing or
// expired (delete is unconditional but the expires_at check filters out
// stale rows). One-shot semantics prevent /finish replay — the row is gone
// after the first successful consume.
func (r *Repo) ConsumeWebAuthnChallenge(ctx context.Context, id uuid.UUID) (core.WebAuthnChallenge, bool, error) {
	const q = `
		DELETE FROM webauthn_challenges
		WHERE id = $1 AND expires_at > now()
		RETURNING id, app_id, user_id, purpose, challenge, session_data, expires_at, created_at
	`
	var c core.WebAuthnChallenge
	var purpose string
	var userID *uuid.UUID
	if err := r.db.Pool().QueryRow(ctx, q, id).Scan(
		&c.ID, &c.AppID, &userID, &purpose, &c.Challenge, &c.SessionData, &c.ExpiresAt, &c.CreatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.WebAuthnChallenge{}, false, nil
		}
		return core.WebAuthnChallenge{}, false, fmt.Errorf("ConsumeWebAuthnChallenge: %w", err)
	}
	c.UserID = userID
	c.Purpose = core.WebAuthnChallengePurpose(purpose)
	return c, true, nil
}

// DeleteExpiredWebAuthnChallenges sweeps stale ceremony rows. Pair with the
// same periodic cleanup goroutine that runs DeleteExpiredDPopReplay.
func (r *Repo) DeleteExpiredWebAuthnChallenges(ctx context.Context, now time.Time) (int64, error) {
	const q = `DELETE FROM webauthn_challenges WHERE expires_at < $1`
	tag, err := r.db.Pool().Exec(ctx, q, now)
	if err != nil {
		return 0, fmt.Errorf("DeleteExpiredWebAuthnChallenges: %w", err)
	}
	return tag.RowsAffected(), nil
}
