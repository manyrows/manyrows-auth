package repo

import (
	"context"
	"errors"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// ConsumeAPIKeyToken applies one token-bucket decrement for the given API
// key and reports whether the request is within budget. Bucket state lives
// in Postgres (not process memory) so the budget is shared across all
// replicas. capacity is the max/burst size; refillPerSec is how many tokens
// accrue per second.
//
// The refill-and-spend is a single statement so concurrent requests — even
// from different replicas — can't double-spend: the ON CONFLICT branch reads
// the existing row under its row lock, refills from elapsed time (capped at
// capacity), and the WHERE guard only lets the decrement happen when at
// least one token is available. A first request for a key inserts a full
// bucket and spends one; an empty bucket makes the upsert a no-op (no row
// returned via pgx.ErrNoRows) and the request is rejected.
func (r *Repo) ConsumeAPIKeyToken(ctx context.Context, keyID uuid.UUID, capacity, refillPerSec float64) (bool, error) {
	const q = `
insert into api_key_rate_limits as rl (api_key_id, tokens, last_refill)
values ($1, $2 - 1, now())
on conflict (api_key_id) do update
set tokens = least($2, rl.tokens + extract(epoch from (now() - rl.last_refill)) * $3) - 1,
    last_refill = now()
where least($2, rl.tokens + extract(epoch from (now() - rl.last_refill)) * $3) >= 1
returning tokens;
`
	var tokens float64
	err := r.db.Pool().QueryRow(ctx, q, keyID, capacity, refillPerSec).Scan(&tokens)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// WHERE guard failed: bucket empty, no state change → rejected.
			return false, nil
		}
		return false, err
	}
	return true, nil
}
