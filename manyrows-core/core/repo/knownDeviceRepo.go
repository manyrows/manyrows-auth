package repo

import (
	"context"
	"fmt"

	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
)

// UpsertKnownDevice records that (userID, appID) signed in from the device
// identified by uaHash, refreshing last_seen_at / last_ip / user_agent on a
// repeat sighting. It returns:
//
//   - wasNew: true if this device had never been seen for the account+app
//     before (an INSERT, not an UPDATE).
//   - priorCount: how many devices the account already had for this app
//     before this call.
//
// Callers combine the two — alert only when wasNew && priorCount > 0 — so a
// user's very first device (and the first login after the feature ships)
// doesn't raise a "new device" alert. The count and upsert run in one
// transaction so a single login sees a consistent snapshot.
func (r *Repo) UpsertKnownDevice(ctx context.Context, userID, appID uuid.UUID, uaHash, userAgent, ip string) (wasNew bool, priorCount int, err error) {
	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return false, 0, fmt.Errorf("UpsertKnownDevice begin: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM client_known_devices WHERE user_id = $1 AND app_id = $2`,
		userID, appID).Scan(&priorCount); err != nil {
		return false, 0, fmt.Errorf("UpsertKnownDevice count: %w", err)
	}

	// xmax = 0 on the affected row means it was freshly INSERTed; a non-zero
	// xmax means the ON CONFLICT path UPDATEd an existing row.
	if err := tx.QueryRow(ctx, `
INSERT INTO client_known_devices (id, user_id, app_id, ua_hash, user_agent, last_ip)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (user_id, app_id, ua_hash)
DO UPDATE SET last_seen_at = now(), last_ip = excluded.last_ip, user_agent = excluded.user_agent
RETURNING (xmax = 0)`,
		utils.NewUUID(), userID, appID, uaHash, userAgent, ip).Scan(&wasNew); err != nil {
		return false, 0, fmt.Errorf("UpsertKnownDevice upsert: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return false, 0, fmt.Errorf("UpsertKnownDevice commit: %w", err)
	}
	return wasNew, priorCount, nil
}
