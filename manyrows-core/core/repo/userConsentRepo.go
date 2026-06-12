package repo

import (
	"context"
	"errors"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// InsertUserConsent records an acceptance event. ip may be "" (stored NULL).
func (r *Repo) InsertUserConsent(ctx context.Context, id, userID, appID uuid.UUID, kind, version, ip, userAgent string) error {
	const q = `
INSERT INTO user_consents (id, user_id, app_id, kind, version, ip, user_agent)
VALUES ($1, $2, $3, $4, $5, NULLIF($6,'')::inet, $7);`
	_, err := r.db.Pool().Exec(ctx, q, id, userID, appID, kind, version, ip, userAgent)
	return err
}

// GetLatestUserConsent returns the most recent acceptance of kind for (user,app),
// or (nil, nil) when none exists.
func (r *Repo) GetLatestUserConsent(ctx context.Context, userID, appID uuid.UUID, kind string) (*core.UserConsent, error) {
	const q = `
SELECT id, user_id, app_id, kind, version, COALESCE(host(ip), ''), COALESCE(user_agent,''), accepted_at
FROM user_consents
WHERE user_id=$1 AND app_id=$2 AND kind=$3
ORDER BY accepted_at DESC
LIMIT 1;`
	var c core.UserConsent
	err := r.db.Pool().QueryRow(ctx, q, userID, appID, kind).Scan(
		&c.ID, &c.UserID, &c.AppID, &c.Kind, &c.Version, &c.IP, &c.UserAgent, &c.AcceptedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &c, nil
}
