package repo

import (
	"context"
	"fmt"
	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
)

// InsertCorsOrigin inserts a CORS origin row (scoped to an app).
func (r *Repo) InsertCorsOrigin(ctx context.Context, origin core.CorsOrigin) error {
	const q = `
		insert into app_cors_origins (
			id,
			app_id,
			origin,
			created_at
		) values (
			$1, $2, $3, $4
		)
	`
	_, err := r.db.Pool().Exec(ctx, q, origin.ID, origin.AppID, origin.Origin, origin.CreatedAt)
	return err
}

// InsertCorsOriginWithLimit atomically inserts a CORS origin only if the app has fewer than maxLimit origins.
func (r *Repo) InsertCorsOriginWithLimit(ctx context.Context, origin core.CorsOrigin, maxLimit int) (bool, error) {
	const q = `
		INSERT INTO app_cors_origins (id, app_id, origin, created_at)
		SELECT $1, $2, $3, $4
		WHERE (SELECT count(*) FROM app_cors_origins WHERE app_id = $2) < $5
	`
	tag, err := r.db.Pool().Exec(ctx, q, origin.ID, origin.AppID, origin.Origin, origin.CreatedAt, maxLimit)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// DeleteCorsOrigin deletes a CORS origin by id within an app.
func (r *Repo) DeleteCorsOrigin(ctx context.Context, appID uuid.UUID, id uuid.UUID) error {
	const q = `
		delete from app_cors_origins
		where id = $1
		  and app_id = $2
	`
	_, err := r.db.Pool().Exec(ctx, q, id, appID)
	return err
}

// GetCorsOrigins returns all CORS origins for an app.
func (r *Repo) GetCorsOrigins(ctx context.Context, appID uuid.UUID) ([]core.CorsOrigin, error) {
	const q = `
		select
			id,
			app_id,
			origin,
			created_at
		from app_cors_origins
		where app_id = $1
		order by created_at desc
	`

	rows, err := r.db.Pool().Query(ctx, q, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.CorsOrigin
	for rows.Next() {
		var c core.CorsOrigin
		if err := rows.Scan(
			&c.ID,
			&c.AppID,
			&c.Origin,
			&c.CreatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, c)
	}

	return out, rows.Err()
}

// CountCorsOriginsForApp returns count of CORS origins for an app.
func (r *Repo) CountCorsOriginsForApp(ctx context.Context, appID uuid.UUID) (int, error) {
	const q = `
		select count(*)
		from app_cors_origins
		where app_id = $1
	`

	var count int
	if err := r.db.Pool().QueryRow(ctx, q, appID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count cors origins: %w", err)
	}

	return count, nil
}

// UpdateCORSOrigin updates the origin URL for an existing CORS origin.
func (r *Repo) UpdateCORSOrigin(ctx context.Context, appID uuid.UUID, originID uuid.UUID, origin string) error {
	const q = `
		UPDATE app_cors_origins
		SET origin = $1
		WHERE id = $2
		  AND app_id = $3
	`
	res, err := r.db.Pool().Exec(ctx, q, origin, originID, appID)
	if err != nil {
		if IsUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ExistsCorsOrigin checks if an origin exists for an app.
func (r *Repo) ExistsCorsOrigin(ctx context.Context, appID uuid.UUID, origin string) (bool, error) {
	const q = `
		select exists(
			select 1
			from app_cors_origins
			where app_id = $1
			  and origin = $2
		)
	`
	var exists bool
	if err := r.db.Pool().QueryRow(ctx, q, appID, origin).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}
