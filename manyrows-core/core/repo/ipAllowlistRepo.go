package repo

import (
	"context"
	"errors"
	"fmt"
	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// InsertIPAllowlistEntryWithLimit atomically inserts an IP allowlist entry only if the app has fewer than maxLimit entries.
func (r *Repo) InsertIPAllowlistEntryWithLimit(ctx context.Context, entry core.IPAllowlistEntry, maxLimit int) (bool, error) {
	const q = `
		INSERT INTO app_ip_allowlist (id, app_id, ip_range, description, created_at)
		SELECT $1, $2, $3, $4, $5
		WHERE (SELECT count(*) FROM app_ip_allowlist WHERE app_id = $2) < $6
	`
	tag, err := r.db.Pool().Exec(ctx, q, entry.ID, entry.AppID, entry.IPRange, entry.Description, entry.CreatedAt, maxLimit)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// DeleteIPAllowlistEntry deletes an IP allowlist entry by id within an app.
func (r *Repo) DeleteIPAllowlistEntry(ctx context.Context, appID uuid.UUID, id uuid.UUID) error {
	const q = `
		delete from app_ip_allowlist
		where id = $1
		  and app_id = $2
	`
	_, err := r.db.Pool().Exec(ctx, q, id, appID)
	return err
}

// GetIPAllowlist returns all IP allowlist entries for an app.
func (r *Repo) GetIPAllowlist(ctx context.Context, appID uuid.UUID) ([]core.IPAllowlistEntry, error) {
	const q = `
		select
			id,
			app_id,
			ip_range,
			coalesce(description, ''),
			created_at
		from app_ip_allowlist
		where app_id = $1
		order by created_at desc
	`

	rows, err := r.db.Pool().Query(ctx, q, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.IPAllowlistEntry
	for rows.Next() {
		var e core.IPAllowlistEntry
		if err := rows.Scan(
			&e.ID,
			&e.AppID,
			&e.IPRange,
			&e.Description,
			&e.CreatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, e)
	}

	return out, rows.Err()
}

// UpdateIPAllowlistEntry updates the ip_range and description of an IP allowlist entry.
func (r *Repo) UpdateIPAllowlistEntry(ctx context.Context, appID uuid.UUID, id uuid.UUID, ipRange string, description string) (core.IPAllowlistEntry, error) {
	const q = `
		update app_ip_allowlist
		set ip_range = $1, description = $2
		where id = $3 and app_id = $4
		returning id, app_id, ip_range, coalesce(description, ''), created_at
	`

	var e core.IPAllowlistEntry
	err := r.db.Pool().QueryRow(ctx, q, ipRange, description, id, appID).Scan(
		&e.ID,
		&e.AppID,
		&e.IPRange,
		&e.Description,
		&e.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.IPAllowlistEntry{}, ErrNotFound
		}
		return core.IPAllowlistEntry{}, err
	}
	return e, nil
}

// CountIPAllowlistForApp returns count of IP allowlist entries for an app.
func (r *Repo) CountIPAllowlistForApp(ctx context.Context, appID uuid.UUID) (int, error) {
	const q = `
		select count(*)
		from app_ip_allowlist
		where app_id = $1
	`

	var count int
	if err := r.db.Pool().QueryRow(ctx, q, appID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count ip allowlist: %w", err)
	}

	return count, nil
}

// HasIPAllowlist returns true if the app has any IP allowlist entries.
func (r *Repo) HasIPAllowlist(ctx context.Context, appID uuid.UUID) (bool, error) {
	const q = `
		select exists(
			select 1
			from app_ip_allowlist
			where app_id = $1
		)
	`
	var exists bool
	if err := r.db.Pool().QueryRow(ctx, q, appID).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}
