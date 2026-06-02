// Package encmigrate walks every server-encrypted column and rewrites
// each row to the canonical AAD-bound, kid-tagged format under the
// currently-active key. It's used for two distinct flows:
//
//  1. Format upgrade: bring legacy v0x03 rows (no kid) onto v0x04.
//     One-time after the rotation-tooling rollout.
//  2. Key rotation: with the previous key supplied via
//     MANYROWS_ENCRYPTION_KEY_PREVIOUS, rewrite every row under the
//     new active key, then unset that env var.
//
// Run-mode: invoked from start.go when the binary is launched with the
// "migrate-encryption" subcommand:
//
//	./web migrate-encryption
//
// The walker is idempotent (rows already canonical under the active
// key are skipped via SecretEncryptor.IsCanonical) and resumable (each
// row commits independently — a crash mid-run leaves a partial set of
// canonical rows that the next run picks up where the previous left
// off).
//
// Memory: each column is buffered into memory before the per-row
// re-encrypt+update phase. For ManyRows-scale tables (low millions max)
// this is fine; if any column ever grows past ~1M rows, switch to
// LIMIT/OFFSET batching.
package encmigrate

import (
	"context"
	"fmt"

	"manyrows-core/core/repo"
	"manyrows-core/crypto"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// column describes one bytea column to migrate. idCol is whatever
// uniquely identifies the row for both UPDATE WHERE and the AAD —
// usually "id", but workspace_smtp_config keys on workspace_id.
type column struct {
	table   string
	idCol   string
	dataCol string
}

// columns enumerates every server-side encrypted bytea column.
// config_values.value_encrypted is intentionally absent — those rows
// are end-to-end encrypted in the browser; the server never sees the
// plaintext and has no key to migrate them with.
var columns = []column{
	{"accounts", "id", "totp_secret_encrypted"},
	{"accounts", "id", "totp_backup_codes_encrypted"},
	{"users", "id", "totp_secret_encrypted"},
	{"users", "id", "totp_backup_codes_encrypted"},
	{"apps", "id", "google_oauth_client_secret_encrypted"},
	{"apps", "id", "apple_private_key_encrypted"},
	{"apps", "id", "microsoft_client_secret_encrypted"},
	{"apps", "id", "github_client_secret_encrypted"},
	{"workspace_smtp_config", "workspace_id", "password_encrypted"},
}

// Stats reports how the walker did. Migrated + Skipped + Errors should
// equal the total non-null rows touched (Errors are NOT subtracted from
// Migrated — they're the rows that failed to re-encrypt and were left
// unchanged).
type Stats struct {
	Migrated int64
	Skipped  int64
	Errors   int64
}

// Run walks every column in turn. Returns the first column-level error;
// per-row errors are logged and counted but don't abort the run.
func Run(ctx context.Context, r *repo.Repo, enc crypto.SecretEncryptor) (Stats, error) {
	var total Stats
	for _, c := range columns {
		s, err := migrateColumn(ctx, r, enc, c)
		total.Migrated += s.Migrated
		total.Skipped += s.Skipped
		total.Errors += s.Errors

		ev := log.Info().
			Str("table", c.table).
			Str("column", c.dataCol).
			Int64("migrated", s.Migrated).
			Int64("skipped", s.Skipped).
			Int64("errors", s.Errors)

		if err != nil {
			ev.Err(err).Msg("encryption migration: column FAILED")
			return total, fmt.Errorf("%s.%s: %w", c.table, c.dataCol, err)
		}
		ev.Msg("encryption migration: column complete")
	}
	return total, nil
}

func migrateColumn(ctx context.Context, r *repo.Repo, enc crypto.SecretEncryptor, c column) (Stats, error) {
	var stats Stats

	// Identifiers come from a static allowlist (the columns slice above) so
	// fmt.Sprintf into the SQL is safe — no user input ever reaches here.
	selectQ := fmt.Sprintf(
		`SELECT %s, %s FROM %s WHERE %s IS NOT NULL AND length(%s) > 0`,
		c.idCol, c.dataCol, c.table, c.dataCol, c.dataCol,
	)
	updateQ := fmt.Sprintf(
		`UPDATE %s SET %s = $1 WHERE %s = $2`,
		c.table, c.dataCol, c.idCol,
	)

	type rowEntry struct {
		id   uuid.UUID
		data []byte
	}

	rows, err := r.DB().Pool().Query(ctx, selectQ)
	if err != nil {
		return stats, fmt.Errorf("select: %w", err)
	}
	var entries []rowEntry
	for rows.Next() {
		var e rowEntry
		if err := rows.Scan(&e.id, &e.data); err != nil {
			rows.Close()
			return stats, fmt.Errorf("scan: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return stats, fmt.Errorf("rows iter: %w", err)
	}
	rows.Close()

	for _, e := range entries {
		aad := crypto.AAD(c.table, c.dataCol, e.id)
		newCt, action, rowErr := migrateRow(enc, e.data, aad)
		switch action {
		case actionSkipped:
			stats.Skipped++
		case actionError:
			log.Err(rowErr).
				Str("table", c.table).
				Str("column", c.dataCol).
				Str("id", e.id.String()).
				Msg("encryption migration: row decrypt/re-encrypt failed (row left unchanged)")
			stats.Errors++
		case actionMigrated:
			if _, err := r.DB().Pool().Exec(ctx, updateQ, newCt, e.id); err != nil {
				log.Err(err).
					Str("table", c.table).
					Str("column", c.dataCol).
					Str("id", e.id.String()).
					Msg("encryption migration: update failed (row left unchanged)")
				stats.Errors++
				continue
			}
			stats.Migrated++
		}
	}

	return stats, nil
}
