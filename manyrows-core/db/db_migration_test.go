package db

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// testDatabaseURL gates the Postgres-backed tests on a dedicated test
// database. They drop and recreate the manyrows/manyrowsauth schemas, so
// they must never run against a real database.
func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed migration tests")
	}
	return url
}

// rawPool opens a direct pool (no schema pinning) for test setup and
// assertions, independent of the DB-under-test.
func rawPool(t *testing.T, url string) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("open raw pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func dropAppSchemas(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for _, s := range []string{legacySchema, defaultSchema} {
		if _, err := pool.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+s+" CASCADE"); err != nil {
			t.Fatalf("drop schema %s: %v", s, err)
		}
	}
}

func schemaPresent(t *testing.T, pool *pgxpool.Pool, name string) bool {
	t.Helper()
	var exists bool
	err := pool.QueryRow(context.Background(),
		"SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = $1)", name).Scan(&exists)
	if err != nil {
		t.Fatalf("check schema %s: %v", name, err)
	}
	return exists
}

// newDB boots the DB-under-test. MaxConns mirrors what the real config
// always supplies (pgxpool rejects a zero pool size).
func newDB(t *testing.T, url, schema string) *DB {
	t.Helper()
	db, err := New(Config{DatabaseURL: url, Schema: schema, MaxConns: 5})
	if err != nil {
		t.Fatalf("New(schema=%q): %v", schema, err)
	}
	return db
}

func TestLegacySchemaMigration(t *testing.T) {
	url := testDatabaseURL(t)

	t.Run("fresh install creates the new default schema", func(t *testing.T) {
		raw := rawPool(t, url)
		dropAppSchemas(t, raw)

		db := newDB(t, url, "")
		defer db.Shutdown()

		if db.Schema() != defaultSchema {
			t.Errorf("Schema() = %q, want %q", db.Schema(), defaultSchema)
		}
		if !schemaPresent(t, raw, defaultSchema) {
			t.Errorf("expected schema %q to exist", defaultSchema)
		}
		if schemaPresent(t, raw, legacySchema) {
			t.Errorf("did not expect legacy schema %q to exist on a fresh install", legacySchema)
		}
	})

	t.Run("legacy manyrows schema is renamed in place with data preserved", func(t *testing.T) {
		raw := rawPool(t, url)
		dropAppSchemas(t, raw)

		// Stand up a real, fully-migrated legacy install under "manyrows".
		legacy := newDB(t, url, legacySchema)
		// Seed a sentinel object so we can prove the rename carried the data
		// over, rather than just re-running migrations into a fresh schema.
		ctx := context.Background()
		if _, err := legacy.Pool().Exec(ctx, "CREATE TABLE "+legacySchema+".sentinel (note text)"); err != nil {
			t.Fatalf("create sentinel: %v", err)
		}
		if _, err := legacy.Pool().Exec(ctx, "INSERT INTO "+legacySchema+".sentinel VALUES ('keepme')"); err != nil {
			t.Fatalf("seed sentinel: %v", err)
		}
		legacy.Shutdown()

		// Boot on the default — should rename manyrows -> manyrowsauth.
		db := newDB(t, url, "")
		defer db.Shutdown()

		if schemaPresent(t, raw, legacySchema) {
			t.Errorf("legacy schema %q should have been renamed away", legacySchema)
		}
		if !schemaPresent(t, raw, defaultSchema) {
			t.Fatalf("expected schema %q to exist after rename", defaultSchema)
		}
		var note string
		if err := raw.QueryRow(ctx, "SELECT note FROM "+defaultSchema+".sentinel").Scan(&note); err != nil {
			t.Fatalf("sentinel not carried into %q: %v", defaultSchema, err)
		}
		if note != "keepme" {
			t.Errorf("sentinel note = %q, want %q", note, "keepme")
		}
	})

	t.Run("explicit manyrows pin is left untouched", func(t *testing.T) {
		raw := rawPool(t, url)
		dropAppSchemas(t, raw)

		legacy := newDB(t, url, legacySchema)
		legacy.Shutdown()

		// Operator explicitly pins the old name — it must NOT be renamed.
		db := newDB(t, url, legacySchema)
		defer db.Shutdown()

		if !schemaPresent(t, raw, legacySchema) {
			t.Errorf("explicitly pinned schema %q must be preserved", legacySchema)
		}
		if schemaPresent(t, raw, defaultSchema) {
			t.Errorf("did not expect %q to be created when pinned to %q", defaultSchema, legacySchema)
		}
	})

	t.Run("unrelated schema named manyrows is not hijacked", func(t *testing.T) {
		raw := rawPool(t, url)
		dropAppSchemas(t, raw)

		// A schema called "manyrows" that isn't ours (no goose_db_version).
		ctx := context.Background()
		if _, err := raw.Exec(ctx, "CREATE SCHEMA "+legacySchema); err != nil {
			t.Fatalf("create unrelated schema: %v", err)
		}
		if _, err := raw.Exec(ctx, "CREATE TABLE "+legacySchema+".not_ours (x int)"); err != nil {
			t.Fatalf("create unrelated table: %v", err)
		}

		db := newDB(t, url, "")
		defer db.Shutdown()

		if !schemaPresent(t, raw, legacySchema) {
			t.Errorf("unrelated schema %q must not be renamed/hijacked", legacySchema)
		}
		if !schemaPresent(t, raw, defaultSchema) {
			t.Errorf("expected fresh %q to be created alongside it", defaultSchema)
		}
	})
}
