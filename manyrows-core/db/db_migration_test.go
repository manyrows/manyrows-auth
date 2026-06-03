package db

import (
	"context"
	neturl "net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// migrationTestURL provisions a throwaway database derived from
// TEST_DATABASE_URL and returns a URL pointing at it.
//
// These tests drop, create, and rename the real manyrows/manyrowsauth
// schemas, so they MUST run in isolation: the api package's tests share
// TEST_DATABASE_URL's database and the default (manyrowsauth) schema, and
// `go test ./...` runs packages in parallel — so operating on that shared
// schema here would clobber api mid-migration. A dedicated database keeps
// the two from ever touching the same catalog.
func migrationTestURL(t *testing.T) string {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed migration tests")
	}
	u, err := neturl.Parse(base)
	if err != nil {
		t.Fatalf("parse TEST_DATABASE_URL: %v", err)
	}
	origDB := strings.TrimPrefix(u.Path, "/")
	if origDB == "" {
		t.Fatalf("TEST_DATABASE_URL has no database name: %q", base)
	}
	isolated := origDB + "_migtest"

	provisionDatabase(t, base, isolated)

	u.Path = "/" + isolated
	return u.String()
}

// provisionDatabase (re)creates `name` over a connection to baseURL and
// registers its teardown. CREATE/DROP DATABASE can't run inside a
// transaction, so they go over a plain autocommit Exec.
func provisionDatabase(t *testing.T, baseURL, name string) {
	t.Helper()
	ctx := context.Background()

	admin, err := pgxpool.New(ctx, baseURL)
	if err != nil {
		t.Fatalf("connect to provision %s: %v", name, err)
	}
	defer admin.Close()

	if err := dropDatabase(ctx, admin, name); err != nil {
		t.Fatalf("drop stale %s: %v", name, err)
	}
	if _, err := admin.Exec(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}

	t.Cleanup(func() {
		adm, err := pgxpool.New(context.Background(), baseURL)
		if err != nil {
			t.Logf("cleanup: reconnect to drop %s: %v", name, err)
			return
		}
		defer adm.Close()
		if err := dropDatabase(context.Background(), adm, name); err != nil {
			t.Logf("cleanup: drop %s: %v", name, err)
		}
	})
}

// dropDatabase boots any lingering sessions on `name` (so DROP won't block)
// and drops it if present. Only the named database is touched — never the
// one the other test packages run against.
func dropDatabase(ctx context.Context, pool *pgxpool.Pool, name string) error {
	if _, err := pool.Exec(ctx,
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()", name); err != nil {
		return err
	}
	_, err := pool.Exec(ctx, `DROP DATABASE IF EXISTS "`+name+`"`)
	return err
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
	url := migrationTestURL(t)

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
