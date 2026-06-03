package db

import (
	"context"
	neturl "net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// testPinnedSchema is a custom schema name used to verify that an operator who
// pins MANYROWS_DB_SCHEMA gets exactly that schema (and not the default).
const testPinnedSchema = "pinned_custom"

// migrationTestURL provisions a throwaway database derived from
// TEST_DATABASE_URL and returns a URL pointing at it.
//
// These tests drop and create the manyrowsauth (and a custom pinned) schema,
// so they MUST run in isolation: the api package's tests share
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
	for _, s := range []string{defaultSchema, testPinnedSchema} {
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

func TestSchemaProvisioning(t *testing.T) {
	url := migrationTestURL(t)

	t.Run("fresh install creates the default schema", func(t *testing.T) {
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
	})

	t.Run("explicit schema pin is honored", func(t *testing.T) {
		raw := rawPool(t, url)
		dropAppSchemas(t, raw)

		// Operator pins a custom schema — migrations land there, and the
		// default schema is not auto-created.
		db := newDB(t, url, testPinnedSchema)
		defer db.Shutdown()

		if db.Schema() != testPinnedSchema {
			t.Errorf("Schema() = %q, want %q", db.Schema(), testPinnedSchema)
		}
		if !schemaPresent(t, raw, testPinnedSchema) {
			t.Errorf("expected pinned schema %q to exist", testPinnedSchema)
		}
		if schemaPresent(t, raw, defaultSchema) {
			t.Errorf("did not expect default %q to be created when pinned to %q", defaultSchema, testPinnedSchema)
		}
	})
}
