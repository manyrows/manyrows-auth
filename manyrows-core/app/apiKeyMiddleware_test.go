package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/db"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// Integration test for apiKeyMiddleware: the API-key auth + per-app scoping that
// the rest of the S2S handler tests (in package api) deliberately bypass with a
// synthetic key. Needs a real DB; skips without TEST_DATABASE_URL so the other
// app-package unit tests stay DB-free.

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// makeAPIKey inserts an API key and returns the full presentable key
// (mr_<prefix>_<secret>). appID nil = workspace-wide (no per-app scope).
func makeAPIKey(t *testing.T, rpo *repo.Repo, wsID, createdBy uuid.UUID, appID *uuid.UUID) string {
	t.Helper()
	prefix := randHex(4) // 8 hex chars, matches parseAPIKeyPrefix's length check
	secret := randHex(16)
	fullKey := "mr_" + prefix + "_" + secret
	sum := sha256.Sum256([]byte(fullKey))
	key := &core.APIKey{
		ID:          utils.NewUUID(),
		WorkspaceID: wsID,
		AppID:       appID,
		Name:        "test key",
		Prefix:      prefix,
		Hash:        hex.EncodeToString(sum[:]),
		CreatedAt:   time.Now().UTC(),
		CreatedBy:   createdBy,
	}
	if err := rpo.InsertAPIKey(context.Background(), key); err != nil {
		t.Fatalf("InsertAPIKey: %v", err)
	}
	t.Cleanup(func() {
		_ = rpo.DeleteAPIKey(context.Background(), wsID, key.ID)
	})
	return fullKey
}

func TestAPIKeyMiddleware(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed apiKeyMiddleware test")
	}
	dbInstance, err := db.New(db.Config{DatabaseURL: dbURL, MaxConns: 3})
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	defer dbInstance.Shutdown()
	rpo := repo.NewRepo(dbInstance)
	ctx := context.Background()
	pool := dbInstance.Pool()

	// Account + workspace for the FKs.
	acc := &core.Account{ID: utils.NewUUID(), Email: "apikey-mw-" + randHex(6) + "@example.com", Name: "Test", CreatedAt: time.Now().UTC()}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if vr, err := rpo.InsertAccount(ctx, tx, acc); err != nil || !vr.Ok() {
		_ = tx.Rollback(ctx)
		t.Fatalf("InsertAccount: err=%v vr=%v", err, vr.Issues)
	}
	ws := &core.Workspace{ID: utils.NewUUID(), Name: "MW Test", Slug: "mw-" + randHex(6), CreatedBy: &acc.ID}
	if err := rpo.InsertWorkspace(ctx, ws, tx); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("InsertWorkspace: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// A real product + user pool + app, so a key can be scoped to app_id (FK).
	product := core.Product{ID: utils.NewUUID(), WorkspaceID: ws.ID, Name: "MW Product", CreatedBy: acc.ID}
	if err := rpo.InsertProduct(ctx, product); err != nil {
		t.Fatalf("InsertProduct: %v", err)
	}
	userPool, err := rpo.CreateUserPool(ctx, ws.ID, "MW Pool "+randHex(4))
	if err != nil {
		t.Fatalf("CreateUserPool: %v", err)
	}
	appA := utils.NewUUID()
	if _, err := pool.Exec(ctx, `
		INSERT INTO apps (id, workspace_id, product_id, user_pool_id, type, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'dev', true, NOW(), NOW())`,
		appA, ws.ID, product.ID, userPool.ID); err != nil {
		t.Fatalf("insert app: %v", err)
	}
	appB := utils.NewUUID() // a different app id; the middleware only compares it, never loads it
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM apps WHERE id = $1", appA)
		_, _ = pool.Exec(ctx, "DELETE FROM user_pools WHERE id = $1", userPool.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM products WHERE id = $1", product.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspaces WHERE id = $1", ws.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM accounts WHERE id = $1", acc.ID)
	})

	unscopedKey := makeAPIKey(t, rpo, ws.ID, acc.ID, nil)
	scopedKey := makeAPIKey(t, rpo, ws.ID, acc.ID, &appA)
	unscopedPrefix, _ := parseAPIKeyPrefix(unscopedKey)

	// Router: inject the workspace (as wsMiddleware would) then the real
	// apiKeyMiddleware, guarding a probe handler under /apps/{appId}.
	throttle := newLastUsedThrottle(time.Hour)
	r := chi.NewRouter()
	r.Route("/x/{workspaceSlug}/api/v1/apps/{appId}", func(sub chi.Router) {
		sub.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				next.ServeHTTP(w, req.WithContext(core.WithWorkspace(req.Context(), ws)))
			})
		})
		sub.Use(apiKeyMiddleware(rpo, throttle))
		sub.Get("/probe", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	})

	do := func(appID, apiKey string) int {
		req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/api/v1/apps/"+appID+"/probe", nil)
		if apiKey != "" {
			req.Header.Set("X-API-Key", apiKey)
		}
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		return rr.Code
	}

	cases := []struct {
		name   string
		appID  string
		apiKey string
		want   int
	}{
		{"no key", appA.String(), "", http.StatusUnauthorized},
		{"malformed key", appA.String(), "not-an-api-key", http.StatusUnauthorized},
		{"unknown prefix", appA.String(), "mr_" + randHex(4) + "_" + randHex(16), http.StatusUnauthorized},
		{"right prefix wrong secret", appA.String(), "mr_" + unscopedPrefix + "_" + randHex(16), http.StatusUnauthorized},
		{"valid unscoped key", appB.String(), unscopedKey, http.StatusOK},
		{"scoped key on its app", appA.String(), scopedKey, http.StatusOK},
		{"scoped key on another app", appB.String(), scopedKey, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := do(tc.appID, tc.apiKey); got != tc.want {
				t.Fatalf("%s: want %d, got %d", tc.name, tc.want, got)
			}
		})
	}
}
