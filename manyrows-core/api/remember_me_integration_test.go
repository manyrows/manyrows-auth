package api_test

// Integration tests for the remember-me flag — exercise the full
// CreateSessionWithOptions → repo round trip plus a persistence check on
// the session row. Live Postgres via testEnv.

import (
	"context"
	"testing"
	"time"

	clientauth "manyrows-core/auth/client"
)

func TestCreateSessionWithOptions_PersistsRememberMeAndExtendsTTL(t *testing.T) {
	cfg := GetTestConfig()
	clientAuth, err := clientauth.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("create auth service: %v", err)
	}

	emailAddr := "rememberme-" + GenerateUniqueSlug("t") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "RememberMe WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	t.Cleanup(func() {
		ctx := context.Background()
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM client_sessions WHERE app_id = $1", app.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM apps WHERE id = $1", app.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM projects WHERE id = $1", app.ProjectID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspace_admins WHERE workspace_id = $1", ws.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspaces WHERE id = $1", ws.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM accounts WHERE id = $1", acc.ID)
	})

	userID := insertTestUser(t, "registered", app.ID)

	// rememberMe=true session
	ses, err := clientAuth.CreateSessionWithOptions(
		context.Background(), userID, app.ID, "test-agent", "127.0.0.1", true, 0, 0, 0,
	)
	if err != nil {
		t.Fatalf("CreateSessionWithOptions: %v", err)
	}
	if !ses.RememberMe {
		t.Error("session.RememberMe should be true after rememberMe=true login")
	}

	// Round-trip via repo to confirm persistence (not just struct field
	// being set in memory).
	loaded, err := testEnv.Repo.GetClientSessionByID(context.Background(), ses.ID)
	if err != nil {
		t.Fatalf("GetClientSessionByID: %v", err)
	}
	if !loaded.RememberMe {
		t.Error("session.RememberMe should round-trip through the DB as true")
	}

	// ExpiresAt should be at least RememberMeTTL minutes from now (allow
	// 5min slack for slow CI).
	minExpiry := time.Now().UTC().Add(clientauth.RememberMeTTL).Add(-5 * time.Minute)
	if loaded.ExpiresAt.Before(minExpiry) {
		t.Errorf("expiresAt = %v, expected at least %v", loaded.ExpiresAt, minExpiry)
	}

	// Now create a non-remember session and confirm RememberMe is false.
	user2ID := insertTestUser(t, "registered", app.ID)
	ses2, err := clientAuth.CreateSessionWithOptions(
		context.Background(), user2ID, app.ID, "test-agent", "127.0.0.1", false, 0, 0, 0,
	)
	if err != nil {
		t.Fatalf("CreateSessionWithOptions (no remember): %v", err)
	}
	loaded2, err := testEnv.Repo.GetClientSessionByID(context.Background(), ses2.ID)
	if err != nil {
		t.Fatalf("GetClientSessionByID: %v", err)
	}
	if loaded2.RememberMe {
		t.Error("session.RememberMe should be false after rememberMe=false login")
	}
}

func TestCreateSession_Shim_DefaultsToRememberMeFalse(t *testing.T) {
	// The CreateSession backward-compat shim must NEVER opt into rememberMe
	// — protects all the non-login callers from accidentally getting
	// long-lived sessions.
	cfg := GetTestConfig()
	clientAuth, err := clientauth.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("create auth service: %v", err)
	}

	emailAddr := "rememberme-shim-" + GenerateUniqueSlug("t") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "RememberMe-Shim WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	userID := insertTestUser(t, "registered", app.ID)

	t.Cleanup(func() {
		ctx := context.Background()
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM client_sessions WHERE app_id = $1", app.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM apps WHERE id = $1", app.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM projects WHERE id = $1", app.ProjectID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspace_admins WHERE workspace_id = $1", ws.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspaces WHERE id = $1", ws.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM accounts WHERE id = $1", acc.ID)
	})

	ses, err := clientAuth.CreateSession(
		context.Background(), userID, app.ID, "test-agent", "127.0.0.1",
	)
	if err != nil {
		t.Fatalf("CreateSession (shim): %v", err)
	}
	if ses.RememberMe {
		t.Error("CreateSession shim must default RememberMe to false")
	}

	loaded, err := testEnv.Repo.GetClientSessionByID(context.Background(), ses.ID)
	if err != nil {
		t.Fatalf("GetClientSessionByID: %v", err)
	}
	if loaded.RememberMe {
		t.Error("RememberMe must round-trip as false through the shim")
	}
}
