package api_test

import (
	"context"
	"testing"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
)

// TestPasskeyRepoSignCounterRegression covers the sign-counter regression
// guard in UpdatePasskeyOnLogin. Earlier the SQL was
// `($2 = 0 OR $2 > sign_count)`, which let new=0 overwrite stored=5 — a
// clone could have rolled the counter back. The fix is
// `(($2 = 0 AND sign_count = 0) OR $2 > sign_count)`. These cases pin
// the corrected behavior.
func TestPasskeyRepoSignCounterRegression(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "passkeyrepo-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "passkey-repo-ws", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, "passkeyuser-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceRegistered)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Helper to insert a fresh passkey with a given starting sign count.
	insertPasskey := func(initialCount uint32) core.UserPasskey {
		t.Helper()
		credID := uuid.Must(uuid.NewV4())
		pubKey := uuid.Must(uuid.NewV4())
		p, err := testEnv.Repo.InsertPasskey(ctx, core.UserPasskey{
			AppID:        app.ID,
			UserID:       user.ID,
			CredentialID: credID.Bytes(),
			PublicKey:    pubKey.Bytes(),
			SignCount:    initialCount,
			Transports:   []string{"internal"},
		})
		if err != nil {
			t.Fatalf("insert passkey: %v", err)
		}
		return p
	}

	t.Run("strictly increasing counter accepts updates", func(t *testing.T) {
		p := insertPasskey(0)

		if err := testEnv.Repo.UpdatePasskeyOnLogin(ctx, p.ID, 1, false); err != nil {
			t.Fatalf("0 → 1 should succeed, got: %v", err)
		}
		if err := testEnv.Repo.UpdatePasskeyOnLogin(ctx, p.ID, 5, false); err != nil {
			t.Fatalf("1 → 5 should succeed, got: %v", err)
		}
		if err := testEnv.Repo.UpdatePasskeyOnLogin(ctx, p.ID, 99, false); err != nil {
			t.Fatalf("5 → 99 should succeed, got: %v", err)
		}
	})

	t.Run("regression to lower value rejected", func(t *testing.T) {
		p := insertPasskey(10)
		if err := testEnv.Repo.UpdatePasskeyOnLogin(ctx, p.ID, 5, false); err == nil {
			t.Fatal("10 → 5 should be rejected as a clone, got no error")
		}
	})

	t.Run("equal counter rejected", func(t *testing.T) {
		p := insertPasskey(7)
		if err := testEnv.Repo.UpdatePasskeyOnLogin(ctx, p.ID, 7, false); err == nil {
			t.Fatal("7 → 7 should be rejected (not strictly greater), got no error")
		}
	})

	t.Run("new=0 against non-zero stored rejected (was the bug)", func(t *testing.T) {
		// This is the case the old SQL got wrong: stored=5, new=0 used to
		// be accepted because of `$2 = 0 OR ...`. The fix changes that
		// disjunct to `$2 = 0 AND sign_count = 0`.
		p := insertPasskey(5)
		if err := testEnv.Repo.UpdatePasskeyOnLogin(ctx, p.ID, 0, false); err == nil {
			t.Fatal("stored=5, new=0 should be rejected as a clone, got no error")
		}
	})

	t.Run("all-zero stays accepted (authenticator doesn't track counter)", func(t *testing.T) {
		// Some authenticators don't track a counter — every assertion
		// reports 0. We must accept this case or those keys can never
		// log in.
		p := insertPasskey(0)
		if err := testEnv.Repo.UpdatePasskeyOnLogin(ctx, p.ID, 0, false); err != nil {
			t.Fatalf("stored=0, new=0 should be accepted, got: %v", err)
		}
		// Repeat — still accepted.
		if err := testEnv.Repo.UpdatePasskeyOnLogin(ctx, p.ID, 0, false); err != nil {
			t.Fatalf("stored=0, new=0 (second time) should be accepted, got: %v", err)
		}
	})

	t.Run("counter that starts incrementing after zero accepted", func(t *testing.T) {
		// Some authenticators initially report 0 then start incrementing.
		// First few logins look like the "doesn't track" case, then 1, 2, 3…
		p := insertPasskey(0)
		if err := testEnv.Repo.UpdatePasskeyOnLogin(ctx, p.ID, 0, false); err != nil {
			t.Fatalf("0 → 0 should succeed, got: %v", err)
		}
		if err := testEnv.Repo.UpdatePasskeyOnLogin(ctx, p.ID, 1, false); err != nil {
			t.Fatalf("0 → 1 should succeed, got: %v", err)
		}
	})
}

// TestPasskeyRepoCRUD covers the basic insert/list/lookup/delete shape so a
// future schema change can't silently break them.
func TestPasskeyRepoCRUD(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "pkcrud-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "pkcrud-ws", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, "crud-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceRegistered)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	credID := uuid.Must(uuid.NewV4())
	name := "Test passkey"

	inserted, err := testEnv.Repo.InsertPasskey(ctx, core.UserPasskey{
		AppID:        app.ID,
		UserID:       user.ID,
		CredentialID: credID.Bytes(),
		PublicKey:    []byte("public-key-bytes"),
		Transports:   []string{"internal", "hybrid"},
		Name:         &name,
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if inserted.ID == uuid.Nil {
		t.Fatal("expected ID assigned")
	}

	list, err := testEnv.Repo.ListPasskeysByUser(ctx, app.ID, user.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: got %d, err=%v", len(list), err)
	}
	if list[0].Name == nil || *list[0].Name != "Test passkey" {
		t.Errorf("name: got %v, want %q", list[0].Name, "Test passkey")
	}

	got, err := testEnv.Repo.GetPasskeyByCredentialID(ctx, app.ID, credID.Bytes())
	if err != nil || got.ID != inserted.ID {
		t.Fatalf("get-by-credential: got %v, err=%v", got.ID, err)
	}

	// Renaming with an empty pointer-string should clear the name.
	cleared := ""
	_ = testEnv.Repo.RenamePasskey(ctx, app.ID, user.ID, inserted.ID, &cleared)
	list2, _ := testEnv.Repo.ListPasskeysByUser(ctx, app.ID, user.ID)
	if list2[0].Name != nil && *list2[0].Name != "" {
		t.Errorf("rename-empty: expected nil/empty, got %v", list2[0].Name)
	}

	// Delete scoped to (app, user) — wrong user must NOT delete.
	otherUser, _, err := testEnv.GetOrCreateUserWithMembership(ctx, "other-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceRegistered)
	if err != nil {
		t.Fatalf("create other user: %v", err)
	}
	if err := testEnv.Repo.DeletePasskey(ctx, app.ID, otherUser.ID, inserted.ID); err == nil {
		t.Error("delete scoped to other user should have failed (not found)")
	}
	list3, _ := testEnv.Repo.ListPasskeysByUser(ctx, app.ID, user.ID)
	if len(list3) != 1 {
		t.Errorf("after wrong-user delete: still want 1, got %d", len(list3))
	}

	// Correct (app, user) deletes successfully.
	if err := testEnv.Repo.DeletePasskey(ctx, app.ID, user.ID, inserted.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	list4, _ := testEnv.Repo.ListPasskeysByUser(ctx, app.ID, user.ID)
	if len(list4) != 0 {
		t.Errorf("after delete: want 0, got %d", len(list4))
	}
}

// TestPasskeyRepoCrossAppIsolation ensures a credential ID can be re-used
// across apps without collision (each app has its own RPID, so the same
// authenticator generates different credentials anyway, but the unique
// constraint is per-app and should not block legitimate insert).
func TestPasskeyRepoCrossAppIsolation(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "iso-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "iso-ws", GenerateUniqueSlug("ws"))
	app1 := testEnv.CreateTestApp(t, ws, acc)
	app2 := testEnv.CreateTestApp(t, ws, acc)

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, "iso-user-"+GenerateUniqueSlug("u")+"@example.com", app1, core.UserSourceRegistered)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	credID := uuid.Must(uuid.NewV4()).Bytes()

	if _, err := testEnv.Repo.InsertPasskey(ctx, core.UserPasskey{
		AppID: app1.ID, UserID: user.ID, CredentialID: credID, PublicKey: []byte("k1"),
	}); err != nil {
		t.Fatalf("insert app1: %v", err)
	}
	// Same credential ID under a different app id — should NOT conflict.
	if _, err := testEnv.Repo.InsertPasskey(ctx, core.UserPasskey{
		AppID: app2.ID, UserID: user.ID, CredentialID: credID, PublicKey: []byte("k2"),
	}); err != nil {
		t.Fatalf("insert app2 with same credential ID: %v", err)
	}

	// Same (app, credential ID) — must conflict.
	if _, err := testEnv.Repo.InsertPasskey(ctx, core.UserPasskey{
		AppID: app1.ID, UserID: user.ID, CredentialID: credID, PublicKey: []byte("k3"),
	}); err == nil {
		t.Error("duplicate (app, credentialID) should have been rejected")
	}
}
