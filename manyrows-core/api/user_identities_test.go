package api_test

import (
	"context"
	"errors"
	"testing"

	"manyrows-core/api"
	"manyrows-core/core"
	"manyrows-core/core/repo"

	"github.com/gofrs/uuid/v5"
)

/*
Tests for the OAuth identity layer added in migration 00007:

  - UpsertUserIdentity is the only write path; it refuses to silently
    swap provider_subject on an existing (user, provider) row.
  - ResolveOAuthSignInIdentity prefers (provider, subject) match over
    email match, falls back to email when no identity row exists, and
    creates one on the fallback path.
  - The identity-conflict path returns api.ErrIdentityConflict so the
    OAuth handler can turn it into a 409 rather than a 500.
*/

// ---- UpsertUserIdentity ----

func TestUpsertUserIdentity_CreatesRow(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "uid-create-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	user, _, err := testEnv.Repo.GetOrCreateUser(ctx,
		"u-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceGoogle)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}

	if err := testEnv.Repo.UpsertUserIdentity(ctx, user.ID, app.UserPoolID,
		core.UserSourceGoogle, "google-sub-001", "google-user@example.com"); err != nil {
		t.Fatalf("UpsertUserIdentity: %v", err)
	}

	rows, err := testEnv.Repo.ListUserIdentities(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListUserIdentities: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 identity row, got %d", len(rows))
	}
	if rows[0].Provider != core.UserSourceGoogle || rows[0].ProviderSubject != "google-sub-001" {
		t.Errorf("unexpected row: %+v", rows[0])
	}
}

func TestUpsertUserIdentity_RefreshesEmailAndLastLogin(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "uid-refresh-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	user, _, err := testEnv.Repo.GetOrCreateUser(ctx,
		"u-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceGoogle)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}

	const sub = "google-sub-stable"
	if err := testEnv.Repo.UpsertUserIdentity(ctx, user.ID, app.UserPoolID,
		core.UserSourceGoogle, sub, "old@example.com"); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	first, err := testEnv.Repo.ListUserIdentities(ctx, user.ID)
	if err != nil || len(first) != 1 {
		t.Fatalf("first list: rows=%d err=%v", len(first), err)
	}
	firstLogin := first[0].LastLoginAt

	if err := testEnv.Repo.UpsertUserIdentity(ctx, user.ID, app.UserPoolID,
		core.UserSourceGoogle, sub, "new@example.com"); err != nil {
		t.Fatalf("second upsert (same subject, new email): %v", err)
	}
	second, err := testEnv.Repo.ListUserIdentities(ctx, user.ID)
	if err != nil || len(second) != 1 {
		t.Fatalf("second list: rows=%d err=%v", len(second), err)
	}
	if second[0].ProviderEmail != "new@example.com" {
		t.Errorf("expected provider_email to refresh, got %q", second[0].ProviderEmail)
	}
	if !second[0].LastLoginAt.After(firstLogin) {
		t.Errorf("expected last_login_at to advance, first=%v second=%v", firstLogin, second[0].LastLoginAt)
	}
}

func TestUpsertUserIdentity_RefusesSubjectChange(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "uid-mismatch-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	user, _, err := testEnv.Repo.GetOrCreateUser(ctx,
		"u-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceGoogle)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}

	if err := testEnv.Repo.UpsertUserIdentity(ctx, user.ID, app.UserPoolID,
		core.UserSourceGoogle, "google-sub-A", "a@example.com"); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	err = testEnv.Repo.UpsertUserIdentity(ctx, user.ID, app.UserPoolID,
		core.UserSourceGoogle, "google-sub-B", "b@example.com")
	if !errors.Is(err, repo.ErrIdentitySubjectMismatch) {
		t.Fatalf("expected ErrIdentitySubjectMismatch on different subject, got %v", err)
	}

	rows, err := testEnv.Repo.ListUserIdentities(ctx, user.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("list after refused upsert: rows=%d err=%v", len(rows), err)
	}
	if rows[0].ProviderSubject != "google-sub-A" {
		t.Errorf("subject must not have been overwritten; got %q", rows[0].ProviderSubject)
	}
}

// ---- FindUserByIdentity ----

func TestFindUserByIdentity_FindsLinkedUser(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "fui-find-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	user, _, err := testEnv.Repo.GetOrCreateUser(ctx,
		"u-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceGoogle)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	if err := testEnv.Repo.UpsertUserIdentity(ctx, user.ID, app.UserPoolID,
		core.UserSourceGoogle, "find-me", "x@example.com"); err != nil {
		t.Fatalf("UpsertUserIdentity: %v", err)
	}

	got, err := testEnv.Repo.FindUserByIdentity(ctx, app.UserPoolID, core.UserSourceGoogle, "find-me")
	if err != nil {
		t.Fatalf("FindUserByIdentity: %v", err)
	}
	if got == nil || got.ID != user.ID {
		t.Fatalf("expected to find user %s, got %+v", user.ID, got)
	}
}

func TestFindUserByIdentity_NilWhenAbsent(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "fui-nil-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	got, err := testEnv.Repo.FindUserByIdentity(ctx, app.UserPoolID, core.UserSourceGoogle, "does-not-exist")
	if err != nil {
		t.Fatalf("FindUserByIdentity: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for missing identity, got %+v", got)
	}
}

// ---- ResolveOAuthSignInIdentity ----

func TestResolveOAuthSignInIdentity_PrefersSubjectMatchOverEmail(t *testing.T) {
	// The user changed their Google email upstream. We must still
	// recognize them via (provider, sub), even though the email we
	// receive doesn't match any pool user.
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "roi-sub-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	app = allowReg(t, app, true)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	oldEmail := "old-" + GenerateUniqueSlug("u") + "@example.com"
	seed, _, err := testEnv.Repo.GetOrCreateUser(ctx, oldEmail, app, core.UserSourceGoogle)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, _, err := testEnv.Repo.EnsureAppMember(ctx, app.ID, seed.ID, core.UserSourceGoogle); err != nil {
		t.Fatalf("seed member: %v", err)
	}
	if err := testEnv.Repo.UpsertUserIdentity(ctx, seed.ID, app.UserPoolID,
		core.UserSourceGoogle, "sub-stable", oldEmail); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	ts := NewTestServices(t)
	newEmail := "new-" + GenerateUniqueSlug("u") + "@example.com"
	user, created, err := ts.Handler.ResolveOAuthSignInIdentity(ctx, app, newEmail, core.UserSourceGoogle, "", "sub-stable")
	if err != nil {
		t.Fatalf("ResolveOAuthSignInIdentity: %v", err)
	}
	if created {
		t.Error("expected userCreated=false; existing user matched by subject")
	}
	if user.ID != seed.ID {
		t.Errorf("expected user %s, got %s", seed.ID, user.ID)
	}
	// users.email must not have been silently changed.
	reloaded, err := testEnv.Repo.GetUserByID(ctx, seed.ID)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if reloaded.Email != oldEmail {
		t.Errorf("users.email must not change on sign-in; got %q", reloaded.Email)
	}
}

func TestResolveOAuthSignInIdentity_FallsBackToEmailAndLinks(t *testing.T) {
	// First-time Google sign-in for a user who already exists via
	// password registration: match by email, then link the identity so
	// the next sign-in takes the subject-match fast path.
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "roi-fallback-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	app = allowReg(t, app, true)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	email := "fallback-" + GenerateUniqueSlug("u") + "@example.com"
	seed, _, err := testEnv.Repo.GetOrCreateUser(ctx, email, app, core.UserSourceRegistered)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, _, err := testEnv.Repo.EnsureAppMember(ctx, app.ID, seed.ID, core.UserSourceRegistered); err != nil {
		t.Fatalf("seed member: %v", err)
	}

	ts := NewTestServices(t)
	user, created, err := ts.Handler.ResolveOAuthSignInIdentity(ctx, app, email, core.UserSourceGoogle, "", "new-sub-001")
	if err != nil {
		t.Fatalf("ResolveOAuthSignInIdentity: %v", err)
	}
	if created {
		t.Error("expected userCreated=false; existing user matched by email")
	}
	if user.ID != seed.ID {
		t.Errorf("expected user %s, got %s", seed.ID, user.ID)
	}

	rows, err := testEnv.Repo.ListUserIdentities(ctx, seed.ID)
	if err != nil {
		t.Fatalf("ListUserIdentities: %v", err)
	}
	if len(rows) != 1 || rows[0].ProviderSubject != "new-sub-001" {
		t.Fatalf("expected linked identity sub=new-sub-001, got %+v", rows)
	}
}

func TestResolveOAuthSignInIdentity_RefusesEmailFallbackOnSubjectMismatch(t *testing.T) {
	// User X already has a Google identity (sub-A). A different Google
	// account (sub-B) sends a token that happens to share user X's
	// email. Subject match fails, email fallback resolves to user X,
	// upsert detects the mismatch and we refuse rather than overwrite.
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "roi-mismatch-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	app = allowReg(t, app, true)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	email := "mismatch-" + GenerateUniqueSlug("u") + "@example.com"
	seed, _, err := testEnv.Repo.GetOrCreateUser(ctx, email, app, core.UserSourceGoogle)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, _, err := testEnv.Repo.EnsureAppMember(ctx, app.ID, seed.ID, core.UserSourceGoogle); err != nil {
		t.Fatalf("seed member: %v", err)
	}
	if err := testEnv.Repo.UpsertUserIdentity(ctx, seed.ID, app.UserPoolID,
		core.UserSourceGoogle, "sub-A", email); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	ts := NewTestServices(t)
	_, _, err = ts.Handler.ResolveOAuthSignInIdentity(ctx, app, email, core.UserSourceGoogle, "", "sub-B")
	if !errors.Is(err, api.ErrIdentityConflict) {
		t.Fatalf("expected ErrIdentityConflict on subject mismatch, got %v", err)
	}

	rows, err := testEnv.Repo.ListUserIdentities(ctx, seed.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("list after refusal: rows=%d err=%v", len(rows), err)
	}
	if rows[0].ProviderSubject != "sub-A" {
		t.Errorf("subject must not have been overwritten; got %q", rows[0].ProviderSubject)
	}
}

func TestResolveOAuthSignInIdentity_CreatesUserAndIdentityWhenRegistrationOn(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "roi-create-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	app = allowReg(t, app, true)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	email := "fresh-oauth-" + GenerateUniqueSlug("u") + "@example.com"
	ts := NewTestServices(t)
	user, created, err := ts.Handler.ResolveOAuthSignInIdentity(ctx, app, email, core.UserSourceGoogle, "", "brand-new-sub")
	if err != nil {
		t.Fatalf("ResolveOAuthSignInIdentity: %v", err)
	}
	if !created {
		t.Error("expected userCreated=true for first-time sign-in")
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}
	rows, err := testEnv.Repo.ListUserIdentities(ctx, user.ID)
	if err != nil || len(rows) != 1 || rows[0].ProviderSubject != "brand-new-sub" {
		t.Fatalf("expected one identity row with sub=brand-new-sub, got %+v err=%v", rows, err)
	}
}

func TestResolveOAuthSignInIdentity_GenericPerProviderIsolation(t *testing.T) {
	// The whole point of the provider-key decoupling: two distinct
	// external IdPs can return the SAME `sub` (a sub is unique only
	// per-issuer). With per-IdP keys ("idp:<config-uuid>") they must link
	// as two SEPARATE identities on the same pool user — matched by email
	// — not collide into one. And user.source stays the coarse "external"
	// bucket, never a per-provider value.
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "roi-genidp-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	app = allowReg(t, app, true)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	email := "genidp-" + GenerateUniqueSlug("u") + "@example.com"
	ts := NewTestServices(t)

	idpA := uuid.Must(uuid.NewV4()) // e.g. an Okta config
	idpB := uuid.Must(uuid.NewV4()) // e.g. an Auth0 config
	keyA := core.ExternalIDPProviderKey(idpA)
	keyB := core.ExternalIDPProviderKey(idpB)

	// First IdP creates the user.
	u1, created1, err := ts.Handler.ResolveOAuthSignInIdentity(ctx, app, email,
		core.UserSourceExternalIDP, keyA, "shared-sub-123")
	if err != nil {
		t.Fatalf("idp A sign-in: %v", err)
	}
	if !created1 {
		t.Error("expected first generic sign-in to create the user")
	}

	// Second IdP with the SAME sub but a different config key — resolves
	// to the same user by email and links a SECOND identity.
	u2, created2, err := ts.Handler.ResolveOAuthSignInIdentity(ctx, app, email,
		core.UserSourceExternalIDP, keyB, "shared-sub-123")
	if err != nil {
		t.Fatalf("idp B sign-in: %v", err)
	}
	if created2 {
		t.Error("expected second generic sign-in to match the existing user, not create")
	}
	if u1.ID != u2.ID {
		t.Fatalf("both IdPs should resolve to the same pool user; got %s vs %s", u1.ID, u2.ID)
	}

	// Two distinct identity rows — the shared sub did NOT collapse them.
	rows, err := testEnv.Repo.ListUserIdentities(ctx, u1.ID)
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 distinct identities (one per idp config), got %d: %+v", len(rows), rows)
	}
	gotProviders := map[string]bool{}
	for _, row := range rows {
		gotProviders[string(row.Provider)] = true
	}
	if !gotProviders[keyA] || !gotProviders[keyB] {
		t.Fatalf("expected keys %q and %q, got %+v", keyA, keyB, gotProviders)
	}

	// Coarse origin only — not a per-slug value.
	reloaded, err := testEnv.Repo.GetUserByID(ctx, u1.ID)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if reloaded.Source != core.UserSourceExternalIDP {
		t.Errorf("user.source should be coarse %q, got %q", core.UserSourceExternalIDP, reloaded.Source)
	}
}

func TestResolveOAuthSignInIdentity_NoSubjectStillWorksWithoutLinking(t *testing.T) {
	// Defensive: a provider that returns an empty `sub` shouldn't break
	// sign-in - it just skips identity recording. The warn-log fires in
	// the handler, not here.
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "roi-nosub-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	app = allowReg(t, app, true)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	email := "nosub-" + GenerateUniqueSlug("u") + "@example.com"
	ts := NewTestServices(t)
	user, created, err := ts.Handler.ResolveOAuthSignInIdentity(ctx, app, email, core.UserSourceGithub, "", "")
	if err != nil {
		t.Fatalf("ResolveOAuthSignInIdentity (empty sub): %v", err)
	}
	if !created {
		t.Error("expected userCreated=true")
	}
	rows, err := testEnv.Repo.ListUserIdentities(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListUserIdentities: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected no identity row when sub is empty, got %+v", rows)
	}
}

// ---- DeleteUserIdentity ----

func TestDeleteUserIdentity_RemovesRow(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "did-rm-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	user, _, err := testEnv.Repo.GetOrCreateUser(ctx,
		"u-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceGoogle)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	if err := testEnv.Repo.UpsertUserIdentity(ctx, user.ID, app.UserPoolID,
		core.UserSourceGoogle, "to-delete", ""); err != nil {
		t.Fatalf("UpsertUserIdentity: %v", err)
	}

	if err := testEnv.Repo.DeleteUserIdentity(ctx, user.ID, core.UserSourceGoogle); err != nil {
		t.Fatalf("DeleteUserIdentity: %v", err)
	}
	rows, err := testEnv.Repo.ListUserIdentities(ctx, user.ID)
	if err != nil || len(rows) != 0 {
		t.Errorf("expected zero rows after delete, got %d err=%v", len(rows), err)
	}

	// Deleting again is a no-op (idempotent).
	if err := testEnv.Repo.DeleteUserIdentity(ctx, user.ID, core.UserSourceGoogle); err != nil {
		t.Errorf("expected idempotent delete, got %v", err)
	}
}
