package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"manyrows-core/api"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
)

/*
Tests for the user-pool + app_users refactor. The invariants we lock down:

  - A user is keyed on (email, user_pool_id), not (email, app_id).
  - Per-app membership is the app_users row. Roles are orthogonal: a
    member can have zero roles and still appear in the member list and
    still sign in (password sign-in additionally requires app_users.status='active').
  - Two apps pointing at the same pool share users.
  - Admin invite without role + registration without default role both succeed.
*/

// ---- EnsureAppMember ----

func TestEnsureAppMember_CreatesActiveRow(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "epm-create-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, "m-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}

	m, created, err := testEnv.Repo.EnsureAppMember(ctx, app.ID, user.ID, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("EnsureAppMember: %v", err)
	}
	if !created {
		t.Fatal("expected created=true on first call")
	}
	if m.Status != core.AppUserStatusActive {
		t.Errorf("expected status=active, got %q", m.Status)
	}
	if m.Source != core.UserSourceInvited {
		t.Errorf("expected source=invited, got %q", m.Source)
	}
}

func TestEnsureAppMember_IdempotentPreservesStatus(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "epm-idem-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, "m-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}

	if _, _, err := testEnv.Repo.EnsureAppMember(ctx, app.ID, user.ID, core.UserSourceInvited); err != nil {
		t.Fatalf("EnsureAppMember first call: %v", err)
	}
	if err := testEnv.Repo.SetAppUserStatus(ctx, app.ID, user.ID, core.AppUserStatusDisabled); err != nil {
		t.Fatalf("SetAppUserStatus: %v", err)
	}

	// A second EnsureAppMember (e.g. another OAuth sign-in) must NOT
	// silently re-enable a disabled member.
	m, created, err := testEnv.Repo.EnsureAppMember(ctx, app.ID, user.ID, core.UserSourceGoogle)
	if err != nil {
		t.Fatalf("EnsureAppMember second call: %v", err)
	}
	if created {
		t.Error("expected created=false on repeat")
	}
	if m.Status != core.AppUserStatusDisabled {
		t.Errorf("status leaked to %q; admin disable must survive repeat sign-in", m.Status)
	}
	if m.Source != core.UserSourceInvited {
		t.Errorf("source leaked to %q; first-touch source must be preserved", m.Source)
	}
}

// ---- Password sign-in requires membership ----

func TestGetUserWithPasswordByEmailAndApp_RequiresActiveMembership(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "pwd-mem-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	email := "p-" + GenerateUniqueSlug("u") + "@example.com"
	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, email, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	// Give them a password (raw set, bypasses hashing logic).
	if _, err := testEnv.DB.Pool().Exec(ctx,
		`UPDATE users SET password_hash = $2, password_set_at = now() WHERE id = $1`,
		user.ID, "fake-hash",
	); err != nil {
		t.Fatalf("set password: %v", err)
	}

	// Without an app_users row, sign-in lookup must return nil.
	u, hash, err := testEnv.Repo.GetUserWithPasswordByEmailAndApp(ctx, email, app)
	if err != nil {
		t.Fatalf("GetUserWithPasswordByEmailAndApp: %v", err)
	}
	if u != nil || hash != "" {
		t.Fatalf("expected nil user, got %+v hash=%q (membership not enforced)", u, hash)
	}

	// Add membership; lookup now succeeds.
	if _, _, err := testEnv.Repo.EnsureAppMember(ctx, app.ID, user.ID, core.UserSourceInvited); err != nil {
		t.Fatalf("EnsureAppMember: %v", err)
	}
	u, hash, err = testEnv.Repo.GetUserWithPasswordByEmailAndApp(ctx, email, app)
	if err != nil {
		t.Fatalf("GetUserWithPasswordByEmailAndApp after EnsureAppMember: %v", err)
	}
	if u == nil || hash != "fake-hash" {
		t.Fatalf("expected user + hash, got user=%+v hash=%q", u, hash)
	}

	// Disable membership; sign-in lookup must return nil again.
	if err := testEnv.Repo.SetAppUserStatus(ctx, app.ID, user.ID, core.AppUserStatusDisabled); err != nil {
		t.Fatalf("SetAppUserStatus: %v", err)
	}
	u, _, err = testEnv.Repo.GetUserWithPasswordByEmailAndApp(ctx, email, app)
	if err != nil {
		t.Fatalf("GetUserWithPasswordByEmailAndApp after disable: %v", err)
	}
	if u != nil {
		t.Errorf("disabled member should not sign in via password; got user=%+v", u)
	}
}

// ---- Two apps sharing a pool ----

func TestSharedUserPool_OneIdentityAcrossTwoApps(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "shared-pool-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	appA := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	// Build a second app pointing at appA's pool. CreateTestApp would
	// auto-create a new pool, so we insert directly. appB lives in a
	// sibling project (different project_id) so the (project_id, type)
	// unique constraint doesn't fire when both are type=dev - and that
	// matches the canonical "Acme dashboard + Acme marketing share
	// users across two projects" SSO case.
	appBProjectID := utils.NewUUID()
	if _, err := testEnv.DB.Pool().Exec(ctx, `
		INSERT INTO projects (id, workspace_id, name, created_at, updated_at, created_by_account_id)
		VALUES ($1, $2, $3, NOW(), NOW(), $4)
	`, appBProjectID, ws.ID, "Shared Sibling "+GenerateUniqueSlug("p"), acc.ID); err != nil {
		t.Fatalf("insert sibling project: %v", err)
	}
	appBID := utils.NewUUID()
	if _, err := testEnv.DB.Pool().Exec(ctx, `
		INSERT INTO apps (id, workspace_id, project_id, user_pool_id, type, enabled, primary_auth_method, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'dev', true, 'password', NOW(), NOW())
	`, appBID, ws.ID, appBProjectID, appA.UserPoolID); err != nil {
		t.Fatalf("insert appB: %v", err)
	}
	appB, err := testEnv.Repo.GetAppByID(ctx, appBID)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}
	if appA.UserPoolID != appB.UserPoolID {
		t.Fatalf("test setup: pool ids differ A=%s B=%s", appA.UserPoolID, appB.UserPoolID)
	}

	// Creating "the same email" via appA should NOT produce a second
	// user when looked up via appB; they share the pool.
	email := "shared-" + GenerateUniqueSlug("u") + "@example.com"
	uA, createdA, err := testEnv.Repo.GetOrCreateUser(ctx, email, appA, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser A: %v", err)
	}
	if !createdA {
		t.Fatal("expected user created on first call")
	}
	uB, createdB, err := testEnv.Repo.GetOrCreateUser(ctx, email, &appB, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser B: %v", err)
	}
	if createdB {
		t.Error("second call (same pool) should not create a new user row")
	}
	if uA.ID != uB.ID {
		t.Errorf("expected same identity across shared pool, got A=%s B=%s", uA.ID, uB.ID)
	}
}

// ---- Member listing includes roleless ----

func TestListUsersByApp_IncludesRolelessMember(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "list-roleless-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	email := "rl-" + GenerateUniqueSlug("u") + "@example.com"
	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, email, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	if _, _, err := testEnv.Repo.EnsureAppMember(ctx, app.ID, user.ID, core.UserSourceInvited); err != nil {
		t.Fatalf("EnsureAppMember: %v", err)
	}
	// Intentionally no roles assigned.

	users, err := testEnv.Repo.ListUsersByApp(ctx, app.ID)
	if err != nil {
		t.Fatalf("ListUsersByApp: %v", err)
	}
	if !containsUser(users, email) {
		t.Errorf("roleless member %q missing from ListUsersByApp; got %d users", email, len(users))
	}
}

func TestGetProjectMembersByApp_IncludesRolelessMember(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "pm-roleless-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	email := "pm-" + GenerateUniqueSlug("u") + "@example.com"
	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, email, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	if _, _, err := testEnv.Repo.EnsureAppMember(ctx, app.ID, user.ID, core.UserSourceInvited); err != nil {
		t.Fatalf("EnsureAppMember: %v", err)
	}

	members, total, err := testEnv.Repo.GetProjectMembersByApp(ctx, app.ProjectID, app.ID, 0, 100, "", 0, repo.MemberEnabledFilterAny, repo.MemberRoleFilter{})
	if err != nil {
		t.Fatalf("GetProjectMembersByApp: %v", err)
	}
	if total < 1 {
		t.Errorf("expected total >= 1, got %d", total)
	}
	if !containsMember(members, email) {
		t.Errorf("roleless member %q missing from GetProjectMembersByApp", email)
	}
}

// ---- Admin invite without roles ----

func TestCreateWorkspaceAccount_RolelessInviteSucceeds(t *testing.T) {
	router := setupWorkspaceAccountsRouter(t)

	acc := testEnv.CreateTestAccount(t, "rl-inv-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	newEmail := "rl-target-" + GenerateUniqueSlug("u") + "@example.com"
	body := map[string]any{
		"email":   newEmail,
		"appId":   app.ID.String(),
		"roleIds": []string{}, // no roles, no default role on the app
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/accounts", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// The user must now be a member of the app, even with no roles.
	m, err := testEnv.Repo.GetAppUser(context.Background(), app.ID,
		mustExtractUserID(t, rr.Body.Bytes()))
	if err != nil {
		t.Fatalf("GetAppUser: %v", err)
	}
	if m == nil {
		t.Fatal("invite created no app_users row")
	}
	if m.Status != core.AppUserStatusActive {
		t.Errorf("expected status=active, got %q", m.Status)
	}
}

// ---- App registration update tolerates nil default role ----

func TestUpdateAppRegistration_NoDefaultRoleAllowed(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "reg-nodef-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	updated, err := testEnv.Repo.UpdateAppRegistration(ctx, ws.ID, app.ProjectID, app.ID, repo.AppRegistrationUpdate{
		AllowRegistration:    true,
		AllowAccountDeletion: true,
		AllowEmailChange:     false,
		DefaultRoleID:        nil,
		AllowedEmailDomains:  []string{},
		Require2FA:           false,
	})
	if err != nil {
		t.Fatalf("UpdateAppRegistration with allow_registration=true + DefaultRoleID=nil: %v", err)
	}
	if !updated.AllowRegistration {
		t.Error("AllowRegistration not persisted")
	}
	if updated.DefaultRoleID != nil {
		t.Errorf("expected DefaultRoleID=nil, got %v", updated.DefaultRoleID)
	}
}

// ---- Pool auto-naming on collision ----

func TestCreateUserPoolWithUniqueName_AppendsSuffixOnCollision(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "pool-collide-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	base := "Same Name " + GenerateUniqueSlug("p")

	p1, err := testEnv.Repo.CreateUserPoolWithUniqueName(ctx, ws.ID, base)
	if err != nil {
		t.Fatalf("CreateUserPoolWithUniqueName 1: %v", err)
	}
	if p1.Name != base {
		t.Errorf("expected first pool to keep base name, got %q", p1.Name)
	}

	p2, err := testEnv.Repo.CreateUserPoolWithUniqueName(ctx, ws.ID, base)
	if err != nil {
		t.Fatalf("CreateUserPoolWithUniqueName 2: %v", err)
	}
	if p2.ID == p1.ID {
		t.Fatal("second call returned the same pool; expected a new row")
	}
	if !strings.Contains(p2.Name, base) || !strings.HasSuffix(p2.Name, "(2)") {
		t.Errorf("expected second name to be %q + ' (2)', got %q", base, p2.Name)
	}
}

/* ---- Position B: ResolveSignInIdentity gates email-proof sign-in ---- */

// allowReg flips AllowRegistration on the app via the same path the
// admin endpoint uses, so the underlying app row matches a live app.
func allowReg(t *testing.T, app *core.App, on bool) *core.App {
	t.Helper()
	updated, err := testEnv.Repo.UpdateAppRegistration(context.Background(),
		app.WorkspaceID, app.ProjectID, app.ID, repo.AppRegistrationUpdate{
			AllowRegistration:    on,
			AllowAccountDeletion: app.AllowAccountDeletion,
			AllowEmailChange:     app.AllowEmailChange,
			DefaultRoleID:        app.DefaultRoleID,
			AllowedEmailDomains:  app.AllowedEmailDomains,
			Require2FA:           app.Require2FA,
		})
	if err != nil {
		t.Fatalf("UpdateAppRegistration: %v", err)
	}
	return &updated
}

func TestResolveSignInIdentity_RejectsUnknownEmailWhenRegistrationOff(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "rsi-1-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc) // AllowRegistration=false by default
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	ts := NewTestServices(t)
	_, _, err := ts.Handler.ResolveSignInIdentity(ctx, app,
		"unknown-"+GenerateUniqueSlug("u")+"@example.com", core.UserSourceRegistered)
	if !errors.Is(err, api.ErrRegistrationDisabled) {
		t.Fatalf("expected ErrRegistrationDisabled for fresh email + AllowRegistration=false, got %v", err)
	}
}

func TestResolveSignInIdentity_RejectsPoolUserWithoutMembershipWhenRegistrationOff(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "rsi-2-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	email := "pool-" + GenerateUniqueSlug("u") + "@example.com"
	if _, _, err := testEnv.Repo.GetOrCreateUser(ctx, email, app, core.UserSourceInvited); err != nil {
		t.Fatalf("seed pool user: %v", err)
	}
	// Note: no EnsureAppMember call - user is in the pool but not a
	// member of this app. The "SSO from another app sharing the pool"
	// scenario.

	ts := NewTestServices(t)
	_, _, err := ts.Handler.ResolveSignInIdentity(ctx, app, email, core.UserSourceGoogle)
	if !errors.Is(err, api.ErrRegistrationDisabled) {
		t.Fatalf("expected ErrRegistrationDisabled for pool-user-without-membership + AllowRegistration=false, got %v", err)
	}
}

func TestResolveSignInIdentity_CreatesUserAndMemberWhenRegistrationOn(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "rsi-3-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	app = allowReg(t, app, true)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	email := "fresh-" + GenerateUniqueSlug("u") + "@example.com"
	ts := NewTestServices(t)
	user, created, err := ts.Handler.ResolveSignInIdentity(ctx, app, email, core.UserSourceRegistered)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !created {
		t.Error("expected userCreated=true on first sign-in")
	}
	if user == nil || !strings.EqualFold(user.Email, email) {
		t.Fatalf("unexpected user: %+v", user)
	}
	m, err := testEnv.Repo.GetAppUser(ctx, app.ID, user.ID)
	if err != nil || m == nil {
		t.Fatalf("expected membership row, got m=%v err=%v", m, err)
	}
	if m.Status != core.AppUserStatusActive {
		t.Errorf("expected active member, got %q", m.Status)
	}
}

func TestResolveSignInIdentity_AddsMembershipForExistingPoolUserWhenRegistrationOn(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "rsi-4-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	app = allowReg(t, app, true)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	email := "sso-" + GenerateUniqueSlug("u") + "@example.com"
	seed, _, err := testEnv.Repo.GetOrCreateUser(ctx, email, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("seed pool user: %v", err)
	}

	ts := NewTestServices(t)
	user, created, err := ts.Handler.ResolveSignInIdentity(ctx, app, email, core.UserSourceGoogle)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if created {
		t.Error("userCreated must be false; pool user already existed")
	}
	if user.ID != seed.ID {
		t.Errorf("expected same user id %s, got %s", seed.ID, user.ID)
	}
	m, err := testEnv.Repo.GetAppUser(ctx, app.ID, user.ID)
	if err != nil || m == nil {
		t.Fatalf("expected membership row to be auto-created, got m=%v err=%v", m, err)
	}
}

func TestResolveSignInIdentity_ActiveMember_SucceedsEvenWhenRegistrationOff(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "rsi-5-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc) // AllowRegistration=false
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	email := "member-" + GenerateUniqueSlug("u") + "@example.com"
	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, email, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("seed pool user: %v", err)
	}
	if _, _, err := testEnv.Repo.EnsureAppMember(ctx, app.ID, user.ID, core.UserSourceInvited); err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	ts := NewTestServices(t)
	gotUser, created, err := ts.Handler.ResolveSignInIdentity(ctx, app, email, core.UserSourceGoogle)
	if err != nil {
		t.Fatalf("an existing active member must sign in regardless of AllowRegistration; got err=%v", err)
	}
	if created {
		t.Error("returning member: userCreated must be false")
	}
	if gotUser.ID != user.ID {
		t.Errorf("expected user %s, got %s", user.ID, gotUser.ID)
	}
}

func TestResolveSignInIdentity_DisabledMember_RejectedEvenWhenRegistrationOn(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "rsi-6-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	app = allowReg(t, app, true) // even with registration on, disabled blocks
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	email := "disabled-" + GenerateUniqueSlug("u") + "@example.com"
	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, email, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("seed pool user: %v", err)
	}
	if _, _, err := testEnv.Repo.EnsureAppMember(ctx, app.ID, user.ID, core.UserSourceInvited); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	if err := testEnv.Repo.SetAppUserStatus(ctx, app.ID, user.ID, core.AppUserStatusDisabled); err != nil {
		t.Fatalf("disable membership: %v", err)
	}

	ts := NewTestServices(t)
	_, _, err = ts.Handler.ResolveSignInIdentity(ctx, app, email, core.UserSourceGoogle)
	if !errors.Is(err, api.ErrAppUserDisabled) {
		t.Fatalf("disabled member must be rejected at every email-proof path; got %v", err)
	}
}

/* ---- helpers ---- */

func containsUser(users []core.User, email string) bool {
	for _, u := range users {
		if strings.EqualFold(u.Email, email) {
			return true
		}
	}
	return false
}

func containsMember(members []core.MemberResource, email string) bool {
	for _, m := range members {
		if strings.EqualFold(m.Email, email) {
			return true
		}
	}
	return false
}

func mustExtractUserID(t *testing.T, raw []byte) uuid.UUID {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("decode invite response: %v", err)
	}
	s, ok := resp["id"].(string)
	if !ok || s == "" {
		t.Fatalf("invite response missing id: %s", string(raw))
	}
	parsed, err := uuid.FromString(s)
	if err != nil {
		t.Fatalf("parse id: %v", err)
	}
	return parsed
}
