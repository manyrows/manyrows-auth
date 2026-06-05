package api_test

import (
	"context"
	"testing"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
)

func TestApp_OrgColumnsDefault(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "appcol-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	got, err := testEnv.Repo.GetAppByID(ctx, app.ID)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}
	if got.OrganizationsEnabled {
		t.Errorf("organizationsEnabled should default false")
	}
	if got.OrgCreationPolicy != core.OrgCreationInviteOnly {
		t.Errorf("orgCreationPolicy: got %q want invite_only", got.OrgCreationPolicy)
	}
}

func TestOrganization_CreateAddMemberSetRoles(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "org-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, "m-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}

	org, err := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &user.ID)
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if org.Status != core.OrgStatusActive {
		t.Errorf("status: got %q want active", org.Status)
	}

	m, err := testEnv.Repo.AddOrganizationMember(ctx, org.ID, user.ID, core.OrgRoleOwner)
	if err != nil {
		t.Fatalf("AddOrganizationMember: %v", err)
	}
	if m.OrgRole != core.OrgRoleOwner {
		t.Errorf("orgRole: got %q want owner", m.OrgRole)
	}

	got, err := testEnv.Repo.GetOrganizationMember(ctx, org.ID, user.ID)
	if err != nil {
		t.Fatalf("GetOrganizationMember: %v", err)
	}
	if got.ID != m.ID {
		t.Errorf("member id mismatch")
	}

	views, err := testEnv.Repo.ListOrganizationsForUserInApp(ctx, app.ID, user.ID)
	if err != nil {
		t.Fatalf("ListOrganizationsForUserInApp: %v", err)
	}
	if len(views) != 1 || views[0].ID != org.ID || views[0].OrgRole != core.OrgRoleOwner {
		t.Errorf("views: got %+v", views)
	}
}

func TestResolveActiveRoles_OrgVsLegacy(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "res-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, "m-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}

	role, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{
		ProjectID: app.ProjectID, Name: "Org Admin", Slug: GenerateUniqueSlug("orgadmin"), Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	org, err := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &user.ID)
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	member, err := testEnv.Repo.AddOrganizationMember(ctx, org.ID, user.ID, core.OrgRoleOwner)
	if err != nil {
		t.Fatalf("AddOrganizationMember: %v", err)
	}
	if err := testEnv.Repo.SetOrganizationMemberRoles(ctx, member.ID, []uuid.UUID{role.ID}); err != nil {
		t.Fatalf("SetOrganizationMemberRoles: %v", err)
	}

	svc := NewTestServices(t)
	h := svc.Handler
	now := time.Now().UTC()
	ses := &core.ClientSession{ID: utils.NewUUID(), UserID: user.ID, AppID: &app.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now, OrganizationID: &org.ID}

	// Org disabled → org roles must NOT resolve (legacy path, no user_roles seeded → empty).
	appOff, err := testEnv.Repo.GetAppByID(ctx, app.ID)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}
	roles, _, member2, err := h.ResolveActiveRolesAndPermissionsForTest(ctx, &appOff, app.ProjectID, user.ID, ses)
	if err != nil {
		t.Fatalf("resolve (off): %v", err)
	}
	if len(roles) != 0 || member2 != nil {
		t.Fatalf("org-disabled must ignore org roles; got roles=%v member=%v", roles, member2)
	}

	// Enable orgs → org roles resolve.
	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, app.ID, true); err != nil {
		t.Fatalf("SetAppOrganizationsEnabled: %v", err)
	}
	appOn, err := testEnv.Repo.GetAppByID(ctx, app.ID)
	if err != nil {
		t.Fatalf("GetAppByID(on): %v", err)
	}
	roles2, _, member3, err := h.ResolveActiveRolesAndPermissionsForTest(ctx, &appOn, app.ProjectID, user.ID, ses)
	if err != nil {
		t.Fatalf("resolve (on): %v", err)
	}
	if len(roles2) != 1 || roles2[0] != role.Slug || member3 == nil || member3.OrgRole != core.OrgRoleOwner {
		t.Fatalf("org-enabled must resolve org roles; got roles=%v member=%v", roles2, member3)
	}
}

// On an org-enabled app, a user with NO active org must resolve to empty roles
// AND empty permissions, even if they have leftover legacy user_roles / direct
// user_permissions. Org membership is the single source of truth.
func TestResolveActiveRoles_OrgEnabledNoActiveOrg_Empty(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "noorg-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	now := time.Now().UTC()
	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, "m-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}

	// Give the user a LEGACY per-app role assignment, which must be IGNORED once
	// orgs are enabled and there is no active org.
	role, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{ProjectID: app.ProjectID, Name: "Legacy", Slug: GenerateUniqueSlug("legacy"), Now: now})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := testEnv.Repo.ReplaceUserRoles(ctx, repo.ReplaceUserRolesParams{ProjectID: app.ProjectID, UserID: user.ID, AppID: app.ID, RoleIDs: []uuid.UUID{role.ID}, Now: now}); err != nil {
		t.Fatalf("ReplaceUserRoles: %v", err)
	}

	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, app.ID, true); err != nil {
		t.Fatalf("SetAppOrganizationsEnabled: %v", err)
	}
	appOn, err := testEnv.Repo.GetAppByID(ctx, app.ID)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}

	svc := NewTestServices(t)
	ses := &core.ClientSession{ID: utils.NewUUID(), UserID: user.ID, AppID: &app.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now, OrganizationID: nil}

	roles, perms, member, err := svc.Handler.ResolveActiveRolesAndPermissionsForTest(ctx, &appOn, app.ProjectID, user.ID, ses)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(roles) != 0 || len(perms) != 0 || member != nil {
		t.Fatalf("org-enabled + no active org must yield empty roles/perms and nil member (single source of truth); got roles=%v perms=%v member=%v", roles, perms, member)
	}
}

func TestResolveActiveRoles_DisabledMember_Empty(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "disab-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})
	now := time.Now().UTC()

	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, app.ID, true); err != nil {
		t.Fatalf("enable orgs: %v", err)
	}
	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, "m-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	role, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{ProjectID: app.ProjectID, Name: "R", Slug: GenerateUniqueSlug("r"), Now: now})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	org, err := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &user.ID)
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	member, err := testEnv.Repo.AddOrganizationMember(ctx, org.ID, user.ID, core.OrgRoleOwner)
	if err != nil {
		t.Fatalf("AddOrganizationMember: %v", err)
	}
	if err := testEnv.Repo.SetOrganizationMemberRoles(ctx, member.ID, []uuid.UUID{role.ID}); err != nil {
		t.Fatalf("SetOrganizationMemberRoles: %v", err)
	}
	if _, err := testEnv.DB.Pool().Exec(ctx, "UPDATE organization_members SET status='disabled' WHERE id=$1", member.ID); err != nil {
		t.Fatalf("disable member: %v", err)
	}

	appOn, err := testEnv.Repo.GetAppByID(ctx, app.ID)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}
	svc := NewTestServices(t)
	ses := &core.ClientSession{ID: utils.NewUUID(), UserID: user.ID, AppID: &app.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now, OrganizationID: &org.ID}
	roles, perms, m, err := svc.Handler.ResolveActiveRolesAndPermissionsForTest(ctx, &appOn, app.ProjectID, user.ID, ses)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(roles) != 0 || len(perms) != 0 || m != nil {
		t.Fatalf("disabled member must resolve to no roles/perms/member; got roles=%v perms=%v member=%v", roles, perms, m)
	}
}

func TestResolveActiveRoles_ArchivedOrg_Empty(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "arch-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})
	now := time.Now().UTC()

	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, app.ID, true); err != nil {
		t.Fatalf("enable orgs: %v", err)
	}
	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, "m-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	role, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{ProjectID: app.ProjectID, Name: "R", Slug: GenerateUniqueSlug("r"), Now: now})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	org, err := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &user.ID)
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	member, err := testEnv.Repo.AddOrganizationMember(ctx, org.ID, user.ID, core.OrgRoleOwner)
	if err != nil {
		t.Fatalf("AddOrganizationMember: %v", err)
	}
	if err := testEnv.Repo.SetOrganizationMemberRoles(ctx, member.ID, []uuid.UUID{role.ID}); err != nil {
		t.Fatalf("SetOrganizationMemberRoles: %v", err)
	}
	if _, err := testEnv.DB.Pool().Exec(ctx, "UPDATE organizations SET status='archived' WHERE id=$1", org.ID); err != nil {
		t.Fatalf("archive org: %v", err)
	}

	appOn, err := testEnv.Repo.GetAppByID(ctx, app.ID)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}
	svc := NewTestServices(t)
	ses := &core.ClientSession{ID: utils.NewUUID(), UserID: user.ID, AppID: &app.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now, OrganizationID: &org.ID}
	roles, perms, m, err := svc.Handler.ResolveActiveRolesAndPermissionsForTest(ctx, &appOn, app.ProjectID, user.ID, ses)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(roles) != 0 || len(perms) != 0 || m != nil {
		t.Fatalf("archived org must resolve to no roles/perms/member; got roles=%v perms=%v member=%v", roles, perms, m)
	}
}

func TestResolveActiveRoles_CrossAppOrgIgnored(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "xapp-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app1 := testEnv.CreateTestApp(t, ws, acc)
	app2 := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})
	now := time.Now().UTC()

	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, app1.ID, true); err != nil {
		t.Fatalf("enable orgs: %v", err)
	}
	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, "m-"+GenerateUniqueSlug("u")+"@example.com", app1, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	// Org + membership + role live under app2; the session is scoped to app1.
	org2, err := testEnv.Repo.CreateOrganization(ctx, app2.ID, "Other", GenerateUniqueSlug("o"), nil)
	if err != nil {
		t.Fatalf("CreateOrganization app2: %v", err)
	}
	m2, err := testEnv.Repo.AddOrganizationMember(ctx, org2.ID, user.ID, core.OrgRoleOwner)
	if err != nil {
		t.Fatalf("AddOrganizationMember: %v", err)
	}
	roleB, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{ProjectID: app2.ProjectID, Name: "B", Slug: GenerateUniqueSlug("b"), Now: now})
	if err != nil {
		t.Fatalf("CreateRole app2: %v", err)
	}
	if err := testEnv.Repo.SetOrganizationMemberRoles(ctx, m2.ID, []uuid.UUID{roleB.ID}); err != nil {
		t.Fatalf("SetOrganizationMemberRoles: %v", err)
	}

	appOn1, err := testEnv.Repo.GetAppByID(ctx, app1.ID)
	if err != nil {
		t.Fatalf("GetAppByID app1: %v", err)
	}
	svc := NewTestServices(t)
	ses := &core.ClientSession{ID: utils.NewUUID(), UserID: user.ID, AppID: &app1.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now, OrganizationID: &org2.ID}
	roles, perms, m, err := svc.Handler.ResolveActiveRolesAndPermissionsForTest(ctx, &appOn1, app1.ProjectID, user.ID, ses)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(roles) != 0 || len(perms) != 0 || m != nil {
		t.Fatalf("an org from a DIFFERENT app must not resolve; got roles=%v perms=%v member=%v", roles, perms, m)
	}
}

func TestOrganizationWriteMethods_CreateUniqueUpdateArchive(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "owr-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, "m-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}

	o1, err := testEnv.Repo.CreateOrganizationWithUniqueSlug(ctx, app.ID, "Acme", "acme", &user.ID)
	if err != nil {
		t.Fatalf("create 1: %v", err)
	}
	o2, err := testEnv.Repo.CreateOrganizationWithUniqueSlug(ctx, app.ID, "Acme", "acme", &user.ID)
	if err != nil {
		t.Fatalf("create 2: %v", err)
	}
	if o1.Slug != "acme" || o2.Slug != "acme-2" {
		t.Fatalf("slug uniqueness: got %q and %q", o1.Slug, o2.Slug)
	}

	upd, err := testEnv.Repo.UpdateOrganization(ctx, o1.ID, "Acme Renamed", "acme-renamed")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if upd.Name != "Acme Renamed" || upd.Slug != "acme-renamed" {
		t.Fatalf("update result: %+v", upd)
	}

	if err := testEnv.Repo.ArchiveOrganization(ctx, o1.ID); err != nil {
		t.Fatalf("archive: %v", err)
	}
	got, err := testEnv.Repo.GetOrganizationByID(ctx, o1.ID)
	if err != nil {
		t.Fatalf("get after archive: %v", err)
	}
	if got.Status != core.OrgStatusArchived {
		t.Fatalf("status after archive: got %q want archived", got.Status)
	}
}

func TestOrganizationMemberMethods(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "mem-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, err := testEnv.Repo.GetOrCreateUser(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("owner: %v", err)
	}
	other, _, err := testEnv.Repo.GetOrCreateUser(ctx, "oth-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("other: %v", err)
	}

	org, err := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner); err != nil {
		t.Fatalf("add owner: %v", err)
	}
	if _, err := testEnv.Repo.AddOrganizationMember(ctx, org.ID, other.ID, core.OrgRoleAdmin); err != nil {
		t.Fatalf("add other: %v", err)
	}

	members, err := testEnv.Repo.ListOrganizationMembers(ctx, org.ID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(members))
	}

	owners, err := testEnv.Repo.CountActiveOrgOwners(ctx, org.ID)
	if err != nil || owners != 1 {
		t.Fatalf("CountActiveOrgOwners: got %d err %v want 1", owners, err)
	}

	if err := testEnv.Repo.SetOrganizationMemberRole(ctx, org.ID, other.ID, core.OrgRoleOwner); err != nil {
		t.Fatalf("set role: %v", err)
	}
	owners, _ = testEnv.Repo.CountActiveOrgOwners(ctx, org.ID)
	if owners != 2 {
		t.Fatalf("after promote: got %d owners want 2", owners)
	}

	if err := testEnv.Repo.RemoveOrganizationMember(ctx, org.ID, other.ID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	members, _ = testEnv.Repo.ListOrganizationMembers(ctx, org.ID)
	if len(members) != 1 {
		t.Fatalf("after remove: got %d members want 1", len(members))
	}
}

func TestResolveActiveRoles_PinnedOrgIsolation(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "iso-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})
	now := time.Now().UTC()

	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, app.ID, true); err != nil {
		t.Fatalf("enable orgs: %v", err)
	}
	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, "m-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	roleA, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{ProjectID: app.ProjectID, Name: "A", Slug: GenerateUniqueSlug("a"), Now: now})
	if err != nil {
		t.Fatalf("CreateRole A: %v", err)
	}
	roleB, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{ProjectID: app.ProjectID, Name: "B", Slug: GenerateUniqueSlug("b"), Now: now})
	if err != nil {
		t.Fatalf("CreateRole B: %v", err)
	}
	orgA, err := testEnv.Repo.CreateOrganization(ctx, app.ID, "OrgA", GenerateUniqueSlug("a"), &user.ID)
	if err != nil {
		t.Fatalf("CreateOrganization A: %v", err)
	}
	orgB, err := testEnv.Repo.CreateOrganization(ctx, app.ID, "OrgB", GenerateUniqueSlug("b"), &user.ID)
	if err != nil {
		t.Fatalf("CreateOrganization B: %v", err)
	}
	mA, err := testEnv.Repo.AddOrganizationMember(ctx, orgA.ID, user.ID, core.OrgRoleOwner)
	if err != nil {
		t.Fatalf("AddOrganizationMember A: %v", err)
	}
	mB, err := testEnv.Repo.AddOrganizationMember(ctx, orgB.ID, user.ID, core.OrgRoleMember)
	if err != nil {
		t.Fatalf("AddOrganizationMember B: %v", err)
	}
	if err := testEnv.Repo.SetOrganizationMemberRoles(ctx, mA.ID, []uuid.UUID{roleA.ID}); err != nil {
		t.Fatalf("SetOrganizationMemberRoles A: %v", err)
	}
	if err := testEnv.Repo.SetOrganizationMemberRoles(ctx, mB.ID, []uuid.UUID{roleB.ID}); err != nil {
		t.Fatalf("SetOrganizationMemberRoles B: %v", err)
	}

	appOn, err := testEnv.Repo.GetAppByID(ctx, app.ID)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}
	svc := NewTestServices(t)
	ses := &core.ClientSession{ID: utils.NewUUID(), UserID: user.ID, AppID: &app.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now, OrganizationID: &orgB.ID}
	roles, _, m, err := svc.Handler.ResolveActiveRolesAndPermissionsForTest(ctx, &appOn, app.ProjectID, user.ID, ses)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(roles) != 1 || roles[0] != roleB.Slug || m == nil || m.OrgID != orgB.ID {
		t.Fatalf("pinned org B must yield only B's role; got roles=%v member=%v", roles, m)
	}
	for _, rr := range roles {
		if rr == roleA.Slug {
			t.Fatalf("org A role leaked into org B context")
		}
	}
}
