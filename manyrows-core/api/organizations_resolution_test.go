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
