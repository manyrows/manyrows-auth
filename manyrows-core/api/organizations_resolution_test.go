package api_test

import (
	"context"
	"testing"

	"manyrows-core/core"
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
