package api_test

import (
	"context"
	"errors"
	"testing"

	"manyrows-core/core"
	"manyrows-core/core/repo"

	"github.com/gofrs/uuid/v5"
)

func TestListOrganizationsForApp_CountsAndIncludesArchived(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "loa-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	member, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "mem-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)

	active, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Active Org", GenerateUniqueSlug("a"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, active.ID, owner.ID, core.OrgRoleOwner)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, active.ID, member.ID, core.OrgRoleMember)

	archived, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Archived Org", GenerateUniqueSlug("z"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, archived.ID, owner.ID, core.OrgRoleOwner)
	if err := testEnv.Repo.ArchiveOrganization(ctx, archived.ID); err != nil {
		t.Fatalf("archive: %v", err)
	}

	list, err := testEnv.Repo.ListOrganizationsForApp(ctx, app.ID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 orgs, got %d", len(list))
	}
	activeCount := -1
	archivedStatus := ""
	for _, v := range list {
		if v.ID == active.ID {
			activeCount = v.MemberCount
		}
		if v.ID == archived.ID {
			archivedStatus = v.Status
		}
	}
	if activeCount != 2 {
		t.Fatalf("active org expected 2 active members, got %d", activeCount)
	}
	if archivedStatus != core.OrgStatusArchived {
		t.Fatalf("archived org expected status archived, got %q", archivedStatus)
	}
}

func TestUpdateAppOrganizationsEnabled_ScopedGuard(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "uoe-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	out, err := testEnv.Repo.UpdateAppOrganizationsEnabled(ctx, ws.ID, app.ProjectID, app.ID, true)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !out.OrganizationsEnabled {
		t.Fatalf("expected OrganizationsEnabled true")
	}

	foreign := uuid.Must(uuid.NewV4())
	if _, err := testEnv.Repo.UpdateAppOrganizationsEnabled(ctx, foreign, app.ProjectID, app.ID, false); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for foreign workspace, got %v", err)
	}
}
