package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"manyrows-core/api"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
)

// On an org-enabled app, CheckPermission must reflect the user's permissions
// resolved through their ACTIVE org's roles, not the legacy per-app user_roles.
func TestCheckPermission_OrgScoped(t *testing.T) {
	router := setupClientAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "cp-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
	}()

	ctx := context.Background()
	now := time.Now().UTC()
	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, appID, true); err != nil {
		t.Fatalf("enable orgs: %v", err)
	}

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUserWithMembership: %v", err)
	}

	perm := core.Permission{ID: utils.NewUUID(), ProjectID: project.ID, Name: "Read Posts", Slug: "posts:read", CreatedAt: now, UpdatedAt: now}
	if err := testEnv.Repo.CreatePermission(ctx, perm); err != nil {
		t.Fatalf("CreatePermission: %v", err)
	}
	role, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{ProjectID: project.ID, Name: "Editor", Slug: GenerateUniqueSlug("editor"), Now: now})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := testEnv.Repo.ReplaceRolePermissions(ctx, repo.ReplaceRolePermissionsParams{ProjectID: project.ID, RoleID: role.ID, PermissionIDs: []uuid.UUID{perm.ID}, Now: now}); err != nil {
		t.Fatalf("ReplaceRolePermissions: %v", err)
	}

	org, err := testEnv.Repo.CreateOrganization(ctx, appID, "Acme", GenerateUniqueSlug("acme"), &user.ID)
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

	_, accessToken := createTestClientSessionForApp(t, ws, acc, &core.App{ID: appID})

	// Activate the org on the session (sets client_sessions.organization_id).
	swReq := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+appID.String()+"/a/session/organization",
		strings.NewReader(`{"organizationId":"`+org.ID.String()+`"}`))
	swReq.Header.Set("Authorization", "Bearer "+accessToken)
	swReq.Header.Set("Content-Type", "application/json")
	swRR := httptest.NewRecorder()
	router.ServeHTTP(swRR, swReq)
	if swRR.Code != http.StatusOK {
		t.Fatalf("switch: got %d (%s)", swRR.Code, swRR.Body.String())
	}

	check := func(permSlug string) bool {
		req := httptest.NewRequest(http.MethodGet,
			"/x/"+ws.Slug+"/apps/"+appID.String()+"/a/check-permission?permission="+permSlug, nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("check %q: got %d (%s)", permSlug, rr.Code, rr.Body.String())
		}
		var resp api.CheckPermissionResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("parse: %v", err)
		}
		return resp.Allowed
	}

	if !check("posts:read") {
		t.Errorf("expected posts:read allowed via org role")
	}
	if check("posts:delete") {
		t.Errorf("expected posts:delete NOT allowed")
	}
}
