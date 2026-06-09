package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"

	"github.com/gofrs/uuid/v5"
)

// PUT /organizations/{orgId}/members/{userId}/roles sets a member's project
// roles via the server API (previously only the tier could be set server-side).
func TestServerSetOrgMemberRoles(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "smr-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	member, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "mem-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, member.ID, core.OrgRoleMember)

	role, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{
		ProjectID: app.ProjectID, Name: "Editor", Slug: GenerateUniqueSlug("ed"), Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	router := setupServerOrgRouter(t, ws, app)
	rolesURL := orgBase(app) + "/" + org.ID.String() + "/members/" + member.ID.String() + "/roles"

	put := func(roleIDs []string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"roleIds": roleIDs})
		req := httptest.NewRequest(http.MethodPut, rolesURL, bytes.NewReader(body))
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	// Happy path: assign the role → 204, and the member actually has it.
	if rr := put([]string{role.ID.String()}); rr.Code != http.StatusNoContent {
		t.Fatalf("set roles: expected 204, got %d (%s)", rr.Code, rr.Body.String())
	}
	m, err := testEnv.Repo.GetOrganizationMember(ctx, org.ID, member.ID)
	if err != nil {
		t.Fatalf("load membership: %v", err)
	}
	roleIDs, err := testEnv.Repo.GetOrgMemberRoleIDs(ctx, m.ID)
	if err != nil {
		t.Fatalf("get member role ids: %v", err)
	}
	found := false
	for _, id := range roleIDs {
		if id == role.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("member should have the assigned role after the set call; got %v", roleIDs)
	}

	// A role id that isn't in this project → 400.
	if rr := put([]string{uuid.Must(uuid.NewV4()).String()}); rr.Code != http.StatusBadRequest {
		t.Fatalf("stray role id: expected 400, got %d (%s)", rr.Code, rr.Body.String())
	}

	// Setting roles for a user who isn't a member → 404.
	stranger := uuid.Must(uuid.NewV4())
	strangerURL := orgBase(app) + "/" + org.ID.String() + "/members/" + stranger.String() + "/roles"
	body, _ := json.Marshal(map[string]any{"roleIds": []string{}})
	req := httptest.NewRequest(http.MethodPut, strangerURL, bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("non-member: expected 404, got %d (%s)", rr.Code, rr.Body.String())
	}
}
