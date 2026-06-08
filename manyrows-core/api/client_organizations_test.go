package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/core"
)

// clientOrgTestApp spins up an org-enabled app + an authed end-user session.
func clientOrgTestApp(t *testing.T) (ws *core.Workspace, app *core.App, user *core.User, accessToken string) {
	t.Helper()
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "cso-"+GenerateUniqueSlug("u")+"@example.com")
	ws = testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app = testEnv.CreateTestApp(t, ws, acc)
	t.Cleanup(func() { testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws}) })
	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, app.ID, true); err != nil {
		t.Fatalf("enable orgs: %v", err)
	}
	reloaded, err := testEnv.Repo.GetAppByID(ctx, app.ID)
	if err != nil {
		t.Fatalf("reload app: %v", err)
	}
	app = &reloaded
	u, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	user = u
	_, accessToken = createTestClientSessionForApp(t, ws, acc, app)
	return ws, app, user, accessToken
}

func clientOrgURL(ws *core.Workspace, app *core.App, suffix string) string {
	return "/x/" + ws.Slug + "/apps/" + app.ID.String() + "/a/organizations" + suffix
}

func TestClientListOrgMembers_MemberOK_NonMember404(t *testing.T) {
	ctx := context.Background()
	ws, app, owner, ownerTok := clientOrgTestApp(t)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)

	router := setupClientAPIRouter(t)

	// Member (owner) -> 200 with members.
	req := httptest.NewRequest(http.MethodGet, clientOrgURL(ws, app, "/"+org.ID.String()+"/members"), nil)
	req.Header.Set("Authorization", "Bearer "+ownerTok)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("member list: got %d (%s)", rr.Code, rr.Body.String())
	}

	// Same-app user who is NOT a member of this org -> 404 (gate must not leak existence).
	acc2 := testEnv.CreateTestAccount(t, "nm-"+GenerateUniqueSlug("u")+"@example.com")
	_, _, _ = testEnv.GetOrCreateUserWithMembership(ctx, acc2.Email, app, core.UserSourceInvited)
	_, otherTok := createTestClientSessionForApp(t, ws, acc2, app)
	req3 := httptest.NewRequest(http.MethodGet, clientOrgURL(ws, app, "/"+org.ID.String()+"/members"), nil)
	req3.Header.Set("Authorization", "Bearer "+otherTok)
	rr3 := httptest.NewRecorder()
	router.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusNotFound {
		t.Fatalf("same-app non-member must be 404, got %d (%s)", rr3.Code, rr3.Body.String())
	}
}

func TestClientListOrganizations(t *testing.T) {
	ctx := context.Background()
	ws, app, user, token := clientOrgTestApp(t)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &user.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, user.ID, core.OrgRoleOwner)

	router := setupClientAPIRouter(t)
	req := httptest.NewRequest(http.MethodGet, clientOrgURL(ws, app, ""), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("list: got %d (%s)", rr.Code, rr.Body.String())
	}
	var out struct {
		Organizations []core.OrganizationMembershipView `json:"organizations"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Organizations) != 1 || out.Organizations[0].OrgRole != core.OrgRoleOwner {
		t.Fatalf("expected 1 owned org, got %+v", out.Organizations)
	}
}
