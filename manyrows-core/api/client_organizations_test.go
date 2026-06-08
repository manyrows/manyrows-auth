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
