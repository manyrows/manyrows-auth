package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/core"

	"github.com/go-chi/chi/v5"
)

// setupAdminUserOrgsRouter registers the user-organizations endpoint under the
// standard admin/workspace scaffold (mirrors setupInsightsRouter).
func setupAdminUserOrgsRouter(t *testing.T) *chi.Mux {
	t.Helper()
	svc := NewTestServices(t)
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)
	wsRouter.Route("/projects/{projectId}/apps/{appId}", func(r chi.Router) {
		r.Get("/users/{userId}/organizations", svc.Handler.HandleAdminUserOrganizations)
	})
	return r
}

func hitUserOrgs(t *testing.T, router *chi.Mux, ws *core.Workspace, app *core.App, userID string, claims core.TokenClaims) *httptest.ResponseRecorder {
	t.Helper()
	url := fmt.Sprintf("/admin/workspace/%s/projects/%s/apps/%s/users/%s/organizations",
		ws.ID, app.ProjectID, app.ID, userID)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// TestAdminUserOrganizations_ListsMemberships verifies that the endpoint returns
// both orgs the user belongs to (with correct names and org roles).
func TestAdminUserOrganizations_ListsMemberships(t *testing.T) {
	ctx := context.Background()
	router := setupAdminUserOrgsRouter(t)

	acc := testEnv.CreateTestAccount(t, "auol-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, app.ID, true); err != nil {
		t.Fatalf("enable orgs: %v", err)
	}

	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, "orgu-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}

	org1, err := testEnv.Repo.CreateOrganization(ctx, app.ID, "Alpha Corp", GenerateUniqueSlug("alpha"), nil)
	if err != nil {
		t.Fatalf("CreateOrganization alpha: %v", err)
	}
	org2, err := testEnv.Repo.CreateOrganization(ctx, app.ID, "Beta LLC", GenerateUniqueSlug("beta"), nil)
	if err != nil {
		t.Fatalf("CreateOrganization beta: %v", err)
	}

	if _, err := testEnv.Repo.AddOrganizationMember(ctx, org1.ID, user.ID, core.OrgRoleOwner); err != nil {
		t.Fatalf("AddOrganizationMember org1: %v", err)
	}
	if _, err := testEnv.Repo.AddOrganizationMember(ctx, org2.ID, user.ID, core.OrgRoleMember); err != nil {
		t.Fatalf("AddOrganizationMember org2: %v", err)
	}

	rr := hitUserOrgs(t, router, ws, app, user.ID.String(), claims)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Organizations []core.OrganizationMembershipView `json:"organizations"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Organizations) != 2 {
		t.Fatalf("expected 2 orgs, got %d: %+v", len(resp.Organizations), resp.Organizations)
	}

	// ListOrganizationsForUserInApp returns results ordered by name ASC.
	// "Alpha Corp" < "Beta LLC"
	if resp.Organizations[0].Name != "Alpha Corp" || resp.Organizations[0].OrgRole != core.OrgRoleOwner {
		t.Errorf("org[0]: got name=%q role=%q, want Alpha Corp/owner", resp.Organizations[0].Name, resp.Organizations[0].OrgRole)
	}
	if resp.Organizations[1].Name != "Beta LLC" || resp.Organizations[1].OrgRole != core.OrgRoleMember {
		t.Errorf("org[1]: got name=%q role=%q, want Beta LLC/member", resp.Organizations[1].Name, resp.Organizations[1].OrgRole)
	}
}

// TestAdminUserOrganizations_EmptyForNonMember verifies that a user in no orgs
// gets a 200 with an empty (non-null) organizations array.
func TestAdminUserOrganizations_EmptyForNonMember(t *testing.T) {
	ctx := context.Background()
	router := setupAdminUserOrgsRouter(t)

	acc := testEnv.CreateTestAccount(t, "auoe-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, app.ID, true); err != nil {
		t.Fatalf("enable orgs: %v", err)
	}

	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, "empty-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}

	rr := hitUserOrgs(t, router, ws, app, user.ID.String(), claims)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	// Must decode to a proper empty array, not null.
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	raw, ok := resp["organizations"]
	if !ok {
		t.Fatal("response missing 'organizations' key")
	}
	if string(raw) == "null" {
		t.Errorf("organizations must be [] not null, got: %s", raw)
	}
	var orgs []core.OrganizationMembershipView
	if err := json.Unmarshal(raw, &orgs); err != nil {
		t.Fatalf("decode organizations: %v", err)
	}
	if len(orgs) != 0 {
		t.Errorf("expected 0 orgs, got %d", len(orgs))
	}
}
