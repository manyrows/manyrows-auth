package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
)

func setupAdminOrgRouter(t *testing.T) (*chi.Mux, *TestServices) {
	t.Helper()
	svc := NewTestServices(t)
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)
	wsRouter.Put("/projects/{projectId}/apps/{appId}/organizations-enabled", svc.Handler.HandleUpdateAppOrganizationsEnabled)
	wsRouter.Get("/projects/{projectId}/apps/{appId}/organizations", svc.Handler.HandleListAppOrganizations)
	wsRouter.Get("/projects/{projectId}/apps/{appId}/organizations/{orgId}/members", svc.Handler.HandleListAppOrganizationMembers)
	wsRouter.Put("/projects/{projectId}/apps/{appId}/organizations/{orgId}/members/{userId}/roles", svc.Handler.HandleSetAppOrganizationMemberRoles)
	wsRouter.Put("/projects/{projectId}/apps/{appId}/organizations-creation-policy", svc.Handler.HandleUpdateAppOrgCreationPolicy)
	wsRouter.Patch("/projects/{projectId}/apps/{appId}/organizations/{orgId}/members/{userId}", svc.Handler.HandleSetAppOrganizationMemberTier)
	wsRouter.Delete("/projects/{projectId}/apps/{appId}/organizations/{orgId}/members/{userId}", svc.Handler.HandleRemoveAppOrganizationMember)
	wsRouter.Patch("/projects/{projectId}/apps/{appId}/organizations/{orgId}", svc.Handler.HandleRenameAppOrganization)
	wsRouter.Delete("/projects/{projectId}/apps/{appId}/organizations/{orgId}", svc.Handler.HandleArchiveAppOrganization)
	wsRouter.Post("/projects/{projectId}/apps/{appId}/organizations/{orgId}/restore", svc.Handler.HandleRestoreAppOrganization)
	wsRouter.Delete("/projects/{projectId}/apps/{appId}/organizations/{orgId}/permanent", svc.Handler.HandleDeleteAppOrganization)
	return r, svc
}

func adminAppOrgBase(ws *core.Workspace, app *core.App) string {
	return "/admin/workspace/" + ws.ID.String() + "/projects/" + app.ProjectID.String() + "/apps/" + app.ID.String()
}

func TestAdminOrgs_SetMemberRoles(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "asmr-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	editor, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{ProjectID: app.ProjectID, Name: "Editor", Slug: GenerateUniqueSlug("ed"), Now: time.Now().UTC()})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	member, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "m-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &member.ID)
	om, _ := testEnv.Repo.AddOrganizationMember(ctx, org.ID, member.ID, core.OrgRoleMember)

	put := func(roleIDs []string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"roleIds": roleIDs})
		req := httptest.NewRequest(http.MethodPut, adminAppOrgBase(ws, app)+"/organizations/"+org.ID.String()+"/members/"+member.ID.String()+"/roles", bytes.NewReader(body))
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	// Assign EDITOR -> 204, role persisted.
	if rr := put([]string{editor.ID.String()}); rr.Code != http.StatusNoContent {
		t.Fatalf("assign role: expected 204, got %d (%s)", rr.Code, rr.Body.String())
	}
	if got, _ := testEnv.Repo.GetOrgMemberRoleIDs(ctx, om.ID); len(got) != 1 || got[0] != editor.ID {
		t.Fatalf("expected EDITOR assigned, got %v", got)
	}

	// Stray role id (not in the app's project) -> 400.
	if rr := put([]string{utils.NewUUID().String()}); rr.Code != http.StatusBadRequest {
		t.Fatalf("stray role id: expected 400, got %d (%s)", rr.Code, rr.Body.String())
	}

	// Empty set clears the assignment -> 204, no roles.
	if rr := put([]string{}); rr.Code != http.StatusNoContent {
		t.Fatalf("clear roles: expected 204, got %d (%s)", rr.Code, rr.Body.String())
	}
	if got, _ := testEnv.Repo.GetOrgMemberRoleIDs(ctx, om.ID); len(got) != 0 {
		t.Fatalf("expected roles cleared, got %v", got)
	}
}

func TestAdminOrgs_SetCreationPolicy(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "acp-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	put := func(policy string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"orgCreationPolicy": policy})
		req := httptest.NewRequest(http.MethodPut, adminAppOrgBase(ws, app)+"/organizations-creation-policy", bytes.NewReader(body))
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	// Valid policy -> 200 + persisted (proves self_serve is now reachable).
	rr := put(core.OrgCreationSelfServe)
	if rr.Code != http.StatusOK {
		t.Fatalf("set policy: expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		OrgCreationPolicy string `json:"orgCreationPolicy"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.OrgCreationPolicy != core.OrgCreationSelfServe {
		t.Fatalf("expected self_serve in response, got %q", resp.OrgCreationPolicy)
	}
	if reloaded, _ := testEnv.Repo.GetAppByID(ctx, app.ID); reloaded.OrgCreationPolicy != core.OrgCreationSelfServe {
		t.Fatalf("expected DB policy self_serve, got %q", reloaded.OrgCreationPolicy)
	}

	// Invalid policy -> 400.
	if rr := put("whatever"); rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid policy: expected 400, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestAdminOrgs_SetMemberTier(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "asmt-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)
	member, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "m-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, member.ID, core.OrgRoleMember)

	patch := func(userID, role string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"orgRole": role})
		req := httptest.NewRequest(http.MethodPatch, adminAppOrgBase(ws, app)+"/organizations/"+org.ID.String()+"/members/"+userID, bytes.NewReader(body))
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	// Promote member -> owner: 204 (admin operates above the org, no tier guard
	// beyond last-owner).
	if rr := patch(member.ID.String(), core.OrgRoleOwner); rr.Code != http.StatusNoContent {
		t.Fatalf("promote member->owner: expected 204, got %d (%s)", rr.Code, rr.Body.String())
	}
	if m, _ := testEnv.Repo.GetOrganizationMember(ctx, org.ID, member.ID); m == nil || m.OrgRole != core.OrgRoleOwner {
		t.Fatalf("expected member promoted to owner, got %+v", m)
	}
	// Two owners now — demoting the original owner is fine: 204.
	if rr := patch(owner.ID.String(), core.OrgRoleMember); rr.Code != http.StatusNoContent {
		t.Fatalf("demote owner (2 owners): expected 204, got %d (%s)", rr.Code, rr.Body.String())
	}
	// `member` is now the last owner — demoting them must 409.
	if rr := patch(member.ID.String(), core.OrgRoleMember); rr.Code != http.StatusConflict {
		t.Fatalf("demote last owner: expected 409, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestAdminOrgs_RemoveMember(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "arm-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)
	member, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "m-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, member.ID, core.OrgRoleMember)

	del := func(userID string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, adminAppOrgBase(ws, app)+"/organizations/"+org.ID.String()+"/members/"+userID, nil)
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	// Remove the plain member: 204, gone.
	if rr := del(member.ID.String()); rr.Code != http.StatusNoContent {
		t.Fatalf("remove member: expected 204, got %d (%s)", rr.Code, rr.Body.String())
	}
	if _, err := testEnv.Repo.GetOrganizationMember(ctx, org.ID, member.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("member should be gone, got err=%v", err)
	}
	// Removing the last owner must 409.
	if rr := del(owner.ID.String()); rr.Code != http.StatusConflict {
		t.Fatalf("remove last owner: expected 409, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestAdminOrgs_EnableToggle(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "aoe-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	put := func(enabled bool) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"organizationsEnabled": enabled})
		req := httptest.NewRequest(http.MethodPut, adminAppOrgBase(ws, app)+"/organizations-enabled", bytes.NewReader(body))
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	rr := put(true)
	if rr.Code != http.StatusOK {
		t.Fatalf("enable: expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		OrganizationsEnabled bool `json:"organizationsEnabled"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if !resp.OrganizationsEnabled {
		t.Fatalf("expected organizationsEnabled=true in response")
	}
	reloaded, err := testEnv.Repo.GetAppByID(ctx, app.ID)
	if err != nil || !reloaded.OrganizationsEnabled {
		t.Fatalf("expected DB flag true, err=%v", err)
	}

	rr = put(false)
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if rr.Code != http.StatusOK || resp.OrganizationsEnabled {
		t.Fatalf("disable: expected 200 + false, got %d %v", rr.Code, resp.OrganizationsEnabled)
	}
}

func TestAdminOrgs_EnableToggle_SyncsWholeProject(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "aoesync-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc) // "dev" app + a fresh project
	// A sibling app ("staging") in the SAME project.
	pool2, err := testEnv.Repo.CreateUserPool(ctx, ws.ID, "Pool2 "+GenerateUniqueSlug("pool"))
	if err != nil {
		t.Fatalf("pool2: %v", err)
	}
	sibling, err := testEnv.Repo.InsertApp(ctx, core.App{
		WorkspaceID:       ws.ID,
		ProjectID:         app.ProjectID,
		UserPoolID:        pool2.ID,
		Type:              "staging",
		Enabled:           true,
		PrimaryAuthMethod: core.PrimaryAuthMethodPassword,
	})
	if err != nil {
		t.Fatalf("insert sibling: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM apps WHERE id = $1", sibling.ID)
		_, _ = testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM user_pools WHERE id = $1", pool2.ID)
	})
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	put := func(target *core.App, enabled bool) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"organizationsEnabled": enabled})
		req := httptest.NewRequest(http.MethodPut, adminAppOrgBase(ws, target)+"/organizations-enabled", bytes.NewReader(body))
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	// Enabling via ONE app's endpoint enables orgs across the whole project.
	rr := put(app, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("enable: expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		OrganizationsEnabled bool `json:"organizationsEnabled"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if !resp.OrganizationsEnabled {
		t.Fatalf("response for the addressed app should be enabled")
	}
	for _, a := range []*core.App{app, &sibling} {
		got, err := testEnv.Repo.GetAppByID(ctx, a.ID)
		if err != nil || !got.OrganizationsEnabled {
			t.Fatalf("app %s expected enabled after project toggle, err=%v", a.ID, err)
		}
	}

	// Disabling via the SIBLING's endpoint turns the whole project back off.
	if rr := put(&sibling, false); rr.Code != http.StatusOK {
		t.Fatalf("disable: expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	for _, a := range []*core.App{app, &sibling} {
		if got, _ := testEnv.Repo.GetAppByID(ctx, a.ID); got.OrganizationsEnabled {
			t.Fatalf("app %s expected disabled after project toggle off", a.ID)
		}
	}
}

func TestAdminOrgs_EnableMissingField_400(t *testing.T) {
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "aoe2-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	req := httptest.NewRequest(http.MethodPut, adminAppOrgBase(ws, app)+"/organizations-enabled", bytes.NewReader([]byte(`{}`)))
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing field, got %d (%s)", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("error.badRequest")) {
		t.Fatalf("expected error.badRequest, got %s", rr.Body.String())
	}
}

func TestAdminOrgs_List(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "aol-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	owner, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)

	req := httptest.NewRequest(http.MethodGet, adminAppOrgBase(ws, app)+"/organizations", nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		Organizations []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Status      string `json:"status"`
			MemberCount int    `json:"memberCount"`
		} `json:"organizations"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Organizations) != 1 || resp.Organizations[0].ID != org.ID.String() {
		t.Fatalf("expected 1 org %s, got %+v", org.ID, resp.Organizations)
	}
	if resp.Organizations[0].MemberCount != 1 || resp.Organizations[0].Status != core.OrgStatusActive {
		t.Fatalf("expected 1 active member + active status, got %+v", resp.Organizations[0])
	}
}

func TestAdminOrgs_ListMembers(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "aom-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	ownerEmail := "own-" + GenerateUniqueSlug("u") + "@example.com"
	owner, _, _ := testEnv.Repo.GetOrCreateUser(ctx, ownerEmail, app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)

	req := httptest.NewRequest(http.MethodGet, adminAppOrgBase(ws, app)+"/organizations/"+org.ID.String()+"/members", nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		Members []repo.OrganizationMemberView `json:"members"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Members) != 1 || resp.Members[0].Email != ownerEmail || resp.Members[0].OrgRole != core.OrgRoleOwner {
		t.Fatalf("expected 1 owner member %s, got %+v", ownerEmail, resp.Members)
	}
}

func TestAdminOrgs_CrossAppOrg_404(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "aox-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	appA := testEnv.CreateTestApp(t, ws, acc)
	appB := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	owner, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", appB, core.UserSourceInvited)
	orgB, _ := testEnv.Repo.CreateOrganization(ctx, appB.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)

	req := httptest.NewRequest(http.MethodGet, adminAppOrgBase(ws, appA)+"/organizations/"+orgB.ID.String()+"/members", nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for cross-app org, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestAdminOrgs_Rename_KeepsSlug(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "aor-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	owner, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Old Name", GenerateUniqueSlug("acme"), &owner.ID)
	originalSlug := org.Slug

	body, _ := json.Marshal(map[string]string{"name": "New Name"})
	req := httptest.NewRequest(http.MethodPatch, adminAppOrgBase(ws, app)+"/organizations/"+org.ID.String(), bytes.NewReader(body))
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Name != "New Name" {
		t.Fatalf("expected renamed to New Name, got %q", resp.Name)
	}
	if resp.Slug != originalSlug {
		t.Fatalf("expected slug unchanged %q, got %q", originalSlug, resp.Slug)
	}
}

func TestAdminOrgs_Archive_Idempotent(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "aoa-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	owner, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)

	del := func() int {
		req := httptest.NewRequest(http.MethodDelete, adminAppOrgBase(ws, app)+"/organizations/"+org.ID.String(), nil)
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr.Code
	}
	if code := del(); code != http.StatusNoContent {
		t.Fatalf("archive: expected 204, got %d", code)
	}
	reloaded, err := testEnv.Repo.GetOrganizationByID(ctx, org.ID)
	if err != nil || reloaded.Status != core.OrgStatusArchived {
		t.Fatalf("expected archived status, err=%v status=%v", err, reloaded)
	}
	if code := del(); code != http.StatusNoContent {
		t.Fatalf("re-archive: expected 204 (idempotent), got %d", code)
	}
}

func TestAdminOrgs_ForeignApp_404(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)

	accA := testEnv.CreateTestAccount(t, "fa-a-"+GenerateUniqueSlug("u")+"@example.com")
	wsA := testEnv.CreateTestWorkspace(t, accA, "WSA", GenerateUniqueSlug("ws"))
	sessA, claimsA := testEnv.CreateTestSession(t, accA)

	accB := testEnv.CreateTestAccount(t, "fa-b-"+GenerateUniqueSlug("u")+"@example.com")
	wsB := testEnv.CreateTestWorkspace(t, accB, "WSB", GenerateUniqueSlug("ws"))
	appB := testEnv.CreateTestApp(t, wsB, accB)

	defer testEnv.CleanupTestData(t, &TestFixtures{Account: accA, Workspace: wsA, Session: sessA})
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: accB, Workspace: wsB})

	owner, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", appB, core.UserSourceInvited)
	orgB, _ := testEnv.Repo.CreateOrganization(ctx, appB.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, orgB.ID, owner.ID, core.OrgRoleOwner)

	// A's workspace (accA is a member) but B's project + app + org in the path.
	base := "/admin/workspace/" + wsA.ID.String() + "/projects/" + appB.ProjectID.String() + "/apps/" + appB.ID.String()

	hit := func(method, path string, withBody bool) int {
		var rr *httptest.ResponseRecorder
		if withBody {
			req := httptest.NewRequest(method, path, bytes.NewReader([]byte(`{"name":"x"}`)))
			testEnv.SetSessionCookie(t, req, claimsA)
			rr = httptest.NewRecorder()
			router.ServeHTTP(rr, req)
		} else {
			req := httptest.NewRequest(method, path, nil)
			testEnv.SetSessionCookie(t, req, claimsA)
			rr = httptest.NewRecorder()
			router.ServeHTTP(rr, req)
		}
		return rr.Code
	}

	if code := hit(http.MethodGet, base+"/organizations", false); code != http.StatusNotFound {
		t.Fatalf("list foreign app: expected 404, got %d", code)
	}
	if code := hit(http.MethodGet, base+"/organizations/"+orgB.ID.String()+"/members", false); code != http.StatusNotFound {
		t.Fatalf("members foreign app: expected 404, got %d", code)
	}
	if code := hit(http.MethodPatch, base+"/organizations/"+orgB.ID.String(), true); code != http.StatusNotFound {
		t.Fatalf("rename foreign app: expected 404, got %d", code)
	}
	if code := hit(http.MethodDelete, base+"/organizations/"+orgB.ID.String(), false); code != http.StatusNotFound {
		t.Fatalf("archive foreign app: expected 404, got %d", code)
	}
	if code := hit(http.MethodPost, base+"/organizations/"+orgB.ID.String()+"/restore", false); code != http.StatusNotFound {
		t.Fatalf("restore foreign app: expected 404, got %d", code)
	}
	if code := hit(http.MethodDelete, base+"/organizations/"+orgB.ID.String()+"/permanent", false); code != http.StatusNotFound {
		t.Fatalf("delete foreign app: expected 404, got %d", code)
	}
}

func TestAdminOrgs_DeletePermanent(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "aodp-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	owner, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	if err := testEnv.Repo.ArchiveOrganization(ctx, org.ID); err != nil {
		t.Fatalf("archive setup: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, adminAppOrgBase(ws, app)+"/organizations/"+org.ID.String()+"/permanent", nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d (%s)", rr.Code, rr.Body.String())
	}
	if _, err := testEnv.Repo.GetOrganizationByID(ctx, org.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("expected org gone (ErrNotFound), got %v", err)
	}
}

func TestAdminOrgs_DeleteActive_409(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "aoda-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	owner, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	// NOT archived — delete must be refused with 409.

	req := httptest.NewRequest(http.MethodDelete, adminAppOrgBase(ws, app)+"/organizations/"+org.ID.String()+"/permanent", nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("delete active: expected 409, got %d", rr.Code)
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("error.organizationNotArchived")) {
		t.Fatalf("expected error.organizationNotArchived in body, got %s", rr.Body.String())
	}
	if _, err := testEnv.Repo.GetOrganizationByID(ctx, org.ID); err != nil {
		t.Fatalf("expected org to still exist, got err %v", err)
	}
}

func TestAdminOrgs_Restore(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "aore-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	owner, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	if err := testEnv.Repo.ArchiveOrganization(ctx, org.ID); err != nil {
		t.Fatalf("archive setup: %v", err)
	}

	post := func() int {
		req := httptest.NewRequest(http.MethodPost, adminAppOrgBase(ws, app)+"/organizations/"+org.ID.String()+"/restore", nil)
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr.Code
	}
	if code := post(); code != http.StatusNoContent {
		t.Fatalf("restore: expected 204, got %d", code)
	}
	reloaded, err := testEnv.Repo.GetOrganizationByID(ctx, org.ID)
	if err != nil || reloaded.Status != core.OrgStatusActive {
		t.Fatalf("expected active status, err=%v status=%v", err, reloaded)
	}
	if code := post(); code != http.StatusNoContent {
		t.Fatalf("re-restore: expected 204 (idempotent), got %d", code)
	}
}
