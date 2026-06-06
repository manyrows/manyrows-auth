package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/core"
	"manyrows-core/core/repo"

	"github.com/go-chi/chi/v5"
)

func setupAdminOrgRouter(t *testing.T) (*chi.Mux, *TestServices) {
	t.Helper()
	svc := NewTestServices(t)
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)
	wsRouter.Put("/projects/{projectId}/apps/{appId}/organizations-enabled", svc.Handler.HandleUpdateAppOrganizationsEnabled)
	wsRouter.Get("/projects/{projectId}/apps/{appId}/organizations", svc.Handler.HandleListAppOrganizations)
	wsRouter.Get("/projects/{projectId}/apps/{appId}/organizations/{orgId}/members", svc.Handler.HandleListAppOrganizationMembers)
	wsRouter.Patch("/projects/{projectId}/apps/{appId}/organizations/{orgId}", svc.Handler.HandleRenameAppOrganization)
	wsRouter.Delete("/projects/{projectId}/apps/{appId}/organizations/{orgId}", svc.Handler.HandleArchiveAppOrganization)
	return r, svc
}

func adminAppOrgBase(ws *core.Workspace, app *core.App) string {
	return "/admin/workspace/" + ws.ID.String() + "/projects/" + app.ProjectID.String() + "/apps/" + app.ID.String()
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
}
