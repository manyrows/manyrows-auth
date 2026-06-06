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
