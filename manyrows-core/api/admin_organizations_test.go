package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
	wsRouter.Post("/projects/{projectId}/apps/{appId}/organizations", svc.Handler.HandleCreateAppOrganization)
	wsRouter.Post("/projects/{projectId}/apps/{appId}/organizations/{orgId}/members", svc.Handler.HandleAddAppOrganizationMember)
	wsRouter.Get("/projects/{projectId}/apps/{appId}/organizations/{orgId}/invites", svc.Handler.HandleListAppOrganizationInvites)
	wsRouter.Post("/projects/{projectId}/apps/{appId}/organizations/{orgId}/invites", svc.Handler.HandleCreateAppOrganizationInvite)
	wsRouter.Delete("/projects/{projectId}/apps/{appId}/organizations/{orgId}/invites/{inviteId}", svc.Handler.HandleRevokeAppOrganizationInvite)
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

func TestAdminOrgs_CreateOrg(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "aco-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	post := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"name": "Acme Inc"})
		req := httptest.NewRequest(http.MethodPost, adminAppOrgBase(ws, app)+"/organizations", bytes.NewReader(body))
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	// Orgs disabled -> 409 (fail loud, like the server provisioning API).
	if rr := post(); rr.Code != http.StatusConflict {
		t.Fatalf("create with orgs disabled: expected 409, got %d (%s)", rr.Code, rr.Body.String())
	}
	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, app.ID, true); err != nil {
		t.Fatalf("enable orgs: %v", err)
	}

	rr := post()
	if rr.Code != http.StatusCreated {
		t.Fatalf("create org: expected 201, got %d (%s)", rr.Code, rr.Body.String())
	}
	var resp struct{ ID, Name, Slug, Status string }
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.ID == "" || resp.Name != "Acme Inc" || resp.Status != core.OrgStatusActive {
		t.Fatalf("unexpected create response: %+v", resp)
	}
	views, _ := testEnv.Repo.ListOrganizationsForApp(ctx, app.ID)
	found := false
	for _, v := range views {
		if v.ID.String() == resp.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("created org not in app list")
	}
}

func TestAdminOrgs_AddMember(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "aam-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})
	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, app.ID, true); err != nil {
		t.Fatalf("enable orgs: %v", err)
	}
	user, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "joiner-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), nil)

	post := func(payload map[string]any) *httptest.ResponseRecorder {
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, adminAppOrgBase(ws, app)+"/organizations/"+org.ID.String()+"/members", bytes.NewReader(body))
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	// Add an existing app user by email at admin tier.
	if rr := post(map[string]any{"email": user.Email, "orgRole": "admin"}); rr.Code != http.StatusCreated {
		t.Fatalf("add member: expected 201, got %d (%s)", rr.Code, rr.Body.String())
	}
	if m, _ := testEnv.Repo.GetOrganizationMember(ctx, org.ID, user.ID); m == nil || m.OrgRole != core.OrgRoleAdmin {
		t.Fatalf("expected admin member, got %+v", m)
	}
	// Re-add -> 409 (already a member).
	if rr := post(map[string]any{"email": user.Email}); rr.Code != http.StatusConflict {
		t.Fatalf("dup add: expected 409, got %d (%s)", rr.Code, rr.Body.String())
	}
	// Email that isn't an app user -> 409.
	if rr := post(map[string]any{"email": "ghost-" + GenerateUniqueSlug("g") + "@example.com"}); rr.Code != http.StatusConflict {
		t.Fatalf("unknown email: expected 409, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestAdminOrgs_Invites(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "ainv-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})
	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, app.ID, true); err != nil {
		t.Fatalf("enable orgs: %v", err)
	}
	// Invites need an app URL for the accept link.
	if _, err := testEnv.DB.Pool().Exec(ctx, "UPDATE apps SET app_url=$1 WHERE id=$2", "https://app.example.com", app.ID); err != nil {
		t.Fatalf("set app url: %v", err)
	}
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), nil)
	base := adminAppOrgBase(ws, app) + "/organizations/" + org.ID.String() + "/invites"

	// Create.
	email := "invitee-" + GenerateUniqueSlug("e") + "@example.com"
	body, _ := json.Marshal(map[string]any{"email": email, "orgRole": "member"})
	reqC := httptest.NewRequest(http.MethodPost, base, bytes.NewReader(body))
	testEnv.SetSessionCookie(t, reqC, claims)
	rrC := httptest.NewRecorder()
	router.ServeHTTP(rrC, reqC)
	if rrC.Code != http.StatusCreated {
		t.Fatalf("create invite: expected 201, got %d (%s)", rrC.Code, rrC.Body.String())
	}

	// List shows it.
	reqL := httptest.NewRequest(http.MethodGet, base, nil)
	testEnv.SetSessionCookie(t, reqL, claims)
	rrL := httptest.NewRecorder()
	router.ServeHTTP(rrL, reqL)
	if rrL.Code != http.StatusOK {
		t.Fatalf("list invites: expected 200, got %d (%s)", rrL.Code, rrL.Body.String())
	}
	var listResp struct {
		Invites []struct {
			ID      string `json:"id"`
			Email   string `json:"email"`
			OrgRole string `json:"orgRole"`
			Status  string `json:"status"`
		} `json:"invites"`
	}
	_ = json.Unmarshal(rrL.Body.Bytes(), &listResp)
	if len(listResp.Invites) != 1 || listResp.Invites[0].Email != email {
		t.Fatalf("expected 1 pending invite for %s, got %+v", email, listResp.Invites)
	}

	// Revoke.
	reqD := httptest.NewRequest(http.MethodDelete, base+"/"+listResp.Invites[0].ID, nil)
	testEnv.SetSessionCookie(t, reqD, claims)
	rrD := httptest.NewRecorder()
	router.ServeHTTP(rrD, reqD)
	if rrD.Code != http.StatusNoContent {
		t.Fatalf("revoke invite: expected 204, got %d (%s)", rrD.Code, rrD.Body.String())
	}
	if list, _, _ := testEnv.Repo.ListPendingOrgInvites(ctx, org.ID, 0, 200, ""); len(list) != 0 {
		t.Fatalf("expected 0 pending after revoke, got %d", len(list))
	}
}

func TestAdminOrgs_MutationsRejectArchivedOrg(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "amra-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})
	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, app.ID, true); err != nil {
		t.Fatalf("enable orgs: %v", err)
	}
	if _, err := testEnv.DB.Pool().Exec(ctx, "UPDATE apps SET app_url=$1 WHERE id=$2", "https://app.example.com", app.ID); err != nil {
		t.Fatalf("set app url: %v", err)
	}
	target, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "t-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	existing, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "e-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	role, _ := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{ProjectID: app.ProjectID, Name: "Ed", Slug: GenerateUniqueSlug("ed"), Now: time.Now().UTC()})
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), nil)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, existing.ID, core.OrgRoleMember)
	inv, _ := testEnv.Repo.CreateOrganizationInvite(ctx, org.ID, "p-"+GenerateUniqueSlug("e")+"@example.com", core.OrgRoleMember, nil, nil, "h-"+GenerateUniqueSlug("h"), time.Now().UTC().Add(72*time.Hour))
	if err := testEnv.Repo.ArchiveOrganization(ctx, org.ID); err != nil {
		t.Fatalf("archive: %v", err)
	}

	base := adminAppOrgBase(ws, app) + "/organizations/" + org.ID.String()
	do := func(method, path string, payload map[string]any) int {
		var rdr *bytes.Reader
		if payload != nil {
			b, _ := json.Marshal(payload)
			rdr = bytes.NewReader(b)
		} else {
			rdr = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, rdr)
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr.Code
	}

	// Every membership/invite mutation on an archived org must be refused (409).
	if c := do(http.MethodPost, base+"/members", map[string]any{"email": target.Email}); c != http.StatusConflict {
		t.Fatalf("add-member archived: want 409, got %d", c)
	}
	if c := do(http.MethodPost, base+"/invites", map[string]any{"email": "x-" + GenerateUniqueSlug("e") + "@example.com"}); c != http.StatusConflict {
		t.Fatalf("create-invite archived: want 409, got %d", c)
	}
	if c := do(http.MethodPatch, base+"/members/"+existing.ID.String(), map[string]any{"orgRole": "admin"}); c != http.StatusConflict {
		t.Fatalf("set-tier archived: want 409, got %d", c)
	}
	if c := do(http.MethodPut, base+"/members/"+existing.ID.String()+"/roles", map[string]any{"roleIds": []string{role.ID.String()}}); c != http.StatusConflict {
		t.Fatalf("set-roles archived: want 409, got %d", c)
	}
	if c := do(http.MethodDelete, base+"/members/"+existing.ID.String(), nil); c != http.StatusConflict {
		t.Fatalf("remove-member archived: want 409, got %d", c)
	}
	if c := do(http.MethodDelete, base+"/invites/"+inv.ID.String(), nil); c != http.StatusConflict {
		t.Fatalf("revoke-invite archived: want 409, got %d", c)
	}
}

func TestAdminOrgs_AddMemberRequiresOrgsEnabled(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "amroe-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc) // orgs disabled by default
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	user, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "u-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), nil) // active, but orgs feature off

	body, _ := json.Marshal(map[string]any{"email": user.Email})
	req := httptest.NewRequest(http.MethodPost, adminAppOrgBase(ws, app)+"/organizations/"+org.ID.String()+"/members", bytes.NewReader(body))
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("add-member with orgs disabled: want 409, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestAdminOrgs_RenameTooLong(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "artl-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), nil)

	body, _ := json.Marshal(map[string]any{"name": strings.Repeat("a", 201)}) // > maxOrgNameLen (200)
	req := httptest.NewRequest(http.MethodPatch, adminAppOrgBase(ws, app)+"/organizations/"+org.ID.String(), bytes.NewReader(body))
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("rename too long: want 400, got %d (%s)", rr.Code, rr.Body.String())
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
