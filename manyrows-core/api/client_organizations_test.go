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
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
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

func setClientOrgCreationPolicy(t *testing.T, appID uuid.UUID, policy string) *core.App {
	t.Helper()
	ctx := context.Background()
	if _, err := testEnv.DB.Pool().Exec(ctx, "UPDATE apps SET org_creation_policy=$1 WHERE id=$2", policy, appID); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	a, err := testEnv.Repo.GetAppByID(ctx, appID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	return &a
}

func TestClientCreateOrganization_SelfServe(t *testing.T) {
	ctx := context.Background()
	ws, app, user, token := clientOrgTestApp(t)
	setClientOrgCreationPolicy(t, app.ID, core.OrgCreationSelfServe)

	router := setupClientAPIRouter(t)
	body, _ := json.Marshal(map[string]string{"name": "Acme Inc"})
	req := httptest.NewRequest(http.MethodPost, clientOrgURL(ws, app, ""), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: got %d (%s)", rr.Code, rr.Body.String())
	}
	var org struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &org)
	m, err := testEnv.Repo.GetOrganizationMember(ctx, mustUUID(t, org.ID), user.ID)
	if err != nil || m.OrgRole != core.OrgRoleOwner || m.Status != core.OrgMemberStatusActive {
		t.Fatalf("creator must be active owner: %+v err=%v", m, err)
	}
}

func TestClientCreateOrganization_InviteOnly_403(t *testing.T) {
	ws, app, _, token := clientOrgTestApp(t)
	setClientOrgCreationPolicy(t, app.ID, core.OrgCreationInviteOnly)
	router := setupClientAPIRouter(t)
	body, _ := json.Marshal(map[string]string{"name": "Nope"})
	req := httptest.NewRequest(http.MethodPost, clientOrgURL(ws, app, ""), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("invite_only create must be 403, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestClientArchiveOrganization(t *testing.T) {
	ctx := context.Background()
	ws, app, owner, ownerTok := clientOrgTestApp(t)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)
	acc2 := testEnv.CreateTestAccount(t, "adm-"+GenerateUniqueSlug("u")+"@example.com")
	adm, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, acc2.Email, app, core.UserSourceInvited)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, adm.ID, core.OrgRoleAdmin)
	_, admTok := createTestClientSessionForApp(t, ws, acc2, app)

	router := setupClientAPIRouter(t)
	// admin -> 403 (owner-only)
	reqA := httptest.NewRequest(http.MethodDelete, clientOrgURL(ws, app, "/"+org.ID.String()), nil)
	reqA.Header.Set("Authorization", "Bearer "+admTok)
	rrA := httptest.NewRecorder()
	router.ServeHTTP(rrA, reqA)
	if rrA.Code != http.StatusForbidden {
		t.Fatalf("admin archive must be 403, got %d", rrA.Code)
	}
	// owner -> 204 + archived
	req := httptest.NewRequest(http.MethodDelete, clientOrgURL(ws, app, "/"+org.ID.String()), nil)
	req.Header.Set("Authorization", "Bearer "+ownerTok)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("owner archive: got %d (%s)", rr.Code, rr.Body.String())
	}
	got, _ := testEnv.Repo.GetOrganizationByID(ctx, org.ID)
	if got.Status != core.OrgStatusArchived {
		t.Fatalf("expected archived, got %q", got.Status)
	}
}

func TestClientRenameOrganization(t *testing.T) {
	ctx := context.Background()
	ws, app, owner, ownerTok := clientOrgTestApp(t)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Old", GenerateUniqueSlug("old"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)
	// plain member
	acc2 := testEnv.CreateTestAccount(t, "mem-"+GenerateUniqueSlug("u")+"@example.com")
	mem, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, acc2.Email, app, core.UserSourceInvited)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, mem.ID, core.OrgRoleMember)
	_, memTok := createTestClientSessionForApp(t, ws, acc2, app)

	router := setupClientAPIRouter(t)
	body, _ := json.Marshal(map[string]string{"name": "New Name"})

	req := httptest.NewRequest(http.MethodPatch, clientOrgURL(ws, app, "/"+org.ID.String()), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ownerTok)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("owner rename: got %d (%s)", rr.Code, rr.Body.String())
	}

	body2, _ := json.Marshal(map[string]string{"name": "Hacked"})
	req2 := httptest.NewRequest(http.MethodPatch, clientOrgURL(ws, app, "/"+org.ID.String()), bytes.NewReader(body2))
	req2.Header.Set("Authorization", "Bearer "+memTok)
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("member rename must be 403, got %d", rr2.Code)
	}
}

func TestClientSetMemberRole_Matrix(t *testing.T) {
	ctx := context.Background()
	ws, app, owner, ownerTok := clientOrgTestApp(t)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)

	// admin actor
	accA := testEnv.CreateTestAccount(t, "adm-"+GenerateUniqueSlug("u")+"@example.com")
	adm, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, accA.Email, app, core.UserSourceInvited)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, adm.ID, core.OrgRoleAdmin)
	_, admTok := createTestClientSessionForApp(t, ws, accA, app)

	// plain member target
	accM := testEnv.CreateTestAccount(t, "mem-"+GenerateUniqueSlug("u")+"@example.com")
	mem, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, accM.Email, app, core.UserSourceInvited)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, mem.ID, core.OrgRoleMember)

	router := setupClientAPIRouter(t)
	patch := func(tok, targetUserID string, payload map[string]any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPatch, clientOrgURL(ws, app, "/"+org.ID.String()+"/members/"+targetUserID), bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	// owner: member -> admin => 204
	if rr := patch(ownerTok, mem.ID.String(), map[string]any{"orgRole": "admin"}); rr.Code != http.StatusNoContent {
		t.Fatalf("owner promote member->admin: got %d (%s)", rr.Code, rr.Body.String())
	}
	// admin: promote (now-admin) member -> owner => 403 (only owner makes owners)
	if rr := patch(admTok, mem.ID.String(), map[string]any{"orgRole": "owner"}); rr.Code != http.StatusForbidden {
		t.Fatalf("admin promote->owner must be 403, got %d", rr.Code)
	}
	// admin: modify the owner => 403 (admin can't act on owner)
	if rr := patch(admTok, owner.ID.String(), map[string]any{"orgRole": "admin"}); rr.Code != http.StatusForbidden {
		t.Fatalf("admin modify owner must be 403, got %d", rr.Code)
	}
	// owner: demote self (last owner) => 409
	if rr := patch(ownerTok, owner.ID.String(), map[string]any{"orgRole": "admin"}); rr.Code != http.StatusConflict {
		t.Fatalf("demote last owner must be 409, got %d", rr.Code)
	}
	// owner: assign a stray roleId => 400
	if rr := patch(ownerTok, mem.ID.String(), map[string]any{"roleIds": []string{utils.NewUUID().String()}}); rr.Code != http.StatusBadRequest {
		t.Fatalf("stray roleId must be 400, got %d", rr.Code)
	}
	// owner: assign a valid project role => 204
	role, _ := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{ProjectID: app.ProjectID, Name: "Ed", Slug: GenerateUniqueSlug("ed"), Now: time.Now().UTC()})
	if rr := patch(ownerTok, mem.ID.String(), map[string]any{"roleIds": []string{role.ID.String()}}); rr.Code != http.StatusNoContent {
		t.Fatalf("valid roleId: got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestClientRemoveOrLeaveMember(t *testing.T) {
	ctx := context.Background()
	ws, app, owner, ownerTok := clientOrgTestApp(t)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)
	accM := testEnv.CreateTestAccount(t, "mem-"+GenerateUniqueSlug("u")+"@example.com")
	mem, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, accM.Email, app, core.UserSourceInvited)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, mem.ID, core.OrgRoleMember)
	_, memTok := createTestClientSessionForApp(t, ws, accM, app)

	router := setupClientAPIRouter(t)
	del := func(tok, target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, clientOrgURL(ws, app, "/"+org.ID.String()+"/members/"+target), nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	// member leaves self -> 204
	if rr := del(memTok, mem.ID.String()); rr.Code != http.StatusNoContent {
		t.Fatalf("self-leave: got %d (%s)", rr.Code, rr.Body.String())
	}
	// owner self-leave as last owner -> 409
	if rr := del(ownerTok, owner.ID.String()); rr.Code != http.StatusConflict {
		t.Fatalf("last-owner leave must be 409, got %d", rr.Code)
	}

	// admin removing owner -> 403
	accA := testEnv.CreateTestAccount(t, "adm-"+GenerateUniqueSlug("u")+"@example.com")
	adm, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, accA.Email, app, core.UserSourceInvited)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, adm.ID, core.OrgRoleAdmin)
	_, admTok := createTestClientSessionForApp(t, ws, accA, app)
	if rr := del(admTok, owner.ID.String()); rr.Code != http.StatusForbidden {
		t.Fatalf("admin remove owner must be 403, got %d", rr.Code)
	}
}

func TestClientCreateInvite(t *testing.T) {
	ctx := context.Background()
	ws, app, owner, ownerTok := clientOrgTestApp(t)
	// invites need an app URL.
	if _, err := testEnv.DB.Pool().Exec(ctx, "UPDATE apps SET app_url=$1 WHERE id=$2", "https://app.example.com", app.ID); err != nil {
		t.Fatalf("set app_url: %v", err)
	}
	reloaded, _ := testEnv.Repo.GetAppByID(ctx, app.ID)
	app = &reloaded
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)

	router := setupClientAPIRouter(t)
	body, _ := json.Marshal(map[string]any{"email": "newperson-" + GenerateUniqueSlug("e") + "@example.com", "orgRole": "admin"})
	req := httptest.NewRequest(http.MethodPost, clientOrgURL(ws, app, "/"+org.ID.String()+"/invites"), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ownerTok)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("owner invite: got %d (%s)", rr.Code, rr.Body.String())
	}

	// admin cannot invite as owner.
	accA := testEnv.CreateTestAccount(t, "adm-"+GenerateUniqueSlug("u")+"@example.com")
	adm, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, accA.Email, app, core.UserSourceInvited)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, adm.ID, core.OrgRoleAdmin)
	_, admTok := createTestClientSessionForApp(t, ws, accA, app)
	b2, _ := json.Marshal(map[string]any{"email": "x-" + GenerateUniqueSlug("e") + "@example.com", "orgRole": "owner"})
	req2 := httptest.NewRequest(http.MethodPost, clientOrgURL(ws, app, "/"+org.ID.String()+"/invites"), bytes.NewReader(b2))
	req2.Header.Set("Authorization", "Bearer "+admTok)
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("admin invite-as-owner must be 403, got %d (%s)", rr2.Code, rr2.Body.String())
	}
}

func TestCountRolesInProject(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "crp-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	t.Cleanup(func() { testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws}) })

	role, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{ProjectID: app.ProjectID, Name: "R", Slug: GenerateUniqueSlug("r"), Now: time.Now().UTC()})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	stray := utils.NewUUID()

	n, err := testEnv.Repo.CountRolesInProject(ctx, app.ProjectID, []uuid.UUID{role.ID})
	if err != nil || n != 1 {
		t.Fatalf("in-project role: n=%d err=%v", n, err)
	}
	n2, err := testEnv.Repo.CountRolesInProject(ctx, app.ProjectID, []uuid.UUID{role.ID, stray})
	if err != nil || n2 != 1 {
		t.Fatalf("stray excluded: n=%d err=%v", n2, err)
	}
	n3, err := testEnv.Repo.CountRolesInProject(ctx, app.ProjectID, []uuid.UUID{})
	if err != nil || n3 != 0 {
		t.Fatalf("empty input: n=%d err=%v", n3, err)
	}
}
