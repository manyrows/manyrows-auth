package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/core"
	"manyrows-core/core/repo"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// setupServerOrgRouter mounts the server org handlers behind test middleware
// that injects workspace + app into context (bypassing the API-key auth the
// production server router uses — same approach as apikeys_test.go). The org
// handlers read only the app from context.
func setupServerOrgRouter(t *testing.T, ws *core.Workspace, app *core.App) *chi.Mux {
	t.Helper()
	svc := NewTestServices(t)
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := req.Context()
			ctx = core.WithWorkspace(ctx, ws)
			ctx = core.WithApp(ctx, app)
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	r.Route("/v1/apps/{appId}/organizations", func(or chi.Router) {
		or.Post("/", svc.Handler.ServerCreateOrganization)
		or.Get("/", svc.Handler.ServerListOrganizationsForUser)
		or.Get("/{orgId}", svc.Handler.ServerGetOrganization)
		or.Patch("/{orgId}", svc.Handler.ServerUpdateOrganization)
		or.Delete("/{orgId}", svc.Handler.ServerDeleteOrganization)
		or.Get("/{orgId}/members", svc.Handler.ServerListOrgMembers)
		or.Post("/{orgId}/members", svc.Handler.ServerAddOrgMember)
		or.Get("/{orgId}/members/{userId}", svc.Handler.ServerGetOrgMember)
		or.Patch("/{orgId}/members/{userId}", svc.Handler.ServerSetOrgMemberRole)
		or.Delete("/{orgId}/members/{userId}", svc.Handler.ServerRemoveOrgMember)
	})
	return r
}

func orgBase(app *core.App) string { return "/v1/apps/" + app.ID.String() + "/organizations" }

// serverOrgResp decodes the (unexported) api.serverOrgResponse; tags must match.
type serverOrgResp struct {
	ID     string `json:"id"`
	AppID  string `json:"appId"`
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Status string `json:"status"`
}

func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.FromString(s)
	if err != nil {
		t.Fatalf("bad uuid %q: %v", s, err)
	}
	return id
}

func TestServerCreateOrganization_SeedsOwner(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "sco-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, app.ID, true); err != nil {
		t.Fatalf("enable orgs: %v", err)
	}
	reloaded, err := testEnv.Repo.GetAppByID(ctx, app.ID)
	if err != nil {
		t.Fatalf("reload app: %v", err)
	}
	app = &reloaded

	owner, _, err := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("owner: %v", err)
	}

	router := setupServerOrgRouter(t, ws, app)
	body, _ := json.Marshal(map[string]string{"name": "Acme", "ownerUserId": owner.ID.String()})
	req := httptest.NewRequest(http.MethodPost, orgBase(app), bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: got %d (%s)", rr.Code, rr.Body.String())
	}
	var org serverOrgResp
	_ = json.Unmarshal(rr.Body.Bytes(), &org)
	if org.ID == "" || org.Slug == "" {
		t.Fatalf("bad create response: %s", rr.Body.String())
	}

	m, err := testEnv.Repo.GetOrganizationMember(ctx, mustUUID(t, org.ID), owner.ID)
	if err != nil {
		t.Fatalf("owner membership missing: %v", err)
	}
	if m.OrgRole != core.OrgRoleOwner || m.Status != core.OrgMemberStatusActive {
		t.Fatalf("owner tier/status: %+v", m)
	}
}

func TestServerListOrganizationsForUser(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "slo-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	user, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "u-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	for i := 0; i < 2; i++ {
		o, err := testEnv.Repo.CreateOrganization(ctx, app.ID, "Org", GenerateUniqueSlug("o"), &user.ID)
		if err != nil {
			t.Fatalf("org: %v", err)
		}
		if _, err := testEnv.Repo.AddOrganizationMember(ctx, o.ID, user.ID, core.OrgRoleOwner); err != nil {
			t.Fatalf("member: %v", err)
		}
	}

	router := setupServerOrgRouter(t, ws, app)
	req := httptest.NewRequest(http.MethodGet, orgBase(app)+"?userId="+user.ID.String(), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: got %d (%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		Organizations []core.OrganizationMembershipView `json:"organizations"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Organizations) != 2 {
		t.Fatalf("expected 2 orgs, got %d", len(resp.Organizations))
	}
}

func TestServerAddOrgMember_ByEmailMissing_409(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "aem-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)

	router := setupServerOrgRouter(t, ws, app)
	body, _ := json.Marshal(map[string]string{"email": "nobody-" + GenerateUniqueSlug("x") + "@example.com", "orgRole": "admin"})
	req := httptest.NewRequest(http.MethodPost, orgBase(app)+"/"+org.ID.String()+"/members", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("unknown email must be 409, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestServerAddOrgMember_ByEmailExisting(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "aee-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)

	teammateEmail := "tm-" + GenerateUniqueSlug("u") + "@example.com"
	teammate, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, teammateEmail, app, core.UserSourceInvited)

	router := setupServerOrgRouter(t, ws, app)
	body, _ := json.Marshal(map[string]string{"email": teammateEmail, "orgRole": "admin"})
	req := httptest.NewRequest(http.MethodPost, orgBase(app)+"/"+org.ID.String()+"/members", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("add existing: got %d (%s)", rr.Code, rr.Body.String())
	}
	m, err := testEnv.Repo.GetOrganizationMember(ctx, org.ID, teammate.ID)
	if err != nil || m.OrgRole != core.OrgRoleAdmin {
		t.Fatalf("teammate not added as admin: %v %+v", err, m)
	}
}

func TestServerLastOwnerGuard(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "log-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)

	router := setupServerOrgRouter(t, ws, app)
	base := orgBase(app) + "/" + org.ID.String() + "/members/" + owner.ID.String()

	body, _ := json.Marshal(map[string]string{"orgRole": "admin"})
	req := httptest.NewRequest(http.MethodPatch, base, bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("demote last owner: got %d want 409 (%s)", rr.Code, rr.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodDelete, base, nil)
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusConflict {
		t.Fatalf("remove last owner: got %d want 409 (%s)", rr2.Code, rr2.Body.String())
	}
}

func TestServerAddOrgMember_ByUserId(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "abu-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	teammate, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "tm-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)

	router := setupServerOrgRouter(t, ws, app)
	body, _ := json.Marshal(map[string]string{"userId": teammate.ID.String(), "orgRole": "member"})
	req := httptest.NewRequest(http.MethodPost, orgBase(app)+"/"+org.ID.String()+"/members", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("add by userId: got %d (%s)", rr.Code, rr.Body.String())
	}
	m, err := testEnv.Repo.GetOrganizationMember(ctx, org.ID, teammate.ID)
	if err != nil || m.OrgRole != core.OrgRoleMember {
		t.Fatalf("teammate not added as member: %v %+v", err, m)
	}
}

func TestServerLastOwnerGuard_AllowsWithMultipleOwners(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "amo-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	o1, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "o1-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	o2, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "o2-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &o1.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, o1.ID, core.OrgRoleOwner)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, o2.ID, core.OrgRoleOwner) // two owners

	router := setupServerOrgRouter(t, ws, app)

	// Demote o2 while a second owner (o1) exists → allowed (204).
	body, _ := json.Marshal(map[string]string{"orgRole": "admin"})
	req := httptest.NewRequest(http.MethodPatch, orgBase(app)+"/"+org.ID.String()+"/members/"+o2.ID.String(), bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("demote with 2 owners should be 204, got %d (%s)", rr.Code, rr.Body.String())
	}

	// Now o1 is the only owner → removing o1 → 409.
	req2 := httptest.NewRequest(http.MethodDelete, orgBase(app)+"/"+org.ID.String()+"/members/"+o1.ID.String(), nil)
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusConflict {
		t.Fatalf("remove now-last owner should be 409, got %d (%s)", rr2.Code, rr2.Body.String())
	}
}

func TestServerGetOrgMember_MiddlewareGate(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "gom-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	outsider, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "out-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)

	router := setupServerOrgRouter(t, ws, app)

	req := httptest.NewRequest(http.MethodGet, orgBase(app)+"/"+org.ID.String()+"/members/"+owner.ID.String(), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("member gate: got %d (%s)", rr.Code, rr.Body.String())
	}
	req2 := httptest.NewRequest(http.MethodGet, orgBase(app)+"/"+org.ID.String()+"/members/"+outsider.ID.String(), nil)
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusNotFound {
		t.Fatalf("outsider gate: got %d want 404", rr2.Code)
	}
}

func TestServerOrg_CrossApp404(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "xa-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app1 := testEnv.CreateTestApp(t, ws, acc)
	app2 := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "o-"+GenerateUniqueSlug("u")+"@example.com", app2, core.UserSourceInvited)
	org2, err := testEnv.Repo.CreateOrganization(ctx, app2.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	if err != nil {
		t.Fatalf("create org under app2: %v", err)
	}

	// Reaching app2's org through the app1-scoped router must 404 (no cross-app leak).
	router := setupServerOrgRouter(t, ws, app1)
	req := httptest.NewRequest(http.MethodGet, orgBase(app1)+"/"+org2.ID.String(), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("cross-app org must be 404, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestServerCreateOrganization_ForeignPoolOwner_404(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "fp-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app1 := testEnv.CreateTestApp(t, ws, acc)
	app2 := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, app1.ID, true); err != nil {
		t.Fatalf("enable orgs: %v", err)
	}
	reloaded1, err := testEnv.Repo.GetAppByID(ctx, app1.ID)
	if err != nil {
		t.Fatalf("reload app1: %v", err)
	}
	app1 = &reloaded1

	// This user belongs to app2's pool, not app1's.
	foreign, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "f-"+GenerateUniqueSlug("u")+"@example.com", app2, core.UserSourceInvited)

	router := setupServerOrgRouter(t, ws, app1)
	body, _ := json.Marshal(map[string]string{"name": "Acme", "ownerUserId": foreign.ID.String()})
	req := httptest.NewRequest(http.MethodPost, orgBase(app1), bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("foreign-pool owner must be 404, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestServerGetOrgMember_DisabledMember_404(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "dm-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)
	if _, err := testEnv.DB.Pool().Exec(ctx, "UPDATE organization_members SET status='disabled' WHERE org_id=$1 AND user_id=$2", org.ID, owner.ID); err != nil {
		t.Fatalf("disable: %v", err)
	}

	router := setupServerOrgRouter(t, ws, app)
	req := httptest.NewRequest(http.MethodGet, orgBase(app)+"/"+org.ID.String()+"/members/"+owner.ID.String(), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("disabled member gate must be 404, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestServerOrg_ArchivedOrg_404(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "ar-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)
	if err := testEnv.Repo.ArchiveOrganization(ctx, org.ID); err != nil {
		t.Fatalf("archive: %v", err)
	}

	router := setupServerOrgRouter(t, ws, app)
	// Gate on an archived org → 404.
	req := httptest.NewRequest(http.MethodGet, orgBase(app)+"/"+org.ID.String()+"/members/"+owner.ID.String(), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("archived-org gate must be 404, got %d (%s)", rr.Code, rr.Body.String())
	}
	// Rename of an archived org → 404.
	body, _ := json.Marshal(map[string]string{"name": "Nope"})
	req2 := httptest.NewRequest(http.MethodPatch, orgBase(app)+"/"+org.ID.String(), bytes.NewReader(body))
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusNotFound {
		t.Fatalf("rename archived org must be 404, got %d (%s)", rr2.Code, rr2.Body.String())
	}
}

func TestServerDeleteOrganization_HardDeletes(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "del-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)

	router := setupServerOrgRouter(t, ws, app)
	req := httptest.NewRequest(http.MethodDelete, orgBase(app)+"/"+org.ID.String()+"?actorUserId="+owner.ID.String(), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d (%s)", rr.Code, rr.Body.String())
	}
	// Hard-deleted: the row is gone, not merely archived.
	if _, err := testEnv.Repo.GetOrganizationByID(ctx, org.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("org should be hard-deleted (ErrNotFound), got %v", err)
	}
	// Members cascade-deleted.
	if _, err := testEnv.Repo.GetOrganizationMember(ctx, org.ID, owner.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("member should cascade-delete (ErrNotFound), got %v", err)
	}
}

// Strict owner-only delete: without an actorUserId the server refuses
// (fail-closed), so a backend can't delete a tenant without naming the acting
// end-user whose tier is then verified.
func TestServerDeleteOrganization_RequiresActorUserId_400(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "delna-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)

	router := setupServerOrgRouter(t, ws, app)
	req := httptest.NewRequest(http.MethodDelete, orgBase(app)+"/"+org.ID.String(), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("delete without actorUserId must be 400, got %d (%s)", rr.Code, rr.Body.String())
	}
	// A rejected delete must leave the org intact.
	if _, err := testEnv.Repo.GetOrganizationByID(ctx, org.ID); err != nil {
		t.Fatalf("org must still exist after rejected delete, got %v", err)
	}
}

// Only an owner may delete the org — an admin-tier member is refused (403).
func TestServerDeleteOrganization_AdminActor_403(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "dela-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	admin, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "adm-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, admin.ID, core.OrgRoleAdmin)

	router := setupServerOrgRouter(t, ws, app)
	req := httptest.NewRequest(http.MethodDelete, orgBase(app)+"/"+org.ID.String()+"?actorUserId="+admin.ID.String(), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("admin-tier actor delete must be 403, got %d (%s)", rr.Code, rr.Body.String())
	}
	if _, err := testEnv.Repo.GetOrganizationByID(ctx, org.ID); err != nil {
		t.Fatalf("org must still exist after forbidden delete, got %v", err)
	}
}

func TestServerCreateOrganization_OrgsDisabled_409(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "od-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc) // orgs NOT enabled (default false)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)

	router := setupServerOrgRouter(t, ws, app)
	body, _ := json.Marshal(map[string]string{"name": "Acme", "ownerUserId": owner.ID.String()})
	req := httptest.NewRequest(http.MethodPost, orgBase(app), bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("create on orgs-disabled app must be 409, got %d (%s)", rr.Code, rr.Body.String())
	}
}

// A user who exists in the app's pool but is NOT an app member must not be
// addable to an org by userId (cross-app injection guard).
func TestServerAddOrgMember_NonAppMemberByID_404(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "nam-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)

	// Pool-only user (no app_users membership).
	nonMember, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "nm-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)

	router := setupServerOrgRouter(t, ws, app)
	body, _ := json.Marshal(map[string]string{"userId": nonMember.ID.String(), "orgRole": "admin"})
	req := httptest.NewRequest(http.MethodPost, orgBase(app)+"/"+org.ID.String()+"/members", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("non-app-member by id must be 404, got %d (%s)", rr.Code, rr.Body.String())
	}
}

// A user in the pool (e.g. via a sibling app) but not a member of THIS app must
// get the same 409 "sign in first" when added by email.
func TestServerAddOrgMember_InPoolNonMemberByEmail_409(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "ipn-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)

	nmEmail := "nm-" + GenerateUniqueSlug("u") + "@example.com"
	_, _, _ = testEnv.Repo.GetOrCreateUser(ctx, nmEmail, app, core.UserSourceInvited) // in pool, no membership

	router := setupServerOrgRouter(t, ws, app)
	body, _ := json.Marshal(map[string]string{"email": nmEmail, "orgRole": "admin"})
	req := httptest.NewRequest(http.MethodPost, orgBase(app)+"/"+org.ID.String()+"/members", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("in-pool non-member by email must be 409, got %d (%s)", rr.Code, rr.Body.String())
	}
}

// A name-only rename via the server API silently regenerates the slug from the
// new name (Pier's path — Pier never sends a slug).
func TestServerUpdateOrganization_RegeneratesSlugFromName(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "urs-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	org, err := testEnv.Repo.CreateOrganization(ctx, app.ID, "Drum Kingdom", "sdafadsf", nil)
	if err != nil {
		t.Fatalf("create org: %v", err)
	}

	router := setupServerOrgRouter(t, ws, app)
	body, _ := json.Marshal(map[string]string{"name": "Foo Bar"})
	req := httptest.NewRequest(http.MethodPatch, orgBase(app)+"/"+org.ID.String(), bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("rename: got %d (%s)", rr.Code, rr.Body.String())
	}
	var resp serverOrgResp
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Name != "Foo Bar" || resp.Slug != "foo-bar" {
		t.Fatalf("expected name 'Foo Bar' slug 'foo-bar', got name %q slug %q", resp.Name, resp.Slug)
	}
}

// Regenerating onto a slug another org already holds appends -2 instead of
// failing with a conflict.
func TestServerUpdateOrganization_SlugCollisionSuffix(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "ucs-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	if _, err := testEnv.Repo.CreateOrganization(ctx, app.ID, "Existing", "foo", nil); err != nil {
		t.Fatalf("create org A: %v", err)
	}
	orgB, err := testEnv.Repo.CreateOrganization(ctx, app.ID, "Other", "bar", nil)
	if err != nil {
		t.Fatalf("create org B: %v", err)
	}

	router := setupServerOrgRouter(t, ws, app)
	body, _ := json.Marshal(map[string]string{"name": "Foo"})
	req := httptest.NewRequest(http.MethodPatch, orgBase(app)+"/"+orgB.ID.String(), bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("rename: got %d (%s)", rr.Code, rr.Body.String())
	}
	var resp serverOrgResp
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Slug != "foo-2" {
		t.Fatalf("expected collision slug 'foo-2', got %q", resp.Slug)
	}
}

// An explicit slug in the request is honored (still run through the collision
// loop); a name omitted leaves the name untouched.
func TestServerUpdateOrganization_ExplicitSlugHonored(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "ues-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	org, err := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", "acme", nil)
	if err != nil {
		t.Fatalf("create org: %v", err)
	}

	router := setupServerOrgRouter(t, ws, app)
	body, _ := json.Marshal(map[string]string{"slug": "custom-handle"})
	req := httptest.NewRequest(http.MethodPatch, orgBase(app)+"/"+org.ID.String(), bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("update: got %d (%s)", rr.Code, rr.Body.String())
	}
	var resp serverOrgResp
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Slug != "custom-handle" || resp.Name != "Acme" {
		t.Fatalf("expected slug 'custom-handle' name 'Acme', got slug %q name %q", resp.Slug, resp.Name)
	}
}

// Renaming to the same name (slug already matches) is idempotent — the org's own
// row is not treated as a collision, so no -2 suffix is appended.
func TestServerUpdateOrganization_SameNameKeepsSlug(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "usn-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	org, err := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", "acme", nil)
	if err != nil {
		t.Fatalf("create org: %v", err)
	}

	router := setupServerOrgRouter(t, ws, app)
	body, _ := json.Marshal(map[string]string{"name": "Acme"})
	req := httptest.NewRequest(http.MethodPatch, orgBase(app)+"/"+org.ID.String(), bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("rename: got %d (%s)", rr.Code, rr.Body.String())
	}
	var resp serverOrgResp
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Slug != "acme" {
		t.Fatalf("idempotent rename should keep slug 'acme', got %q", resp.Slug)
	}
}

// Seeding an org owner who is not an app member must be rejected (404).
func TestServerCreateOrganization_NonAppMemberOwner_404(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "nmo-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})
	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, app.ID, true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	reloaded, _ := testEnv.Repo.GetAppByID(ctx, app.ID)
	app = &reloaded

	nonMember, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "nm-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	router := setupServerOrgRouter(t, ws, app)
	body, _ := json.Marshal(map[string]string{"name": "Acme", "ownerUserId": nonMember.ID.String()})
	req := httptest.NewRequest(http.MethodPost, orgBase(app), bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("non-app-member owner must be 404, got %d (%s)", rr.Code, rr.Body.String())
	}
}
