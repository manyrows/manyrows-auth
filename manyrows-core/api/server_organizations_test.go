package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/core"

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
		or.Delete("/{orgId}", svc.Handler.ServerArchiveOrganization)
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

	owner, _, err := testEnv.Repo.GetOrCreateUser(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
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

	user, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "u-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
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

	owner, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
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

	owner, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)

	teammateEmail := "tm-" + GenerateUniqueSlug("u") + "@example.com"
	teammate, _, _ := testEnv.Repo.GetOrCreateUser(ctx, teammateEmail, app, core.UserSourceInvited)

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

	owner, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
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

	owner, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	teammate, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "tm-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
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

	o1, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "o1-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	o2, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "o2-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
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

	owner, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	outsider, _, _ := testEnv.Repo.GetOrCreateUser(ctx, "out-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
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
