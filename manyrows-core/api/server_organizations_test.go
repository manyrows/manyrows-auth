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
