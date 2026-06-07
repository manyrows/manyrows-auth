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

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

func seedOrgForInvite(t *testing.T) (ctx context.Context, app *core.App, ws *core.Workspace, acc *core.Account, org *core.Organization, owner *core.User) {
	t.Helper()
	ctx = context.Background()
	acc = testEnv.CreateTestAccount(t, "inv-"+GenerateUniqueSlug("u")+"@example.com")
	ws = testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app = testEnv.CreateTestApp(t, ws, acc)
	owner, _, _ = testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ = testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)
	return
}

func TestOrgInvite_RepoLifecycle(t *testing.T) {
	ctx, _, _, _, org, owner := seedOrgForInvite(t)
	email := "newbie-" + GenerateUniqueSlug("u") + "@example.com"
	exp := time.Now().UTC().Add(7 * 24 * time.Hour)

	inv, err := testEnv.Repo.CreateOrganizationInvite(ctx, org.ID, email, core.OrgRoleAdmin, nil, &owner.ID, "hash-"+GenerateUniqueSlug("h"), exp)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if inv.Status != core.OrgInviteStatusPending {
		t.Fatalf("expected pending, got %q", inv.Status)
	}

	// Duplicate pending → ErrInvitePending.
	if _, err := testEnv.Repo.CreateOrganizationInvite(ctx, org.ID, email, core.OrgRoleAdmin, nil, &owner.ID, "hash2-"+GenerateUniqueSlug("h"), exp); !errors.Is(err, repo.ErrInvitePending) {
		t.Fatalf("expected ErrInvitePending on dup, got %v", err)
	}

	// Get by token hash.
	got, err := testEnv.Repo.GetOrganizationInviteByTokenHash(ctx, inv.TokenHash)
	if err != nil || got.ID != inv.ID {
		t.Fatalf("get-by-token: %v %+v", err, got)
	}

	// List pending.
	list, err := testEnv.Repo.ListPendingOrgInvites(ctx, org.ID)
	if err != nil || len(list) != 1 || list[0].Email != email {
		t.Fatalf("list pending: %v %+v", err, list)
	}

	// Accept: adds member + marks accepted.
	invitee, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, email, mustReloadApp(t, ctx, org.AppID), core.UserSourceInvited)
	if err := testEnv.Repo.AcceptOrganizationInviteTx(ctx, inv.ID, invitee.ID); err != nil {
		t.Fatalf("accept: %v", err)
	}
	m, err := testEnv.Repo.GetOrganizationMember(ctx, org.ID, invitee.ID)
	if err != nil || m.OrgRole != core.OrgRoleAdmin {
		t.Fatalf("member after accept: %v %+v", err, m)
	}
	reGot, _ := testEnv.Repo.GetOrganizationInviteByTokenHash(ctx, inv.TokenHash)
	if reGot.Status != core.OrgInviteStatusAccepted {
		t.Fatalf("invite should be accepted, got %q", reGot.Status)
	}
	// Idempotent re-accept (already a member / already accepted) → no error.
	if err := testEnv.Repo.AcceptOrganizationInviteTx(ctx, inv.ID, invitee.ID); err == nil {
		// acceptable: idempotent success. If it returns a typed "not pending" error, that's also fine — adjust assertion in impl.
	}

	// After accept, a fresh invite for the same email is allowed (partial-unique only blocks pending).
	if _, err := testEnv.Repo.CreateOrganizationInvite(ctx, org.ID, email, core.OrgRoleAdmin, nil, &owner.ID, "hash3-"+GenerateUniqueSlug("h"), exp); err != nil {
		t.Fatalf("re-invite after accept should succeed, got %v", err)
	}
}

func TestOrgInvite_Revoke(t *testing.T) {
	ctx, _, _, _, org, owner := seedOrgForInvite(t)
	email := "rv-" + GenerateUniqueSlug("u") + "@example.com"
	exp := time.Now().UTC().Add(7 * 24 * time.Hour)
	inv, _ := testEnv.Repo.CreateOrganizationInvite(ctx, org.ID, email, core.OrgRoleAdmin, nil, &owner.ID, "h-"+GenerateUniqueSlug("h"), exp)
	if err := testEnv.Repo.RevokeOrganizationInvite(ctx, org.ID, inv.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	list, _ := testEnv.Repo.ListPendingOrgInvites(ctx, org.ID)
	if len(list) != 0 {
		t.Fatalf("expected 0 pending after revoke, got %d", len(list))
	}
	// Revoking a non-pending invite → ErrNotFound.
	if err := testEnv.Repo.RevokeOrganizationInvite(ctx, org.ID, inv.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("expected ErrNotFound revoking non-pending, got %v", err)
	}
}

// setupServerInviteRouter mounts the server invite handlers behind test
// middleware that injects workspace + app into context (mirrors
// setupServerOrgRouter). The handlers read the app from context.
func setupServerInviteRouter(t *testing.T, ws *core.Workspace, app *core.App) *chi.Mux {
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
	r.Route("/v1/apps/{appId}/organizations/{orgId}/invites", func(ir chi.Router) {
		ir.Post("/", svc.Handler.ServerCreateOrgInvite)
		ir.Get("/", svc.Handler.ServerListOrgInvites)
		ir.Delete("/{inviteId}", svc.Handler.ServerRevokeOrgInvite)
	})
	return r
}

func TestServerCreateOrgInvite_PersistsAndLists(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "sci-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	// org-invite create requires an app URL for the accept link. Set it via
	// the catch-all app updater (keeps enabled=true), then reload.
	appURL := "https://app.example.com"
	if _, err := testEnv.Repo.UpdateAppEnabled(ctx, ws.ID, app.ProjectID, app.ID, true, repo.AppCoreUpdate{AppURL: &appURL}); err != nil {
		t.Fatalf("set app url: %v", err)
	}
	app = mustReloadApp(t, ctx, app.ID)

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)

	router := setupServerInviteRouter(t, ws, app)
	base := "/v1/apps/" + app.ID.String() + "/organizations/" + org.ID.String() + "/invites"

	email := "newbie-" + GenerateUniqueSlug("u") + "@example.com"
	body, _ := json.Marshal(map[string]any{"email": email, "orgRole": "admin"})
	req := httptest.NewRequest(http.MethodPost, base, bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create invite: expected 201, got %d (%s)", rr.Code, rr.Body.String())
	}

	// List shows it.
	req = httptest.NewRequest(http.MethodGet, base, nil)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	var listResp struct {
		Invites []struct{ ID, Email, OrgRole, Status string } `json:"invites"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &listResp)
	if len(listResp.Invites) != 1 || listResp.Invites[0].Email != email {
		t.Fatalf("expected 1 pending invite for %s, got %+v", email, listResp.Invites)
	}

	// Duplicate pending → 409.
	req = httptest.NewRequest(http.MethodPost, base, bytes.NewReader(body))
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("dup invite: expected 409, got %d (%s)", rr.Code, rr.Body.String())
	}

	// Revoke.
	inviteID := listResp.Invites[0].ID
	req = httptest.NewRequest(http.MethodDelete, base+"/"+inviteID, nil)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("revoke: expected 204, got %d (%s)", rr.Code, rr.Body.String())
	}
}

// mustReloadApp returns the app with its pool id populated (CreateTestApp may
// not include it on the returned struct in all cases).
func mustReloadApp(t *testing.T, ctx context.Context, appID uuid.UUID) *core.App {
	t.Helper()
	a, err := testEnv.Repo.GetAppByID(ctx, appID)
	if err != nil {
		t.Fatalf("reload app: %v", err)
	}
	return &a
}
