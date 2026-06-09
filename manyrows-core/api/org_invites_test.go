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
	list, _, err := testEnv.Repo.ListPendingOrgInvites(ctx, org.ID, 0, 200, "")
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
	// Re-accept of an already-ACCEPTED invite → ErrInviteNotPending (the
	// invitee is already a member; the handler treats this as already-joined).
	if err := testEnv.Repo.AcceptOrganizationInviteTx(ctx, inv.ID, invitee.ID); !errors.Is(err, repo.ErrInviteNotPending) {
		t.Fatalf("re-accept of accepted invite: want ErrInviteNotPending, got %v", err)
	}

	// After accept, a fresh invite for the same email is allowed (partial-unique only blocks pending).
	if _, err := testEnv.Repo.CreateOrganizationInvite(ctx, org.ID, email, core.OrgRoleAdmin, nil, &owner.ID, "hash3-"+GenerateUniqueSlug("h"), exp); err != nil {
		t.Fatalf("re-invite after accept should succeed, got %v", err)
	}
}

// TestAcceptOrganizationInviteTx_StoredExpiredStatus guards the handler's
// "ErrInviteNotPending => already a member, sign them in" fall-through. The tx
// must surface ErrInviteExpired (not the generic ErrInviteNotPending) for an
// invite whose stored status is 'expired', so a future expiry sweeper can never
// turn an unaccepted invite into a session without an actual membership.
func TestAcceptOrganizationInviteTx_StoredExpiredStatus(t *testing.T) {
	ctx, _, _, _, org, owner := seedOrgForInvite(t)
	email := "stexp-" + GenerateUniqueSlug("u") + "@example.com"
	// Not time-expired (expires_at in the future) — only the stored status is
	// 'expired', isolating the status branch from the time check.
	exp := time.Now().UTC().Add(7 * 24 * time.Hour)
	inv, err := testEnv.Repo.CreateOrganizationInvite(ctx, org.ID, email, core.OrgRoleAdmin, nil, &owner.ID, "h-"+GenerateUniqueSlug("h"), exp)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if _, err := testEnv.DB.Pool().Exec(ctx, "UPDATE organization_invites SET status='expired' WHERE id=$1", inv.ID); err != nil {
		t.Fatalf("force expired status: %v", err)
	}

	invitee, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, email, mustReloadApp(t, ctx, org.AppID), core.UserSourceInvited)
	if err := testEnv.Repo.AcceptOrganizationInviteTx(ctx, inv.ID, invitee.ID); !errors.Is(err, repo.ErrInviteExpired) {
		t.Fatalf("accept of stored-expired invite: want ErrInviteExpired, got %v", err)
	}
	if _, err := testEnv.Repo.GetOrganizationMember(ctx, org.ID, invitee.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("stored-expired accept must not create a membership, got err=%v", err)
	}
}

// TestAcceptOrganizationInviteTx_AppliesRoleIDs asserts that the project roles
// carried on an invite (validated + stored at create time) are actually applied
// to the membership on accept — they were previously dropped, so an admin who
// scoped an invite to specific roles silently granted none.
func TestAcceptOrganizationInviteTx_AppliesRoleIDs(t *testing.T) {
	ctx, app, _, _, org, owner := seedOrgForInvite(t)
	role, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{ProjectID: app.ProjectID, Name: "Editor", Slug: GenerateUniqueSlug("ed"), Now: time.Now().UTC()})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	email := "rl-" + GenerateUniqueSlug("u") + "@example.com"
	exp := time.Now().UTC().Add(7 * 24 * time.Hour)
	inv, err := testEnv.Repo.CreateOrganizationInvite(ctx, org.ID, email, core.OrgRoleMember, []uuid.UUID{role.ID}, &owner.ID, "h-"+GenerateUniqueSlug("h"), exp)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	invitee, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, email, app, core.UserSourceInvited)
	if err := testEnv.Repo.AcceptOrganizationInviteTx(ctx, inv.ID, invitee.ID); err != nil {
		t.Fatalf("accept: %v", err)
	}

	m, err := testEnv.Repo.GetOrganizationMember(ctx, org.ID, invitee.ID)
	if err != nil {
		t.Fatalf("member: %v", err)
	}
	roleIDs, err := testEnv.Repo.GetOrgMemberRoleIDs(ctx, m.ID)
	if err != nil {
		t.Fatalf("member roles: %v", err)
	}
	found := false
	for _, rid := range roleIDs {
		if rid == role.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("invite role_ids must be applied on accept; got %v want to include %s", roleIDs, role.ID)
	}
}

func TestListPendingOrgInvites_Pagination(t *testing.T) {
	ctx, _, _, _, org, owner := seedOrgForInvite(t)
	exp := time.Now().UTC().Add(72 * time.Hour)
	needle := "needle" + GenerateUniqueSlug("x")
	for i := 0; i < 5; i++ {
		email := GenerateUniqueSlug("inv") + "@example.com"
		if i == 0 {
			email = needle + "@example.com"
		}
		if _, err := testEnv.Repo.CreateOrganizationInvite(ctx, org.ID, email, core.OrgRoleMember, nil, &owner.ID, "h-"+GenerateUniqueSlug("h"), exp); err != nil {
			t.Fatalf("invite %d: %v", i, err)
		}
	}

	// Page 0, size 2 -> 2 rows, total 5.
	list, total, err := testEnv.Repo.ListPendingOrgInvites(ctx, org.ID, 0, 2, "")
	if err != nil || len(list) != 2 || total != 5 {
		t.Fatalf("page0 size2: len=%d total=%d err=%v", len(list), total, err)
	}
	// Search narrows to the single needle invite.
	list, total, _ = testEnv.Repo.ListPendingOrgInvites(ctx, org.ID, 0, 50, needle)
	if len(list) != 1 || total != 1 || list[0].Email != needle+"@example.com" {
		t.Fatalf("search: len=%d total=%d list=%+v", len(list), total, list)
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
	list, _, _ := testEnv.Repo.ListPendingOrgInvites(ctx, org.ID, 0, 200, "")
	if len(list) != 0 {
		t.Fatalf("expected 0 pending after revoke, got %d", len(list))
	}
	// Revoking a non-pending invite → ErrNotFound.
	if err := testEnv.Repo.RevokeOrganizationInvite(ctx, org.ID, inv.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("expected ErrNotFound revoking non-pending, got %v", err)
	}

	// Accepting a REVOKED invite via the tx must surface ErrInviteRevoked (NOT
	// the generic ErrInviteNotPending) so the handler can refuse sign-in. This
	// guards the race window between the handler's status pre-check and the tx's
	// FOR UPDATE re-read: a revoke landing in that window must never sign in.
	invitee, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, email, mustReloadApp(t, ctx, org.AppID), core.UserSourceInvited)
	if err := testEnv.Repo.AcceptOrganizationInviteTx(ctx, inv.ID, invitee.ID); !errors.Is(err, repo.ErrInviteRevoked) {
		t.Fatalf("accept of revoked invite: want ErrInviteRevoked, got %v", err)
	}
	// And it must NOT have created a membership.
	if _, err := testEnv.Repo.GetOrganizationMember(ctx, org.ID, invitee.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("revoked accept must not create a membership, got err=%v", err)
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

// TestServerCreateOrgInvite_DefaultsToMember asserts that an invite created
// without an explicit orgRole lands on the least-privileged tier (member), not
// admin — a backend integration that forgets the field must not silently grant
// admin to every invitee.
func TestServerCreateOrgInvite_DefaultsToMember(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "scidm-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

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

	// orgRole omitted entirely → must default to the least-privileged tier.
	email := "newbie-" + GenerateUniqueSlug("u") + "@example.com"
	body, _ := json.Marshal(map[string]any{"email": email})
	req := httptest.NewRequest(http.MethodPost, base, bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create invite: expected 201, got %d (%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		OrgRole string `json:"orgRole"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.OrgRole != core.OrgRoleMember {
		t.Fatalf("omitted orgRole should default to member, got %q", resp.OrgRole)
	}
}

// setupAcceptInviteRouter mounts the PUBLIC org-invite accept handler behind
// test middleware that injects workspace + app into context (mirrors the
// /auth group's workspace/app-context middleware in the real external router).
// The handler reads ws+app from context, so the bare router suffices.
func setupAcceptInviteRouter(t *testing.T, ws *core.Workspace, app *core.App) (*chi.Mux, *TestServices) {
	t.Helper()
	svc := NewTestServices(t)
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := core.WithApp(core.WithWorkspace(req.Context(), ws), app)
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	r.Get("/x/{workspaceSlug}/apps/{appId}/auth/org-invite", svc.Handler.AcceptOrgInvite)
	return r, svc
}

// seedOrgWithAppURL creates an account/workspace/app (with an AppURL set so the
// accept flow has a redirect target) plus an org owned by a fresh owner.
func seedOrgWithAppURL(t *testing.T, ctx context.Context) (acc *core.Account, ws *core.Workspace, app *core.App, org *core.Organization, owner *core.User) {
	t.Helper()
	acc = testEnv.CreateTestAccount(t, "ai-"+GenerateUniqueSlug("u")+"@example.com")
	ws = testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app = testEnv.CreateTestApp(t, ws, acc)

	appURL := "https://app.example.com"
	if _, err := testEnv.Repo.UpdateAppEnabled(ctx, ws.ID, app.ProjectID, app.ID, true, repo.AppCoreUpdate{AppURL: &appURL}); err != nil {
		t.Fatalf("set app url: %v", err)
	}
	app = mustReloadApp(t, ctx, app.ID)

	owner, _, _ = testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ = testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)
	return
}

func TestAcceptOrgInvite_HappyPath(t *testing.T) {
	ctx := context.Background()
	acc, ws, app, org, owner := seedOrgWithAppURL(t, ctx)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	router, _ := setupAcceptInviteRouter(t, ws, app)

	// Seed a pending invite with a token hash matching what the handler
	// derives via adminAuthService.HashMagicToken (generateTestMagicToken
	// mirrors that exact derivation: base64url(raw) -> sha256-hex).
	raw, hash := generateTestMagicToken(t)
	inviteeEmail := "newbie-" + GenerateUniqueSlug("u") + "@example.com"
	if _, err := testEnv.Repo.CreateOrganizationInvite(ctx, org.ID, inviteeEmail, core.OrgRoleAdmin, nil, &owner.ID, hash, time.Now().UTC().Add(7*24*time.Hour)); err != nil {
		t.Fatalf("seed invite: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/org-invite?token="+raw, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("accept: expected 302, got %d (%s)", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://app.example.com") {
		t.Fatalf("redirect should target app URL, got %q", loc)
	}
	if !strings.Contains(loc, "mr_session=") {
		t.Fatalf("expected session in redirect fragment, got %q", loc)
	}

	// Invitee is now an org member with the invite's role.
	invitee, _ := testEnv.Repo.GetUserByEmail(ctx, inviteeEmail, app)
	if invitee == nil {
		t.Fatalf("invitee user not created")
	}
	if m, err := testEnv.Repo.GetOrganizationMember(ctx, org.ID, invitee.ID); err != nil || m.OrgRole != core.OrgRoleAdmin {
		t.Fatalf("invitee not an admin member: %v %+v", err, m)
	}
	// Email is marked verified by the sign-in tail.
	if reloaded, _ := testEnv.Repo.GetUserByID(ctx, invitee.ID); reloaded == nil || !reloaded.IsEmailVerified() {
		t.Fatalf("invitee email should be verified after accept, got %+v", reloaded)
	}
	// Invite is now accepted.
	gotInv, _ := testEnv.Repo.GetOrganizationInviteByTokenHash(ctx, hash)
	if gotInv == nil || gotInv.Status != core.OrgInviteStatusAccepted {
		t.Fatalf("invite should be accepted, got %+v", gotInv)
	}
}

func TestAcceptOrgInvite_ExpiredToken(t *testing.T) {
	ctx := context.Background()
	acc, ws, app, org, owner := seedOrgWithAppURL(t, ctx)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	router, _ := setupAcceptInviteRouter(t, ws, app)

	// Seed an already-expired invite.
	raw, hash := generateTestMagicToken(t)
	inviteeEmail := "exp-" + GenerateUniqueSlug("u") + "@example.com"
	if _, err := testEnv.Repo.CreateOrganizationInvite(ctx, org.ID, inviteeEmail, core.OrgRoleAdmin, nil, &owner.ID, hash, time.Now().UTC().Add(-1*time.Hour)); err != nil {
		t.Fatalf("seed expired invite: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/org-invite?token="+raw, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Expired -> redirect to app URL with mr_invite_error, NO session.
	if rr.Code != http.StatusFound {
		t.Fatalf("expired accept: expected 302, got %d (%s)", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "mr_invite_error=") {
		t.Fatalf("expected mr_invite_error in redirect, got %q", loc)
	}
	if strings.Contains(loc, "mr_session=") {
		t.Fatalf("expired invite must not mint a session, got %q", loc)
	}
	// No membership created.
	if invitee, _ := testEnv.Repo.GetUserByEmail(ctx, inviteeEmail, app); invitee != nil {
		if m, _ := testEnv.Repo.GetOrganizationMember(ctx, org.ID, invitee.ID); m != nil {
			t.Fatalf("expired invite should not have created a membership, got %+v", m)
		}
	}
}

func TestAcceptOrgInvite_UnknownToken(t *testing.T) {
	ctx := context.Background()
	acc, ws, app, _, _ := seedOrgWithAppURL(t, ctx)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	router, _ := setupAcceptInviteRouter(t, ws, app)

	raw, _ := generateTestMagicToken(t) // never persisted as an invite
	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/org-invite?token="+raw, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("unknown token: expected 302, got %d (%s)", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "mr_invite_error=") || strings.Contains(loc, "mr_session=") {
		t.Fatalf("unknown token should redirect with mr_invite_error and no session, got %q", loc)
	}
}

func TestAcceptOrgInvite_RevokedToken(t *testing.T) {
	ctx := context.Background()
	acc, ws, app, org, owner := seedOrgWithAppURL(t, ctx)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	router, _ := setupAcceptInviteRouter(t, ws, app)

	// Seed a pending invite, then revoke it before the invitee hits the link.
	raw, hash := generateTestMagicToken(t)
	inviteeEmail := "rvk-" + GenerateUniqueSlug("u") + "@example.com"
	inv, err := testEnv.Repo.CreateOrganizationInvite(ctx, org.ID, inviteeEmail, core.OrgRoleAdmin, nil, &owner.ID, hash, time.Now().UTC().Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("seed invite: %v", err)
	}
	if err := testEnv.Repo.RevokeOrganizationInvite(ctx, org.ID, inv.ID); err != nil {
		t.Fatalf("revoke invite: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/org-invite?token="+raw, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Revoked -> redirect to app URL with mr_invite_error, NO session.
	if rr.Code != http.StatusFound {
		t.Fatalf("revoked accept: expected 302, got %d (%s)", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "mr_invite_error=") {
		t.Fatalf("expected mr_invite_error in redirect, got %q", loc)
	}
	if strings.Contains(loc, "mr_session=") {
		t.Fatalf("revoked invite must not mint a session, got %q", loc)
	}
	// The invitee must NOT have become an org member.
	if invitee, _ := testEnv.Repo.GetUserByEmail(ctx, inviteeEmail, app); invitee != nil {
		if _, err := testEnv.Repo.GetOrganizationMember(ctx, org.ID, invitee.ID); !errors.Is(err, repo.ErrNotFound) {
			t.Fatalf("revoked invite must not create a membership, got err=%v", err)
		}
	}
}

// TestAcceptOrgInvite_SuspendedAppMemberDenied asserts that accepting an org
// invite is NOT a backdoor around app-level suspension. Every normal sign-in
// path runs through ResolveSignInIdentity, which refuses a member whose
// app_users.status='disabled' (ErrAppUserDisabled). The invite-accept flow must
// uphold the same control: a suspended member must not receive a session, and
// the invite must not add an org membership while they're suspended.
func TestAcceptOrgInvite_SuspendedAppMemberDenied(t *testing.T) {
	ctx := context.Background()
	acc, ws, app, org, owner := seedOrgWithAppURL(t, ctx)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	router, _ := setupAcceptInviteRouter(t, ws, app)

	// The invitee already has an app membership that has been suspended.
	// (Pool-level identity stays enabled — only the per-app membership is
	// disabled, which is exactly the gap the invite path must not skip.)
	inviteeEmail := "susp-" + GenerateUniqueSlug("u") + "@example.com"
	invitee, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, inviteeEmail, app, core.UserSourceInvited)
	if err := testEnv.Repo.SetAppUserStatus(ctx, app.ID, invitee.ID, core.AppUserStatusDisabled); err != nil {
		t.Fatalf("suspend app member: %v", err)
	}

	// Seed a pending invite for the suspended email.
	raw, hash := generateTestMagicToken(t)
	if _, err := testEnv.Repo.CreateOrganizationInvite(ctx, org.ID, inviteeEmail, core.OrgRoleAdmin, nil, &owner.ID, hash, time.Now().UTC().Add(7*24*time.Hour)); err != nil {
		t.Fatalf("seed invite: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/org-invite?token="+raw, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Suspended -> redirect to app URL with mr_invite_error, NO session.
	if rr.Code != http.StatusFound {
		t.Fatalf("suspended accept: expected 302, got %d (%s)", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if strings.Contains(loc, "mr_session=") {
		t.Fatalf("suspended app member must not get a session via invite accept, got %q", loc)
	}
	if !strings.Contains(loc, "mr_invite_error=") {
		t.Fatalf("expected mr_invite_error in redirect, got %q", loc)
	}
	// And it must NOT have added the org membership while suspended.
	if _, err := testEnv.Repo.GetOrganizationMember(ctx, org.ID, invitee.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("suspended accept must not create an org membership, got err=%v", err)
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
