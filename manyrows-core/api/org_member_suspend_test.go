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
)

// setupServerOrgSuspendRouter mirrors setupServerOrgRouter but additionally
// registers the member status route under test.
func setupServerOrgSuspendRouter(t *testing.T, ws *core.Workspace, app *core.App) *chi.Mux {
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
		or.Patch("/{orgId}/members/{userId}/status", svc.Handler.ServerSetOrgMemberStatus)
	})
	return r
}

func TestOrgMemberSuspend(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "oms-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	member, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "mem-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	if _, err := testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner); err != nil {
		t.Fatalf("add owner: %v", err)
	}
	if _, err := testEnv.Repo.AddOrganizationMember(ctx, org.ID, member.ID, core.OrgRoleMember); err != nil {
		t.Fatalf("add member: %v", err)
	}

	memberStatus := func() string {
		t.Helper()
		m, err := testEnv.Repo.GetOrganizationMember(ctx, org.ID, member.ID)
		if err != nil {
			t.Fatalf("load membership: %v", err)
		}
		return m.Status
	}

	// (a) repo: disable the member → reflected in the read.
	if err := testEnv.Repo.SetOrganizationMemberStatusGuarded(ctx, org.ID, member.ID, core.OrgMemberStatusDisabled); err != nil {
		t.Fatalf("disable member: %v", err)
	}
	if got := memberStatus(); got != core.OrgMemberStatusDisabled {
		t.Fatalf("expected member status %q, got %q", core.OrgMemberStatusDisabled, got)
	}

	// (b) read denial: a disabled member resolves to zero roles (no access)
	// via the single guarded chokepoint resolveOrgMemberRoleIDs (exercised here
	// through the server permission-check handler isn't needed — assert the
	// repo read denies). The cheapest read assertion: the member is no longer
	// returned by ListOrganizationsForUserInApp (active-only).
	views, err := testEnv.Repo.ListOrganizationsForUserInApp(ctx, app.ID, member.ID)
	if err != nil {
		t.Fatalf("list orgs for user: %v", err)
	}
	for _, v := range views {
		if v.ID == org.ID {
			t.Fatalf("disabled member should not see org %s in their active org list", org.ID)
		}
	}

	// (c) reactivate → reflected.
	if err := testEnv.Repo.SetOrganizationMemberStatusGuarded(ctx, org.ID, member.ID, core.OrgMemberStatusActive); err != nil {
		t.Fatalf("reactivate member: %v", err)
	}
	if got := memberStatus(); got != core.OrgMemberStatusActive {
		t.Fatalf("expected member status %q after reactivate, got %q", core.OrgMemberStatusActive, got)
	}

	// (d) last-owner guard: an org with a single active owner refuses to disable
	// that owner, leaving the status unchanged.
	soloOwner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "solo-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	soloOrg, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Solo", GenerateUniqueSlug("solo"), &soloOwner.ID)
	if _, err := testEnv.Repo.AddOrganizationMember(ctx, soloOrg.ID, soloOwner.ID, core.OrgRoleOwner); err != nil {
		t.Fatalf("add solo owner: %v", err)
	}
	if err := testEnv.Repo.SetOrganizationMemberStatusGuarded(ctx, soloOrg.ID, soloOwner.ID, core.OrgMemberStatusDisabled); !errors.Is(err, repo.ErrLastOwner) {
		t.Fatalf("expected ErrLastOwner disabling sole owner, got %v", err)
	}
	soloM, err := testEnv.Repo.GetOrganizationMember(ctx, soloOrg.ID, soloOwner.ID)
	if err != nil {
		t.Fatalf("load solo owner membership: %v", err)
	}
	if soloM.Status != core.OrgMemberStatusActive {
		t.Fatalf("sole owner status should be unchanged (active) after refused disable, got %q", soloM.Status)
	}

	// (e) invalid status → error, status unchanged.
	if err := testEnv.Repo.SetOrganizationMemberStatusGuarded(ctx, org.ID, member.ID, "frob"); err == nil {
		t.Fatalf("expected error for invalid status, got nil")
	}
	if got := memberStatus(); got != core.OrgMemberStatusActive {
		t.Fatalf("member status should be unchanged after invalid status, got %q", got)
	}

	// (f) server handler: PATCH .../members/{userId}/status.
	router := setupServerOrgSuspendRouter(t, ws, app)
	patchStatus := func(orgID, userID, status string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"status": status})
		url := orgBase(app) + "/" + orgID + "/members/" + userID + "/status"
		req := httptest.NewRequest(http.MethodPatch, url, bytes.NewReader(body))
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	// Disable a non-last-owner member via the handler → 204 (matches SetRole).
	if rr := patchStatus(org.ID.String(), member.ID.String(), core.OrgMemberStatusDisabled); rr.Code != http.StatusNoContent {
		t.Fatalf("disable via handler: expected 204, got %d (%s)", rr.Code, rr.Body.String())
	}
	if got := memberStatus(); got != core.OrgMemberStatusDisabled {
		t.Fatalf("member should be disabled via handler, got %q", got)
	}

	// Sole-owner disable via the handler → 409 (last-owner mapped to conflict).
	if rr := patchStatus(soloOrg.ID.String(), soloOwner.ID.String(), core.OrgMemberStatusDisabled); rr.Code != http.StatusConflict {
		t.Fatalf("disable sole owner via handler: expected 409, got %d (%s)", rr.Code, rr.Body.String())
	}
}
