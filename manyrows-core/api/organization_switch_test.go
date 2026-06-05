package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
)

func TestSetClientSessionOrganization_RoundTrip(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "sess-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, "m-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	org, err := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &user.ID)
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}

	now := time.Now().UTC()
	ses := &core.ClientSession{
		ID:         utils.NewUUID(),
		UserID:     user.ID,
		AppID:      &app.ID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
		LastSeenAt: now,
	}
	if err := testEnv.Repo.InsertClientSession(ctx, ses); err != nil {
		t.Fatalf("InsertClientSession: %v", err)
	}

	if err := testEnv.Repo.SetClientSessionOrganization(ctx, ses.ID, &org.ID); err != nil {
		t.Fatalf("SetClientSessionOrganization: %v", err)
	}
	got, err := testEnv.Repo.GetClientSessionByID(ctx, ses.ID)
	if err != nil {
		t.Fatalf("GetClientSessionByID: %v", err)
	}
	if got.OrganizationID == nil || *got.OrganizationID != org.ID {
		t.Fatalf("organization_id: got %v want %v", got.OrganizationID, org.ID)
	}

	if err := testEnv.Repo.SetClientSessionOrganization(ctx, ses.ID, nil); err != nil {
		t.Fatalf("clear: %v", err)
	}
	got2, _ := testEnv.Repo.GetClientSessionByID(ctx, ses.ID)
	if got2.OrganizationID != nil {
		t.Fatalf("expected cleared org, got %v", got2.OrganizationID)
	}
}

func TestSwitchOrganization_RequiresMembership(t *testing.T) {
	router := setupClientAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "sw-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
	}()

	ctx := context.Background()
	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, appID, true); err != nil {
		t.Fatalf("enable orgs: %v", err)
	}

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUserWithMembership: %v", err)
	}

	orgA, err := testEnv.Repo.CreateOrganization(ctx, appID, "Acme", GenerateUniqueSlug("acme"), &user.ID)
	if err != nil {
		t.Fatalf("CreateOrganization A: %v", err)
	}
	if _, err := testEnv.Repo.AddOrganizationMember(ctx, orgA.ID, user.ID, core.OrgRoleOwner); err != nil {
		t.Fatalf("AddOrganizationMember: %v", err)
	}
	orgB, err := testEnv.Repo.CreateOrganization(ctx, appID, "Other", GenerateUniqueSlug("other"), nil)
	if err != nil {
		t.Fatalf("CreateOrganization B: %v", err)
	}

	_, accessToken := createTestClientSessionForApp(t, ws, acc, &core.App{ID: appID})
	switchURL := "/x/" + ws.Slug + "/apps/" + appID.String() + "/a/session/organization"

	// Active member can switch to org A → 200.
	req := httptest.NewRequest(http.MethodPost, switchURL, strings.NewReader(`{"organizationId":"`+orgA.ID.String()+`"}`))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("member switch: got %d want 200 (body=%s)", rr.Code, rr.Body.String())
	}

	// Switching to an org the user is NOT a member of → 403.
	req2 := httptest.NewRequest(http.MethodPost, switchURL, strings.NewReader(`{"organizationId":"`+orgB.ID.String()+`"}`))
	req2.Header.Set("Authorization", "Bearer "+accessToken)
	req2.Header.Set("Content-Type", "application/json")
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("non-member switch: got %d want 403 (body=%s)", rr2.Code, rr2.Body.String())
	}
}

func TestCreateSession_DefaultsSingleOrg(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "def-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	if err := testEnv.Repo.SetAppOrganizationsEnabled(ctx, app.ID, true); err != nil {
		t.Fatalf("enable orgs: %v", err)
	}

	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, "m-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	org, err := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &user.ID)
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if _, err := testEnv.Repo.AddOrganizationMember(ctx, org.ID, user.ID, core.OrgRoleOwner); err != nil {
		t.Fatalf("AddOrganizationMember: %v", err)
	}

	svc := NewTestServices(t)
	ses, err := svc.ClientAuth.CreateSession(ctx, user.ID, app.ID, "ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if ses.OrganizationID == nil || *ses.OrganizationID != org.ID {
		t.Fatalf("expected default active org %v, got %v", org.ID, ses.OrganizationID)
	}
}
