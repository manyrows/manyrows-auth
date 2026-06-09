package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/core"
)

// Destructive org actions must leave an audit trail in auth_logs.
func TestServerDeleteOrganization_AuditLogged(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "oad-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	owner, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, "own-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	org, _ := testEnv.Repo.CreateOrganization(ctx, app.ID, "Acme", GenerateUniqueSlug("acme"), &owner.ID)
	_, _ = testEnv.Repo.AddOrganizationMember(ctx, org.ID, owner.ID, core.OrgRoleOwner)

	router := setupServerOrgRouter(t, ws, app)
	req := httptest.NewRequest(http.MethodDelete,
		orgBase(app)+"/"+org.ID.String()+"?actorUserId="+owner.ID.String(), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d (%s)", rr.Code, rr.Body.String())
	}

	var count int
	if err := testEnv.DB.Pool().QueryRow(ctx,
		`SELECT count(*) FROM auth_logs WHERE event = $1 AND app_id = $2 AND metadata->>'orgId' = $3`,
		"organization.deleted", app.ID, org.ID.String()).Scan(&count); err != nil {
		t.Fatalf("query auth_logs: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 organization.deleted audit log for the org, got %d", count)
	}
}
