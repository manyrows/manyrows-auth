package api_test

import (
	"context"
	"testing"
	"time"

	"manyrows-core/core"
	"manyrows-core/utils"
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
