package api_test

import (
	"context"
	"testing"
)

func TestApp_BruteForceProtectionDefaultsTrue(t *testing.T) {
	acc := testEnv.CreateTestAccount(t, "bfp-default-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "BFP WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	if !app.BruteForceProtectionEnabled {
		t.Fatalf("expected BruteForceProtectionEnabled to default true, got false")
	}
}

func TestUpdateAppBruteForceProtectionConfig(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "bfp-upd-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "BFP Upd WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	// Disable.
	out, err := testEnv.Repo.UpdateAppBruteForceProtectionConfig(ctx, ws.ID, app.ProjectID, app.ID, false)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if out.BruteForceProtectionEnabled {
		t.Fatalf("expected disabled, got enabled=true")
	}

	// Re-enable.
	out, err = testEnv.Repo.UpdateAppBruteForceProtectionConfig(ctx, ws.ID, app.ProjectID, app.ID, true)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !out.BruteForceProtectionEnabled {
		t.Fatalf("expected enabled, got false")
	}
}
