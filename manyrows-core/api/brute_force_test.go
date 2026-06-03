package api_test

import (
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
