package api_test

import (
	"context"
	"testing"

	"manyrows-core/core/repo"

	"github.com/gofrs/uuid/v5"
)

// TestUpdateAppNaverConfig_TrustUnverifiedEmailRoundTrips verifies the per-app
// Naver "trust unverified email" opt-in persists through the repo layer:
// migration column + core.App field + scanAppFull + UpdateAppNaverConfig
// wiring. New apps must default to false (secure), and the flag must round-trip
// both ways.
func TestUpdateAppNaverConfig_TrustUnverifiedEmailRoundTrips(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "naver-trust-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Naver WS", GenerateUniqueSlug("ws"))
	proj := testEnv.CreateTestProject(t, ws, acc, "Naver Prod", GenerateUniqueSlug("p"))
	appID := createTestApp(t, ws.ID, proj.ID, uuid.Nil, "Naver App")
	t.Cleanup(func() { _, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM apps WHERE id = $1", appID) })

	clientID := "naver-client-1"

	// New apps default to false (secure) — the migration's NOT NULL DEFAULT.
	app0, err := testEnv.Repo.GetAppByID(ctx, appID)
	if err != nil {
		t.Fatalf("get app: %v", err)
	}
	if app0.NaverTrustUnverifiedEmail {
		t.Fatal("new app must default NaverTrustUnverifiedEmail=false")
	}

	// Opt in → persists true (returned value and on reload).
	out, err := testEnv.Repo.UpdateAppNaverConfig(ctx, ws.ID, proj.ID, appID, repo.AppNaverConfigUpdate{
		AuthMethodNaver:      true,
		ClientID:             &clientID,
		TrustUnverifiedEmail: true,
	})
	if err != nil {
		t.Fatalf("update naver config (opt in): %v", err)
	}
	if !out.NaverTrustUnverifiedEmail {
		t.Error("UpdateAppNaverConfig should return NaverTrustUnverifiedEmail=true")
	}
	if reloaded, _ := testEnv.Repo.GetAppByID(ctx, appID); !reloaded.NaverTrustUnverifiedEmail {
		t.Error("opt-in must persist: GetAppByID should report NaverTrustUnverifiedEmail=true")
	}

	// Opt back out → persists false.
	out2, err := testEnv.Repo.UpdateAppNaverConfig(ctx, ws.ID, proj.ID, appID, repo.AppNaverConfigUpdate{
		AuthMethodNaver:      true,
		ClientID:             &clientID,
		TrustUnverifiedEmail: false,
	})
	if err != nil {
		t.Fatalf("update naver config (opt out): %v", err)
	}
	if out2.NaverTrustUnverifiedEmail {
		t.Error("opt-out must persist: NaverTrustUnverifiedEmail should be false")
	}
}
