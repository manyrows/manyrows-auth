package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gofrs/uuid/v5"
)

// TestOIDCConsent_UpsertAndGet verifies GetOIDCConsent and UpsertOIDCConsent
// behave correctly: fresh → not found; first upsert stores scope; second
// upsert unions with existing.
func TestOIDCConsent_UpsertAndGet(t *testing.T) {
	ctx := context.Background()

	// Fresh user + app so this test is fully isolated.
	acc := testEnv.CreateTestAccount(t, "consent-upsert-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Consent WS", GenerateUniqueSlug("ws"))
	proj := testEnv.CreateTestProject(t, ws, acc, "Consent Proj", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, proj.ID, uuid.Nil, "Consent App")

	// Seed a user in the pool that belongs to appID.
	app, err := testEnv.Repo.GetAppByID(ctx, appID)
	if err != nil {
		t.Fatalf("load app: %v", err)
	}
	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, "consent-user-"+GenerateUniqueSlug("u")+"@example.com", &app, "password")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// 1. Fresh → not found.
	scope, found, err := testEnv.Repo.GetOIDCConsent(ctx, user.ID, appID)
	if err != nil {
		t.Fatalf("GetOIDCConsent: %v", err)
	}
	if found {
		t.Fatalf("expected found=false for fresh user+app, got scope=%q", scope)
	}

	// 2. First upsert stores scope.
	if err := testEnv.Repo.UpsertOIDCConsent(ctx, user.ID, appID, "openid email"); err != nil {
		t.Fatalf("UpsertOIDCConsent first: %v", err)
	}
	scope, found, err = testEnv.Repo.GetOIDCConsent(ctx, user.ID, appID)
	if err != nil {
		t.Fatalf("GetOIDCConsent after first upsert: %v", err)
	}
	if !found {
		t.Fatal("expected found=true after first upsert")
	}
	if scope != "openid email" {
		t.Fatalf("expected scope %q, got %q", "openid email", scope)
	}

	// 3. Second upsert unions — existing tokens kept first, new unique
	//    tokens appended.
	if err := testEnv.Repo.UpsertOIDCConsent(ctx, user.ID, appID, "openid offline_access"); err != nil {
		t.Fatalf("UpsertOIDCConsent second: %v", err)
	}
	scope, found, err = testEnv.Repo.GetOIDCConsent(ctx, user.ID, appID)
	if err != nil {
		t.Fatalf("GetOIDCConsent after second upsert: %v", err)
	}
	if !found {
		t.Fatal("expected found=true after second upsert")
	}
	want := "openid email offline_access"
	if scope != want {
		t.Fatalf("expected unioned scope %q, got %q", want, scope)
	}
}

// TestOIDCConsent_RequireConsentConfigRoundTrip verifies:
//  1. A fresh app has RequireConsent=false.
//  2. Toggling it to true via the admin OIDC config endpoint persists it.
//  3. Updating other fields (redirect URIs) without mentioning
//     requireConsent leaves the toggle unchanged.
func TestOIDCConsent_RequireConsentConfigRoundTrip(t *testing.T) {
	ctx := context.Background()
	router := setupOIDCAdminRouter(t)

	acc := testEnv.CreateTestAccount(t, "consent-cfg-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Consent Cfg WS", GenerateUniqueSlug("ws"))
	proj := testEnv.CreateTestProject(t, ws, acc, "Consent Cfg Proj", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, proj.ID, uuid.Nil, "Consent Cfg App")

	// Put app in cookie mode so OIDC can be enabled.
	if _, err := testEnv.DB.Pool().Exec(ctx,
		`update apps set transport_mode = 'cookie' where id = $1`, appID); err != nil {
		t.Fatalf("set transport_mode=cookie: %v", err)
	}

	_, claims := testEnv.CreateTestSession(t, acc)

	// 1. Fresh app: GetAppOIDCConfig().RequireConsent == false.
	cfg, err := testEnv.Repo.GetAppOIDCConfig(ctx, appID)
	if err != nil {
		t.Fatalf("GetAppOIDCConfig initial: %v", err)
	}
	if cfg.RequireConsent {
		t.Fatal("expected RequireConsent=false on fresh app")
	}

	// 2. Enable OIDC and set requireConsent=true via the admin update handler.
	rr := putOIDCConfig(t, router, ws, proj, appID, claims, map[string]any{
		"enabled":        true,
		"redirectUris":   []string{"https://customer.example/cb"},
		"requireConsent": true,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT oidc-config expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}

	// Verify response carries requireConsent=true.
	var respBody map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &respBody); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if v, ok := respBody["oidcRequireConsent"]; !ok || v != true {
		t.Fatalf("expected oidcRequireConsent=true in response, got %v (body=%s)", v, rr.Body.String())
	}

	// Reload via repo and confirm persisted.
	cfg, err = testEnv.Repo.GetAppOIDCConfig(ctx, appID)
	if err != nil {
		t.Fatalf("GetAppOIDCConfig after enable: %v", err)
	}
	if !cfg.RequireConsent {
		t.Fatal("expected RequireConsent=true after update")
	}

	// 3. Update only redirect URIs — requireConsent must stay true.
	rr2 := putOIDCConfig(t, router, ws, proj, appID, claims, map[string]any{
		"redirectUris": []string{"https://customer.example/cb", "https://other.example/cb"},
	})
	if rr2.Code != http.StatusOK {
		t.Fatalf("URI-only PUT expected 200, got %d (body=%s)", rr2.Code, rr2.Body.String())
	}
	var resp2 map[string]any
	if err := json.Unmarshal(rr2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("unmarshal URI-only response: %v", err)
	}
	if v, ok := resp2["oidcRequireConsent"]; !ok || v != true {
		t.Fatalf("requireConsent should remain true after URI-only update; oidcRequireConsent=%v body=%s", v, rr2.Body.String())
	}

	cfg, err = testEnv.Repo.GetAppOIDCConfig(ctx, appID)
	if err != nil {
		t.Fatalf("GetAppOIDCConfig after URI update: %v", err)
	}
	if !cfg.RequireConsent {
		t.Fatal("RequireConsent should remain true after an unrelated update")
	}
}
