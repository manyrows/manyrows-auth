package api_test

import (
	"context"
	"testing"

	"manyrows-core/core"
	"manyrows-core/utils"
)

func TestApp_ConsentColumnsRoundTrip(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "consent-"+GenerateUniqueSlug("t")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Consent WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	// Defaults: empty/false.
	got, err := testEnv.Repo.GetAppByID(ctx, app.ID)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}
	if got.RequireConsent || got.ConsentVersion != "" || got.TermsURL != "" || got.PrivacyURL != "" {
		t.Fatalf("expected empty consent defaults, got %+v", got)
	}

	// Set via raw SQL, re-read through the scanner.
	if _, err := testEnv.DB.Pool().Exec(ctx,
		`UPDATE apps SET terms_url=$2, privacy_url=$3, consent_version=$4, require_consent=true WHERE id=$1`,
		app.ID, "https://t", "https://p", "v1"); err != nil {
		t.Fatalf("update: %v", err)
	}
	got2, _ := testEnv.Repo.GetAppByID(ctx, app.ID)
	if !got2.RequireConsent || got2.ConsentVersion != "v1" || got2.TermsURL != "https://t" || got2.PrivacyURL != "https://p" {
		t.Fatalf("consent columns not scanned: %+v", got2)
	}
}

func TestUserConsentRepo_InsertAndGet(t *testing.T) {
	ctx := context.Background()
	emailAddr := "uc-" + GenerateUniqueSlug("t") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "UC WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() { _, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id=$1", user.ID) })

	if err := testEnv.Repo.InsertUserConsent(ctx, utils.NewUUID(), user.ID, app.ID, "terms", "v1", "203.0.113.5", "test-agent"); err != nil {
		t.Fatalf("InsertUserConsent: %v", err)
	}
	got, err := testEnv.Repo.GetLatestUserConsent(ctx, user.ID, app.ID, "terms")
	if err != nil {
		t.Fatalf("GetLatestUserConsent: %v", err)
	}
	if got == nil || got.Version != "v1" || got.Kind != "terms" {
		t.Fatalf("unexpected consent: %+v", got)
	}
}
