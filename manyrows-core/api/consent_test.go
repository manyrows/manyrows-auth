package api_test

import (
	"context"
	"testing"
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