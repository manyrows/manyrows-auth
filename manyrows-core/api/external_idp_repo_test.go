package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// TestExternalIDPProviderKey_RoutesAsPathParam guards the disconnect
// endpoint /a/me/identities/{provider}: an external-IdP key is
// "idp:<uuid>" (contains a colon). chi does NOT percent-decode path
// params, so the AppKit client must send the key VERBATIM (raw colon) —
// "idp:<uuid>" has only path-safe characters, so the raw form routes
// correctly while URL-encoding the colon would silently break the match
// (DeleteUserIdentity would look up "idp%3A<uuid>" and find nothing).
func TestExternalIDPProviderKey_RoutesAsPathParam(t *testing.T) {
	key := core.ExternalIDPProviderKey(uuid.Must(uuid.NewV4())) // "idp:<uuid>"

	r := chi.NewRouter()
	var got string
	r.Delete("/identities/{provider}", func(w http.ResponseWriter, req *http.Request) {
		got = utils.GetPathString("provider", req)
		w.WriteHeader(http.StatusNoContent)
	})

	// Raw key (what the client must send) round-trips intact.
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/identities/"+key, nil))
	if got != key {
		t.Fatalf("raw key: chi captured %q, want %q", got, key)
	}

	// Regression guard: chi does not decode %3A. If this ever starts
	// matching, the don't-encode assumption changed — revisit the
	// disconnect client (Profile.tsx must keep the provider raw).
	got = ""
	encoded := "idp%3A" + key[len("idp:"):]
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodDelete, "/identities/"+encoded, nil))
	if got == key {
		t.Fatal("chi unexpectedly percent-decoded the path param; the disconnect client must NOT URL-encode the provider key")
	}
}

// TestExternalIDPRepo_CRUD exercises the full lifecycle and, by running
// against the real test DB, validates that migration 00005 applies and
// the NULL/COALESCE round-trip + repo defaults behave.
func TestExternalIDPRepo_CRUD(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "extidp-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "ExtIDP WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	e := &core.ExternalIDP{
		AppID:                 app.ID,
		Slug:                  "acme-okta",
		DisplayName:           "Acme Okta",
		Enabled:               true,
		Mode:                  core.ExternalIDPModeOIDC,
		IssuerURL:             "https://acme.okta.com",
		ClientID:              "client-123",
		ClientSecretEncrypted: []byte("ciphertext-bytes"),
		// Scopes / SubjectField / EmailField intentionally left empty —
		// the repo must fill the standard-claim defaults.
	}
	if err := testEnv.Repo.CreateExternalIDP(ctx, e); err != nil {
		t.Fatalf("create: %v", err)
	}
	if e.ID == uuid.Nil {
		t.Fatal("create must assign an ID")
	}
	if e.Scopes != "openid email profile" {
		t.Fatalf("default scopes not applied: %q", e.Scopes)
	}
	if e.SubjectField != "sub" || e.EmailField != "email" {
		t.Fatalf("default claim fields not applied: sub=%q email=%q", e.SubjectField, e.EmailField)
	}

	got, err := testEnv.Repo.GetExternalIDPByAppAndSlug(ctx, app.ID, "acme-okta")
	if err != nil {
		t.Fatalf("get by slug: %v", err)
	}
	if got.IssuerURL != "https://acme.okta.com" {
		t.Fatalf("issuer round-trip: %q", got.IssuerURL)
	}
	if string(got.ClientSecretEncrypted) != "ciphertext-bytes" {
		t.Fatalf("secret round-trip mismatch")
	}
	if got.Mode != core.ExternalIDPModeOIDC {
		t.Fatalf("mode round-trip: %q", got.Mode)
	}
	// OAuth2-only columns were never set → stored NULL → COALESCEd to "".
	if got.AuthorizeURL != "" || got.TokenURL != "" || got.UserinfoURL != "" {
		t.Fatalf("oidc row should have empty oauth2 endpoints, got authorize=%q token=%q userinfo=%q",
			got.AuthorizeURL, got.TokenURL, got.UserinfoURL)
	}
	if got.ProviderKey() != "idp:"+got.ID.String() {
		t.Fatalf("provider key should be idp:<config-uuid>, got %q", got.ProviderKey())
	}

	all, err := testEnv.Repo.ListExternalIDPsByApp(ctx, app.ID)
	if err != nil || len(all) != 1 {
		t.Fatalf("list-by-app: err=%v len=%d", err, len(all))
	}

	// Disable → drops out of the enabled-only list AppKit reads.
	got.DisplayName = "Acme Okta (prod)"
	got.Enabled = false
	if err := testEnv.Repo.UpdateExternalIDP(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	enabled, err := testEnv.Repo.ListEnabledExternalIDPsByApp(ctx, app.ID)
	if err != nil {
		t.Fatalf("list-enabled: %v", err)
	}
	if len(enabled) != 0 {
		t.Fatalf("expected 0 enabled after disable, got %d", len(enabled))
	}

	ok, err := testEnv.Repo.DeleteExternalIDP(ctx, app.ID, got.ID)
	if err != nil || !ok {
		t.Fatalf("delete: ok=%v err=%v", ok, err)
	}
	if _, err := testEnv.Repo.GetExternalIDPByAppAndSlug(ctx, app.ID, "acme-okta"); !errors.Is(err, repo.ErrExternalIDPNotFound) {
		t.Fatalf("expected ErrExternalIDPNotFound after delete, got %v", err)
	}
}

// TestExternalIDPState_SignVerifyRoundTrip proves the generic flow can
// sign + verify OAuth state under the "idp:<uuid>" provider key.
// Regression for migration 00006: oauth_states.provider originally had a
// CHECK allowlisting only {google,apple,microsoft,github}, which would
// reject this at InsertOAuthState time and break the authorize handler.
func TestExternalIDPState_SignVerifyRoundTrip(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "extidp-state-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "ExtIDP State WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	key := []byte("test-oauth-state-hmac-key-0123456789")
	providerKey := core.ExternalIDPProviderKey(uuid.Must(uuid.NewV4()))

	state, err := auth.SignOAuthState(ctx, testEnv.Repo, key, app.ID, providerKey, "https://app.example", nil, false, "", time.Minute)
	if err != nil {
		t.Fatalf("SignOAuthState with %q provider failed (oauth_states CHECK?): %v", providerKey, err)
	}
	gotApp, origin, _, _, _, err := auth.VerifyOAuthState(ctx, testEnv.Repo, key, state, providerKey)
	if err != nil {
		t.Fatalf("VerifyOAuthState: %v", err)
	}
	if gotApp != app.ID {
		t.Fatalf("verified appID = %s, want %s", gotApp, app.ID)
	}
	if origin != "https://app.example" {
		t.Fatalf("openerOrigin round-trip = %q", origin)
	}
}

// TestExternalIDP_DeleteLeavesIdentityOrphanedNotCascaded pins a
// deliberate design choice: user_identities has no FK to external_idps,
// so deleting a provider config does NOT delete users' identity links.
// The orphaned "idp:<uuid>" rows are inert — no live flow ever queries a
// deleted provider's key (the key is its UUID) — and we keep them rather
// than destroy identity data as a side effect of a config change.
func TestExternalIDP_DeleteLeavesIdentityOrphanedNotCascaded(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "extidp-orphan-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Orphan WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	idp := &core.ExternalIDP{
		AppID: app.ID, Slug: "okta", DisplayName: "Okta", Enabled: true,
		Mode: core.ExternalIDPModeOIDC, IssuerURL: "https://okta.example",
		ClientID: "c", ClientSecretEncrypted: []byte("x"),
	}
	if err := testEnv.Repo.CreateExternalIDP(ctx, idp); err != nil {
		t.Fatalf("create provider: %v", err)
	}

	email := "orphan-" + GenerateUniqueSlug("u") + "@example.com"
	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, email, app, core.UserSourceExternalIDP)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	providerKey := core.UserSource(idp.ProviderKey())
	if err := testEnv.Repo.UpsertUserIdentity(ctx, user.ID, app.UserPoolID, providerKey, "sub-1", email); err != nil {
		t.Fatalf("link identity: %v", err)
	}

	if ok, err := testEnv.Repo.DeleteExternalIDP(ctx, app.ID, idp.ID); err != nil || !ok {
		t.Fatalf("delete provider: ok=%v err=%v", ok, err)
	}

	// The identity link survives (orphaned, not cascaded); the user too.
	rows, err := testEnv.Repo.ListUserIdentities(ctx, user.ID)
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	found := false
	for _, r := range rows {
		if r.Provider == providerKey {
			found = true
		}
	}
	if !found {
		t.Fatalf("identity link should survive provider deletion (no FK cascade); got %+v", rows)
	}
	if u, _ := testEnv.Repo.GetUserByID(ctx, user.ID); u == nil {
		t.Fatal("user must not be affected by provider deletion")
	}
}

// TestOAuthState_ConsentRoundTrip signs with consentAccepted=true + consentVersion="v1"
// and asserts VerifyOAuthState returns them (round-trip through DB).
func TestOAuthState_ConsentRoundTrip(t *testing.T) {
	ctx := context.Background()
	appID := utils.NewUUID()
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")
	token, err := auth.SignOAuthState(ctx, testEnv.Repo, key, appID, "google", "https://opener.example", nil, true, "v1", 5*time.Minute)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	gotApp, _, _, accepted, version, err := auth.VerifyOAuthState(ctx, testEnv.Repo, key, token, "google")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if gotApp != appID || !accepted || version != "v1" {
		t.Fatalf("consent did not round-trip: app=%v accepted=%v version=%q", gotApp, accepted, version)
	}
}

// TestExternalIDPRepo_ModeConstraints validates the per-mode endpoint
// CHECK and the slug-format CHECK from migration 00005.
func TestExternalIDPRepo_ModeConstraints(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "extidp-c-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "ExtIDP Constraints WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	// OIDC mode without an issuer_url must violate the per-mode CHECK.
	if err := testEnv.Repo.CreateExternalIDP(ctx, &core.ExternalIDP{
		AppID: app.ID, Slug: "no-issuer", DisplayName: "x", Mode: core.ExternalIDPModeOIDC,
		ClientID: "c", ClientSecretEncrypted: []byte("x"),
	}); err == nil {
		t.Fatal("expected CHECK violation: oidc mode requires issuer_url")
	}

	// OAuth2 mode with the three explicit endpoints must insert cleanly.
	if err := testEnv.Repo.CreateExternalIDP(ctx, &core.ExternalIDP{
		AppID: app.ID, Slug: "discord", DisplayName: "Discord", Mode: core.ExternalIDPModeOAuth2,
		AuthorizeURL: "https://discord.com/oauth2/authorize",
		TokenURL:     "https://discord.com/api/oauth2/token",
		UserinfoURL:  "https://discord.com/api/users/@me",
		ClientID:     "c", ClientSecretEncrypted: []byte("x"), Scopes: "identify email",
	}); err != nil {
		t.Fatalf("oauth2 with all endpoints should insert: %v", err)
	}

	// A non-DNS-label slug must violate the slug-format CHECK.
	if err := testEnv.Repo.CreateExternalIDP(ctx, &core.ExternalIDP{
		AppID: app.ID, Slug: "Bad Slug!", DisplayName: "x", Mode: core.ExternalIDPModeOIDC,
		IssuerURL: "https://x.example", ClientID: "c", ClientSecretEncrypted: []byte("x"),
	}); err == nil {
		t.Fatal("expected CHECK violation: bad slug format")
	}
}
