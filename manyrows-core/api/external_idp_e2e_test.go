package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"manyrows-core/api"
	"manyrows-core/auth"
	"manyrows-core/auth/client"
	"manyrows-core/core"
	"manyrows-core/crypto"
	"manyrows-core/email"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
)

// e2eMockIDP is a minimal OpenID provider: discovery + JWKS + a token
// endpoint that signs whatever claims the test set.
type e2eMockIDP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	claims jwt.MapClaims // baked into the id_token returned by /token
}

func newE2EMockIDP(t *testing.T) *e2eMockIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	m := &e2eMockIDP{key: key, kid: "e2e-kid"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 m.server.URL,
			"authorization_endpoint": m.server.URL + "/authorize",
			"token_endpoint":         m.server.URL + "/token",
			"userinfo_endpoint":      m.server.URL + "/userinfo",
			"jwks_uri":               m.server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := m.key.Public().(*rsa.PublicKey)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": m.kid,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, m.claims)
		tok.Header["kid"] = m.kid
		signed, err := tok.SignedString(m.key)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": signed, "access_token": "at", "token_type": "Bearer"})
	})
	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

// TestExternalIDP_E2E drives the real authorize + callback handlers
// end-to-end against a mock IdP: it would have caught the oauth_states
// CHECK that rejected idp: provider keys, and it exercises the
// email-verified gate added by the audit.
func TestExternalIDP_E2E(t *testing.T) {
	ctx := context.Background()
	cfg := GetTestConfig()
	adminAuthService, err := auth.NewAuthService(cfg, testEnv.Repo)
	if err != nil {
		t.Fatalf("admin auth service: %v", err)
	}
	cas, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("client auth service: %v", err)
	}
	h := api.NewRequestHandler(testEnv.Repo, adminAuthService, cas, email.NewEmailService(true, nil), cfg, nil, nil)

	r := chi.NewRouter()
	wsRouter := chi.NewRouter()
	wsRouter.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ws, ok, err := testEnv.Repo.GetWorkspaceBySlug(req.Context(), chi.URLParam(req, "workspaceSlug"))
			if err != nil || !ok {
				http.Error(w, "no ws", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, req.WithContext(core.WithWorkspace(req.Context(), ws)))
		})
	})
	wsRouter.Route("/apps/{appId}", func(ar chi.Router) {
		ar.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				wsCtx, _ := core.WorkspaceFromContext(req.Context())
				appID, perr := uuid.FromString(chi.URLParam(req, "appId"))
				if perr != nil {
					http.Error(w, "bad app id", http.StatusBadRequest)
					return
				}
				app, aerr := testEnv.Repo.GetAppByID(req.Context(), appID)
				if aerr != nil || app.WorkspaceID != wsCtx.ID || !app.Enabled {
					http.Error(w, "no app", http.StatusNotFound)
					return
				}
				next.ServeHTTP(w, req.WithContext(core.WithApp(req.Context(), &app)))
			})
		})
		ar.Get("/", h.HandleGetAppForAppKit)
		ar.Route("/auth", func(authR chi.Router) {
			authR.Get("/idp/{providerSlug}/authorize", h.WorkspaceExternalIDPAuthorize)
			authR.Get("/idp/{providerSlug}/callback", h.WorkspaceExternalIDPCallback)
		})
	})
	r.Mount("/x/{workspaceSlug}", wsRouter)

	acc := testEnv.CreateTestAccount(t, "e2e-extidp-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "E2E ExtIDP WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	app = allowReg(t, app, true)

	openerOrigin := "https://app.example"
	if err := testEnv.Repo.InsertCorsOrigin(ctx, core.CorsOrigin{
		ID: uuid.Must(uuid.NewV4()), AppID: app.ID, Origin: openerOrigin, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed cors origin: %v", err)
	}

	idp := newE2EMockIDP(t)

	// Provision the provider directly, encrypting with an encryptor built
	// from the same cfg the handler uses (so the callback can decrypt).
	enc := crypto.NewMySecretEncryptor(cfg)
	idpID := uuid.Must(uuid.NewV4())
	secretEnc, err := enc.EncryptToBytesWithAAD([]byte("client-secret-1"), crypto.AAD("external_idps", "client_secret_encrypted", idpID))
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}
	if err := testEnv.Repo.CreateExternalIDP(ctx, &core.ExternalIDP{
		ID: idpID, AppID: app.ID, Slug: "mock", DisplayName: "Mock IdP", Enabled: true,
		Mode: core.ExternalIDPModeOIDC, IssuerURL: idp.server.URL,
		ClientID: "client-1", ClientSecretEncrypted: secretEnc,
	}); err != nil {
		t.Fatalf("create provider: %v", err)
	}

	// A second provider on the same mock IdP, opted into trusting
	// unverified emails (e.g. an IdP that verifies but omits the claim).
	trustedID := uuid.Must(uuid.NewV4())
	trustedSecret, err := enc.EncryptToBytesWithAAD([]byte("client-secret-2"), crypto.AAD("external_idps", "client_secret_encrypted", trustedID))
	if err != nil {
		t.Fatalf("encrypt trusted secret: %v", err)
	}
	if err := testEnv.Repo.CreateExternalIDP(ctx, &core.ExternalIDP{
		ID: trustedID, AppID: app.ID, Slug: "mock-trusted", DisplayName: "Mock Trusted", Enabled: true,
		Mode: core.ExternalIDPModeOIDC, IssuerURL: idp.server.URL,
		ClientID: "client-1", ClientSecretEncrypted: trustedSecret, TrustUnverifiedEmail: true,
	}); err != nil {
		t.Fatalf("create trusted provider: %v", err)
	}

	// A disabled provider — must NOT surface in the public AppKit config.
	disabledID := uuid.Must(uuid.NewV4())
	disabledSecret, _ := enc.EncryptToBytesWithAAD([]byte("x"), crypto.AAD("external_idps", "client_secret_encrypted", disabledID))
	if err := testEnv.Repo.CreateExternalIDP(ctx, &core.ExternalIDP{
		ID: disabledID, AppID: app.ID, Slug: "mock-disabled", DisplayName: "Mock Disabled", Enabled: false,
		Mode: core.ExternalIDPModeOIDC, IssuerURL: idp.server.URL, ClientID: "client-1", ClientSecretEncrypted: disabledSecret,
	}); err != nil {
		t.Fatalf("create disabled provider: %v", err)
	}

	// authorizeAndCallback runs one full flow for the given provider slug
	// and returns the callback's (HTML-wrapped) response. emailVerified
	// controls the id_token claim.
	authorizeAndCallback := func(t *testing.T, slug, signInEmail, sub string, emailVerified bool) *httptest.ResponseRecorder {
		t.Helper()
		authzPath := "/x/" + ws.Slug + "/apps/" + app.ID.String() + "/auth/idp/" + slug + "/authorize"
		cbPath := "/x/" + ws.Slug + "/apps/" + app.ID.String() + "/auth/idp/" + slug + "/callback"
		authzRR := httptest.NewRecorder()
		r.ServeHTTP(authzRR, httptest.NewRequest(http.MethodGet, authzPath+"?openerOrigin="+url.QueryEscape(openerOrigin), nil))
		if authzRR.Code != http.StatusOK {
			t.Fatalf("authorize: %d (%s)", authzRR.Code, authzRR.Body.String())
		}
		var authz struct {
			URL   string `json:"url"`
			State string `json:"state"`
		}
		if err := json.Unmarshal(authzRR.Body.Bytes(), &authz); err != nil {
			t.Fatalf("authorize body: %v", err)
		}
		au, err := url.Parse(authz.URL)
		if err != nil {
			t.Fatalf("parse authorize url: %v", err)
		}
		if !strings.HasPrefix(authz.URL, idp.server.URL+"/authorize") {
			t.Fatalf("authorize URL should target the IdP, got %s", authz.URL)
		}
		if au.Query().Get("code_challenge") == "" || au.Query().Get("code_challenge_method") != "S256" {
			t.Fatalf("authorize URL missing PKCE: %s", authz.URL)
		}
		nonce := au.Query().Get("nonce")
		if nonce == "" {
			t.Fatal("authorize URL missing nonce")
		}

		// Mint the id_token the mock /token will return, with the nonce
		// the handler derived for this state.
		idp.claims = jwt.MapClaims{
			"iss": idp.server.URL, "aud": "client-1", "sub": sub,
			"email": signInEmail, "email_verified": emailVerified, "nonce": nonce,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(),
		}

		cbRR := httptest.NewRecorder()
		r.ServeHTTP(cbRR, httptest.NewRequest(http.MethodGet, cbPath+"?code=auth-code&state="+url.QueryEscape(authz.State), nil))
		// The callback always wraps its result in a 200 HTML postMessage.
		if cbRR.Code != http.StatusOK {
			t.Fatalf("callback HTTP status should be 200 (HTML wrapper), got %d", cbRR.Code)
		}
		return cbRR
	}

	// --- Happy path: verified email → session + linked identity ---
	t.Run("verified email signs in and links identity", func(t *testing.T) {
		signInEmail := "e2e-ok-" + GenerateUniqueSlug("u") + "@example.com"
		cbRR := authorizeAndCallback(t, "mock", signInEmail, "mock-sub-1", true)
		if strings.Contains(cbRR.Body.String(), "emailNotVerified") {
			t.Fatalf("verified sign-in should not be rejected: %s", cbRR.Body.String())
		}

		user, err := testEnv.Repo.GetUserByEmail(ctx, signInEmail, app)
		if err != nil || user == nil {
			t.Fatalf("user should have been created: user=%v err=%v", user, err)
		}
		rows, err := testEnv.Repo.ListUserIdentities(ctx, user.ID)
		if err != nil {
			t.Fatalf("list identities: %v", err)
		}
		wantKey := core.ExternalIDPProviderKey(idpID)
		found := false
		for _, row := range rows {
			if string(row.Provider) == wantKey && row.ProviderSubject == "mock-sub-1" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected identity %q sub=mock-sub-1, got %+v", wantKey, rows)
		}
	})

	// --- Verified-email gate: unverified email is refused ---
	t.Run("unverified email is rejected", func(t *testing.T) {
		signInEmail := "e2e-unverified-" + GenerateUniqueSlug("u") + "@example.com"
		cbRR := authorizeAndCallback(t, "mock", signInEmail, "mock-sub-2", false)
		if !strings.Contains(cbRR.Body.String(), "emailNotVerified") {
			t.Fatalf("unverified email must be rejected with emailNotVerified, got: %s", cbRR.Body.String())
		}
		// And no account should have been created.
		if user, _ := testEnv.Repo.GetUserByEmail(ctx, signInEmail, app); user != nil {
			t.Fatal("no user should be created for an unverified-email sign-in")
		}
	})

	// --- Opt-out: a trusted IdP accepts an unverified email ---
	// --- Public AppKit config lists enabled providers only ---
	t.Run("public config exposes enabled providers, hides disabled + secrets", func(t *testing.T) {
		cfgRR := httptest.NewRecorder()
		r.ServeHTTP(cfgRR, httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/", nil))
		if cfgRR.Code != http.StatusOK {
			t.Fatalf("get app config: %d (%s)", cfgRR.Code, cfgRR.Body.String())
		}
		var cfg struct {
			ExternalIdps []struct {
				Slug        string `json:"slug"`
				DisplayName string `json:"displayName"`
			} `json:"externalIdps"`
		}
		if err := json.Unmarshal(cfgRR.Body.Bytes(), &cfg); err != nil {
			t.Fatalf("unmarshal config: %v", err)
		}
		got := map[string]bool{}
		for _, p := range cfg.ExternalIdps {
			got[p.Slug] = true
		}
		if !got["mock"] || !got["mock-trusted"] {
			t.Fatalf("enabled providers missing from config: %+v", cfg.ExternalIdps)
		}
		if got["mock-disabled"] {
			t.Fatal("disabled provider must not appear in the public config")
		}
		// No secret/clientId fields are even present in the public shape.
		if bytes.Contains(cfgRR.Body.Bytes(), []byte("client-1")) || bytes.Contains(cfgRR.Body.Bytes(), []byte("clientSecret")) {
			t.Fatalf("public config leaked sensitive provider fields: %s", cfgRR.Body.String())
		}
	})

	t.Run("trust_unverified_email accepts an unverified email", func(t *testing.T) {
		signInEmail := "e2e-trusted-" + GenerateUniqueSlug("u") + "@example.com"
		cbRR := authorizeAndCallback(t, "mock-trusted", signInEmail, "mock-sub-3", false)
		if strings.Contains(cbRR.Body.String(), "emailNotVerified") {
			t.Fatalf("trusted IdP should accept an unverified email: %s", cbRR.Body.String())
		}
		user, err := testEnv.Repo.GetUserByEmail(ctx, signInEmail, app)
		if err != nil || user == nil {
			t.Fatalf("user should be created via the trusted IdP: user=%v err=%v", user, err)
		}
		rows, _ := testEnv.Repo.ListUserIdentities(ctx, user.ID)
		wantKey := core.ExternalIDPProviderKey(trustedID)
		found := false
		for _, row := range rows {
			if string(row.Provider) == wantKey {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected identity %q, got %+v", wantKey, rows)
		}
	})

	// --- Voluntary TOTP is enforced on OAuth logins ---
	// Regression test for the bug where the OAuth completion path only
	// checked TOTP when the app forced 2FA (Require2FA). A user who
	// enrolled TOTP themselves must still be challenged when signing in
	// via an external IdP — otherwise the second factor they enabled is
	// bypassable by choosing the OAuth front door.
	t.Run("voluntary TOTP is enforced on OAuth login (Require2FA off)", func(t *testing.T) {
		// Force the app to NOT require 2FA, so this exercises the
		// voluntary path specifically (the bug was invisible when
		// Require2FA was on, since that branch already challenged).
		if _, err := testEnv.DB.Pool().Exec(ctx, "UPDATE apps SET require_2fa = false WHERE id = $1", app.ID); err != nil {
			t.Fatalf("clear require_2fa: %v", err)
		}

		signInEmail := "e2e-voltotp-" + GenerateUniqueSlug("u") + "@example.com"
		// Pre-create the user in the app's pool and enroll TOTP on them.
		totpUser, _, err := testEnv.GetOrCreateUserWithMembership(ctx, signInEmail, app, core.UserSourceInvited)
		if err != nil {
			t.Fatalf("create totp user: %v", err)
		}
		secretEnc, err := enc.EncryptToBytesWithAAD([]byte("JBSWY3DPEHPK3PXP"), crypto.AAD("users", "totp_secret_encrypted", totpUser.ID))
		if err != nil {
			t.Fatalf("encrypt totp secret: %v", err)
		}
		if err := testEnv.Repo.SetUserTOTPSecret(ctx, totpUser.ID, secretEnc); err != nil {
			t.Fatalf("set totp secret: %v", err)
		}
		backupEnc, err := enc.EncryptToBytesWithAAD([]byte("[]"), crypto.AAD("users", "totp_backup_codes_encrypted", totpUser.ID))
		if err != nil {
			t.Fatalf("encrypt backup codes: %v", err)
		}
		if err := testEnv.Repo.EnableUserTOTP(ctx, totpUser.ID, time.Now().UTC(), backupEnc); err != nil {
			t.Fatalf("enable totp: %v", err)
		}

		cbRR := authorizeAndCallback(t, "mock", signInEmail, "mock-voltotp-sub", true)
		body := cbRR.Body.String()
		if !strings.Contains(body, "totpRequired") {
			t.Fatalf("voluntary TOTP must be challenged on OAuth login, got: %s", body)
		}
		// And crucially: no session/tokens are issued before the second
		// factor is satisfied.
		if strings.Contains(body, "accessToken") || strings.Contains(body, "refreshToken") {
			t.Fatalf("no tokens may be issued before TOTP is satisfied, got: %s", body)
		}
	})
}
