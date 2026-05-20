package api_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"manyrows-core/api"
	"manyrows-core/auth"
	"manyrows-core/auth/client"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/email"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
)

// =====================
// OIDC test scaffolding
// =====================

type oidcTestEnv struct {
	router  *chi.Mux
	handler *api.RequestHandler
	cas     *client.AuthService

	ws  *core.Workspace
	app *core.App
}

func setupOIDCRouter(t *testing.T) *oidcTestEnv {
	t.Helper()

	cfg := GetTestConfig()

	adminAuthService, err := auth.NewAuthService(cfg, testEnv.Repo)
	if err != nil {
		t.Fatalf("create admin auth service: %v", err)
	}
	cas, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("create client auth service: %v", err)
	}
	emailSvc := email.NewEmailService(true, nil)
	h := api.NewRequestHandler(testEnv.Repo, adminAuthService, cas, emailSvc, cfg, nil, nil)

	r := chi.NewRouter()
	// JWKS is install-wide in production; mount it at the same root
	// path here so the e2e RP test can fetch it via the URL the
	// discovery doc advertises.
	r.Get("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		doc, err := cas.JWKSDocument()
		if err != nil {
			http.Error(w, "jwks unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	})
	wsRouter := chi.NewRouter()
	wsRouter.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slug := chi.URLParam(r, "workspaceSlug")
			ws, ok, err := testEnv.Repo.GetWorkspaceBySlug(r.Context(), slug)
			if err != nil || !ok {
				http.Error(w, "workspace not found", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(core.WithWorkspace(r.Context(), ws)))
		})
	})

	wsRouter.Route("/apps/{appId}", func(ar chi.Router) {
		ar.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := r.Context()
				ws, _ := core.WorkspaceFromContext(ctx)
				appIDStr := chi.URLParam(r, "appId")
				appID, err := uuid.FromString(appIDStr)
				if err != nil {
					http.Error(w, "invalid app id", http.StatusBadRequest)
					return
				}
				app, err := testEnv.Repo.GetAppByID(ctx, appID)
				if err != nil || app.WorkspaceID != ws.ID || !app.Enabled {
					http.Error(w, "app not found", http.StatusNotFound)
					return
				}
				next.ServeHTTP(w, r.WithContext(core.WithApp(ctx, &app)))
			})
		})

		ar.Get("/.well-known/openid-configuration", h.OIDCDiscovery)
		ar.Route("/oidc", func(oidc chi.Router) {
			oidc.Get("/authorize", h.OIDCAuthorize)
			oidc.Get("/authorize/resume", h.OIDCAuthorizeResume)
			oidc.Get("/login", h.OIDCLoginPage)
			oidc.Post("/token", h.OIDCToken)
			oidc.Get("/userinfo", h.OIDCUserInfo)
			oidc.Post("/userinfo", h.OIDCUserInfo)
			oidc.Get("/end-session", h.OIDCEndSession)
			oidc.Post("/end-session", h.OIDCEndSession)
		})
	})

	r.Mount("/x/{workspaceSlug}", wsRouter)

	acc := testEnv.CreateTestAccount(t, fmt.Sprintf("oidc-%s@test.example", GenerateUniqueSlug("u")))
	ws := testEnv.CreateTestWorkspace(t, acc, "OIDC Test WS", GenerateUniqueSlug("ws"))
	// MANYROWS_BASE_URL pinning is handled by GetTestConfig (sets it
	// to http://localhost:8080 via os.Setenv); AppOIDCIssuer reads
	// from there.
	app := testEnv.CreateTestApp(t, ws, acc)

	// OIDC requires cookie transport mode (admin-config validation +
	// runtime check both enforce this). Flip the app post-create so
	// every test's enableOIDC succeeds; tests that want to verify the
	// local-mode-rejection behaviour set it back to "local".
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`update apps set transport_mode = 'cookie' where id = $1`, app.ID); err != nil {
		t.Fatalf("set transport_mode=cookie: %v", err)
	}
	app.TransportMode = core.TransportModeCookie

	return &oidcTestEnv{
		router:  r,
		handler: h,
		cas:     cas,
		ws:      ws,
		app:     app,
	}
}

// enableOIDC configures the app for OIDC with the supplied redirect
// URI allowlist. Returns the raw client_secret (caller can use it for
// confidential-client tests; leave empty by passing "" for public
// clients).
func (e *oidcTestEnv) enableOIDC(t *testing.T, redirectURIs []string, postLogoutURIs []string, rawSecret string) {
	t.Helper()
	var secretHash *string
	if rawSecret != "" {
		h := sha256.Sum256([]byte(rawSecret))
		s := fmt.Sprintf("%x", h[:])
		secretHash = &s
	} else {
		empty := ""
		secretHash = &empty
	}
	if err := testEnv.Repo.UpdateAppOIDCConfig(context.Background(), e.app.ID, repo.UpdateAppOIDCConfigParams{
		Enabled:                true,
		ClientSecretHash:       secretHash,
		RedirectURIs:           redirectURIs,
		PostLogoutRedirectURIs: postLogoutURIs,
	}); err != nil {
		t.Fatalf("UpdateAppOIDCConfig: %v", err)
	}
}

// seedSessionForApp creates a client_sessions row + user for the app
// and returns the session along with a signed access JWT bound to it.
// Lets us simulate "user is already signed in to this app" at OIDC
// /authorize time.
func (e *oidcTestEnv) seedSessionForApp(t *testing.T) (*core.ClientSession, string) {
	t.Helper()
	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, fmt.Sprintf("user-%s@test.example", GenerateUniqueSlug("u")), e.app, core.UserSourceRegistered)
	if err != nil {
		t.Fatalf("GetOrCreateUserWithMembership: %v", err)
	}
	now := time.Now().UTC()
	appID := e.app.ID
	ses := &core.ClientSession{
		ID:         uuid.Must(uuid.NewV4()),
		UserID:     user.ID,
		AppID:      &appID,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}
	if err := testEnv.Repo.InsertClientSession(ctx, ses); err != nil {
		t.Fatalf("InsertClientSession: %v", err)
	}
	issuer := "http://localhost:8080/x/" + e.ws.Slug + "/apps/" + e.app.ID.String()
	access, _, err := e.cas.IssueAccessToken(ses, 15*time.Minute, issuer)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	return ses, access
}

// makePKCE returns (verifier, S256 challenge) for a fresh PKCE pair.
// Verifier is exactly 64 chars — comfortably inside RFC 7636 §4.1's
// 43–128 range with room to spare and high entropy from the slug suffix.
func makePKCE() (string, string) {
	v := ("verifier-pkce-rfc7636-min43chars-x-" + GenerateUniqueSlug("v"))
	// Pad / trim to exactly 64.
	if len(v) < 64 {
		v += strings.Repeat("a", 64-len(v))
	} else if len(v) > 64 {
		v = v[:64]
	}
	sum := sha256.Sum256([]byte(v))
	return v, base64.RawURLEncoding.EncodeToString(sum[:])
}

// =====================
// Discovery
// =====================

func TestOIDCDiscovery_NotFoundWhenDisabled(t *testing.T) {
	e := setupOIDCRouter(t)

	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when OIDC disabled, got %d (body=%s)", rr.Code, rr.Body.String())
	}
}

func TestOIDCDiscovery_OKWhenEnabled(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")

	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal discovery doc: %v", err)
	}
	wantIssuer := "http://localhost:8080/x/" + e.ws.Slug + "/apps/" + e.app.ID.String()
	if got := doc["issuer"]; got != wantIssuer {
		t.Fatalf("issuer mismatch: got %v want %s", got, wantIssuer)
	}
	if got := doc["token_endpoint"]; got != wantIssuer+"/oidc/token" {
		t.Fatalf("token_endpoint mismatch: got %v", got)
	}
	if got := doc["jwks_uri"]; got != "http://localhost:8080/.well-known/jwks.json" {
		t.Fatalf("jwks_uri mismatch: got %v", got)
	}
	for _, key := range []string{"authorization_endpoint", "userinfo_endpoint", "end_session_endpoint",
		"response_types_supported", "id_token_signing_alg_values_supported", "code_challenge_methods_supported"} {
		if _, ok := doc[key]; !ok {
			t.Fatalf("discovery doc missing required key %q", key)
		}
	}
}

// =====================
// Authorize
// =====================

func TestOIDCAuthorize_RejectsUnregisteredRedirectURI(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDC(t, []string{"https://customer.example/callback"}, nil, "")

	_, challenge := makePKCE()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.app.ID.String()},
		"redirect_uri":          {"https://attacker.example/callback"},
		"scope":                 {"openid email"},
		"state":                 {"xyz"},
		"nonce":                 {"abc"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	// Per OIDC §3.1.2.6, render an error page rather than redirect
	// when redirect_uri isn't registered.
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unregistered redirect_uri, got %d (loc=%s body=%s)",
			rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
}

func TestOIDCAuthorize_RedirectsToLoginWhenNoSession(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")

	_, challenge := makePKCE()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.app.ID.String()},
		"redirect_uri":          {redirect},
		"scope":                 {"openid email"},
		"state":                 {"xyz"},
		"nonce":                 {"abc"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect to login, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/oidc/login?req=") {
		t.Fatalf("expected redirect to oidc/login with req, got %q", loc)
	}
}

func TestOIDCAuthorize_MissingPKCERejected(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")

	q := url.Values{
		"response_type": {"code"},
		"client_id":     {e.app.ID.String()},
		"redirect_uri":  {redirect},
		"scope":         {"openid email"},
		"state":         {"xyz"},
	}
	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	// Should redirect back to redirect_uri with ?error=invalid_request
	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 error redirect, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, redirect) || !strings.Contains(loc, "error=invalid_request") {
		t.Fatalf("expected error redirect to %s with invalid_request, got %q", redirect, loc)
	}
}

// =====================
// Token endpoint — happy path
// =====================

func TestOIDCToken_AuthCodeGrant_PublicClient(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")

	_, accessJWT := e.seedSessionForApp(t)
	verifier, challenge := makePKCE()

	// Drive /authorize with the access JWT as Authorization header so
	// GetSession() finds our seeded session.
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.app.ID.String()},
		"redirect_uri":          {redirect},
		"scope":                 {"openid email"},
		"state":                 {"st"},
		"nonce":                 {"n0nce"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/authorize?"+q.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+accessJWT)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 with code, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %s", loc.String())
	}
	if got := loc.Query().Get("state"); got != "st" {
		t.Fatalf("state not echoed: got %q", got)
	}

	// Now exchange at /token.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
		"client_id":     {e.app.ID.String()},
	}
	tokReq := httptest.NewRequest("POST", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRR := httptest.NewRecorder()
	e.router.ServeHTTP(tokRR, tokReq)

	if tokRR.Code != http.StatusOK {
		t.Fatalf("expected 200 from /token, got %d (body=%s)", tokRR.Code, tokRR.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(tokRR.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal token response: %v (body=%s)", err, tokRR.Body.String())
	}
	if resp.AccessToken == "" {
		t.Fatalf("no access_token in response")
	}
	if resp.IDToken == "" {
		t.Fatalf("no id_token in response")
	}
	if resp.TokenType != "Bearer" {
		t.Fatalf("token_type should be Bearer, got %q", resp.TokenType)
	}
	if resp.ExpiresIn <= 0 {
		t.Fatalf("expires_in should be positive, got %d", resp.ExpiresIn)
	}
}

func TestOIDCToken_PKCEMismatch(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")

	_, accessJWT := e.seedSessionForApp(t)
	_, challenge := makePKCE()

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.app.ID.String()},
		"redirect_uri":          {redirect},
		"scope":                 {"openid"},
		"state":                 {"x"},
		"nonce":                 {"n"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/authorize?"+q.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+accessJWT)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	loc, _ := url.Parse(rr.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect (rr=%d body=%s)", rr.Code, rr.Body.String())
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {"this-verifier-does-not-match-the-challenge-at-all"},
		"client_id":     {e.app.ID.String()},
	}
	tokReq := httptest.NewRequest("POST", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRR := httptest.NewRecorder()
	e.router.ServeHTTP(tokRR, tokReq)

	if tokRR.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on PKCE mismatch, got %d (body=%s)", tokRR.Code, tokRR.Body.String())
	}
	var errResp struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(tokRR.Body.Bytes(), &errResp)
	if errResp.Error != "invalid_grant" {
		t.Fatalf("expected invalid_grant, got %q (body=%s)", errResp.Error, tokRR.Body.String())
	}
}

func TestOIDCToken_ConfidentialClientNeedsSecret(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	const rawSecret = "test-client-secret-32-bytes-random"
	e.enableOIDC(t, []string{redirect}, nil, rawSecret)

	// Mint a code first.
	_, accessJWT := e.seedSessionForApp(t)
	verifier, challenge := makePKCE()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.app.ID.String()},
		"redirect_uri":          {redirect},
		"scope":                 {"openid"},
		"state":                 {"x"},
		"nonce":                 {"n"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/authorize?"+q.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+accessJWT)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	loc, _ := url.Parse(rr.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect (rr=%d body=%s)", rr.Code, rr.Body.String())
	}

	// Token request WITHOUT client_secret on a confidential client → 401.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
		"client_id":     {e.app.ID.String()},
	}
	tokReq := httptest.NewRequest("POST", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRR := httptest.NewRecorder()
	e.router.ServeHTTP(tokRR, tokReq)

	if tokRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing client_secret, got %d (body=%s)", tokRR.Code, tokRR.Body.String())
	}
}

// =====================
// Userinfo
// =====================

func TestOIDCUserInfo_RequiresBearer(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDC(t, []string{"https://customer.example/callback"}, nil, "")

	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/userinfo", nil)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("expected WWW-Authenticate: Bearer..., got %q", rr.Header().Get("WWW-Authenticate"))
	}
}

// =====================
// End-to-end: drive the full code flow as a real RP would
// =====================

// TestOIDCFullFlow_RPEndToEnd walks the entire OIDC code flow:
//
//  1. Fetch discovery doc, extract endpoint URLs + jwks_uri.
//  2. Fetch JWKS via the advertised jwks_uri (proves the URL the
//     discovery doc points at actually serves a key set).
//  3. Drive /authorize, capture code from redirect.
//  4. POST to /token with the matching PKCE verifier.
//  5. Parse the returned id_token JWT.
//  6. Verify id_token signature against the fetched JWKS, the
//     standard claims (iss, aud, exp, iat), and the OIDC extras
//     (sub, auth_time, nonce echo).
//  7. Call /userinfo with the access_token, confirm sub matches.
//
// Any failure here is a real interop bug — the flow that customer
// RP libraries follow against a live install.
func TestOIDCFullFlow_RPEndToEnd(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/cb"
	e.enableOIDC(t, []string{redirect}, nil, "")

	// Spin up a test HTTP server so JWKS fetch can use a real URL.
	srv := httptest.NewServer(e.router)
	t.Cleanup(srv.Close)

	// Make the test config's BASE_URL line up with the test server's
	// origin so the discovery doc advertises URLs the RP can actually
	// hit. The handler reads cfg.GetBaseURL() at request time, so we
	// override the env var (set by GetTestConfig) just for this test.
	origBaseURL := os.Getenv("MANYROWS_BASE_URL")
	t.Setenv("MANYROWS_BASE_URL", srv.URL)
	defer func() { _ = os.Setenv("MANYROWS_BASE_URL", origBaseURL) }()

	appPath := "/x/" + e.ws.Slug + "/apps/" + e.app.ID.String()

	// Step 1: discovery.
	discResp, err := http.Get(srv.URL + appPath + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("fetch discovery: %v", err)
	}
	defer discResp.Body.Close()
	if discResp.StatusCode != http.StatusOK {
		t.Fatalf("discovery returned %d", discResp.StatusCode)
	}
	var disc struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		UserinfoEndpoint      string `json:"userinfo_endpoint"`
		JwksURI               string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(discResp.Body).Decode(&disc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	expectedIssuer := srv.URL + appPath
	if disc.Issuer != expectedIssuer {
		t.Fatalf("issuer mismatch: got %q want %q", disc.Issuer, expectedIssuer)
	}

	// Step 2: fetch JWKS via the URL the discovery doc advertised.
	jwksResp, err := http.Get(disc.JwksURI)
	if err != nil {
		t.Fatalf("fetch JWKS at %s: %v", disc.JwksURI, err)
	}
	defer jwksResp.Body.Close()
	if jwksResp.StatusCode != http.StatusOK {
		t.Fatalf("JWKS returned %d at %s", jwksResp.StatusCode, disc.JwksURI)
	}
	var jwksDoc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(jwksResp.Body).Decode(&jwksDoc); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	if len(jwksDoc.Keys) == 0 {
		t.Fatalf("JWKS has no keys")
	}
	pubKeys := map[string]*ecdsa.PublicKey{}
	for _, k := range jwksDoc.Keys {
		xb, _ := base64.RawURLEncoding.DecodeString(k.X)
		yb, _ := base64.RawURLEncoding.DecodeString(k.Y)
		pubKeys[k.Kid] = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		}
	}

	// Step 3: /authorize. Seed an existing session so the handler
	// skips the AppKit redirect and mints a code straight away.
	_, accessJWT := e.seedSessionForApp(t)
	verifier, challenge := makePKCE()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.app.ID.String()},
		"redirect_uri":          {redirect},
		"scope":                 {"openid email"},
		"state":                 {"e2e-state"},
		"nonce":                 {"e2e-nonce"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	httpClient := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	authReq, _ := http.NewRequest("GET", disc.AuthorizationEndpoint+"?"+q.Encode(), nil)
	authReq.Header.Set("Authorization", "Bearer "+accessJWT)
	authResp, err := httpClient.Do(authReq)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("authorize expected 302, got %d", authResp.StatusCode)
	}
	loc, _ := url.Parse(authResp.Header.Get("Location"))
	if !strings.HasPrefix(loc.String(), redirect) {
		t.Fatalf("authorize did not redirect to RP redirect_uri: %s", loc.String())
	}
	if loc.Query().Get("state") != "e2e-state" {
		t.Fatalf("state not echoed at authorize")
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in authorize redirect")
	}

	// Step 4: /token.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
		"client_id":     {e.app.ID.String()},
	}
	tokResp, err := http.Post(disc.TokenEndpoint, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("token expected 200, got %d (body=%s)", tokResp.StatusCode, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(tokResp.Body).Decode(&tok); err != nil {
		t.Fatalf("decode token response: %v", err)
	}

	// Step 5/6: parse + verify id_token against the JWKS.
	parsed, err := jwt.Parse(tok.IDToken, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodES256 {
			return nil, fmt.Errorf("unexpected alg: %v", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		k, ok := pubKeys[kid]
		if !ok {
			return nil, fmt.Errorf("kid not in JWKS: %s", kid)
		}
		return k, nil
	})
	if err != nil {
		t.Fatalf("parse/verify id_token: %v", err)
	}
	if !parsed.Valid {
		t.Fatalf("id_token signature invalid")
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("unexpected claims type: %T", parsed.Claims)
	}
	if claims["iss"] != expectedIssuer {
		t.Fatalf("iss claim mismatch: got %v want %v", claims["iss"], expectedIssuer)
	}
	aud, _ := claims["aud"].([]any)
	if len(aud) == 0 || aud[0] != e.app.ID.String() {
		t.Fatalf("aud claim mismatch: %v", claims["aud"])
	}
	if claims["nonce"] != "e2e-nonce" {
		t.Fatalf("nonce not echoed: %v", claims["nonce"])
	}
	if _, ok := claims["sub"].(string); !ok {
		t.Fatalf("sub missing or not a string: %v", claims["sub"])
	}
	if _, ok := claims["auth_time"]; !ok {
		t.Fatalf("auth_time missing")
	}
	if claims["email"] == "" {
		t.Fatalf("email claim empty under openid+email scope")
	}
	// email_verified must be present (boolean) when email is present —
	// audit fix to spec §5.1.
	if _, ok := claims["email_verified"]; !ok {
		t.Fatalf("email_verified missing from id_token despite email present")
	}

	// Audit fix: access_token iss is host-only (AppBaseURL), id_token
	// iss is the per-app-path (AppOIDCIssuer). Verify the split.
	atParsed, err := jwt.Parse(tok.AccessToken, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		return pubKeys[kid], nil
	})
	if err != nil {
		t.Fatalf("parse access_token: %v", err)
	}
	atClaims, _ := atParsed.Claims.(jwt.MapClaims)
	if atClaims["iss"] != srv.URL {
		t.Fatalf("access_token iss should be host-only %q for SDK compat, got %v", srv.URL, atClaims["iss"])
	}

	// Step 7: /userinfo.
	uiReq, _ := http.NewRequest("GET", disc.UserinfoEndpoint, nil)
	uiReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	uiResp, err := httpClient.Do(uiReq)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	defer uiResp.Body.Close()
	if uiResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(uiResp.Body)
		t.Fatalf("userinfo expected 200, got %d (body=%s)", uiResp.StatusCode, body)
	}
	var ui map[string]any
	if err := json.NewDecoder(uiResp.Body).Decode(&ui); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	if ui["sub"] != claims["sub"] {
		t.Fatalf("userinfo sub %v != id_token sub %v", ui["sub"], claims["sub"])
	}
	if ui["email"] != claims["email"] {
		t.Fatalf("userinfo email %v != id_token email %v", ui["email"], claims["email"])
	}
}

// =====================
// Audit-fix tests: replay, refresh, end-session
// =====================

// TestOIDCToken_CodeReuseRevokesSession is the OIDC §3.1.3.2 replay
// defence — the second presentation of a consumed code must (1) be
// rejected as invalid_grant and (2) revoke the session's refresh
// tokens so any stolen tokens become unusable. We verify (2) by
// trying to use the refresh_token after replay; it must fail.
func TestOIDCToken_CodeReuseRevokesSession(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")

	_, accessJWT := e.seedSessionForApp(t)
	verifier, challenge := makePKCE()

	// /authorize → code (request offline_access so first /token mints
	// a refresh we can later try to reuse).
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.app.ID.String()},
		"redirect_uri":          {redirect},
		"scope":                 {"openid offline_access"},
		"state":                 {"s"},
		"nonce":                 {"n"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/authorize?"+q.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+accessJWT)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	loc, _ := url.Parse(rr.Header().Get("Location"))
	code := loc.Query().Get("code")

	// First exchange — succeeds, captures a refresh_token.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
		"client_id":     {e.app.ID.String()},
	}
	tokReq := httptest.NewRequest("POST", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRR := httptest.NewRecorder()
	e.router.ServeHTTP(tokRR, tokReq)
	if tokRR.Code != http.StatusOK {
		t.Fatalf("first /token expected 200, got %d (body=%s)", tokRR.Code, tokRR.Body.String())
	}
	var first struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(tokRR.Body.Bytes(), &first)
	if first.RefreshToken == "" {
		t.Fatalf("expected refresh_token after offline_access grant")
	}

	// Second exchange of the SAME code — must be rejected.
	tokReq2 := httptest.NewRequest("POST", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/token", strings.NewReader(form.Encode()))
	tokReq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRR2 := httptest.NewRecorder()
	e.router.ServeHTTP(tokRR2, tokReq2)
	if tokRR2.Code != http.StatusBadRequest {
		t.Fatalf("code-reuse second /token expected 400, got %d (body=%s)", tokRR2.Code, tokRR2.Body.String())
	}

	// The refresh_token from the legitimate first exchange must now be
	// dead — that's the replay defence in action.
	refForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first.RefreshToken},
		"client_id":     {e.app.ID.String()},
	}
	refReq := httptest.NewRequest("POST", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/token", strings.NewReader(refForm.Encode()))
	refReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refRR := httptest.NewRecorder()
	e.router.ServeHTTP(refRR, refReq)
	if refRR.Code == http.StatusOK {
		t.Fatalf("refresh_token should be revoked after code reuse, but /token succeeded: %s", refRR.Body.String())
	}
}

// TestOIDCToken_RefreshGrant rotates a refresh token via /token and
// confirms the response contains a fresh access_token, id_token, and
// rotated refresh_token.
func TestOIDCToken_RefreshGrant(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")

	// Full code-flow with offline_access to get a real refresh_token.
	_, accessJWT := e.seedSessionForApp(t)
	verifier, challenge := makePKCE()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.app.ID.String()},
		"redirect_uri":          {redirect},
		"scope":                 {"openid email offline_access"},
		"state":                 {"s"},
		"nonce":                 {"n"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/authorize?"+q.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+accessJWT)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	loc, _ := url.Parse(rr.Header().Get("Location"))
	code := loc.Query().Get("code")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
		"client_id":     {e.app.ID.String()},
	}
	tokReq := httptest.NewRequest("POST", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRR := httptest.NewRecorder()
	e.router.ServeHTTP(tokRR, tokReq)
	if tokRR.Code != http.StatusOK {
		t.Fatalf("code-flow /token expected 200, got %d (body=%s)", tokRR.Code, tokRR.Body.String())
	}
	var first struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(tokRR.Body.Bytes(), &first); err != nil {
		t.Fatalf("decode first token response: %v", err)
	}
	if first.RefreshToken == "" {
		t.Fatalf("offline_access scope should yield a refresh_token; got none")
	}

	// Refresh grant.
	form2 := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first.RefreshToken},
		"client_id":     {e.app.ID.String()},
		"scope":         {"openid email"},
	}
	tokReq2 := httptest.NewRequest("POST", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/token", strings.NewReader(form2.Encode()))
	tokReq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRR2 := httptest.NewRecorder()
	e.router.ServeHTTP(tokRR2, tokReq2)
	if tokRR2.Code != http.StatusOK {
		t.Fatalf("refresh /token expected 200, got %d (body=%s)", tokRR2.Code, tokRR2.Body.String())
	}
	var second struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(tokRR2.Body.Bytes(), &second); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}
	if second.AccessToken == "" || second.IDToken == "" || second.RefreshToken == "" {
		t.Fatalf("refresh grant should mint a full triple; got access=%t id=%t refresh=%t",
			second.AccessToken != "", second.IDToken != "", second.RefreshToken != "")
	}
	if second.RefreshToken == first.RefreshToken {
		t.Fatalf("refresh token must rotate; got the same value back")
	}
	if second.AccessToken == first.AccessToken {
		t.Fatalf("access token should be freshly minted")
	}
}

// TestOIDCEndSession_RevokesAndRedirects exercises RP-initiated logout:
// the session is revoked and the browser is redirected to the
// allowlisted post_logout_redirect_uri, with state echoed.
func TestOIDCEndSession_RevokesAndRedirects(t *testing.T) {
	e := setupOIDCRouter(t)
	postLogout := "https://customer.example/signed-out"
	e.enableOIDC(t, []string{"https://customer.example/cb"}, []string{postLogout}, "")

	ses, accessJWT := e.seedSessionForApp(t)

	q := url.Values{
		"post_logout_redirect_uri": {postLogout},
		"state":                    {"logout-state"},
	}
	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/end-session?"+q.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+accessJWT)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if loc.Scheme+"://"+loc.Host+loc.Path != postLogout {
		t.Fatalf("post-logout redirect mismatch: got %s want %s", loc.String(), postLogout)
	}
	if loc.Query().Get("state") != "logout-state" {
		t.Fatalf("state should round-trip on end-session, got %q", loc.Query().Get("state"))
	}

	// Session should be gone.
	got, err := testEnv.Repo.GetClientSessionByID(context.Background(), ses.ID)
	if err != nil && !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "expired") {
		t.Fatalf("unexpected error after logout: %v", err)
	}
	if got != nil && got.IsActive(time.Now().UTC()) {
		t.Fatalf("session should be revoked after end-session, still active")
	}
}

// TestOIDCConfig_RejectsLocalTransportMode is the admin-side guard:
// enabling OIDC on an app whose transport_mode is "local" returns
// ErrOIDCRequiresCookieTransport so the admin handler can surface a
// targeted "switch transport mode first" message.
func TestOIDCConfig_RejectsLocalTransportMode(t *testing.T) {
	e := setupOIDCRouter(t)
	// Force the app back to local mode.
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`update apps set transport_mode = 'local' where id = $1`, e.app.ID); err != nil {
		t.Fatalf("set transport_mode=local: %v", err)
	}

	err := testEnv.Repo.UpdateAppOIDCConfig(context.Background(), e.app.ID, repo.UpdateAppOIDCConfigParams{
		Enabled:      true,
		RedirectURIs: []string{"https://customer.example/cb"},
	})
	if !errors.Is(err, repo.ErrOIDCRequiresCookieTransport) {
		t.Fatalf("expected ErrOIDCRequiresCookieTransport when enabling OIDC on local-mode app, got %v", err)
	}
}

// TestOIDCConfig_AllowsDisableOnLocalTransportMode confirms the guard
// only fires when ENABLING — disabling OIDC on a local-mode app is
// fine (you should always be able to turn OIDC off regardless of
// other config state).
func TestOIDCConfig_AllowsDisableOnLocalTransportMode(t *testing.T) {
	e := setupOIDCRouter(t)
	// Enable first (cookie mode passes the guard).
	if err := testEnv.Repo.UpdateAppOIDCConfig(context.Background(), e.app.ID, repo.UpdateAppOIDCConfigParams{
		Enabled:      true,
		RedirectURIs: []string{"https://customer.example/cb"},
	}); err != nil {
		t.Fatalf("enable on cookie-mode app should succeed, got %v", err)
	}
	// Now flip to local — should still be able to disable.
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`update apps set transport_mode = 'local' where id = $1`, e.app.ID); err != nil {
		t.Fatalf("set transport_mode=local: %v", err)
	}
	if err := testEnv.Repo.UpdateAppOIDCConfig(context.Background(), e.app.ID, repo.UpdateAppOIDCConfigParams{
		Enabled:      false,
		RedirectURIs: []string{},
	}); err != nil {
		t.Fatalf("disable on local-mode app should succeed, got %v", err)
	}
}

// TestOIDCAuthorize_RejectsLocalTransportModeAtRuntime is the
// defence-in-depth check: even if the DB somehow ended up with
// oidc_enabled=true AND transport_mode=local (e.g., a raw SQL edit),
// /authorize refuses to proceed rather than start a sign-in flow
// that would deadlock at /resume.
func TestOIDCAuthorize_RejectsLocalTransportModeAtRuntime(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/cb"
	e.enableOIDC(t, []string{redirect}, nil, "")

	// Bypass the admin-config guard via raw SQL — simulate config
	// drift after enable.
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`update apps set transport_mode = 'local' where id = $1`, e.app.ID); err != nil {
		t.Fatalf("set transport_mode=local: %v", err)
	}

	_, challenge := makePKCE()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.app.ID.String()},
		"redirect_uri":          {redirect},
		"scope":                 {"openid"},
		"state":                 {"x"},
		"nonce":                 {"n"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	// Should render a page (400), NOT redirect back to the RP with an
	// error code — this is operator misconfiguration, not RP-fixable.
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 page on transport-mode mismatch, got %d (loc=%s body=%s)",
			rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "transport_mode") {
		t.Fatalf("expected error body to mention transport_mode, got %s", rr.Body.String())
	}
}

// TestOIDCEndSession_ClearedCookieMatchesAppDomain prevents a
// regression caught in audit pass #3: a custom cookie-clear helper
// hardcoded Secure=true, SameSite=Lax, and omitted Domain entirely,
// so for apps with cookie_domain set the browser kept the stale
// cookie in its jar. The fix is to use the shared
// handler.clearSessionCookies which threads the right attributes.
//
// This test sets cookie_domain on the test app, exercises end-session,
// and asserts the Set-Cookie response includes the matching Domain.
func TestOIDCEndSession_ClearedCookieMatchesAppDomain(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDC(t, []string{"https://customer.example/cb"}, nil, "")

	// Set a custom cookie_domain on the app so the clear-cookie path
	// has something non-empty to put in the Domain attribute.
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`update apps set cookie_domain = $2 where id = $1`,
		e.app.ID, "customer.example"); err != nil {
		t.Fatalf("set cookie_domain: %v", err)
	}

	// Seed a session so end-session has something to revoke + cookies
	// to clear.
	_, accessJWT := e.seedSessionForApp(t)

	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/end-session", nil)
	req.Header.Set("Authorization", "Bearer "+accessJWT)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	setCookies := rr.Result().Cookies()
	if len(setCookies) == 0 {
		t.Fatalf("expected Set-Cookie headers on end-session, got none")
	}
	var sawAccessClear bool
	for _, c := range setCookies {
		if c.Name == "mr_at_"+e.app.ID.String() {
			sawAccessClear = true
			if c.Domain != "customer.example" {
				t.Fatalf("access cookie clear must include the app's Domain attribute; got %q want %q",
					c.Domain, "customer.example")
			}
			if c.MaxAge != -1 {
				t.Fatalf("clear cookie must have MaxAge=-1; got %d", c.MaxAge)
			}
		}
	}
	if !sawAccessClear {
		t.Fatalf("expected mr_at_<appID> Set-Cookie clear; got cookies: %+v", setCookies)
	}
}

func TestOIDCEndSession_RejectsUnallowlistedRedirect(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDC(t, []string{"https://customer.example/cb"}, []string{"https://customer.example/signed-out"}, "")

	q := url.Values{
		"post_logout_redirect_uri": {"https://attacker.example/anywhere"},
	}
	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/end-session?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unallowlisted post_logout_redirect_uri, got %d (loc=%s)",
			rr.Code, rr.Header().Get("Location"))
	}
}

// =====================
// Second-pass audit fixes
// =====================

// TestOIDCLoginPage_HasAntiClickjackingHeaders verifies the IdP login
// page can't be framed by a hostile origin. Both modern (CSP
// frame-ancestors) and legacy (X-Frame-Options) headers must be
// present — credential-entry pages MUST NOT be framable.
func TestOIDCLoginPage_HasAntiClickjackingHeaders(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDC(t, []string{"https://customer.example/cb"}, nil, "")

	// Create a pending row to land at /oidc/login with a valid req.
	reqID, err := testEnv.Repo.CreateOIDCPendingAuthorize(context.Background(), e.app.ID, core.OIDCAuthorizeParams{
		ResponseType:        "code",
		ClientID:            e.app.ID.String(),
		RedirectURI:         "https://customer.example/cb",
		Scope:               "openid",
		CodeChallenge:       "x", // not validated at /login
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("create pending: %v", err)
	}

	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/login?req="+reqID.String(), nil)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("/oidc/login expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options should be DENY on /oidc/login, got %q", got)
	}
	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP should include frame-ancestors 'none', got %q", csp)
	}
}

// TestOIDCEndSession_AcceptsPOST verifies the spec-allowed POST method
// (OIDC Session Management 1.0 §5) — some RPs use POST when
// id_token_hint would make a GET URL too long.
func TestOIDCEndSession_AcceptsPOST(t *testing.T) {
	e := setupOIDCRouter(t)
	postLogout := "https://customer.example/signed-out"
	e.enableOIDC(t, []string{"https://customer.example/cb"}, []string{postLogout}, "")

	// Query params still apply on POST per spec.
	q := url.Values{
		"post_logout_redirect_uri": {postLogout},
		"state":                    {"p"},
	}
	req := httptest.NewRequest("POST", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/end-session?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("POST /end-session expected 302, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if loc.Query().Get("state") != "p" {
		t.Fatalf("state lost on POST end-session")
	}
}

// TestOIDCAuthorize_RejectsMalformedCodeChallenge proves the early
// length check on code_challenge — anything other than the 43-char
// base64url SHA-256 output is rejected.
func TestOIDCAuthorize_RejectsMalformedCodeChallenge(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/cb"
	e.enableOIDC(t, []string{redirect}, nil, "")

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.app.ID.String()},
		"redirect_uri":          {redirect},
		"scope":                 {"openid"},
		"state":                 {"x"},
		"nonce":                 {"n"},
		"code_challenge":        {"too-short"},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("malformed code_challenge should redirect with error, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, redirect) || !strings.Contains(loc, "error=invalid_request") {
		t.Fatalf("expected error=invalid_request redirect, got %q", loc)
	}
}

func TestOIDCUserInfo_ReturnsClaimsWithValidBearer(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDC(t, []string{"https://customer.example/callback"}, nil, "")

	_, accessJWT := e.seedSessionForApp(t)

	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessJWT)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if sub, _ := resp["sub"].(string); sub == "" {
		t.Fatalf("expected sub claim, got body=%s", rr.Body.String())
	}
	if email, _ := resp["email"].(string); email == "" {
		t.Fatalf("expected email claim, got body=%s", rr.Body.String())
	}
}
