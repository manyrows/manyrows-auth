package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"manyrows-core/auth/oidc"

	"github.com/golang-jwt/jwt/v5"
)

// mockIDP is an httptest-backed OpenID provider: it serves a discovery
// doc, a JWKS, a token endpoint that returns a freshly-signed id_token,
// and a userinfo endpoint. Tests tweak the knobs then drive the real
// oidc.Authenticate / AuthorizeURL against it.
type mockIDP struct {
	server  *httptest.Server
	key     *rsa.PrivateKey
	kid     string
	signKey *rsa.PrivateKey // key actually used to sign (override for tamper tests)

	idClaims    jwt.MapClaims  // baked into the id_token; nil → omit id_token
	accessToken string         // returned from /token
	userinfo    map[string]any // returned from /userinfo
}

func newMockIDP(t *testing.T) *mockIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	idp := &mockIDP{key: key, signKey: key, kid: "test-kid-1", accessToken: "access-token-abc"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                 idp.issuer(),
			"authorization_endpoint": idp.issuer() + "/authorize",
			"token_endpoint":         idp.issuer() + "/token",
			"userinfo_endpoint":      idp.issuer() + "/userinfo",
			"jwks_uri":               idp.issuer() + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := idp.key.Public().(*rsa.PublicKey)
		writeJSON(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": idp.kid,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{"access_token": idp.accessToken, "token_type": "Bearer"}
		if idp.idClaims != nil {
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, idp.idClaims)
			tok.Header["kid"] = idp.kid
			signed, err := tok.SignedString(idp.signKey)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			resp["id_token"] = signed
		}
		writeJSON(w, resp)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, idp.userinfo)
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (m *mockIDP) issuer() string { return m.server.URL }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func baseClaims(issuer, aud, nonce string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":            issuer,
		"aud":            aud,
		"sub":            "user-sub-1",
		"email":          "Alice@Example.com",
		"email_verified": true,
		"name":           "Alice",
		"nonce":          nonce,
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Add(-time.Minute).Unix(),
	}
}

func TestOIDC_Authenticate_HappyPath(t *testing.T) {
	idp := newMockIDP(t)
	idp.idClaims = baseClaims(idp.issuer(), "client-123", "nonce-xyz")

	cfg := oidc.ProviderConfig{Mode: oidc.ModeOIDC, IssuerURL: idp.issuer(), ClientID: "client-123", ClientSecret: "s"}
	info, err := oidc.Authenticate(context.Background(), cfg, "code", "https://app/cb", "verifier", "nonce-xyz")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if info.Subject != "user-sub-1" {
		t.Errorf("subject = %q", info.Subject)
	}
	if info.Email != "alice@example.com" { // normalized lower-case
		t.Errorf("email = %q, want lowercased", info.Email)
	}
	if !info.EmailVerified {
		t.Error("email_verified should be true")
	}
}

func TestOIDC_Authenticate_NonceMismatch(t *testing.T) {
	idp := newMockIDP(t)
	idp.idClaims = baseClaims(idp.issuer(), "client-123", "the-real-nonce")

	cfg := oidc.ProviderConfig{Mode: oidc.ModeOIDC, IssuerURL: idp.issuer(), ClientID: "client-123"}
	if _, err := oidc.Authenticate(context.Background(), cfg, "code", "https://app/cb", "v", "a-different-nonce"); err == nil {
		t.Fatal("expected nonce-mismatch rejection")
	}
}

func TestOIDC_Authenticate_WrongAudience(t *testing.T) {
	idp := newMockIDP(t)
	idp.idClaims = baseClaims(idp.issuer(), "some-other-client", "n")

	cfg := oidc.ProviderConfig{Mode: oidc.ModeOIDC, IssuerURL: idp.issuer(), ClientID: "client-123"}
	if _, err := oidc.Authenticate(context.Background(), cfg, "code", "https://app/cb", "v", "n"); err == nil {
		t.Fatal("expected wrong-audience rejection")
	}
}

func TestOIDC_Authenticate_TamperedSignature(t *testing.T) {
	idp := newMockIDP(t)
	idp.idClaims = baseClaims(idp.issuer(), "client-123", "n")
	// Sign with a different key than the JWKS advertises.
	wrong, _ := rsa.GenerateKey(rand.Reader, 2048)
	idp.signKey = wrong

	cfg := oidc.ProviderConfig{Mode: oidc.ModeOIDC, IssuerURL: idp.issuer(), ClientID: "client-123"}
	if _, err := oidc.Authenticate(context.Background(), cfg, "code", "https://app/cb", "v", "n"); err == nil {
		t.Fatal("expected signature-verification failure")
	}
}

func TestOIDC_Authenticate_Expired(t *testing.T) {
	idp := newMockIDP(t)
	c := baseClaims(idp.issuer(), "client-123", "n")
	c["exp"] = time.Now().Add(-time.Hour).Unix()
	idp.idClaims = c

	cfg := oidc.ProviderConfig{Mode: oidc.ModeOIDC, IssuerURL: idp.issuer(), ClientID: "client-123"}
	if _, err := oidc.Authenticate(context.Background(), cfg, "code", "https://app/cb", "v", "n"); err == nil {
		t.Fatal("expected expired-token rejection")
	}
}

// id_token with no email → falls back to the userinfo endpoint.
func TestOIDC_Authenticate_EmailFallbackToUserinfo(t *testing.T) {
	idp := newMockIDP(t)
	c := baseClaims(idp.issuer(), "client-123", "n")
	delete(c, "email")
	delete(c, "email_verified")
	idp.idClaims = c
	idp.userinfo = map[string]any{"sub": "user-sub-1", "email": "fromuserinfo@example.com", "email_verified": true}

	cfg := oidc.ProviderConfig{Mode: oidc.ModeOIDC, IssuerURL: idp.issuer(), ClientID: "client-123"}
	info, err := oidc.Authenticate(context.Background(), cfg, "code", "https://app/cb", "v", "n")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if info.Email != "fromuserinfo@example.com" {
		t.Errorf("email should come from userinfo, got %q", info.Email)
	}
}

// OAuth2 mode: no id_token, explicit endpoints, identity from userinfo
// with a non-standard subject field ("id", as Discord uses).
func TestOIDC_Authenticate_OAuth2Userinfo(t *testing.T) {
	idp := newMockIDP(t)
	idp.idClaims = nil // OAuth2 token endpoint returns no id_token
	idp.userinfo = map[string]any{"id": "discord-12345", "email": "gamer@example.com", "verified": true}

	cfg := oidc.ProviderConfig{
		Mode:               oidc.ModeOAuth2,
		AuthorizeURL:       idp.issuer() + "/authorize",
		TokenURL:           idp.issuer() + "/token",
		UserinfoURL:        idp.issuer() + "/userinfo",
		ClientID:           "client-123",
		ClientSecret:       "s",
		Scopes:             "identify email",
		SubjectField:       "id",
		EmailVerifiedField: "verified",
	}
	info, err := oidc.Authenticate(context.Background(), cfg, "code", "https://app/cb", "", "")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if info.Subject != "discord-12345" {
		t.Errorf("subject from 'id' field = %q", info.Subject)
	}
	if info.Email != "gamer@example.com" || !info.EmailVerified {
		t.Errorf("email=%q verified=%v", info.Email, info.EmailVerified)
	}
}

func TestOIDC_RejectsInsecureURLs(t *testing.T) {
	ctx := context.Background()
	// OIDC: a non-loopback http issuer is rejected before any fetch.
	oidcCfg := oidc.ProviderConfig{Mode: oidc.ModeOIDC, IssuerURL: "http://idp.evil.example", ClientID: "c"}
	if _, err := oidc.AuthorizeURL(ctx, oidcCfg, "https://app/cb", "s", "", ""); err == nil {
		t.Fatal("expected a non-loopback http issuer to be rejected")
	}
	// OAuth2: cleartext explicit endpoints are rejected.
	oauthCfg := oidc.ProviderConfig{
		Mode: oidc.ModeOAuth2, ClientID: "c",
		AuthorizeURL: "http://x.example/a", TokenURL: "http://x.example/t", UserinfoURL: "http://x.example/u",
	}
	if _, err := oidc.AuthorizeURL(ctx, oauthCfg, "https://app/cb", "s", "", ""); err == nil {
		t.Fatal("expected cleartext oauth2 endpoints to be rejected")
	}
}

func TestOIDC_AuthorizeURL_IncludesPKCEAndNonce(t *testing.T) {
	idp := newMockIDP(t)
	cfg := oidc.ProviderConfig{Mode: oidc.ModeOIDC, IssuerURL: idp.issuer(), ClientID: "client-123", Scopes: "openid email"}
	u, err := oidc.AuthorizeURL(context.Background(), cfg, "https://app/cb", "state-1", "challenge-1", "nonce-1")
	if err != nil {
		t.Fatalf("authorize url: %v", err)
	}
	for _, want := range []string{
		idp.issuer() + "/authorize",
		"client_id=client-123",
		"code_challenge=challenge-1",
		"code_challenge_method=S256",
		"nonce=nonce-1",
		"state=state-1",
		"response_type=code",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("authorize URL missing %q\n  got: %s", want, u)
		}
	}
}
