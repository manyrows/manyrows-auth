package kakao

// White-box tests: the package keeps its endpoints + JWKS cache in package
// globals (same shape as the Microsoft provider), so the harness swaps those
// globals to point at an httptest server and resets the cache around each test.
// These tests therefore must NOT run in parallel.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// mockKakao is an httptest-backed stand-in for Kakao: a JWKS endpoint, a token
// endpoint that returns a freshly-signed id_token, and a userinfo endpoint.
type mockKakao struct {
	server      *httptest.Server
	key         *rsa.PrivateKey // advertised in the JWKS
	signKey     *rsa.PrivateKey // actually signs the id_token (override for tamper tests)
	kid         string
	idClaims    jwt.MapClaims  // baked into the id_token; nil → omit id_token
	accessToken string         // returned from /oauth/token
	userinfo    map[string]any // returned from /v2/user/me
}

func newMockKakao(t *testing.T) *mockKakao {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	m := &mockKakao{key: key, signKey: key, kid: "kakao-test-kid", accessToken: "kakao-access-abc"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		pub := m.key.Public().(*rsa.PublicKey)
		writeJSON(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": m.kid,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{"access_token": m.accessToken, "token_type": "bearer"}
		if m.idClaims != nil {
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, m.idClaims)
			tok.Header["kid"] = m.kid
			signed, signErr := tok.SignedString(m.signKey)
			if signErr != nil {
				http.Error(w, signErr.Error(), http.StatusInternalServerError)
				return
			}
			resp["id_token"] = signed
		}
		writeJSON(w, resp)
	})
	mux.HandleFunc("/v2/user/me", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, m.userinfo)
	})

	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)

	// Point the package endpoints at the mock and reset the JWKS cache; restore
	// everything afterwards so the global state never leaks across tests.
	prevIssuer, prevToken, prevJWKS, prevUserinfo := issuer, tokenURL, jwksURL, userinfoURL
	issuer = m.server.URL
	tokenURL = m.server.URL + "/oauth/token"
	jwksURL = m.server.URL + "/.well-known/jwks.json"
	userinfoURL = m.server.URL + "/v2/user/me"
	resetJWKSCache()
	t.Cleanup(func() {
		issuer, tokenURL, jwksURL, userinfoURL = prevIssuer, prevToken, prevJWKS, prevUserinfo
		resetJWKSCache()
	})
	return m
}

func resetJWKSCache() {
	jwks.Lock()
	jwks.keys = map[string]any{}
	jwks.lastFetch = time.Time{}
	jwks.Unlock()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// baseClaims builds a valid Kakao id_token claim set. Pass the (swapped) issuer
// and the expected audience (the app's REST API key).
func baseClaims(iss, aud string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":   iss,
		"aud":   aud,
		"sub":   "kakao-user-123",
		"email": "User@Example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
	}
}

func TestBuildAuthorizeURL(t *testing.T) {
	got := BuildAuthorizeURL("rest-key-1", "https://app.example.com/cb", "state-xyz")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Host != "kauth.kakao.com" || u.Path != "/oauth/authorize" {
		t.Errorf("unexpected base: %s", got)
	}
	checks := map[string]string{
		"client_id":     "rest-key-1",
		"redirect_uri":  "https://app.example.com/cb",
		"response_type": "code",
		"scope":         "openid account_email",
		"state":         "state-xyz",
	}
	q := u.Query()
	for k, want := range checks {
		if g := q.Get(k); g != want {
			t.Errorf("query %s: got %q, want %q", k, g, want)
		}
	}
}

func TestExchangeAuthCode_HappyPath_EmailFromIDToken(t *testing.T) {
	m := newMockKakao(t)
	m.idClaims = baseClaims(issuer, "rest-key-1")

	info, err := ExchangeAuthCode(context.Background(), "code", "rest-key-1", "secret", "https://app/cb")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if info.Sub != "kakao-user-123" {
		t.Errorf("sub = %q", info.Sub)
	}
	if info.Email != "user@example.com" { // normalized to lower-case
		t.Errorf("email = %q, want lowercased", info.Email)
	}
	if !info.EmailVerified {
		t.Error("an email present in the id_token should count as verified")
	}
	if info.Aud != "rest-key-1" {
		t.Errorf("aud = %q", info.Aud)
	}
}

func TestExchangeAuthCode_WrongAudience(t *testing.T) {
	m := newMockKakao(t)
	m.idClaims = baseClaims(issuer, "some-other-key")
	if _, err := ExchangeAuthCode(context.Background(), "code", "rest-key-1", "s", "https://app/cb"); err == nil {
		t.Fatal("expected wrong-audience rejection")
	}
}

func TestExchangeAuthCode_TamperedSignature(t *testing.T) {
	m := newMockKakao(t)
	m.idClaims = baseClaims(issuer, "rest-key-1")
	// Sign with a key the JWKS does not advertise.
	wrong, _ := rsa.GenerateKey(rand.Reader, 2048)
	m.signKey = wrong
	if _, err := ExchangeAuthCode(context.Background(), "code", "rest-key-1", "s", "https://app/cb"); err == nil {
		t.Fatal("expected signature-verification failure")
	}
}

func TestExchangeAuthCode_Expired(t *testing.T) {
	m := newMockKakao(t)
	c := baseClaims(issuer, "rest-key-1")
	c["exp"] = time.Now().Add(-2 * time.Hour).Unix()
	c["iat"] = time.Now().Add(-3 * time.Hour).Unix()
	m.idClaims = c
	if _, err := ExchangeAuthCode(context.Background(), "code", "rest-key-1", "s", "https://app/cb"); err == nil {
		t.Fatal("expected expired-token rejection")
	}
}

func TestExchangeAuthCode_WrongIssuer(t *testing.T) {
	m := newMockKakao(t)
	// Sign a token claiming a different issuer than the one we require.
	m.idClaims = baseClaims("https://evil.example.com", "rest-key-1")
	if _, err := ExchangeAuthCode(context.Background(), "code", "rest-key-1", "s", "https://app/cb"); err == nil {
		t.Fatal("expected issuer-mismatch rejection")
	}
}

// id_token without email → recover it from userinfo, honoring kakao_account
// verification flags.
func TestExchangeAuthCode_EmailFallbackToUserinfo(t *testing.T) {
	m := newMockKakao(t)
	c := baseClaims(issuer, "rest-key-1")
	delete(c, "email")
	m.idClaims = c
	m.userinfo = map[string]any{
		"id": 123,
		"kakao_account": map[string]any{
			"email":             "FromUserinfo@Example.com",
			"is_email_valid":    true,
			"is_email_verified": true,
			"profile":           map[string]any{"nickname": "Kim"},
		},
	}
	info, err := ExchangeAuthCode(context.Background(), "code", "rest-key-1", "s", "https://app/cb")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if info.Email != "fromuserinfo@example.com" {
		t.Errorf("email should come from userinfo (lowercased), got %q", info.Email)
	}
	if !info.EmailVerified {
		t.Error("userinfo email that is valid+verified should count as verified")
	}
	if info.Name != "Kim" {
		t.Errorf("name should fall back to userinfo nickname, got %q", info.Name)
	}
	if info.Sub != "kakao-user-123" {
		t.Errorf("subject must stay the id_token's, got %q", info.Sub)
	}
}

// userinfo email present but not yet verified on the Kakao side → EmailVerified
// stays false so the workspace handler rejects it.
func TestExchangeAuthCode_UserinfoUnverifiedEmail(t *testing.T) {
	m := newMockKakao(t)
	c := baseClaims(issuer, "rest-key-1")
	delete(c, "email")
	m.idClaims = c
	m.userinfo = map[string]any{
		"kakao_account": map[string]any{
			"email":             "unverified@example.com",
			"is_email_valid":    true,
			"is_email_verified": false,
		},
	}
	info, err := ExchangeAuthCode(context.Background(), "code", "rest-key-1", "s", "https://app/cb")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if info.Email != "unverified@example.com" {
		t.Errorf("email = %q", info.Email)
	}
	if info.EmailVerified {
		t.Error("an unverified userinfo email must not be treated as verified")
	}
}
