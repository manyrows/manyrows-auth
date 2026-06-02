package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"manyrows-core/auth/jwks"
	"manyrows-core/config"
	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
)

// JWT-only tests — exercise the iss/aud claim behaviour without
// touching the DB. AuthService's IssueAccessToken / parseJWT don't
// use the repo field, so we can construct one with just the signing
// key + a config that returns the test issuer.

const testIssuer = "https://app.manyrows.test"

// freshTestKey mints an in-memory ES256 keypair per test. Avoids
// touching the DB-backed jwks.LoadOrGenerate path and keeps the
// JWT-claim tests fully unit-shaped.
func freshTestKey(t *testing.T) *jwks.Key {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return &jwks.Key{Private: priv, KID: "test-kid"}
}

// newTestAuthService builds an AuthService whose issuer() returns
// testIssuer. We point a fresh Config at an env-var prefix that's
// unique per test and t.Setenv it — keeps tests parallel-safe.
func newTestAuthService(t *testing.T) *AuthService {
	t.Helper()
	t.Setenv("CLIENT_JWT_TEST_BASE_URL", testIssuer)
	cfg := config.NewConfig("CLIENT_JWT_TEST_")
	a := &AuthService{
		cfg:        cfg,
		sessionTTL: 30 * 24 * time.Hour,
	}
	a.jwtKeys.Store(&jwks.KeySet{Current: freshTestKey(t)})
	return a
}

// currentTestKey returns the test service's current signing key.
// Helper for the tests that need to sign tokens directly (foreign
// issuer, missing iss, etc.) — they used to reach for a.jwtKey but
// after the KeySet refactor they go through .Current.
func currentTestKey(a *AuthService) *jwks.Key { return a.jwtKeys.Load().Current }

func newTestSession() *core.ClientSession {
	sid := uuid.Must(uuid.NewV4())
	uid := uuid.Must(uuid.NewV4())
	aid := uuid.Must(uuid.NewV4())
	return &core.ClientSession{
		ID:        sid,
		UserID:    uid,
		AppID:     &aid,
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC(),
	}
}

func TestIssueAccessToken_SetsIssuerAndAudience(t *testing.T) {
	a := newTestAuthService(t)
	s := newTestSession()

	tok, _, err := a.IssueAccessToken(s, 0, "")
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	// Parse without going through a.parseJWT so we can inspect raw claims.
	parsed, err := jwt.ParseWithClaims(tok, &mrClientJWTClaims{}, func(*jwt.Token) (any, error) {
		return &currentTestKey(a).Private.PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	c := parsed.Claims.(*mrClientJWTClaims)

	if c.Issuer != testIssuer {
		t.Errorf("iss: got %q want %q", c.Issuer, testIssuer)
	}
	if len(c.Audience) != 1 || c.Audience[0] != s.AppID.String() {
		t.Errorf("aud: got %v want [%s]", c.Audience, s.AppID.String())
	}
	if c.AppID != s.AppID.String() {
		t.Errorf("app claim: got %q want %q", c.AppID, s.AppID.String())
	}
	if c.SessionID != s.ID.String() {
		t.Errorf("sid: got %q want %q", c.SessionID, s.ID.String())
	}
}

func TestParseJWT_AcceptsOwnIssuer(t *testing.T) {
	a := newTestAuthService(t)
	s := newTestSession()

	tok, _, _ := a.IssueAccessToken(s, 0, "")
	c, ok := a.parseJWT(tok)
	if !ok {
		t.Fatal("parseJWT rejected its own issued token")
	}
	if c.Issuer != testIssuer {
		t.Errorf("parsed iss: got %q want %q", c.Issuer, testIssuer)
	}
}

// parseJWT no longer enforces a fixed iss — per-app AuthDomain means
// iss varies, and the install-private signing key is the security
// boundary. The two tests previously here (RejectsForeignIssuer,
// RejectsMissingIssuer) asserted defense-in-depth behavior we
// intentionally dropped; TestParseJWT_RejectsTamperedSig below covers
// the load-bearing check.

func TestParseJWT_RejectsTamperedSig(t *testing.T) {
	a := newTestAuthService(t)
	s := newTestSession()
	tok, _, _ := a.IssueAccessToken(s, 0, "")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	// Replace one char in the middle of the signature segment to be
	// sure we change the decoded bytes (single-char swaps at the
	// boundary can be base64-equivalent depending on padding).
	sig := parts[2]
	mid := len(sig) / 2
	flip := byte('A')
	if sig[mid] == 'A' {
		flip = 'B'
	}
	tampered := parts[0] + "." + parts[1] + "." + sig[:mid] + string(flip) + sig[mid+1:]
	if _, ok := a.parseJWT(tampered); ok {
		t.Fatal("parseJWT accepted token with tampered signature")
	}
}

func TestIssueAccessToken_FailsWhenBaseURLEmpty(t *testing.T) {
	// First-boot scenario: the binary comes up before any /admin/register
	// has pinned BASE_URL. The client auth service must not be willing
	// to mint a JWT with an empty iss claim — that would silently
	// disable cross-deployment replay protection.
	t.Setenv("CLIENT_JWT_EMPTY_BASE_URL", "")
	a := &AuthService{
		cfg: config.NewConfig("CLIENT_JWT_EMPTY_"),
	}
	a.jwtKeys.Store(&jwks.KeySet{Current: freshTestKey(t)})
	s := newTestSession()
	if _, _, err := a.IssueAccessToken(s, 0, ""); err == nil {
		t.Fatal("expected IssueAccessToken to fail with empty BASE_URL; got nil error")
	}
}
