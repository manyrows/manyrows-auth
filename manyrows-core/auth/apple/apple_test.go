package apple

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// generatePKCS8ECKey returns a PKCS8-PEM-encoded EC P-256 key, the
// format Apple's .p8 files use.
func generatePKCS8ECKey(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestValidatePrivateKey_AcceptsGoodKey(t *testing.T) {
	if err := ValidatePrivateKey(generatePKCS8ECKey(t)); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestValidatePrivateKey_RejectsRandomBytes(t *testing.T) {
	cases := [][]byte{
		[]byte(""),
		[]byte("not a key at all"),
		[]byte("-----BEGIN PRIVATE KEY-----\nbogus body\n-----END PRIVATE KEY-----\n"),
	}
	for i, in := range cases {
		if err := ValidatePrivateKey(in); err == nil {
			t.Errorf("case %d: expected error, got nil", i)
		}
	}
}

func TestValidatePrivateKey_RejectsRSAKey(t *testing.T) {
	// Apple requires EC P-256; reject RSA keys even when PKCS8-encoded
	// since SignedString would fail at runtime with the wrong key type.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8 rsa: %v", err)
	}
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	err = ValidatePrivateKey(rsaPEM)
	if err == nil {
		t.Fatal("expected error for RSA-in-PKCS8")
	}
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestGenerateClientSecret_RoundTrip(t *testing.T) {
	pemBytes := generatePKCS8ECKey(t)
	const teamID, servicesID, keyID = "TEAM12345A", "com.example.signin", "KEY12345A"

	signed, err := GenerateClientSecret(teamID, servicesID, keyID, pemBytes, 5*time.Minute)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Parse with explicit ES256 verification using the public key from the
	// same private key (round-trip self-sign-and-verify).
	block, _ := pem.Decode(pemBytes)
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse pkcs8: %v", err)
	}
	priv := parsedKey.(*ecdsa.PrivateKey)

	parser := jwt.NewParser(jwt.WithValidMethods([]string{"ES256"}))
	tok, err := parser.Parse(signed, func(_ *jwt.Token) (any, error) {
		return &priv.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parse signed token: %v", err)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("unexpected claims type")
	}
	if claims["iss"] != teamID {
		t.Errorf("iss: got %v, want %s", claims["iss"], teamID)
	}
	if claims["sub"] != servicesID {
		t.Errorf("sub: got %v, want %s", claims["sub"], servicesID)
	}
	if claims["aud"] != issuer {
		t.Errorf("aud: got %v, want %s", claims["aud"], issuer)
	}
	if got := tok.Header["kid"]; got != keyID {
		t.Errorf("kid header: got %v, want %s", got, keyID)
	}
	if tok.Header["alg"] != "ES256" {
		t.Errorf("alg: got %v, want ES256", tok.Header["alg"])
	}
}

func TestGenerateClientSecret_RejectsEmptyIDs(t *testing.T) {
	pemBytes := generatePKCS8ECKey(t)
	cases := []struct {
		team, services, key string
	}{
		{"", "svc", "kid"},
		{"team", "", "kid"},
		{"team", "svc", ""},
	}
	for _, c := range cases {
		if _, err := GenerateClientSecret(c.team, c.services, c.key, pemBytes, time.Minute); err == nil {
			t.Errorf("expected error for team=%q services=%q key=%q", c.team, c.services, c.key)
		}
	}
}

func TestBuildAuthorizeURL(t *testing.T) {
	got := BuildAuthorizeURL("com.example.signin", "https://api.example.com/callback", "state-abc")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Host != "appleid.apple.com" || u.Path != "/auth/authorize" {
		t.Errorf("unexpected base: %s", got)
	}
	q := u.Query()
	checks := map[string]string{
		"client_id":     "com.example.signin",
		"redirect_uri":  "https://api.example.com/callback",
		"response_type": "code",
		"scope":         "name email",
		"response_mode": "form_post",
		"state":         "state-abc",
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Errorf("query %s: got %q, want %q", k, got, want)
		}
	}
}

func TestFlexBool_UnmarshalJSON(t *testing.T) {
	cases := []struct {
		in   string
		want bool
		err  bool
	}{
		{`true`, true, false},
		{`false`, false, false},
		{`"true"`, true, false},
		{`"false"`, false, false},
		{`null`, false, false},
		{`""`, false, false},
		{`"maybe"`, false, true},
		{`123`, false, true},
	}
	for _, c := range cases {
		var got flexBool
		err := json.Unmarshal([]byte(c.in), &got)
		if c.err {
			if err == nil {
				t.Errorf("input %q: expected error, got nil", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("input %q: unexpected error: %v", c.in, err)
			continue
		}
		if bool(got) != c.want {
			t.Errorf("input %q: got %v, want %v", c.in, bool(got), c.want)
		}
	}
}

func TestRSAKeyFromJWK_RoundTrip(t *testing.T) {
	// Generate an RSA key, encode its public modulus + exponent as a JWK,
	// then verify rsaKeyFromJWK reconstructs the exact same public key.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}

	// Encode N as base64url big-endian, E as the canonical "AQAB" (65537).
	// Real Apple JWKs use the same encoding per RFC 7518.
	nB64 := base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes())
	// E is 65537 = 0x010001 → bytes {0x01, 0x00, 0x01}
	eB64 := base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01})

	got, err := rsaKeyFromJWK(nB64, eB64)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if got.N.Cmp(priv.PublicKey.N) != 0 {
		t.Errorf("modulus mismatch")
	}
	if got.E != priv.PublicKey.E {
		t.Errorf("exponent: got %d, want %d", got.E, priv.PublicKey.E)
	}
}

func TestRSAKeyFromJWK_InvalidEncoding(t *testing.T) {
	if _, err := rsaKeyFromJWK("!!!not-base64!!!", "AQAB"); err == nil {
		t.Error("expected error on bad modulus encoding")
	}
	if _, err := rsaKeyFromJWK("AQAB", "!!!not-base64!!!"); err == nil {
		t.Error("expected error on bad exponent encoding")
	}
}
