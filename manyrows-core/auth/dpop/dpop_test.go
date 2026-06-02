package dpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// memoryReplay is a tiny in-memory ReplayCache used only by these tests.
// The production verifier is wired against the Postgres repo.
type memoryReplay struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func newMemoryReplay() *memoryReplay {
	return &memoryReplay{entries: make(map[string]time.Time)}
}

func (m *memoryReplay) RecordDPopProofIfNew(_ context.Context, jkt, jti string, expiresAt time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := jkt + "|" + jti
	if exp, ok := m.entries[key]; ok && time.Now().Before(exp) {
		return false, nil
	}
	m.entries[key] = expiresAt
	return true, nil
}

// signDPoPProof produces a DPoP proof JWT signed with the given key, embedding
// the matching public JWK in the header. Used to drive the verifier through
// happy-path and adversarial scenarios.
func signDPoPProof(t *testing.T, key *ecdsa.PrivateKey, htm, htu, jti string, iat time.Time) string {
	t.Helper()
	jwk := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(padCoord(key.X.Bytes())),
		"y":   base64.RawURLEncoding.EncodeToString(padCoord(key.Y.Bytes())),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"htm": htm,
		"htu": htu,
		"jti": jti,
		"iat": iat.Unix(),
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = jwk
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign DPoP: %v", err)
	}
	return signed
}

// padCoord left-pads an EC coordinate to 32 bytes (P-256). The std-lib's
// big.Int.Bytes can omit leading zeros, which would produce an invalid JWK
// thumbprint if not padded.
func padCoord(b []byte) []byte {
	if len(b) == 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

func newTestVerifier() *Verifier {
	return &Verifier{
		IATSkew: 30 * time.Second,
		Replay:  newMemoryReplay(),
		Now:     time.Now,
	}
}

func TestVerify_HappyPath(t *testing.T) {
	v := newTestVerifier()
	key := newKey(t)
	now := time.Now().UTC()

	proof := signDPoPProof(t, key, "POST", "https://api.example.com/auth/refresh", "jti-1", now)

	got, err := v.Verify(context.Background(), proof, "POST", "https://api.example.com/auth/refresh")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if got.JKT == "" {
		t.Error("expected non-empty JKT")
	}
	if got.JTI != "jti-1" {
		t.Errorf("JTI: got %q, want jti-1", got.JTI)
	}
}

func TestVerify_RejectsReplay(t *testing.T) {
	v := newTestVerifier()
	key := newKey(t)
	proof := signDPoPProof(t, key, "POST", "https://x/", "jti-replay", time.Now().UTC())

	if _, err := v.Verify(context.Background(), proof, "POST", "https://x/"); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	_, err := v.Verify(context.Background(), proof, "POST", "https://x/")
	if !errors.Is(err, ErrReplayed) {
		t.Errorf("second verify: got %v, want ErrReplayed", err)
	}
}

func TestVerify_RejectsWrongMethod(t *testing.T) {
	v := newTestVerifier()
	key := newKey(t)
	proof := signDPoPProof(t, key, "GET", "https://x/", "j", time.Now().UTC())

	_, err := v.Verify(context.Background(), proof, "POST", "https://x/")
	if !errors.Is(err, ErrMethodMismatch) {
		t.Errorf("got %v, want ErrMethodMismatch", err)
	}
}

func TestVerify_RejectsWrongURI(t *testing.T) {
	v := newTestVerifier()
	key := newKey(t)
	cases := []struct {
		name      string
		signedURI string
		reqURI    string
	}{
		{"different host", "https://api.example.com/x", "https://attacker.com/x"},
		{"different path", "https://x/auth/refresh", "https://x/auth/login"},
		{"different scheme", "http://x/r", "https://x/r"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proof := signDPoPProof(t, key, "POST", tc.signedURI, "j-"+tc.name, time.Now().UTC())
			_, err := v.Verify(context.Background(), proof, "POST", tc.reqURI)
			if !errors.Is(err, ErrURIMismatch) {
				t.Errorf("got %v, want ErrURIMismatch", err)
			}
		})
	}
}

func TestVerify_AcceptsTrailingSlashDifference(t *testing.T) {
	v := newTestVerifier()
	key := newKey(t)
	proof := signDPoPProof(t, key, "POST", "https://x/auth/refresh", "j-ts", time.Now().UTC())

	_, err := v.Verify(context.Background(), proof, "POST", "https://x/auth/refresh/")
	if err != nil {
		t.Errorf("trailing slash should match: got %v", err)
	}
}

func TestVerify_RejectsIATOutOfWindow(t *testing.T) {
	v := newTestVerifier()
	key := newKey(t)

	tooOld := time.Now().UTC().Add(-2 * time.Minute)
	proof := signDPoPProof(t, key, "POST", "https://x/", "j-old", tooOld)
	_, err := v.Verify(context.Background(), proof, "POST", "https://x/")
	if !errors.Is(err, ErrIATOutOfWindow) {
		t.Errorf("too-old iat: got %v, want ErrIATOutOfWindow", err)
	}

	tooNew := time.Now().UTC().Add(2 * time.Minute)
	proof2 := signDPoPProof(t, key, "POST", "https://x/", "j-new", tooNew)
	_, err = v.Verify(context.Background(), proof2, "POST", "https://x/")
	if !errors.Is(err, ErrIATOutOfWindow) {
		t.Errorf("too-new iat: got %v, want ErrIATOutOfWindow", err)
	}
}

func TestVerify_RejectsBadSignature(t *testing.T) {
	v := newTestVerifier()
	key := newKey(t)
	proof := signDPoPProof(t, key, "POST", "https://x/", "j-sig", time.Now().UTC())

	// Flip a byte in the signature segment (last segment of the JWT).
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	sigBytes[0] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(sigBytes)
	tampered := strings.Join(parts, ".")

	_, err = v.Verify(context.Background(), tampered, "POST", "https://x/")
	if !errors.Is(err, ErrInvalidSig) {
		t.Errorf("got %v, want ErrInvalidSig", err)
	}
}

func TestVerify_RejectsWrongAlg(t *testing.T) {
	v := newTestVerifier()
	// HS256 token with same shape — verifier should refuse.
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"htm": "POST",
		"htu": "https://x/",
		"jti": "j-alg",
		"iat": time.Now().Unix(),
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = map[string]string{"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}
	signed, err := tok.SignedString([]byte("not-a-key"))
	if err != nil {
		t.Fatalf("hs256 sign: %v", err)
	}

	_, err = v.Verify(context.Background(), signed, "POST", "https://x/")
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Errorf("got %v, want ErrUnsupportedAlg", err)
	}
}

func TestVerify_RejectsMissingTyp(t *testing.T) {
	v := newTestVerifier()
	key := newKey(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"htm": "POST",
		"htu": "https://x/",
		"jti": "j-typ",
		"iat": time.Now().Unix(),
	})
	// no typ
	tok.Header["jwk"] = map[string]string{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(padCoord(key.X.Bytes())),
		"y": base64.RawURLEncoding.EncodeToString(padCoord(key.Y.Bytes())),
	}
	signed, _ := tok.SignedString(key)
	_, err := v.Verify(context.Background(), signed, "POST", "https://x/")
	if !errors.Is(err, ErrMalformedProof) {
		t.Errorf("got %v, want ErrMalformedProof", err)
	}
}

func TestVerify_RejectsMissingJTI(t *testing.T) {
	v := newTestVerifier()
	key := newKey(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"htm": "POST",
		"htu": "https://x/",
		"iat": time.Now().Unix(),
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = map[string]string{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(padCoord(key.X.Bytes())),
		"y": base64.RawURLEncoding.EncodeToString(padCoord(key.Y.Bytes())),
	}
	signed, _ := tok.SignedString(key)
	_, err := v.Verify(context.Background(), signed, "POST", "https://x/")
	if !errors.Is(err, ErrMissingJTI) {
		t.Errorf("got %v, want ErrMissingJTI", err)
	}
}

func TestVerify_RejectsForgedJWKWithRealSig(t *testing.T) {
	// Attacker presents the legit user's public JWK in the header but signs
	// with their own private key. Signature verification (against the JWK in
	// the header) must fail.
	v := newTestVerifier()
	legit := newKey(t)
	attacker := newKey(t)

	// Build a token that claims the legit JWK in the header but is signed by
	// the attacker. Easiest construction: use jwt-go with attacker's key and
	// override the jwk header.
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"htm": "POST",
		"htu": "https://x/",
		"jti": "j-forge",
		"iat": time.Now().Unix(),
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = map[string]string{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(padCoord(legit.X.Bytes())),
		"y": base64.RawURLEncoding.EncodeToString(padCoord(legit.Y.Bytes())),
	}
	signed, err := tok.SignedString(attacker)
	if err != nil {
		t.Fatalf("sign with attacker key: %v", err)
	}
	_, err = v.Verify(context.Background(), signed, "POST", "https://x/")
	if !errors.Is(err, ErrInvalidSig) {
		t.Errorf("got %v, want ErrInvalidSig (forged JWK with mismatched sig)", err)
	}
}

func TestVerifyBound_RejectsJKTMismatch(t *testing.T) {
	v := newTestVerifier()
	key := newKey(t)

	proof := signDPoPProof(t, key, "POST", "https://x/", "j-bound", time.Now().UTC())
	_, err := v.VerifyBound(context.Background(), proof, "POST", "https://x/", "not-the-real-jkt")
	if !errors.Is(err, ErrJKTMismatch) {
		t.Errorf("got %v, want ErrJKTMismatch", err)
	}
}

func TestVerifyBound_AcceptsMatchingJKT(t *testing.T) {
	v := newTestVerifier()
	key := newKey(t)

	proof1 := signDPoPProof(t, key, "POST", "https://x/", "j-b1", time.Now().UTC())
	got, err := v.Verify(context.Background(), proof1, "POST", "https://x/")
	if err != nil {
		t.Fatalf("initial verify: %v", err)
	}
	expected := got.JKT

	proof2 := signDPoPProof(t, key, "POST", "https://x/", "j-b2", time.Now().UTC())
	bound, err := v.VerifyBound(context.Background(), proof2, "POST", "https://x/", expected)
	if err != nil {
		t.Fatalf("bound verify with matching jkt: %v", err)
	}
	if bound.JKT != expected {
		t.Errorf("returned jkt %q != expected %q", bound.JKT, expected)
	}
}

func TestVerify_MissingProof(t *testing.T) {
	v := newTestVerifier()
	if _, err := v.Verify(context.Background(), "", "POST", "https://x/"); !errors.Is(err, ErrMissingProof) {
		t.Errorf("got %v, want ErrMissingProof", err)
	}
	if _, err := v.Verify(context.Background(), "   ", "POST", "https://x/"); !errors.Is(err, ErrMissingProof) {
		t.Errorf("whitespace-only: got %v, want ErrMissingProof", err)
	}
}

// TestJKTThumbprint_RFC7638Vector verifies the JKT computation against the
// RFC 7638 §3.1 example. If this regresses, every refresh ever issued under
// DPoP would silently fail to bind, so this is a high-value canary.
func TestJKTThumbprint_RFC7638Vector(t *testing.T) {
	// RFC 7638's example uses an RSA key, which we don't support. Our
	// equivalent canary is end-to-end: derive jkt from a known JWK and assert
	// it matches the reference SHA-256 we precomputed below.
	jwkJSON := []byte(`{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`)
	jkt, err := jktFromECP256JWK(jwkJSON)
	if err != nil {
		t.Fatalf("compute jkt: %v", err)
	}
	// Pinned reference: SHA-256 of the canonical JWK form
	//   {"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}
	// base64url-encoded with no padding. Treat changes to this string as a
	// breaking change to the binding format — every existing DPoP-bound
	// session would be invalidated by altering it.
	const expected = "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"
	if jkt != expected {
		t.Errorf("jkt mismatch:\n got %q\nwant %q", jkt, expected)
	}
}
