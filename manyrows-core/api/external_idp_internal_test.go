package api

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// TestDerivePKCE guards the storage-free PKCE derivation: it must be
// deterministic for a given (state, key) — the authorize and callback
// legs derive it independently and must agree — the challenge must be
// S256(verifier), the verifier must fall in RFC 7636's 43–128 range, and
// it must depend on BOTH the state and the secret server key (the latter
// is what keeps the verifier secret even though the state is public).
func TestDerivePKCE(t *testing.T) {
	key := []byte("test-hmac-key-0123456789abcdef")
	state := "AAAA-state-token-BBBB"

	v1, c1 := derivePKCE(state, key)
	v2, c2 := derivePKCE(state, key)
	if v1 != v2 || c1 != c2 {
		t.Fatal("derivePKCE must be deterministic for the same (state,key)")
	}
	sum := sha256.Sum256([]byte(v1))
	if c1 != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("challenge must equal S256(verifier)")
	}
	if len(v1) < 43 || len(v1) > 128 {
		t.Fatalf("verifier length %d outside PKCE range 43–128", len(v1))
	}
	if v3, _ := derivePKCE("different-state", key); v3 == v1 {
		t.Fatal("a different state must yield a different verifier")
	}
	if v4, _ := derivePKCE(state, []byte("a-different-server-key-99999")); v4 == v1 {
		t.Fatal("the verifier must depend on the server key (else the public state would leak it)")
	}
}

// TestDeriveNonce guards the nonce derivation: deterministic, varies by
// state, and domain-separated from the PKCE verifier so the same state
// can't produce a colliding nonce/verifier pair.
func TestDeriveNonce(t *testing.T) {
	key := []byte("test-hmac-key-0123456789abcdef")
	if deriveNonce("s", key) != deriveNonce("s", key) {
		t.Fatal("deriveNonce must be deterministic")
	}
	if deriveNonce("s", key) == deriveNonce("s2", key) {
		t.Fatal("nonce must vary by state")
	}
	if v, _ := derivePKCE("s", key); deriveNonce("s", key) == v {
		t.Fatal("nonce and PKCE verifier must be domain-separated for the same state")
	}
}
