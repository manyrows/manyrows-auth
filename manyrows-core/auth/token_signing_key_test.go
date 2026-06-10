package auth_test

import (
	"bytes"
	"testing"

	"manyrows-core/auth"
)

// TestDeriveTokenSigningKey pins the domain-separation properties the OAuth /
// TOTP token signers rely on: the derived key is a fixed 32 bytes, differs from
// the master (so it can't be confused with the cookie-store key), is
// deterministic, and a different master yields a different key.
func TestDeriveTokenSigningKey(t *testing.T) {
	master := []byte("session-auth-key-0123456789abcdef")

	k1 := auth.DeriveTokenSigningKey(master)
	if len(k1) != 32 {
		t.Fatalf("derived key length = %d, want 32", len(k1))
	}
	if bytes.Equal(k1, master) {
		t.Fatal("derived key must differ from the master (cookie-store) key")
	}

	if k2 := auth.DeriveTokenSigningKey(master); !bytes.Equal(k1, k2) {
		t.Fatal("derivation must be deterministic for the same master")
	}

	if k3 := auth.DeriveTokenSigningKey([]byte("a-different-session-auth-key-9999")); bytes.Equal(k1, k3) {
		t.Fatal("a different master must yield a different derived key")
	}
}
