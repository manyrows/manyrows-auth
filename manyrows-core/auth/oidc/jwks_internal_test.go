package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"testing"
)

func ecB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// A genuine on-curve key round-trips through ecKeyFromJWK unchanged.
func TestECKeyFromJWK_AcceptsValidPoint(t *testing.T) {
	for _, tc := range []struct {
		crv   string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	} {
		key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		if err != nil {
			t.Fatalf("%s: generate key: %v", tc.crv, err)
		}
		got, err := ecKeyFromJWK(tc.crv, ecB64(key.PublicKey.X.Bytes()), ecB64(key.PublicKey.Y.Bytes()))
		if err != nil {
			t.Fatalf("%s: valid key rejected: %v", tc.crv, err)
		}
		if got.X.Cmp(key.PublicKey.X) != 0 || got.Y.Cmp(key.PublicKey.Y) != 0 {
			t.Fatalf("%s: coordinate round-trip mismatch", tc.crv)
		}
	}
}

// The core security property: a point that is NOT on the declared curve must be
// rejected, so a hostile/MITM'd jwks_uri can't mount an invalid-curve attack.
func TestECKeyFromJWK_RejectsOffCurvePoint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// (X, Y+1) is, with overwhelming probability, not a point on P-256.
	badY := new(big.Int).Add(key.PublicKey.Y, big.NewInt(1))
	if _, err := ecKeyFromJWK("P-256", ecB64(key.PublicKey.X.Bytes()), ecB64(badY.Bytes())); err == nil {
		t.Fatal("off-curve point accepted — invalid-curve attack not prevented")
	}
}

// Coordinates longer than the curve's field size are rejected before they reach
// the on-curve check.
func TestECKeyFromJWK_RejectsOversizedCoordinate(t *testing.T) {
	oversized := make([]byte, 33) // P-256 coordinates are 32 bytes
	oversized[0] = 0x01
	if _, err := ecKeyFromJWK("P-256", ecB64(oversized), ecB64(oversized)); err == nil {
		t.Fatal("oversized P-256 coordinate accepted")
	}
}

func TestECKeyFromJWK_RejectsUnsupportedCurve(t *testing.T) {
	if _, err := ecKeyFromJWK("P-224", "AA", "AA"); err == nil {
		t.Fatal("unsupported curve accepted")
	}
}
