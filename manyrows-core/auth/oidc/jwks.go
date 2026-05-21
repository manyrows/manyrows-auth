package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// jwksTTL bounds how long a provider's verification keys are cached.
// Providers rotate on the order of days/weeks; an hour keeps us fresh
// without hammering the jwks_uri on every sign-in.
const jwksTTL = time.Hour

type jwksCacheEntry struct {
	keys      map[string]any // kid -> *rsa.PublicKey | *ecdsa.PublicKey
	lastFetch time.Time
}

// jwksCache is process-local and keyed by jwks_uri, so every configured
// provider gets its own key set without any shared-state coupling.
var jwksCache = struct {
	sync.Mutex
	byURL map[string]*jwksCacheEntry
}{byURL: map[string]*jwksCacheEntry{}}

// getSigningKey returns the public key for (jwksURL, kid), fetching and
// caching the JWKS on a miss or once the TTL lapses. An empty kid is
// honored only when the set has exactly one key (some providers omit
// kid when they publish a single signer).
func getSigningKey(ctx context.Context, jwksURL, kid string) (any, error) {
	jwksCache.Lock()
	if e := jwksCache.byURL[jwksURL]; e != nil && time.Since(e.lastFetch) < jwksTTL {
		if k := pickKey(e.keys, kid); k != nil {
			jwksCache.Unlock()
			return k, nil
		}
	}
	jwksCache.Unlock()

	keys, err := fetchJWKS(ctx, jwksURL)
	if err != nil {
		return nil, err
	}
	jwksCache.Lock()
	jwksCache.byURL[jwksURL] = &jwksCacheEntry{keys: keys, lastFetch: time.Now().UTC()}
	jwksCache.Unlock()

	if k := pickKey(keys, kid); k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("%w: no signing key for kid %q", ErrInvalidToken, kid)
}

func pickKey(keys map[string]any, kid string) any {
	if kid != "" {
		return keys[kid]
	}
	if len(keys) == 1 {
		for _, k := range keys {
			return k
		}
	}
	return nil
}

// jwk is the subset of a JSON Web Key (RFC 7517/7518) we consume for
// RSA and EC signature verification.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func fetchJWKS(ctx context.Context, jwksURL string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks fetch %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch %s: status %d", jwksURL, resp.StatusCode)
	}

	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("jwks decode: %w", err)
	}

	out := map[string]any{}
	for _, k := range doc.Keys {
		// Skip keys explicitly marked for encryption, not signing.
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		var (
			key any
			err error
		)
		switch k.Kty {
		case "RSA":
			key, err = rsaKeyFromJWK(k.N, k.E)
		case "EC":
			key, err = ecKeyFromJWK(k.Crv, k.X, k.Y)
		default:
			continue
		}
		if err != nil {
			continue // skip unparseable keys rather than failing the set
		}
		out[k.Kid] = key
	}
	if len(out) == 0 {
		return nil, errors.New("jwks: no usable signing keys")
	}
	return out, nil
}

// rsaKeyFromJWK rebuilds an *rsa.PublicKey from base64url modulus +
// exponent (RFC 7518 §6.3).
func rsaKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, errors.New("rsa exponent too large")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e.Int64())}, nil
}

// ecKeyFromJWK rebuilds an *ecdsa.PublicKey from the curve + base64url
// affine coordinates (RFC 7518 §6.2).
func ecKeyFromJWK(crv, xB64, yB64 string) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve %q", crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
