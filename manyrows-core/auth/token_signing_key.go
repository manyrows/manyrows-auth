package auth

import (
	"crypto/hmac"
	"crypto/sha256"
)

// tokenSigningKeyLabel domain-separates the HMAC key used for short-lived
// signed tokens (TOTP challenges, TOTP setup challenges, OAuth state) from the
// raw SESSION_AUTH_KEY bytes — which ALSO key the gorilla securecookie session
// store. Using one key across two different cryptographic constructions (raw
// HMAC-SHA256 here vs. securecookie there) is the smell this removes. The label
// is versioned so the derivation can be rotated independently of the master.
const tokenSigningKeyLabel = "manyrows/token-signing/v1"

// DeriveTokenSigningKey returns a 32-byte HMAC key derived from the install's
// SESSION_AUTH_KEY and cryptographically independent of it (an HMAC-Expand-style
// KDF: HMAC(master, label)). The derived key is what signs/verifies TOTP and
// OAuth-state tokens; the cookie store keeps using the raw master, so changing
// this derivation invalidates only the short-lived (<=10 min) signed tokens,
// never admin session cookies.
func DeriveTokenSigningKey(sessionAuthKey []byte) []byte {
	m := hmac.New(sha256.New, sessionAuthKey)
	m.Write([]byte(tokenSigningKeyLabel))
	return m.Sum(nil)
}
