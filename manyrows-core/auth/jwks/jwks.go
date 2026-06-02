// Package jwks owns the issuer-side keypair ManyRows uses to sign
// access / refresh JWTs. The public half is published at
// /.well-known/jwks.json so consumers (manyrows-go and any other
// JWKS-aware verifier) can verify tokens locally without ever
// holding a shared secret.
//
// Why a dedicated package: the JWT-issuing code in auth/client lives
// behind a Service that needs the loaded keypair at construction
// time, but key persistence + JWKS rendering are concerns the rest
// of auth/client doesn't care about. Splitting them keeps both
// surfaces narrow.
package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

// SecretsStore is the narrow interface the keypair loader needs to
// boot. Implemented by *core/repo.Repo with PutSystemSecret /
// GetSystemSecret. Small enough to fake in tests.
type SecretsStore interface {
	GetSystemSecret(ctx context.Context, name string) (string, error)
	PutSystemSecret(ctx context.Context, name, value string) (string, error)
}

// MutableSecretsStore adds the write surfaces required to rotate the
// signing keypair: UpsertSystemSecret to overwrite the current-key row
// with the new key, and DeleteSystemSecret to retire the previous-key
// row after the overlap window. Production *core/repo.Repo satisfies
// both this and SecretsStore; tests can fake either as needed.
type MutableSecretsStore interface {
	SecretsStore
	UpsertSystemSecret(ctx context.Context, name, value string) error
	DeleteSystemSecret(ctx context.Context, name string) error
}

// Row names used in system_secrets.
//
//	rowKey         — the current signing key. ON CONFLICT DO NOTHING
//	                 on first-boot generate; UpsertSystemSecret on
//	                 rotation.
//	rowKeyPrevious — the most recent prior signing key, kept during a
//	                 rotation window so verifiers can still validate
//	                 tokens issued before the rotation. Cleared via
//	                 DeleteSystemSecret once the operator confirms
//	                 every refresh-token-TTL has elapsed.
const (
	rowKey         = "jwt_signing_key_pem"
	rowKeyPrevious = "jwt_signing_key_pem_previous"
)

// Key is the loaded ES256 keypair plus its Key ID. The kid is the
// RFC 7638 thumbprint of the public JWK, so it's deterministic from
// the key itself — clients can derive it independently if they ever
// need to (tests use this to assert no surprise rotation).
type Key struct {
	Private *ecdsa.PrivateKey
	KID     string
}

// LoadOrGenerate returns the install's signing keypair, creating one
// the first time it's called. Concurrent first-boot callers race
// safely via PutSystemSecret's first-write-wins semantic — the
// loser reads the winner's value back and uses that.
func LoadOrGenerate(ctx context.Context, store SecretsStore) (*Key, error) {
	if store == nil {
		return nil, errors.New("jwks: nil store")
	}

	if pemStr, err := store.GetSystemSecret(ctx, rowKey); err == nil && pemStr != "" {
		k, err := parsePEM(pemStr)
		if err != nil {
			return nil, fmt.Errorf("jwks: stored key parse: %w", err)
		}
		return k, nil
	} else if err != nil {
		return nil, fmt.Errorf("jwks: load: %w", err)
	}

	// Not present: generate, persist, return the value the row
	// actually committed (which may be a concurrent boot's value if
	// we lost the race — that's fine, both are valid).
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("jwks: generate: %w", err)
	}
	pemStr, err := encodePEM(priv)
	if err != nil {
		return nil, fmt.Errorf("jwks: encode: %w", err)
	}

	stored, err := store.PutSystemSecret(ctx, rowKey, pemStr)
	if err != nil {
		return nil, fmt.Errorf("jwks: persist: %w", err)
	}
	return parsePEM(stored)
}

func parsePEM(pemStr string) (*Key, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("not a PEM block")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA private key")
	}
	if ec.Curve != elliptic.P256() {
		return nil, errors.New("not P-256")
	}
	return &Key{
		Private: ec,
		KID:     thumbprint(&ec.PublicKey),
	}, nil
}

func encodePEM(priv *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// thumbprint computes the RFC 7638 SHA-256 thumbprint of a P-256
// public key, returned base64url. Mirrors the DPoP package's jkt
// computation so the wire format is consistent across the codebase.
func thumbprint(pub *ecdsa.PublicKey) string {
	x := base64.RawURLEncoding.EncodeToString(leftPad(pub.X.Bytes(), 32))
	y := base64.RawURLEncoding.EncodeToString(leftPad(pub.Y.Bytes(), 32))
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, x, y)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// JWKSDocument is the JSON shape served at /.well-known/jwks.json.
// Holds one JWK in the steady state, two during a rotation overlap
// window. Verifiers (manyrows-go and the other SDKs) already cache
// by kid and look up the matching JWK, so the document growing to
// two keys is transparent to them.
type JWKSDocument struct {
	Keys []JWK `json:"keys"`
}

// JWK is the public-key JWK for the install's signing key.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// Document renders the public half of k as a single-key JWKS payload.
// Retained for back-compat with callers that hold a *Key directly;
// new callers should use KeySet.Document so rotation overlap windows
// publish both keys.
func (k *Key) Document() ([]byte, error) {
	if k == nil || k.Private == nil {
		return nil, errors.New("jwks: nil key")
	}
	return json.Marshal(JWKSDocument{Keys: []JWK{jwkFor(k)}})
}

// PublicKeyByKID is the lookup verifiers use during signature check.
// Returns nil when kid doesn't match — callers treat that as "kid we
// don't recognise" and refetch JWKS.
func (k *Key) PublicKeyByKID(kid string) *ecdsa.PublicKey {
	if k == nil || k.Private == nil {
		return nil
	}
	if kid != "" && kid != k.KID {
		return nil
	}
	return &k.Private.PublicKey
}

// Belt-and-braces: keep the package importable as a Stringer for
// debug logs without leaking the private scalar.
func (k *Key) String() string {
	if k == nil {
		return "<nil>"
	}
	return fmt.Sprintf("jwks.Key{kid=%s, curve=P-256}", k.KID)
}

// =====================================================================
// KeySet — current key + optional previous, for rotation
// =====================================================================

// KeySet holds the install's signing keypair plus an optional previous
// key kept during a rotation overlap window. New tokens always sign
// with Current; verifiers match by kid against either slot.
//
// In steady state (no rotation), Previous is nil and Document()
// publishes a single JWK. After Rotate(), Previous holds the key that
// signed in-flight tokens until they expire; Document() publishes
// both. RetirePrevious() drops Previous once enough time has elapsed
// that no token signed with the old key can still be in use.
type KeySet struct {
	Current  *Key
	Previous *Key // nil unless a rotation overlap window is open
}

// LoadOrGenerateSet returns the install's full keyset. On first boot
// it generates the current key (no previous). On subsequent boots it
// reads both rows; previous is nil when the row is absent.
//
// A malformed previous-key row is logged and ignored rather than
// failing the boot — the worst case is that old tokens fail signature
// verify and their holders re-authenticate. A malformed CURRENT-key
// row is still fatal (the install can't issue tokens at all).
func LoadOrGenerateSet(ctx context.Context, store SecretsStore) (*KeySet, error) {
	current, err := LoadOrGenerate(ctx, store)
	if err != nil {
		return nil, err
	}
	set := &KeySet{Current: current}

	prevPEM, err := store.GetSystemSecret(ctx, rowKeyPrevious)
	if err != nil {
		return nil, fmt.Errorf("jwks: load previous: %w", err)
	}
	if prevPEM != "" {
		prev, err := parsePEM(prevPEM)
		if err != nil {
			// Don't blow up the boot — drop the previous key and
			// continue. New tokens still sign with current; old
			// tokens fail verify and the holder re-auths.
			return set, fmt.Errorf("jwks: previous key parse failed (ignoring): %w", err)
		}
		set.Previous = prev
	}
	return set, nil
}

// Document emits the JWKS payload — one JWK in steady state, two
// during a rotation overlap window.
func (s *KeySet) Document() ([]byte, error) {
	if s == nil || s.Current == nil {
		return nil, errors.New("jwks: empty keyset")
	}
	keys := []JWK{jwkFor(s.Current)}
	if s.Previous != nil {
		keys = append(keys, jwkFor(s.Previous))
	}
	return json.Marshal(JWKSDocument{Keys: keys})
}

// PublicKeyByKID resolves a kid header to the matching public key,
// checking current first (where most verifications land) and falling
// back to previous during a rotation window. Empty kid matches
// current — covers tokens issued before kid headers were emitted.
// Returns nil when the kid matches neither key; callers treat that
// as "refetch JWKS" or "reject".
func (s *KeySet) PublicKeyByKID(kid string) *ecdsa.PublicKey {
	if s == nil {
		return nil
	}
	if s.Current != nil && (kid == "" || kid == s.Current.KID) {
		return &s.Current.Private.PublicKey
	}
	if s.Previous != nil && kid == s.Previous.KID {
		return &s.Previous.Private.PublicKey
	}
	return nil
}

// Rotate moves the current key into the previous slot and generates a
// fresh current key. Returns the new keyset; the caller should swap
// it into any in-process holder atomically.
//
// Both DB rows are written; we don't wrap them in a single transaction
// because system_secrets is the only authoritative source and the
// failure mode of a half-rotation (previous written, current not) is
// "rerun rotate". UpsertSystemSecret on the previous slot intentionally
// overwrites — operators rotating twice within the overlap window
// lose the oldest key, which is the desired retirement semantic.
//
// Multi-instance note: other replicas still hold the pre-rotation
// keyset in memory until they reload (typically on next deploy /
// restart). Both replicas verify each other's tokens correctly during
// the overlap (current+previous slots cover both keys from either
// side's POV), but the rotating replica is the only one issuing
// tokens under the new kid until the others reload.
func (s *KeySet) Rotate(ctx context.Context, store MutableSecretsStore) (*KeySet, error) {
	if s == nil || s.Current == nil {
		return nil, errors.New("jwks: rotate called on empty keyset")
	}
	if store == nil {
		return nil, errors.New("jwks: rotate needs a mutable store")
	}

	// Generate the new key first so a failure here aborts before any
	// DB write — the previous slot only gets overwritten if we have a
	// valid replacement.
	newPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("jwks: rotate generate: %w", err)
	}
	newPEM, err := encodePEM(newPriv)
	if err != nil {
		return nil, fmt.Errorf("jwks: rotate encode: %w", err)
	}
	newKey := &Key{Private: newPriv, KID: thumbprint(&newPriv.PublicKey)}

	// Promote current → previous. Upsert because previous may already
	// hold an older key from a prior rotation that hasn't been
	// retired yet — that older key is the one we're losing here.
	curPEM, err := encodePEM(s.Current.Private)
	if err != nil {
		return nil, fmt.Errorf("jwks: rotate re-encode current: %w", err)
	}
	if err := store.UpsertSystemSecret(ctx, rowKeyPrevious, curPEM); err != nil {
		return nil, fmt.Errorf("jwks: rotate persist previous: %w", err)
	}

	// Write the new current.
	if err := store.UpsertSystemSecret(ctx, rowKey, newPEM); err != nil {
		// Partial state: previous holds what's still the in-process
		// current. The in-memory keyset hasn't changed yet, so the
		// caller's verify/issue path keeps working under the old key
		// — an operator-visible "rotate failed; retry" is the expected
		// recovery.
		return nil, fmt.Errorf("jwks: rotate persist current: %w", err)
	}

	return &KeySet{Current: newKey, Previous: s.Current}, nil
}

// RetirePrevious drops the previous key from both the DB and the
// returned in-process keyset. Call this once the operator is confident
// no JWT signed with the old key can still be presented (i.e. enough
// time has elapsed to cover the longest live refresh-token TTL).
//
// Safe to call when no previous key is set — returns the keyset
// unchanged.
func (s *KeySet) RetirePrevious(ctx context.Context, store MutableSecretsStore) (*KeySet, error) {
	if s == nil || s.Current == nil {
		return nil, errors.New("jwks: retire called on empty keyset")
	}
	if store == nil {
		return nil, errors.New("jwks: retire needs a mutable store")
	}
	if err := store.DeleteSystemSecret(ctx, rowKeyPrevious); err != nil {
		return nil, fmt.Errorf("jwks: retire previous: %w", err)
	}
	return &KeySet{Current: s.Current, Previous: nil}, nil
}

// jwkFor produces a JWK for a single key. Shared between Document and
// the (unexported here) test helpers.
func jwkFor(k *Key) JWK {
	pub := &k.Private.PublicKey
	return JWK{
		Kty: "EC",
		Crv: "P-256",
		Kid: k.KID,
		Use: "sig",
		Alg: "ES256",
		X:   base64.RawURLEncoding.EncodeToString(leftPad(pub.X.Bytes(), 32)),
		Y:   base64.RawURLEncoding.EncodeToString(leftPad(pub.Y.Bytes(), 32)),
	}
}
