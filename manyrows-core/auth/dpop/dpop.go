// Package dpop implements server-side verification of DPoP proofs (RFC 9449).
//
// A DPoP proof is a short-lived signed JWT that demonstrates possession of a
// private key. ManyRows uses these to bind client refresh tokens to a non-
// extractable browser keypair: an exfiltrated refresh token alone is then
// insufficient to obtain new access tokens, because the proof signature
// requires a key the attacker cannot get out of the browser.
//
// Phase 1 scope: ES256 (ECDSA P-256) only, refresh-token binding only.
// Access-token binding (cnf claim, ath validation) is deliberately deferred —
// see the DPoP entry in todo/TODO.md for rationale.
package dpop

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultIATPastSkew and DefaultIATFutureSkew bound the acceptable
// difference between the proof's iat and the server clock. Asymmetric
// per RFC 9449 §11.1 guidance: a generous past-window is fine because
// the replay cache (TTL >= 2 * IATPastSkew) prevents reuse, but the
// future-window must be tight so a captured proof can't be replayed
// past its intended lifetime by an attacker who only needs to wait
// for the server clock to catch up.
//
// Concretely: DefaultIATPastSkew=30s tolerates clients whose clock is
// up to 30s behind the server (common with NTP drift); DefaultIATFutureSkew=5s
// tolerates only mild future-clock drift since a future-iat proof
// extends its replay window unfairly.
const (
	DefaultIATPastSkew   = 30 * time.Second
	DefaultIATFutureSkew = 5 * time.Second
)

// DefaultIATSkew is kept as an alias for the past-skew value because
// the replay-cache TTL math (2 * IATSkew) was originally derived from
// this single constant. New code should use the asymmetric values.
const DefaultIATSkew = DefaultIATPastSkew

// Common verification errors. All are written to be safe to render in API
// responses without leaking implementation detail.
var (
	ErrMissingProof   = errors.New("dpop: missing proof")
	ErrMalformedProof = errors.New("dpop: malformed proof")
	ErrUnsupportedAlg = errors.New("dpop: unsupported alg")
	ErrInvalidSig     = errors.New("dpop: invalid signature")
	ErrIATOutOfWindow = errors.New("dpop: iat outside acceptable window")
	ErrMethodMismatch = errors.New("dpop: htm does not match request method")
	ErrURIMismatch    = errors.New("dpop: htu does not match request uri")
	ErrReplayed       = errors.New("dpop: jti replayed")
	ErrJKTMismatch    = errors.New("dpop: jkt does not match bound key")
	ErrInvalidJWK     = errors.New("dpop: invalid jwk in header")
	ErrMissingJTI     = errors.New("dpop: missing jti")
)

// Proof is the verified result of a DPoP proof JWT.
type Proof struct {
	JKT string    // RFC 7638 JWK SHA-256 thumbprint, base64url-no-pad
	JTI string    // unique identifier (replay-cache key together with JKT)
	HTM string    // HTTP method asserted by the proof
	HTU string    // HTTP target URI asserted by the proof
	IAT time.Time // issued-at, parsed
}

// ReplayCache tracks (jkt, jti) pairs that have already been accepted, so the
// same proof cannot be replayed within its validity window. Implementations
// must be safe for concurrent use.
//
// The shape matches *repo.Repo's RecordDPopProofIfNew so callers can pass
// their existing repo directly, without needing an adapter.
type ReplayCache interface {
	// RecordDPopProofIfNew returns true if (jkt, jti) is novel (and records it
	// with the given expiry); false if it has already been seen.
	RecordDPopProofIfNew(ctx context.Context, jkt, jti string, expiresAt time.Time) (bool, error)
}

// Verifier verifies DPoP proofs and tracks seen jtis to prevent replay. It is
// safe for concurrent use as long as the underlying ReplayCache is.
//
// IATSkew is preserved for backward compatibility but is now interpreted as
// the past-skew value. Callers that want to override should set both
// IATPastSkew and IATFutureSkew explicitly.
type Verifier struct {
	IATSkew       time.Duration // deprecated: alias for IATPastSkew
	IATPastSkew   time.Duration
	IATFutureSkew time.Duration
	Replay        ReplayCache
	Now           func() time.Time // override for tests; defaults to time.Now
}

// NewVerifier returns a verifier configured with the default asymmetric
// iat skew (30s past, 5s future) and the supplied replay cache.
func NewVerifier(rc ReplayCache) *Verifier {
	return &Verifier{
		IATSkew:       DefaultIATPastSkew,
		IATPastSkew:   DefaultIATPastSkew,
		IATFutureSkew: DefaultIATFutureSkew,
		Replay:        rc,
		Now:           time.Now,
	}
}

// dpopClaims is the parsed payload of a DPoP proof. We deliberately ignore
// access-token-binding claims (ath) because phase 1 doesn't bind access
// tokens. exp/nbf are not part of RFC 9449's required set; iat + iat-skew is
// the time window.
type dpopClaims struct {
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	JTI string `json:"jti"`
	IAT int64  `json:"iat"`
}

func (c dpopClaims) GetExpirationTime() (*jwt.NumericDate, error) { return nil, nil }
func (c dpopClaims) GetNotBefore() (*jwt.NumericDate, error)      { return nil, nil }
func (c dpopClaims) GetIssuer() (string, error)                   { return "", nil }
func (c dpopClaims) GetSubject() (string, error)                  { return "", nil }
func (c dpopClaims) GetAudience() (jwt.ClaimStrings, error)       { return nil, nil }
func (c dpopClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.IAT, 0)), nil
}

// Verify parses the proof JWT, validates its signature against the embedded
// JWK, checks htm/htu/iat/jti, and records the jti in the replay cache. On
// success returns the parsed Proof (including the jkt thumbprint).
//
// reqMethod is the actual HTTP method of the request the proof is attached to
// (e.g. "POST"). reqURL is the HTTP target URI scheme://host/path; query and
// fragment are ignored per RFC 9449 §4.3.
func (v *Verifier) Verify(ctx context.Context, proofJWT, reqMethod, reqURL string) (*Proof, error) {
	if strings.TrimSpace(proofJWT) == "" {
		return nil, ErrMissingProof
	}

	parser := jwt.NewParser(jwt.WithValidMethods([]string{"ES256"}))

	var claims dpopClaims
	tok, err := parser.ParseWithClaims(proofJWT, &claims, func(t *jwt.Token) (any, error) {
		if typ, _ := t.Header["typ"].(string); typ != "dpop+jwt" {
			return nil, ErrMalformedProof
		}
		jwkRaw, ok := t.Header["jwk"]
		if !ok {
			return nil, ErrInvalidJWK
		}
		jwkBytes, err := json.Marshal(jwkRaw)
		if err != nil {
			return nil, ErrInvalidJWK
		}
		return parseECP256JWK(jwkBytes)
	})
	if err != nil {
		if errors.Is(err, ErrInvalidJWK) || errors.Is(err, ErrMalformedProof) {
			return nil, err
		}
		if strings.Contains(err.Error(), "signing method") {
			return nil, ErrUnsupportedAlg
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidSig, err)
	}
	if !tok.Valid {
		return nil, ErrInvalidSig
	}

	if claims.JTI == "" {
		return nil, ErrMissingJTI
	}
	if !strings.EqualFold(claims.HTM, reqMethod) {
		return nil, ErrMethodMismatch
	}
	if !sameURI(claims.HTU, reqURL) {
		return nil, ErrURIMismatch
	}

	iat := time.Unix(claims.IAT, 0)
	now := v.Now()
	// Asymmetric skew: a generous past-window is fine because the
	// replay cache prevents reuse, but a future-iat proof would extend
	// its replay window unfairly so we keep that bound tight.
	pastSkew := v.IATPastSkew
	if pastSkew == 0 {
		pastSkew = v.IATSkew
	}
	futureSkew := v.IATFutureSkew
	if futureSkew == 0 {
		// Default to the historical symmetric behaviour if a verifier
		// was constructed by hand without setting the future bound.
		futureSkew = v.IATSkew
	}
	if now.Sub(iat) > pastSkew || iat.Sub(now) > futureSkew {
		return nil, ErrIATOutOfWindow
	}

	jwkBytes, err := json.Marshal(tok.Header["jwk"])
	if err != nil {
		return nil, ErrInvalidJWK
	}
	jkt, err := jktFromECP256JWK(jwkBytes)
	if err != nil {
		return nil, err
	}

	// Replay-cache TTL covers the full iat acceptance window so a captured
	// proof can't be replayed just outside the cache while still inside
	// the iat window.
	cacheTTL := pastSkew + futureSkew
	novel, err := v.Replay.RecordDPopProofIfNew(ctx, jkt, claims.JTI, now.Add(cacheTTL))
	if err != nil {
		return nil, err
	}
	if !novel {
		return nil, ErrReplayed
	}

	return &Proof{
		JKT: jkt,
		JTI: claims.JTI,
		HTM: claims.HTM,
		HTU: claims.HTU,
		IAT: iat,
	}, nil
}

// VerifyBound is Verify plus an equality check between the proof's jkt and
// the thumbprint stored alongside the resource being accessed (e.g. a refresh
// token's dpop_jkt). expectedJKT must be non-empty; for first issuance use
// Verify.
func (v *Verifier) VerifyBound(ctx context.Context, proofJWT, reqMethod, reqURL, expectedJKT string) (*Proof, error) {
	if expectedJKT == "" {
		return nil, errors.New("dpop: VerifyBound called with empty expected jkt")
	}
	p, err := v.Verify(ctx, proofJWT, reqMethod, reqURL)
	if err != nil {
		return nil, err
	}
	if p.JKT != expectedJKT {
		return nil, ErrJKTMismatch
	}
	return p, nil
}

// jwkEC is the minimal EC JWK we accept (P-256 only).
type jwkEC struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func parseECP256JWK(raw []byte) (*ecdsa.PublicKey, error) {
	var k jwkEC
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, ErrInvalidJWK
	}
	if k.Kty != "EC" || k.Crv != "P-256" || k.X == "" || k.Y == "" {
		return nil, ErrInvalidJWK
	}
	xb, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, ErrInvalidJWK
	}
	yb, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, ErrInvalidJWK
	}

	// Validate the point lies on P-256 by routing through crypto/ecdh's
	// NewPublicKey, which performs the on-curve check (the ecdsa package's
	// equivalent IsOnCurve is deprecated). NewPublicKey expects a SEC1
	// uncompressed point: 0x04 || X(32) || Y(32). Coordinates may decode to
	// fewer than 32 bytes if the leading zero bytes were stripped during
	// encoding, so left-pad before assembling.
	const coordLen = 32
	if len(xb) > coordLen || len(yb) > coordLen {
		return nil, ErrInvalidJWK
	}
	uncompressed := make([]byte, 1+2*coordLen)
	uncompressed[0] = 0x04
	copy(uncompressed[1+coordLen-len(xb):1+coordLen], xb)
	copy(uncompressed[1+2*coordLen-len(yb):], yb)
	if _, err := ecdh.P256().NewPublicKey(uncompressed); err != nil {
		return nil, ErrInvalidJWK
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}, nil
}

// jktFromECP256JWK computes the RFC 7638 SHA-256 thumbprint of an EC P-256
// JWK. The canonical form is the keys {crv, kty, x, y} in lexicographic order
// with no whitespace.
func jktFromECP256JWK(raw []byte) (string, error) {
	var k jwkEC
	if err := json.Unmarshal(raw, &k); err != nil {
		return "", ErrInvalidJWK
	}
	if k.Kty != "EC" || k.Crv != "P-256" || k.X == "" || k.Y == "" {
		return "", ErrInvalidJWK
	}
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, k.Crv, k.Kty, k.X, k.Y)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// sameURI compares two URIs for DPoP htu purposes: scheme + host + path,
// ignoring query, fragment, and trailing slash. Scheme and host are matched
// case-insensitively; path is matched literally.
func sameURI(a, b string) bool {
	pa, err := url.Parse(a)
	if err != nil {
		return false
	}
	pb, err := url.Parse(b)
	if err != nil {
		return false
	}
	if !strings.EqualFold(pa.Scheme, pb.Scheme) {
		return false
	}
	if !strings.EqualFold(pa.Host, pb.Host) {
		return false
	}
	return strings.TrimRight(pa.Path, "/") == strings.TrimRight(pb.Path, "/")
}
