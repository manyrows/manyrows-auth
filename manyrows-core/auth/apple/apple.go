// Package apple implements Sign in with Apple, per
// https://developer.apple.com/documentation/sign_in_with_apple.
//
// Unlike Google, Apple does not provide a hosted tokeninfo endpoint. The ID
// token is verified locally against Apple's JWKS, and the OAuth "client
// secret" is itself a short-lived ES256 JWT signed with the customer's .p8
// private key. The Services ID acts as the OAuth client_id.
package apple

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	issuer       = "https://appleid.apple.com"
	tokenURL     = "https://appleid.apple.com/auth/token"
	authorizeURL = "https://appleid.apple.com/auth/authorize"
	jwksURL      = "https://appleid.apple.com/auth/keys"

	// maxResponseBytes caps every Apple response we decode (a few KB in
	// practice) so a hostile or buggy endpoint can't stream an unbounded body.
	maxResponseBytes = 1 << 20
)

var (
	ErrInvalidToken     = errors.New("invalid apple id token")
	ErrEmailNotVerified = errors.New("apple email not verified")
	ErrCodeExchange     = errors.New("apple auth code exchange failed")
	ErrInvalidKey       = errors.New("invalid apple private key")
)

// TokenInfo is the verified subset of the Apple ID token.
type TokenInfo struct {
	Sub            string // stable Apple user ID; primary key, not email
	Email          string // may be a private relay address
	EmailVerified  bool
	IsPrivateEmail bool
	Aud            string
}

// BuildAuthorizeURL constructs the Apple authorization URL. Apple requires
// response_mode=form_post when name/email scopes are requested, so the
// callback handler must accept POST application/x-www-form-urlencoded.
func BuildAuthorizeURL(servicesID, redirectURI, state string) string {
	v := url.Values{}
	v.Set("client_id", servicesID)
	v.Set("redirect_uri", redirectURI)
	v.Set("response_type", "code")
	v.Set("scope", "name email")
	v.Set("response_mode", "form_post")
	v.Set("state", state)
	return authorizeURL + "?" + v.Encode()
}

// GenerateClientSecret mints the ES256 JWT that Apple expects in place of a
// static client_secret at the token endpoint. Apple caps lifetime at 6
// months; we use a short TTL since this is regenerated per request.
func GenerateClientSecret(teamID, servicesID, keyID string, privateKeyPEM []byte, ttl time.Duration) (string, error) {
	if teamID == "" || servicesID == "" || keyID == "" {
		return "", ErrInvalidKey
	}

	key, err := parseECPrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": teamID,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		"aud": issuer,
		"sub": servicesID,
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = keyID

	signed, err := tok.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("apple client secret sign: %w", err)
	}
	return signed, nil
}

// ValidatePrivateKey returns nil if the bytes parse as a PKCS8 EC private key.
// Used by the admin handler to reject bad uploads up-front.
func ValidatePrivateKey(privateKeyPEM []byte) error {
	_, err := parseECPrivateKey(privateKeyPEM)
	return err
}

func parseECPrivateKey(privateKeyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, ErrInvalidKey
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	ec, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return ec, nil
}

type tokenExchangeResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// ExchangeAuthCode exchanges an authorization code for tokens, then verifies
// the returned ID token. clientSecret must be a JWT minted by
// GenerateClientSecret.
func ExchangeAuthCode(ctx context.Context, code, servicesID, clientSecret, redirectURI string) (*TokenInfo, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, ErrCodeExchange
	}

	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", servicesID)
	form.Set("client_secret", clientSecret)
	form.Set("redirect_uri", redirectURI)
	form.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("apple token exchange: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("apple token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	var tokResp tokenExchangeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&tokResp); err != nil {
		return nil, fmt.Errorf("apple token exchange decode: %w", err)
	}

	if tokResp.Error != "" {
		return nil, fmt.Errorf("%w: %s", ErrCodeExchange, tokResp.ErrorDesc)
	}
	if tokResp.IDToken == "" {
		return nil, ErrCodeExchange
	}

	return VerifyIDToken(ctx, tokResp.IDToken, servicesID)
}

// flexBool decodes a value that Apple sometimes returns as bool and
// sometimes as a string ("true"/"false"). Apple's docs say string; field
// telemetry shows bool in some responses. Tolerate both.
type flexBool bool

func (f *flexBool) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	switch s {
	case "true", `"true"`:
		*f = true
	case "false", `"false"`, "null", "", `""`:
		*f = false
	default:
		return fmt.Errorf("apple flexBool: %q", s)
	}
	return nil
}

type idTokenClaims struct {
	Iss            string   `json:"iss"`
	Sub            string   `json:"sub"`
	Aud            string   `json:"aud"`
	Email          string   `json:"email"`
	EmailVerified  flexBool `json:"email_verified"`
	IsPrivateEmail flexBool `json:"is_private_email"`
	Exp            int64    `json:"exp"`
	Iat            int64    `json:"iat"`
}

func (c idTokenClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.Exp == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.Exp, 0)), nil
}
func (c idTokenClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	if c.Iat == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.Iat, 0)), nil
}
func (c idTokenClaims) GetNotBefore() (*jwt.NumericDate, error) { return nil, nil }
func (c idTokenClaims) GetIssuer() (string, error)              { return c.Iss, nil }
func (c idTokenClaims) GetSubject() (string, error)             { return c.Sub, nil }
func (c idTokenClaims) GetAudience() (jwt.ClaimStrings, error)  { return jwt.ClaimStrings{c.Aud}, nil }

// VerifyIDToken parses an Apple ID token, verifies its RS256 signature
// against Apple's JWKS, and validates the standard claims (iss, aud, exp).
func VerifyIDToken(ctx context.Context, idToken, expectedAud string) (*TokenInfo, error) {
	idToken = strings.TrimSpace(idToken)
	if idToken == "" {
		return nil, ErrInvalidToken
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(expectedAud),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(60*time.Second),
	)

	var claims idTokenClaims
	_, err := parser.ParseWithClaims(idToken, &claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, ErrInvalidToken
		}
		return getApplePublicKey(ctx, kid)
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if claims.Sub == "" {
		return nil, ErrInvalidToken
	}

	return &TokenInfo{
		Sub:            claims.Sub,
		Email:          strings.ToLower(strings.TrimSpace(claims.Email)),
		EmailVerified:  bool(claims.EmailVerified),
		IsPrivateEmail: bool(claims.IsPrivateEmail),
		Aud:            claims.Aud,
	}, nil
}

// JWKS cache. Apple rotates rarely; refetch on miss and at most once per
// hour. The cache is process-local — a small per-dyno cost on cold start is
// fine and avoids the operational baggage of pushing this into Postgres.
var jwks = struct {
	sync.Mutex
	keys      map[string]any
	lastFetch time.Time
}{keys: map[string]any{}}

const jwksTTL = time.Hour

func getApplePublicKey(ctx context.Context, kid string) (any, error) {
	jwks.Lock()
	if k, ok := jwks.keys[kid]; ok && time.Since(jwks.lastFetch) < jwksTTL {
		jwks.Unlock()
		return k, nil
	}
	jwks.Unlock()

	if err := refreshJWKS(ctx); err != nil {
		return nil, err
	}

	jwks.Lock()
	defer jwks.Unlock()
	k, ok := jwks.keys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: unknown kid %q", ErrInvalidToken, kid)
	}
	return k, nil
}

func refreshJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("apple jwks: status %d", resp.StatusCode)
	}

	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&doc); err != nil {
		return err
	}

	parsed := map[string]any{}
	for _, raw := range doc.Keys {
		var jwk struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		}
		if err := json.Unmarshal(raw, &jwk); err != nil || jwk.Kid == "" || jwk.Kty != "RSA" {
			continue
		}
		key, err := rsaKeyFromJWK(jwk.N, jwk.E)
		if err != nil {
			continue
		}
		parsed[jwk.Kid] = key
	}
	if len(parsed) == 0 {
		return errors.New("apple jwks: no usable keys")
	}

	jwks.Lock()
	jwks.keys = parsed
	jwks.lastFetch = time.Now().UTC()
	jwks.Unlock()
	return nil
}

// rsaKeyFromJWK reconstructs an *rsa.PublicKey from the base64url-encoded
// modulus and exponent of an RSA JWK (RFC 7518 §6.3).
func rsaKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, errors.New("rsa exponent too large")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}
