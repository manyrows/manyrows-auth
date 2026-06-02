// Package kakao implements Sign in with Kakao (kauth.kakao.com) via OpenID
// Connect.
//
// Kakao's token endpoint returns an id_token whose signature we verify locally
// against Kakao's JWKS — the same pattern as Microsoft/Apple, and unlike Google
// which exposes a tokeninfo endpoint. The id_token carries flat standard claims:
// iss (always https://kauth.kakao.com), aud (the app's REST API key, i.e. the
// OAuth client_id), sub, exp, and — with the account_email scope plus the user's
// consent — email.
//
// Email handling: Kakao's OIDC id_token has NO email_verified claim — its
// published claims_supported is iss/aud/sub/auth_time/exp/iat/nonce/nickname/
// picture/email — so the presence of an email in the token does NOT prove the
// user verified ownership. We therefore confirm every sign-in's email against
// the userinfo endpoint (kapi.kakao.com/v2/user/me), where the address and its
// verification flags live nested under kakao_account.*, and trust the address
// only when Kakao reports it both is_email_valid and is_email_verified. The
// id_token stays authoritative for the subject (sub); its email is kept only
// for audit/fallback when userinfo can't confirm a verified address.
package kakao

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
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

// Kakao endpoints. Vars (not const) so tests can point them at an httptest
// server; runtime never mutates them. issuer is also the exact value of the
// id_token `iss` claim we require.
var (
	issuer       = "https://kauth.kakao.com"
	authorizeURL = "https://kauth.kakao.com/oauth/authorize"
	tokenURL     = "https://kauth.kakao.com/oauth/token"
	jwksURL      = "https://kauth.kakao.com/.well-known/jwks.json"
	userinfoURL  = "https://kapi.kakao.com/v2/user/me"
)

// requestedScopes: `openid` enables OIDC so an id_token is issued;
// `account_email` is Kakao's email consent item. The customer registers these
// consent items on their own Kakao app and marks email consent required (see
// the admin UI's prerequisites note).
const requestedScopes = "openid account_email"

const (
	httpTimeout      = 10 * time.Second
	maxResponseBytes = 1 << 20 // cap every Kakao response we decode (a few KB in practice)
	jwksTTL          = time.Hour
)

var (
	ErrInvalidToken = errors.New("invalid kakao id token")
	ErrCodeExchange = errors.New("kakao auth code exchange failed")
	ErrUserinfo     = errors.New("kakao userinfo fetch failed")
)

// TokenInfo is the verified subset of a Kakao sign-in.
type TokenInfo struct {
	Sub           string // Kakao's stable per-app user id (stringified)
	Email         string
	EmailVerified bool
	Name          string // nickname; best-effort, empty without a profile scope
	Aud           string // the app's REST API key; enforced == configured client id in VerifyIDToken
}

// BuildAuthorizeURL constructs the Kakao authorization URL for the
// authorization-code flow. clientID is the app's REST API key.
func BuildAuthorizeURL(clientID, redirectURI, state string) string {
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("response_type", "code")
	v.Set("scope", requestedScopes)
	v.Set("state", state)
	return authorizeURL + "?" + v.Encode()
}

type tokenExchangeResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// ExchangeAuthCode swaps an authorization code for tokens at Kakao's token
// endpoint, verifies the returned id_token, and — when the id_token omits the
// email — falls back to the userinfo endpoint to recover it. clientSecret is
// sent only when configured (Kakao's client secret is an opt-in security
// feature on the customer's app).
func ExchangeAuthCode(ctx context.Context, code, clientID, clientSecret, redirectURI string) (*TokenInfo, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, ErrCodeExchange
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", redirectURI)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("kakao token exchange: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kakao token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	var tok tokenExchangeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&tok); err != nil {
		return nil, fmt.Errorf("kakao token exchange decode: %w", err)
	}
	if tok.Error != "" {
		return nil, fmt.Errorf("%w: %s", ErrCodeExchange, strings.TrimSpace(tok.ErrorDesc))
	}
	if tok.IDToken == "" {
		return nil, ErrCodeExchange
	}

	info, err := VerifyIDToken(ctx, tok.IDToken, clientID)
	if err != nil {
		return nil, err
	}

	// Kakao's id_token carries no email_verified claim, so a token email is NOT
	// proof of verification. Confirm the address + its verification flags against
	// userinfo (kakao_account.is_email_valid && is_email_verified), which is
	// authoritative for both — on every sign-in, not just when the id_token omits
	// the email. If userinfo can't confirm a verified address, EmailVerified
	// stays false and the caller rejects the login (fail closed) rather than
	// linking on an unverified address.
	if tok.AccessToken != "" {
		if email, verified, name, uiErr := fetchUserinfo(ctx, tok.AccessToken); uiErr == nil {
			if email != "" {
				info.Email = email
			}
			info.EmailVerified = verified
			if info.Name == "" {
				info.Name = name
			}
		}
	}
	return info, nil
}

// idTokenClaims is the subset of the Kakao id_token we read. It implements the
// jwt.Claims interface so the standard parser validates exp/nbf/iss/aud.
type idTokenClaims struct {
	Iss      string `json:"iss"`
	Sub      string `json:"sub"`
	Aud      string `json:"aud"`
	Email    string `json:"email"`
	Nickname string `json:"nickname"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
	Nbf      int64  `json:"nbf"`
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
func (c idTokenClaims) GetNotBefore() (*jwt.NumericDate, error) {
	if c.Nbf == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.Nbf, 0)), nil
}
func (c idTokenClaims) GetIssuer() (string, error)             { return c.Iss, nil }
func (c idTokenClaims) GetSubject() (string, error)            { return c.Sub, nil }
func (c idTokenClaims) GetAudience() (jwt.ClaimStrings, error) { return jwt.ClaimStrings{c.Aud}, nil }

// VerifyIDToken validates the signature (against Kakao's JWKS), issuer,
// audience (== the app's REST API key), and expiry of a Kakao id_token, then
// returns the identity. EmailVerified is always false here: the id_token carries
// no email_verified claim, so verification is established separately from
// userinfo (see ExchangeAuthCode). The returned Email is the token's address,
// kept for audit/fallback.
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
		// Tolerate small clock skew so a freshly minted token isn't spuriously
		// rejected at exp/nbf.
		jwt.WithLeeway(60*time.Second),
	)

	var claims idTokenClaims
	_, err := parser.ParseWithClaims(idToken, &claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, ErrInvalidToken
		}
		return getKakaoPublicKey(ctx, kid)
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if claims.Sub == "" {
		return nil, ErrInvalidToken
	}

	email := strings.ToLower(strings.TrimSpace(claims.Email))
	return &TokenInfo{
		Sub:           claims.Sub,
		Email:         email,
		EmailVerified: false, // id_token has no email_verified claim; confirmed via userinfo in ExchangeAuthCode
		Name:          strings.TrimSpace(claims.Nickname),
		Aud:           claims.Aud,
	}, nil
}

// userinfoResponse models the subset of kapi.kakao.com/v2/user/me we read.
// Identity nests under kakao_account; the verification flags are pointers so we
// can distinguish "absent" from "false".
type userinfoResponse struct {
	KakaoAccount struct {
		Email           string `json:"email"`
		IsEmailValid    *bool  `json:"is_email_valid"`
		IsEmailVerified *bool  `json:"is_email_verified"`
		Profile         struct {
			Nickname string `json:"nickname"`
		} `json:"profile"`
	} `json:"kakao_account"`
}

// fetchUserinfo reads the email + verification flags from Kakao's userinfo
// endpoint, used only when the id_token omitted the email. An address counts as
// verified only when Kakao reports it both valid and verified.
func fetchUserinfo(ctx context.Context, accessToken string) (email string, verified bool, name string, err error) {
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if reqErr != nil {
		return "", false, "", fmt.Errorf("%w: %v", ErrUserinfo, reqErr)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: httpTimeout}
	resp, doErr := client.Do(req)
	if doErr != nil {
		return "", false, "", fmt.Errorf("%w: %v", ErrUserinfo, doErr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false, "", fmt.Errorf("%w: status %d", ErrUserinfo, resp.StatusCode)
	}

	var ui userinfoResponse
	if decErr := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&ui); decErr != nil {
		return "", false, "", fmt.Errorf("%w: decode: %v", ErrUserinfo, decErr)
	}

	email = strings.ToLower(strings.TrimSpace(ui.KakaoAccount.Email))
	valid := ui.KakaoAccount.IsEmailValid != nil && *ui.KakaoAccount.IsEmailValid
	ver := ui.KakaoAccount.IsEmailVerified != nil && *ui.KakaoAccount.IsEmailVerified
	verified = email != "" && valid && ver
	return email, verified, strings.TrimSpace(ui.KakaoAccount.Profile.Nickname), nil
}

// JWKS cache. Kakao rotates rarely; refetch on miss and at most once per hour.
// Process-local to avoid the operational baggage of pushing this into Postgres
// (same approach as the Microsoft provider).
var jwks = struct {
	sync.Mutex
	keys      map[string]any
	lastFetch time.Time
}{keys: map[string]any{}}

func getKakaoPublicKey(ctx context.Context, kid string) (any, error) {
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
	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kakao jwks: status %d", resp.StatusCode)
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
		return errors.New("kakao jwks: no usable keys")
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
