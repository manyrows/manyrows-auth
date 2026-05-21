// Package oidc is the generic external identity-provider client: it
// signs ManyRows users in via someone else's IdP. It supports two
// modes, mirroring patterns ManyRows already has bespoke:
//
//	"oidc"   — discover endpoints from an issuer URL, verify a signed
//	           id_token against the provider's JWKS (like Google/MS/Apple).
//	"oauth2" — explicit endpoints, identity read from the userinfo
//	           endpoint over TLS, no id_token (like GitHub).
//
// The package takes primitive config (it does not import core) so it
// stays a low-level building block the api layer composes.
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	ModeOIDC   = "oidc"
	ModeOAuth2 = "oauth2"
)

var (
	ErrConfig       = errors.New("oidc: invalid provider config")
	ErrDiscovery    = errors.New("oidc: discovery failed")
	ErrCodeExchange = errors.New("oidc: code exchange failed")
	ErrInvalidToken = errors.New("oidc: invalid id token")
	ErrNoIdentity   = errors.New("oidc: provider returned no usable identity")
)

// httpClient is shared by discovery, JWKS, token-exchange, and userinfo
// calls. A 10s timeout matches the bespoke providers.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// signingMethods is the set we accept on an id_token. All RSA/PSS verify
// with *rsa.PublicKey and all ES verify with *ecdsa.PublicKey, both of
// which the JWKS loader produces.
var signingMethods = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
}

// ProviderConfig is one configured external IdP, in primitives. The api
// layer fills it from core.ExternalIDP.
type ProviderConfig struct {
	Mode string // ModeOIDC | ModeOAuth2

	IssuerURL    string // OIDC: discovery base. OAuth2: informational.
	AuthorizeURL string // OAuth2 (or OIDC manual override)
	TokenURL     string
	UserinfoURL  string
	JWKSURL      string

	ClientID     string
	ClientSecret string
	Scopes       string

	// Claim/field names. Empty falls back to the OIDC standard claim.
	SubjectField       string
	EmailField         string
	EmailVerifiedField string
	NameField          string
}

// TokenInfo is the verified identity extracted from a sign-in.
type TokenInfo struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

type claimFields struct{ subject, email, emailVerified, name string }

func (c ProviderConfig) claimFields() claimFields {
	f := claimFields{
		subject:       c.SubjectField,
		email:         c.EmailField,
		emailVerified: c.EmailVerifiedField,
		name:          c.NameField,
	}
	if f.subject == "" {
		f.subject = "sub"
	}
	if f.email == "" {
		f.email = "email"
	}
	if f.emailVerified == "" {
		f.emailVerified = "email_verified"
	}
	if f.name == "" {
		f.name = "name"
	}
	return f
}

func (c ProviderConfig) scopesOrDefault() string {
	if strings.TrimSpace(c.Scopes) == "" {
		return "openid email profile"
	}
	return c.Scopes
}

// resolveEndpoints returns the effective endpoints for a config: OIDC
// discovers from the issuer (with optional manual overrides); OAuth2
// uses the explicit values.
func resolveEndpoints(ctx context.Context, cfg ProviderConfig) (Endpoints, error) {
	if cfg.Mode == ModeOAuth2 {
		if cfg.AuthorizeURL == "" || cfg.TokenURL == "" {
			return Endpoints{}, fmt.Errorf("%w: oauth2 mode needs authorize+token URLs", ErrConfig)
		}
		return Endpoints{
			Issuer:    cfg.IssuerURL,
			Authorize: cfg.AuthorizeURL,
			Token:     cfg.TokenURL,
			Userinfo:  cfg.UserinfoURL,
			JWKS:      cfg.JWKSURL,
		}, nil
	}
	ep, err := Discover(ctx, cfg.IssuerURL)
	if err != nil {
		return Endpoints{}, err
	}
	// Manual overrides win over discovery (rare, but lets an operator
	// pin an endpoint when a provider's well-known doc is wrong).
	if cfg.AuthorizeURL != "" {
		ep.Authorize = cfg.AuthorizeURL
	}
	if cfg.TokenURL != "" {
		ep.Token = cfg.TokenURL
	}
	if cfg.UserinfoURL != "" {
		ep.Userinfo = cfg.UserinfoURL
	}
	if cfg.JWKSURL != "" {
		ep.JWKS = cfg.JWKSURL
	}
	return ep, nil
}

// AuthorizeURL resolves the provider's authorize endpoint and builds the
// redirect URL (with PKCE + nonce). codeChallenge/nonce may be "".
func AuthorizeURL(ctx context.Context, cfg ProviderConfig, redirectURI, state, codeChallenge, nonce string) (string, error) {
	ep, err := resolveEndpoints(ctx, cfg)
	if err != nil {
		return "", err
	}
	return BuildAuthorizeURL(ep.Authorize, cfg.ClientID, redirectURI, state, cfg.scopesOrDefault(), codeChallenge, nonce), nil
}

// Authenticate runs the callback half: resolve endpoints, exchange the
// code, then derive identity. OIDC verifies the id_token (falling back
// to userinfo only when email is absent); OAuth2 reads identity from
// userinfo directly.
func Authenticate(ctx context.Context, cfg ProviderConfig, code, redirectURI, codeVerifier, expectedNonce string) (*TokenInfo, error) {
	ep, err := resolveEndpoints(ctx, cfg)
	if err != nil {
		return nil, err
	}
	tok, err := ExchangeCode(ctx, ep.Token, cfg.ClientID, cfg.ClientSecret, code, redirectURI, codeVerifier)
	if err != nil {
		return nil, err
	}
	fields := cfg.claimFields()

	if cfg.Mode == ModeOAuth2 {
		if ep.Userinfo == "" || tok.AccessToken == "" {
			return nil, fmt.Errorf("%w: oauth2 mode needs userinfo + access token", ErrConfig)
		}
		return FetchUserinfo(ctx, ep.Userinfo, tok.AccessToken, fields)
	}

	// OIDC: the id_token is the authoritative identity.
	if tok.IDToken == "" {
		return nil, fmt.Errorf("%w: no id_token in response", ErrCodeExchange)
	}
	info, err := VerifyIDToken(ctx, tok.IDToken, ep.Issuer, ep.JWKS, cfg.ClientID, expectedNonce, fields)
	if err != nil {
		return nil, err
	}
	// Some providers omit email from the id_token; pull it from userinfo
	// without disturbing the id_token's authoritative subject.
	if info.Email == "" && ep.Userinfo != "" && tok.AccessToken != "" {
		if ui, uiErr := FetchUserinfo(ctx, ep.Userinfo, tok.AccessToken, fields); uiErr == nil {
			info.Email = ui.Email
			info.EmailVerified = ui.EmailVerified
			if info.Name == "" {
				info.Name = ui.Name
			}
		}
	}
	return info, nil
}

// BuildAuthorizeURL assembles the authorization-code redirect. PKCE
// (S256) and nonce are included when non-empty.
func BuildAuthorizeURL(authorizeEndpoint, clientID, redirectURI, state, scopes, codeChallenge, nonce string) string {
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("response_type", "code")
	v.Set("scope", scopes)
	v.Set("state", state)
	if codeChallenge != "" {
		v.Set("code_challenge", codeChallenge)
		v.Set("code_challenge_method", "S256")
	}
	if nonce != "" {
		v.Set("nonce", nonce)
	}
	sep := "?"
	if strings.Contains(authorizeEndpoint, "?") {
		sep = "&"
	}
	return authorizeEndpoint + sep + v.Encode()
}

// TokenResponse is the subset of the token endpoint's reply we use.
type TokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// ExchangeCode swaps an authorization code for tokens. Client auth is
// the form-body client_secret_post method (the broadest-supported);
// codeVerifier is sent when PKCE was used.
func ExchangeCode(ctx context.Context, tokenEndpoint, clientID, clientSecret, code, redirectURI, codeVerifier string) (*TokenResponse, error) {
	if strings.TrimSpace(code) == "" {
		return nil, fmt.Errorf("%w: empty code", ErrCodeExchange)
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCodeExchange, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCodeExchange, err)
	}
	defer resp.Body.Close()

	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrCodeExchange, err)
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("%w: %s", ErrCodeExchange, strings.TrimSpace(tr.Error+" "+tr.ErrorDesc))
	}
	return &tr, nil
}

// VerifyIDToken validates signature (against the provider JWKS), issuer,
// audience (==clientID), expiry, and nonce, then maps the configured
// claim fields into a TokenInfo.
func VerifyIDToken(ctx context.Context, idToken, issuer, jwksURL, clientID, expectedNonce string, fields claimFields) (*TokenInfo, error) {
	if strings.TrimSpace(idToken) == "" {
		return nil, fmt.Errorf("%w: empty", ErrInvalidToken)
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods(signingMethods),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(clientID),
		jwt.WithExpirationRequired(),
	)
	claims := jwt.MapClaims{}
	_, err := parser.ParseWithClaims(idToken, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return getSigningKey(ctx, jwksURL, kid)
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Nonce binds the id_token to this specific authorize request
	// (replay protection). Required when we sent one.
	if expectedNonce != "" {
		if n, _ := claims["nonce"].(string); n != expectedNonce {
			return nil, fmt.Errorf("%w: nonce mismatch", ErrInvalidToken)
		}
	}

	sub := claimString(claims, fields.subject)
	if sub == "" {
		return nil, fmt.Errorf("%w: missing subject claim %q", ErrInvalidToken, fields.subject)
	}
	return &TokenInfo{
		Subject:       sub,
		Email:         strings.ToLower(strings.TrimSpace(claimString(claims, fields.email))),
		EmailVerified: claimBool(claims, fields.emailVerified),
		Name:          claimString(claims, fields.name),
	}, nil
}

// FetchUserinfo calls the userinfo endpoint with the access token and
// maps the configured fields. This is the OAuth2-mode identity source
// and the OIDC email fallback.
func FetchUserinfo(ctx context.Context, userinfoURL, accessToken string, fields claimFields) (*TokenInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo: status %d", resp.StatusCode)
	}
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("userinfo: decode: %w", err)
	}
	sub := claimString(m, fields.subject)
	email := strings.ToLower(strings.TrimSpace(claimString(m, fields.email)))
	if sub == "" && email == "" {
		return nil, ErrNoIdentity
	}
	return &TokenInfo{
		Subject:       sub,
		Email:         email,
		EmailVerified: claimBool(m, fields.emailVerified),
		Name:          claimString(m, fields.name),
	}, nil
}

// claimString reads a string-valued claim, tolerating absence.
func claimString(m map[string]any, key string) string {
	if key == "" {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// claimBool reads a boolean-ish claim. Providers emit email_verified as
// a real bool or as the strings "true"/"1"; tolerate both.
func claimBool(m map[string]any, key string) bool {
	if key == "" {
		return false
	}
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		return s == "true" || s == "1"
	default:
		return false
	}
}
