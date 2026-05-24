// Package microsoft implements Sign in with Microsoft (Entra ID), per
// https://learn.microsoft.com/azure/active-directory/develop/v2-oauth2-auth-code-flow.
//
// Tenant scope is configured per-app and threaded into both the
// authorize URL and the token-exchange URL. The four allowed values
// are 'common', 'organizations', 'consumers', or a specific tenant
// UUID. Unlike Google's tokeninfo endpoint, Microsoft requires
// local ID-token verification against its JWKS.
package microsoft

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

const (
	authorizeBase = "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize"
	tokenBase     = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	// JWKS keys are the same across all tenants — Microsoft signs all
	// id_tokens with the same key set — so we use the 'common' segment
	// regardless of which tenant the app is configured for.
	jwksURL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
	// maxResponseBytes caps every Microsoft response we decode so a hostile
	// or buggy endpoint can't stream an unbounded body.
	maxResponseBytes = 1 << 20
	// Special tenant ID for personal Microsoft accounts (Outlook,
	// Live, etc.). Used for the 'consumers' / 'organizations' rules.
	consumersTenantID = "9188040d-6c67-4c5b-b112-36a304b66dad"

	TenantCommon        = "common"
	TenantOrganizations = "organizations"
	TenantConsumers     = "consumers"
)

var (
	ErrInvalidToken      = errors.New("invalid microsoft id token")
	ErrCodeExchange      = errors.New("microsoft auth code exchange failed")
	ErrTenantMismatch    = errors.New("microsoft id token tenant not allowed")
	ErrInvalidTenantConf = errors.New("invalid microsoft tenant config")
	// ErrEmailNotVerified fires when a multi-tenant app receives a
	// token without the xms_edov claim (Email Domain Owner Verified).
	// Without it the email claim is not authoritative — anyone with
	// any Entra tenant could mint a token claiming any email, leading
	// to the "nOAuth" account-takeover pattern. Single-tenant apps
	// trust their own tenant and skip this check.
	ErrEmailNotVerified = errors.New("microsoft email not verified — xms_edov claim required for multi-tenant apps")
)

// IsValidTenant returns true if the configured tenant value is one of
// the public segments or a UUID. Used by the API layer to reject bad
// admin input up-front.
func IsValidTenant(tenant string) bool {
	tenant = strings.TrimSpace(tenant)
	switch tenant {
	case TenantCommon, TenantOrganizations, TenantConsumers:
		return true
	}
	// Microsoft tenant IDs are UUIDs. Accept anything that parses as
	// a UUID — we won't verify it exists, just that it's well-formed.
	if _, err := parseUUID(tenant); err == nil {
		return true
	}
	return false
}

// parseUUID is a minimal RFC 4122 textual-form check (8-4-4-4-12 hex).
// Avoids pulling in a uuid lib for one validation.
func parseUUID(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 36 {
		return "", errors.New("uuid: bad length")
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return "", errors.New("uuid: missing hyphen")
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return "", errors.New("uuid: bad hex")
			}
		}
	}
	return s, nil
}

// TokenInfo is the verified subset of the Microsoft ID token.
type TokenInfo struct {
	Sub   string // stable per app+tenant identifier
	Oid   string // stable per-tenant user ID across apps
	Tid   string // tenant ID the user authenticated against
	Email string
	Aud   string
}

// BuildAuthorizeURL constructs the Microsoft authorization URL.
// response_mode=query so the callback gets `code` + `state` in query
// string and the popup HTML wrapper can read them server-side.
func BuildAuthorizeURL(tenant, clientID, redirectURI, state string) string {
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("response_type", "code")
	v.Set("response_mode", "query")
	v.Set("scope", "openid email profile")
	v.Set("state", state)
	return fmt.Sprintf(authorizeBase, url.PathEscape(tenant)) + "?" + v.Encode()
}

type tokenExchangeResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// ExchangeAuthCode exchanges an authorization code for tokens at the
// configured tenant's endpoint, then verifies the returned ID token.
func ExchangeAuthCode(ctx context.Context, code, tenant, clientID, clientSecret, redirectURI string) (*TokenInfo, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, ErrCodeExchange
	}

	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("redirect_uri", redirectURI)
	form.Set("grant_type", "authorization_code")
	form.Set("scope", "openid email profile")

	tokURL := fmt.Sprintf(tokenBase, url.PathEscape(tenant))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("microsoft token exchange: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("microsoft token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	var tokResp tokenExchangeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&tokResp); err != nil {
		return nil, fmt.Errorf("microsoft token exchange decode: %w", err)
	}

	if tokResp.Error != "" {
		return nil, fmt.Errorf("%w: %s", ErrCodeExchange, tokResp.ErrorDesc)
	}
	if tokResp.IDToken == "" {
		return nil, ErrCodeExchange
	}

	return VerifyIDToken(ctx, tokResp.IDToken, clientID, tenant)
}

type idTokenClaims struct {
	Iss     string          `json:"iss"`
	Sub     string          `json:"sub"`
	Aud     string          `json:"aud"`
	Tid     string          `json:"tid"`
	Oid     string          `json:"oid"`
	Email   string          `json:"email"`
	XmsEdov json.RawMessage `json:"xms_edov"` // Email Domain Owner Verified
	Exp     int64           `json:"exp"`
	Iat     int64           `json:"iat"`
	Nbf     int64           `json:"nbf"`
}

// emailDomainOwnerVerified returns true when xms_edov is set to a
// truthy value. Microsoft emits xms_edov as either bool or string
// "1"/"true" depending on the optional-claim configuration; tolerate
// both.
func emailDomainOwnerVerified(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	switch s {
	case "true", `"true"`, "1", `"1"`:
		return true
	}
	return false
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

// VerifyIDToken validates the signature, audience, expiration, and
// per-tenant issuer of an ID token. configuredTenant is the value
// stored on the app (one of common/organizations/consumers/UUID); the
// validation rules differ for each case (see allowedForTenant).
func VerifyIDToken(ctx context.Context, idToken, expectedAud, configuredTenant string) (*TokenInfo, error) {
	idToken = strings.TrimSpace(idToken)
	if idToken == "" {
		return nil, ErrInvalidToken
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithAudience(expectedAud),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(60*time.Second),
		// Issuer is per-tenant; we validate it manually below using the
		// `tid` claim instead of jwt.WithIssuer.
	)

	var claims idTokenClaims
	_, err := parser.ParseWithClaims(idToken, &claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, ErrInvalidToken
		}
		return getMicrosoftPublicKey(ctx, kid)
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Issuer must be exactly login.microsoftonline.com/{tid}/v2.0 with
	// the same tid claim (defends against issuer-claim spoofing).
	expectedIss := "https://login.microsoftonline.com/" + claims.Tid + "/v2.0"
	if claims.Iss != expectedIss {
		return nil, fmt.Errorf("%w: issuer mismatch", ErrInvalidToken)
	}

	if !allowedForTenant(claims.Tid, configuredTenant) {
		return nil, ErrTenantMismatch
	}

	if claims.Sub == "" {
		return nil, ErrInvalidToken
	}

	// nOAuth defense (https://learn.microsoft.com/entra/identity-platform/migrate-off-email-claim-authorization):
	// the `email` claim is mutable for multi-tenant apps — any user of
	// any Entra tenant could mint a token claiming any email. Microsoft
	// ships the `xms_edov` (Email Domain Owner Verified) claim
	// specifically so verifiers know the email's domain is controlled
	// by the user's tenant. We require it for common/organizations/
	// consumers; a customer who configures a specific tenant UUID is
	// trusting that one tenant directly and the check is skipped.
	//
	// `preferred_username` is deliberately not consulted — it's
	// user-mutable with no specified format and would re-open the
	// hole even if `email` were absent.
	emailOut := strings.ToLower(strings.TrimSpace(claims.Email))
	if isMultiTenantConfig(configuredTenant) {
		if !emailDomainOwnerVerified(claims.XmsEdov) {
			return nil, ErrEmailNotVerified
		}
	}

	return &TokenInfo{
		Sub:   claims.Sub,
		Oid:   claims.Oid,
		Tid:   claims.Tid,
		Email: emailOut,
		Aud:   claims.Aud,
	}, nil
}

// isMultiTenantConfig returns true when the configured tenant scope
// admits more than one tenant — meaning the customer hasn't pinned
// to a tenant they trust directly, so token email claims need
// independent verification (xms_edov).
func isMultiTenantConfig(configured string) bool {
	switch configured {
	case TenantCommon, TenantOrganizations, TenantConsumers:
		return true
	}
	return false
}

// allowedForTenant applies the tenant-scope rule the admin chose to
// the tenant the user actually authenticated against (claims.tid).
func allowedForTenant(tokenTid, configured string) bool {
	switch configured {
	case TenantCommon:
		return true
	case TenantOrganizations:
		return tokenTid != consumersTenantID
	case TenantConsumers:
		return tokenTid == consumersTenantID
	default:
		// Specific tenant UUID — must match exactly.
		return strings.EqualFold(tokenTid, configured)
	}
}

// JWKS cache. Microsoft rotates rarely (~weeks); refetch on miss and
// at most once per hour. Process-local to avoid the operational
// baggage of pushing this into Postgres.
var jwks = struct {
	sync.Mutex
	keys      map[string]any
	lastFetch time.Time
}{keys: map[string]any{}}

const jwksTTL = time.Hour

func getMicrosoftPublicKey(ctx context.Context, kid string) (any, error) {
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
		return fmt.Errorf("microsoft jwks: status %d", resp.StatusCode)
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
		return errors.New("microsoft jwks: no usable keys")
	}

	jwks.Lock()
	jwks.keys = parsed
	jwks.lastFetch = time.Now().UTC()
	jwks.Unlock()
	return nil
}

// rsaKeyFromJWK reconstructs an *rsa.PublicKey from the base64url-
// encoded modulus and exponent of an RSA JWK (RFC 7518 §6.3).
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
