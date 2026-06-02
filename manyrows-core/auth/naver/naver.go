// Package naver implements Sign in with Naver (nid.naver.com).
//
// Naver is OAuth 2.0 only — no OpenID Connect, no id_token, no JWKS. The token
// exchange returns a bare access_token; we then call the userinfo endpoint
// (openapi.naver.com/v1/nid/me), whose identity fields are nested under a
// top-level "response" object.
//
// Naver exposes no email-verification flag, so the account email (which Naver
// verifies at signup) is trusted as the identifier — the same optimistic
// stance as the Kakao provider. See the deferred-hardening note there; Naver
// has no userinfo flag to tighten to, so trusting the address is the only
// option short of a separate verification step.
package naver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Naver endpoints. Vars (not const) so tests can point them at an httptest
// server; runtime never mutates them.
var (
	authorizeURL = "https://nid.naver.com/oauth2.0/authorize"
	tokenURL     = "https://nid.naver.com/oauth2.0/token"
	userinfoURL  = "https://openapi.naver.com/v1/nid/me"
)

const (
	httpTimeout      = 10 * time.Second
	maxResponseBytes = 1 << 20 // cap every Naver response we decode
)

var (
	ErrCodeExchange = errors.New("naver auth code exchange failed")
	ErrUserFetch    = errors.New("naver user fetch failed")
)

// TokenInfo is the verified subset returned to the workspace handler. Sub is
// Naver's stable per-app user id.
type TokenInfo struct {
	Sub   string
	Email string
	Name  string // user-set display name, may be empty
}

// BuildAuthorizeURL constructs the Naver authorization URL. Naver has no scope
// parameter — the consent items (email, name, …) are configured on the
// customer's Naver app. state is required (Naver echoes it for CSRF defence).
func BuildAuthorizeURL(clientID, redirectURI, state string) string {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("state", state)
	return authorizeURL + "?" + v.Encode()
}

type tokenExchangeResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// ExchangeAuthCode swaps an authorization code for an access token, then
// fetches the userinfo to assemble the TokenInfo. Naver wants the same `state`
// echoed on the token request, and (unlike the OAuth2 spec) does not take a
// redirect_uri here.
func ExchangeAuthCode(ctx context.Context, code, state, clientID, clientSecret string) (*TokenInfo, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, ErrCodeExchange
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code", code)
	form.Set("state", state)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("naver token exchange: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("naver token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	var tok tokenExchangeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&tok); err != nil {
		return nil, fmt.Errorf("naver token exchange decode: %w", err)
	}
	if tok.Error != "" {
		return nil, fmt.Errorf("%w: %s", ErrCodeExchange, strings.TrimSpace(tok.ErrorDesc))
	}
	if tok.AccessToken == "" {
		return nil, ErrCodeExchange
	}

	return fetchUserinfo(ctx, tok.AccessToken)
}

// userinfoResponse models Naver's /v1/nid/me reply. Naver nests the identity
// under "response" and signals success with resultcode "00".
type userinfoResponse struct {
	ResultCode string `json:"resultcode"`
	Message    string `json:"message"`
	Response   struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"response"`
}

// fetchUserinfo reads the identity from Naver's userinfo endpoint. The email
// may be absent if the user didn't consent to share it; the workspace handler
// turns that into the emailNotProvided outcome.
func fetchUserinfo(ctx context.Context, accessToken string) (*TokenInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUserFetch, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUserFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrUserFetch, resp.StatusCode)
	}

	var ui userinfoResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&ui); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrUserFetch, err)
	}
	// Naver returns resultcode "00" on success; anything else is an error
	// (expired token, revoked consent, etc.).
	if ui.ResultCode != "00" {
		return nil, fmt.Errorf("%w: resultcode %s (%s)", ErrUserFetch, ui.ResultCode, strings.TrimSpace(ui.Message))
	}
	id := strings.TrimSpace(ui.Response.ID)
	if id == "" {
		return nil, ErrUserFetch
	}

	return &TokenInfo{
		Sub:   id,
		Email: strings.ToLower(strings.TrimSpace(ui.Response.Email)),
		Name:  strings.TrimSpace(ui.Response.Name),
	}, nil
}
