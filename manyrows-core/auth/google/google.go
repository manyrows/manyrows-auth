package google

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

// maxResponseBytes caps every Google response we decode so a hostile or
// buggy endpoint can't stream an unbounded body.
const maxResponseBytes = 1 << 20

var (
	ErrInvalidToken     = errors.New("invalid google id token")
	ErrEmailNotVerified = errors.New("google email not verified")
	ErrCodeExchange     = errors.New("google auth code exchange failed")
)

type TokenInfo struct {
	Email         string
	EmailVerified bool
	Name          string
	Sub           string // Google user ID
	Aud           string // Must match our client ID
}

// tokenInfoResponse is the raw JSON response from Google's tokeninfo API.
type tokenInfoResponse struct {
	Iss           string `json:"iss"`
	Sub           string `json:"sub"`
	Aud           string `json:"aud"`
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"` // "true" or "false" as string
	Name          string `json:"name"`
	AtHash        string `json:"at_hash"`
	Exp           string `json:"exp"`
	Error         string `json:"error_description"`
}

// VerifyIDToken verifies a Google ID token by calling Google's tokeninfo endpoint.
// The endpoint handles JWT signature verification and returns the decoded claims.
func VerifyIDToken(ctx context.Context, idToken string) (*TokenInfo, error) {
	idToken = strings.TrimSpace(idToken)
	if idToken == "" {
		return nil, ErrInvalidToken
	}

	reqURL := "https://oauth2.googleapis.com/tokeninfo?id_token=" + url.QueryEscape(idToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("google tokeninfo: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google tokeninfo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrInvalidToken
	}

	var info tokenInfoResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&info); err != nil {
		return nil, fmt.Errorf("google tokeninfo decode: %w", err)
	}

	if info.Error != "" {
		return nil, ErrInvalidToken
	}

	if info.Email == "" || info.Sub == "" {
		return nil, ErrInvalidToken
	}

	return &TokenInfo{
		Email:         strings.ToLower(strings.TrimSpace(info.Email)),
		EmailVerified: info.EmailVerified == "true",
		Name:          strings.TrimSpace(info.Name),
		Sub:           info.Sub,
		Aud:           info.Aud,
	}, nil
}

// BuildAuthorizeURL constructs the Google OAuth 2.0 authorization URL
// for the Authorization Code Flow.
func BuildAuthorizeURL(clientID, redirectURI, state string) string {
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("response_type", "code")
	v.Set("scope", "openid email profile")
	v.Set("access_type", "online")
	v.Set("state", state)
	return "https://accounts.google.com/o/oauth2/v2/auth?" + v.Encode()
}

// tokenExchangeResponse is the JSON response from Google's token endpoint.
type tokenExchangeResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// ExchangeAuthCode exchanges an authorization code for tokens via Google's
// token endpoint, then verifies the returned ID token.
func ExchangeAuthCode(ctx context.Context, code, clientID, clientSecret, redirectURI string) (*TokenInfo, error) {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("google token exchange: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	var tokResp tokenExchangeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&tokResp); err != nil {
		return nil, fmt.Errorf("google token exchange decode: %w", err)
	}

	if tokResp.Error != "" {
		return nil, fmt.Errorf("%w: %s", ErrCodeExchange, tokResp.ErrorDesc)
	}

	if tokResp.IDToken == "" {
		return nil, ErrCodeExchange
	}

	return VerifyIDToken(ctx, tokResp.IDToken)
}
