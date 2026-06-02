// Package github implements Sign in with GitHub.
//
// GitHub uses plain OAuth 2.0 — no JWT id_token, no JWKS. The token
// exchange returns a bare access_token; we then call /user and
// /user/emails to learn who signed in. The /user/emails response
// includes a `verified` flag per address that GitHub sets only when
// the user has actually clicked a verification link, so it's safe
// to trust as the canonical email for the user.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// scope=read:user gets us the public user record (id, login, name).
// scope=user:email gets us /user/emails — the only place we can
// read a verified email when the user has hidden it from public
// view (very common; "Keep my email addresses private" is a
// default GitHub setting).
const requestedScopes = "read:user user:email"

// maxResponseBytes caps every GitHub response we decode so a hostile or
// buggy endpoint can't stream an unbounded body.
const maxResponseBytes = 1 << 20

// Endpoint URLs are vars (not const) so tests can swap them for an
// httptest.Server. Runtime never mutates these.
var (
	authorizeURL = "https://github.com/login/oauth/authorize"
	tokenURL     = "https://github.com/login/oauth/access_token"
	userURL      = "https://api.github.com/user"
	emailsURL    = "https://api.github.com/user/emails"
)

var (
	ErrCodeExchange    = errors.New("github auth code exchange failed")
	ErrUserFetch       = errors.New("github user fetch failed")
	ErrNoVerifiedEmail = errors.New("github account has no verified primary email")
)

// TokenInfo is the verified subset returned to the workspace handler.
// Sub is GitHub's stable numeric user ID, stringified.
type TokenInfo struct {
	Sub   string
	Email string
	Login string // username, useful for audit metadata
	Name  string // user-set display name, may be empty
}

// BuildAuthorizeURL constructs the GitHub authorization URL.
func BuildAuthorizeURL(clientID, redirectURI, state string) string {
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("scope", requestedScopes)
	v.Set("state", state)
	v.Set("allow_signup", "true")
	return authorizeURL + "?" + v.Encode()
}

type tokenExchangeResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type userResponse struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"` // may be empty if user hides public email
}

type emailEntry struct {
	Email      string `json:"email"`
	Primary    bool   `json:"primary"`
	Verified   bool   `json:"verified"`
	Visibility string `json:"visibility"`
}

// ExchangeAuthCode swaps an authorization code for an access token,
// then fetches user + emails to assemble the TokenInfo.
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("github token exchange: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	var tokResp tokenExchangeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&tokResp); err != nil {
		return nil, fmt.Errorf("github token exchange decode: %w", err)
	}
	if tokResp.Error != "" {
		return nil, fmt.Errorf("%w: %s", ErrCodeExchange, tokResp.ErrorDescription)
	}
	if tokResp.AccessToken == "" {
		return nil, ErrCodeExchange
	}

	user, err := fetchUser(ctx, tokResp.AccessToken)
	if err != nil {
		return nil, err
	}
	if user.ID == 0 {
		return nil, ErrUserFetch
	}

	email, err := fetchPrimaryVerifiedEmail(ctx, tokResp.AccessToken)
	if err != nil {
		return nil, err
	}

	return &TokenInfo{
		Sub:   strconv.FormatInt(user.ID, 10),
		Email: email,
		Login: user.Login,
		Name:  user.Name,
	}, nil
}

func fetchUser(ctx context.Context, accessToken string) (*userResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUserFetch, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUserFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrUserFetch, resp.StatusCode)
	}

	var u userResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&u); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrUserFetch, err)
	}
	return &u, nil
}

// fetchPrimaryVerifiedEmail returns the user's primary verified email
// from /user/emails. GitHub's `verified` flag is true only after the
// user clicked a verification link, so the primary verified email is
// the canonical identity for the account.
//
// We deliberately do NOT fall back to "first verified non-primary
// email" if the primary is unverified, even though that path used to
// work. /user/emails ordering is undocumented, so a fallback would
// produce non-deterministic identity selection — the same human could
// end up signed in as a different ManyRows user depending on whether
// they'd verified their current primary at the moment of sign-in.
// Better to fail with ErrNoVerifiedEmail and have the user verify
// their primary email on GitHub before retrying.
//
// Returns ErrNoVerifiedEmail if the user has no verified primary.
func fetchPrimaryVerifiedEmail(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, emailsURL, nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUserFetch, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUserFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: emails status %d", ErrUserFetch, resp.StatusCode)
	}

	var emails []emailEntry
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&emails); err != nil {
		return "", fmt.Errorf("%w: emails decode: %v", ErrUserFetch, err)
	}

	for _, e := range emails {
		addr := strings.ToLower(strings.TrimSpace(e.Email))
		if addr == "" {
			continue
		}
		if e.Primary && e.Verified {
			return addr, nil
		}
	}
	return "", ErrNoVerifiedEmail
}
