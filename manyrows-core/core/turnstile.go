package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const turnstileSiteverifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// TurnstileResult mirrors Cloudflare's siteverify response body.
// See https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
type TurnstileResult struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
	Action      string   `json:"action"`
	CData       string   `json:"cdata"`
}

// ErrTurnstileMissingInput signals a token or secret was empty before we even
// called Cloudflare — treat as a validation failure, not a network failure.
var ErrTurnstileMissingInput = errors.New("turnstile: missing secret or token")

var turnstileHTTPClient = &http.Client{Timeout: 5 * time.Second}

// IsTurnstileTestSecret reports whether the given secret is one of
// Cloudflare's documented always-pass test secret keys. These are intended
// for non-production environments and are bypassed locally — we do not call
// siteverify when the configured secret matches.
//
// See: https://developers.cloudflare.com/turnstile/troubleshooting/testing/
//
//	1x0000000000000000000000000000000AA — always passes
//	3x0000000000000000000000000000000AA — always passes (challenge)
func IsTurnstileTestSecret(secret string) bool {
	return strings.HasPrefix(secret, "1x0000") || strings.HasPrefix(secret, "3x0000")
}

// VerifyTurnstileToken POSTs the token to Cloudflare's siteverify endpoint and
// returns the parsed result. Callers should fail closed on non-nil error (treat
// as "not verified") — don't let a network hiccup become an auth bypass.
//
// remoteIP is optional but recommended: Cloudflare uses it for better scoring.
//
// As a special case, Cloudflare's published always-pass test secret keys
// (`1x...AA` and `3x...AA`) are short-circuited locally — we don't call
// siteverify at all. This keeps the test suite from hitting the network and
// stops a Cloudflare outage from breaking unrelated tests. Production secrets
// must never look like a test key (and shouldn't, since they're issued by
// Cloudflare's dashboard with different prefixes).
func VerifyTurnstileToken(ctx context.Context, secret, token, remoteIP string) (*TurnstileResult, error) {
	if secret == "" {
		return nil, ErrTurnstileMissingInput
	}
	if IsTurnstileTestSecret(secret) {
		return &TurnstileResult{
			Success:     true,
			ChallengeTS: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}
	if token == "" {
		return nil, ErrTurnstileMissingInput
	}

	form := url.Values{}
	form.Set("secret", secret)
	form.Set("response", token)
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, turnstileSiteverifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := turnstileHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result TurnstileResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
