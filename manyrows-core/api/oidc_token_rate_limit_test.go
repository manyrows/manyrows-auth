package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The OIDC token endpoint is a public, unauthenticated surface that
// accepts client_secret + code/refresh_token grants. Without a rate
// limit those secrets and tokens are brute-forceable. These tests pin
// the per-IP attempt cap (maxAttemptsPerIP10Min = 30) on /oidc/token.
//
// All test requests share httptest's default RemoteAddr (192.0.2.1),
// which is not in the trusted-proxy "private" set, so auth.ClientIP
// falls back to it — every request counts against the same IP bucket.

// postOIDCToken posts a form-encoded request to the app's /oidc/token.
func postOIDCToken(t *testing.T, e *oidcTestEnv, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		"/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	return rr
}

// const mirrors api.maxAttemptsPerIP10Min (unexported); keep in sync.
const oidcTokenIPCap = 30

// TestOIDCToken_RateLimit_BadClientSecret verifies that repeated
// invalid client_secret attempts from one IP are throttled with a 429
// once the per-IP cap is reached (client_secret brute-force defence).
func TestOIDCToken_RateLimit_BadClientSecret(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	defer testEnv.ClearRateLimitAttempts(t)

	e := setupOIDCRouter(t)
	e.enableOIDC(t, []string{"https://customer.example/callback"}, nil, "correct-horse-battery-staple-secret")

	badForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {e.app.ID.String()},
		"client_secret": {"wrong-secret"},
		"code":          {"does-not-matter"},
	}

	// The full budget of failed attempts must each be rejected as
	// invalid_client (401), NOT rate-limited yet.
	for i := 0; i < oidcTokenIPCap; i++ {
		rr := postOIDCToken(t, e, badForm)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401 invalid_client, got %d (body=%s)", i+1, rr.Code, rr.Body.String())
		}
	}

	// The next attempt from the same IP must be rate-limited.
	rr := postOIDCToken(t, e, badForm)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d failed attempts, got %d (body=%s)", oidcTokenIPCap, rr.Code, rr.Body.String())
	}
	if ra := rr.Header().Get("Retry-After"); ra == "" {
		t.Errorf("expected Retry-After header on 429 response, got none")
	}
}

// TestOIDCToken_RateLimit_BadRefreshToken verifies that repeated
// invalid refresh_token grants from one IP (with valid client auth) are
// throttled with a 429 once the cap is reached (token brute-force
// defence). Uses a public client so client auth passes and the request
// reaches the refresh grant handler.
func TestOIDCToken_RateLimit_BadRefreshToken(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	defer testEnv.ClearRateLimitAttempts(t)

	e := setupOIDCRouter(t)
	e.enableOIDC(t, []string{"https://customer.example/callback"}, nil, "")

	badForm := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {e.app.ID.String()},
		"refresh_token": {"not-a-real-refresh-token"},
	}

	for i := 0; i < oidcTokenIPCap; i++ {
		rr := postOIDCToken(t, e, badForm)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d: expected 400 invalid_grant, got %d (body=%s)", i+1, rr.Code, rr.Body.String())
		}
	}

	rr := postOIDCToken(t, e, badForm)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d failed refresh attempts, got %d (body=%s)", oidcTokenIPCap, rr.Code, rr.Body.String())
	}
}

// TestOIDCToken_RateLimit_BadAuthCode verifies that repeated invalid
// authorization_code grants from one IP (with valid client auth) are
// throttled with a 429 once the cap is reached (code brute-force
// defence).
func TestOIDCToken_RateLimit_BadAuthCode(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	defer testEnv.ClearRateLimitAttempts(t)

	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")

	badForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {e.app.ID.String()},
		"code":          {"not-a-real-code"},
		"redirect_uri":  {redirect},
		"code_verifier": {"whatever"},
	}

	for i := 0; i < oidcTokenIPCap; i++ {
		rr := postOIDCToken(t, e, badForm)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d: expected 400 invalid_grant, got %d (body=%s)", i+1, rr.Code, rr.Body.String())
		}
	}

	rr := postOIDCToken(t, e, badForm)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d failed code attempts, got %d (body=%s)", oidcTokenIPCap, rr.Code, rr.Body.String())
	}
}

// TestOIDCToken_RateLimit_SuccessDoesNotBurn is a guard on the
// burn-on-failure-only invariant: a successful token exchange must NOT
// consume the per-IP budget, or a busy RP behind a shared egress IP
// would throttle its own users. Fails if anyone changes the limiter to
// burn unconditionally.
func TestOIDCToken_RateLimit_SuccessDoesNotBurn(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	defer testEnv.ClearRateLimitAttempts(t)

	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")

	_, accessJWT := e.seedSessionForApp(t)
	verifier, challenge := makePKCE()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.app.ID.String()},
		"redirect_uri":          {redirect},
		"scope":                 {"openid email"},
		"state":                 {"st"},
		"nonce":                 {"n0nce"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest(http.MethodGet, "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/authorize?"+q.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+accessJWT)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect (rr=%d body=%s)", rr.Code, rr.Body.String())
	}

	tokRR := postOIDCToken(t, e, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
		"client_id":     {e.app.ID.String()},
	})
	if tokRR.Code != http.StatusOK {
		t.Fatalf("expected 200 from /token, got %d (body=%s)", tokRR.Code, tokRR.Body.String())
	}

	// "oidc_token" == api.attemptPurposeOIDCToken; "192.0.2.1" is
	// httptest's default RemoteAddr (see file header).
	since := time.Now().UTC().Add(-time.Hour)
	count, err := testEnv.Repo.CountAttemptsByIP(context.Background(), "oidc_token", "192.0.2.1", since)
	if err != nil {
		t.Fatalf("CountAttemptsByIP: %v", err)
	}
	if count != 0 {
		t.Fatalf("successful token exchange should not burn rate-limit budget, found %d attempts", count)
	}
}
