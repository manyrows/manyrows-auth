package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

// TestOIDCAccessToken_CarriesScopeClaim verifies that an access token issued
// via the OIDC authorization-code grant carries the granted scope as a
// "scope" JWT claim.
func TestOIDCAccessToken_CarriesScopeClaim(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")
	_, accessJWT := e.seedSessionForApp(t)
	verifier, challenge := makePKCE()

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.app.ID.String()},
		"redirect_uri":          {redirect},
		"scope":                 {"openid email offline_access"},
		"state":                 {"s"},
		"nonce":                 {"n"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	rr := authorizeGET(e, q, accessJWT)
	loc, _ := url.Parse(rr.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code from authorize (rr=%d %s)", rr.Code, rr.Body.String())
	}

	tok := oidcPostForm(e, "/oidc/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
		"client_id":     {e.app.ID.String()},
	})
	if tok.Code != http.StatusOK {
		t.Fatalf("token exchange: %d %s", tok.Code, tok.Body.String())
	}

	var resp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(tok.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal token response: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatalf("no access_token in response: %s", tok.Body.String())
	}

	payload := decodeJWTPayload(t, resp.AccessToken)
	scope, _ := payload["scope"].(string)
	if scope != "openid email offline_access" {
		t.Errorf("access token scope = %q, want %q", scope, "openid email offline_access")
	}
}

// TestAppKitAccessToken_NoScopeClaim verifies that a first-party (AppKit)
// access token issued via IssueTokenPair does NOT carry a "scope" claim.
func TestAppKitAccessToken_NoScopeClaim(t *testing.T) {
	e := setupOIDCRouter(t)
	// Seed a session and obtain a first-party access token (no OIDC scope).
	_, accessJWT := e.seedSessionForApp(t)

	payload := decodeJWTPayload(t, accessJWT)
	if _, hasScope := payload["scope"]; hasScope {
		t.Errorf("first-party access token must not carry a scope claim, got scope=%v", payload["scope"])
	}
}

// TestOIDCRefreshRotation_InheritsScope verifies that:
//  1. After an OIDC code grant the stored client_refresh_tokens row carries
//     the granted scope.
//  2. After a refresh-token rotation the newest row still carries the same
//     scope AND the refreshed access token's scope claim equals the stored
//     scope.
func TestOIDCRefreshRotation_InheritsScope(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")
	_, accessJWT := e.seedSessionForApp(t)
	verifier, challenge := makePKCE()

	grantScope := "openid email offline_access"

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.app.ID.String()},
		"redirect_uri":          {redirect},
		"scope":                 {grantScope},
		"state":                 {"s"},
		"nonce":                 {"n"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	rr := authorizeGET(e, q, accessJWT)
	loc, _ := url.Parse(rr.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code from authorize (rr=%d %s)", rr.Code, rr.Body.String())
	}

	tok := oidcPostForm(e, "/oidc/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
		"client_id":     {e.app.ID.String()},
	})
	if tok.Code != http.StatusOK {
		t.Fatalf("code grant: %d %s", tok.Code, tok.Body.String())
	}
	var tokResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(tok.Body.Bytes(), &tokResp); err != nil {
		t.Fatalf("unmarshal token response: %v", err)
	}
	if tokResp.RefreshToken == "" {
		t.Fatalf("expected refresh_token (offline_access), got none: %s", tok.Body.String())
	}

	// --- verify the stored scope after the code grant ---
	// Resolve the session via the access token payload (sid claim).
	atPayload := decodeJWTPayload(t, tokResp.AccessToken)
	sessionID, _ := atPayload["sid"].(string)
	if sessionID == "" {
		t.Fatalf("access token has no sid claim")
	}

	var storedScope string
	err := testEnv.DB.Pool().QueryRow(context.Background(),
		`SELECT oidc_scope FROM client_refresh_tokens
		  WHERE session_id = $1 AND revoked_at IS NULL
		  ORDER BY created_at DESC LIMIT 1`,
		sessionID,
	).Scan(&storedScope)
	if err != nil {
		t.Fatalf("query stored scope after code grant: %v", err)
	}
	if storedScope != grantScope {
		t.Errorf("stored oidc_scope after code grant = %q, want %q", storedScope, grantScope)
	}

	// --- refresh the token ---
	refreshRR := oidcPostForm(e, "/oidc/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokResp.RefreshToken},
		"client_id":     {e.app.ID.String()},
	})
	if refreshRR.Code != http.StatusOK {
		t.Fatalf("refresh grant: %d %s", refreshRR.Code, refreshRR.Body.String())
	}
	var refreshResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(refreshRR.Body.Bytes(), &refreshResp); err != nil {
		t.Fatalf("unmarshal refresh response: %v", err)
	}
	if refreshResp.AccessToken == "" {
		t.Fatalf("no access_token in refresh response: %s", refreshRR.Body.String())
	}

	// Newest stored row must still carry the original scope.
	var newStoredScope string
	err = testEnv.DB.Pool().QueryRow(context.Background(),
		`SELECT oidc_scope FROM client_refresh_tokens
		  WHERE session_id = $1 AND revoked_at IS NULL
		  ORDER BY created_at DESC LIMIT 1`,
		sessionID,
	).Scan(&newStoredScope)
	if err != nil {
		t.Fatalf("query stored scope after refresh: %v", err)
	}
	if newStoredScope != grantScope {
		t.Errorf("stored oidc_scope after rotation = %q, want %q", newStoredScope, grantScope)
	}

	// Refreshed access token's scope claim must equal the granted scope.
	newPayload := decodeJWTPayload(t, refreshResp.AccessToken)
	newScope, _ := newPayload["scope"].(string)
	if newScope != grantScope {
		t.Errorf("refreshed access token scope claim = %q, want %q", newScope, grantScope)
	}
}
