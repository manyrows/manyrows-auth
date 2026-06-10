package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"manyrows-core/auth/client"
)

// oidcFullGrant performs authorize → code → token exchange and returns the
// access token, refresh token, and the session ID embedded in the access
// token's "sid" claim. Callers may pass an empty scope to use the test
// default of "openid email offline_access".
func oidcFullGrant(t *testing.T, e *oidcTestEnv, grantScope string) (accessToken, refreshToken, sessionID string) {
	t.Helper()
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")
	_, accessJWT := e.seedSessionForApp(t)
	verifier, challenge := makePKCE()
	if grantScope == "" {
		grantScope = "openid email offline_access"
	}
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
	var resp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(tok.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal token response: %v", err)
	}
	if resp.RefreshToken == "" {
		t.Fatalf("expected refresh_token (offline_access), got none: %s", tok.Body.String())
	}
	atPayload := decodeJWTPayload(t, resp.AccessToken)
	sid, _ := atPayload["sid"].(string)
	if sid == "" {
		t.Fatalf("access token has no sid claim")
	}
	return resp.AccessToken, resp.RefreshToken, sid
}

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
// access token issued via IssueAccessToken does NOT carry a "scope" claim.
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

// TestOIDCRefresh_NoScopeRequested_ReturnsStoredScope verifies that when the
// client omits the optional scope parameter on a refresh grant, the response
// scope reflects the full stored grant scope ("openid email offline_access").
func TestOIDCRefresh_NoScopeRequested_ReturnsStoredScope(t *testing.T) {
	e := setupOIDCRouter(t)
	_, refreshToken, _ := oidcFullGrant(t, e, "openid email offline_access")

	rr := oidcPostForm(e, "/oidc/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {e.app.ID.String()},
		// no scope field
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh grant: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Scope string `json:"scope"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Scope != "openid email offline_access" {
		t.Errorf("response scope = %q, want %q", resp.Scope, "openid email offline_access")
	}
}

// TestOIDCRefresh_Downscope_Echoed verifies that when the client requests a
// narrower scope on a refresh grant the response scope reflects the narrowed
// value and the id_token omits the email claim.
func TestOIDCRefresh_Downscope_Echoed(t *testing.T) {
	e := setupOIDCRouter(t)
	_, refreshToken, _ := oidcFullGrant(t, e, "openid email offline_access")

	rr := oidcPostForm(e, "/oidc/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {e.app.ID.String()},
		"scope":         {"openid"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh grant: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		IDToken string `json:"id_token"`
		Scope   string `json:"scope"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Scope != "openid" {
		t.Errorf("response scope = %q, want %q", resp.Scope, "openid")
	}
	idPayload := decodeJWTPayload(t, resp.IDToken)
	if _, hasEmail := idPayload["email"]; hasEmail {
		t.Errorf("id_token should not have email claim after downscope to openid-only, got email=%v", idPayload["email"])
	}

	// Decode the refreshed access token and verify its scope claim equals the
	// full stored grant. The AT deliberately keeps the stored grant; only the
	// response body + id_token narrow.
	var atResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &atResp); err != nil {
		t.Fatalf("unmarshal access_token from response: %v", err)
	}
	atPayload := decodeJWTPayload(t, atResp.AccessToken)
	atScope, _ := atPayload["scope"].(string)
	if atScope != "openid email offline_access" {
		t.Errorf("refreshed access token scope claim = %q, want %q (full stored grant)", atScope, "openid email offline_access")
	}
}

// TestOIDCRefresh_EscalationIntersected verifies that when the client requests
// a scope on refresh that includes a token not in the stored grant, the extra
// token is silently dropped (silent intersect). It also confirms that
// downscoping this response does NOT narrow the stored grant — a later
// refresh with the full stored scope will still see the full scope.
func TestOIDCRefresh_EscalationIntersected(t *testing.T) {
	e := setupOIDCRouter(t)
	// Grant does NOT include email.
	_, refreshToken, sessionID := oidcFullGrant(t, e, "openid offline_access")

	// Request scope includes email (escalation attempt).
	rr := oidcPostForm(e, "/oidc/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {e.app.ID.String()},
		"scope":         {"openid email"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh grant: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Response scope must not include email.
	if resp.Scope != "openid" {
		t.Errorf("response scope = %q, want %q (email must be dropped)", resp.Scope, "openid")
	}
	// id_token must not contain email.
	idPayload := decodeJWTPayload(t, resp.IDToken)
	if _, hasEmail := idPayload["email"]; hasEmail {
		t.Errorf("id_token must not have email claim after escalation intersect, got email=%v", idPayload["email"])
	}
	// The new access token scope claim should equal the stored grant (not the narrowed response).
	atPayload := decodeJWTPayload(t, resp.AccessToken)
	atScope, _ := atPayload["scope"].(string)
	if atScope != "openid offline_access" {
		t.Errorf("new access token scope claim = %q, want %q (stored grant, not narrowed response)", atScope, "openid offline_access")
	}
	// Stored row must still carry the original full grant scope.
	var storedScope string
	err := testEnv.DB.Pool().QueryRow(context.Background(),
		`SELECT oidc_scope FROM client_refresh_tokens
		  WHERE session_id = $1 AND revoked_at IS NULL
		  ORDER BY created_at DESC LIMIT 1`,
		sessionID,
	).Scan(&storedScope)
	if err != nil {
		t.Fatalf("query stored scope after refresh: %v", err)
	}
	if storedScope != "openid offline_access" {
		t.Errorf("stored oidc_scope after escalation intersect = %q, want %q", storedScope, "openid offline_access")
	}
}

// oidcUserinfoGET performs a GET /oidc/userinfo with the given bearer token
// and returns the response recorder.
func oidcUserinfoGET(e *oidcTestEnv, bearerToken string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	return rr
}

// TestOIDCUserInfo_OpenidOnly_SubOnly verifies that an access token granted
// with only the "openid" scope returns a userinfo body with "sub" but without
// "email" or "preferred_username".
func TestOIDCUserInfo_OpenidOnly_SubOnly(t *testing.T) {
	e := setupOIDCRouter(t)
	accessToken, _, _ := oidcFullGrant(t, e, "openid offline_access")

	rr := oidcUserinfoGET(e, accessToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("userinfo: expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if sub, _ := resp["sub"].(string); sub == "" {
		t.Errorf("expected sub claim, got body=%s", rr.Body.String())
	}
	if _, hasEmail := resp["email"]; hasEmail {
		t.Errorf("email must be absent for openid-only scope, got body=%s", rr.Body.String())
	}
	if _, hasUN := resp["preferred_username"]; hasUN {
		t.Errorf("preferred_username must be absent for openid-only scope, got body=%s", rr.Body.String())
	}
}

// TestOIDCUserInfo_EmailScope verifies that an access token granted with
// "openid email" returns sub + email (and email_verified) but not
// preferred_username.
func TestOIDCUserInfo_EmailScope(t *testing.T) {
	e := setupOIDCRouter(t)
	accessToken, _, _ := oidcFullGrant(t, e, "openid email offline_access")

	rr := oidcUserinfoGET(e, accessToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("userinfo: expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if sub, _ := resp["sub"].(string); sub == "" {
		t.Errorf("expected sub claim, got body=%s", rr.Body.String())
	}
	if _, hasEmail := resp["email"]; !hasEmail {
		t.Errorf("email must be present for email scope, got body=%s", rr.Body.String())
	}
	if _, hasUN := resp["preferred_username"]; hasUN {
		t.Errorf("preferred_username must be absent when profile scope not granted, got body=%s", rr.Body.String())
	}
}

// TestOIDCUserInfo_ProfileScope verifies that an access token granted with
// "openid profile" returns sub + preferred_username but not email.
func TestOIDCUserInfo_ProfileScope(t *testing.T) {
	e := setupOIDCRouter(t)
	accessToken, _, _ := oidcFullGrant(t, e, "openid profile offline_access")

	rr := oidcUserinfoGET(e, accessToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("userinfo: expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if sub, _ := resp["sub"].(string); sub == "" {
		t.Errorf("expected sub claim, got body=%s", rr.Body.String())
	}
	if _, hasEmail := resp["email"]; hasEmail {
		t.Errorf("email must be absent when email scope not granted, got body=%s", rr.Body.String())
	}
	if _, hasUN := resp["preferred_username"]; !hasUN {
		t.Errorf("preferred_username must be present for profile scope, got body=%s", rr.Body.String())
	}
}

// TestOIDCUserInfo_FirstPartyToken_FullClaims verifies that a first-party
// (AppKit) access token — which carries no scope claim — returns the full
// claim set (sub + email + preferred_username) for back-compat.
func TestOIDCUserInfo_FirstPartyToken_FullClaims(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDC(t, []string{"https://customer.example/callback"}, nil, "")
	_, accessJWT := e.seedSessionForApp(t)

	rr := oidcUserinfoGET(e, accessJWT)
	if rr.Code != http.StatusOK {
		t.Fatalf("userinfo: expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if sub, _ := resp["sub"].(string); sub == "" {
		t.Errorf("expected sub claim, got body=%s", rr.Body.String())
	}
	if _, hasEmail := resp["email"]; !hasEmail {
		t.Errorf("first-party token: email must be present (full claims), got body=%s", rr.Body.String())
	}
	if _, hasUN := resp["preferred_username"]; !hasUN {
		t.Errorf("first-party token: preferred_username must be present (full claims), got body=%s", rr.Body.String())
	}
}

// TestOIDCUserInfo_JunkAuthHeaderWithCookie_FailsSafe verifies the bearer
// extraction guard introduced to align with bearerTokenFromRequest. When the
// Authorization header is a non-Bearer scheme (e.g. "Basic …") the handler
// must NOT treat that header value as an access token; instead it falls
// through to the cookie fallback, reads the real OIDC access token, and
// applies normal scope filtering. Because the grant is "openid" only, the
// response is 200 with "sub" but without "email" — confirming the real token
// was used and scope enforcement ran correctly (not the old bug path that
// silently returned full claims).
func TestOIDCUserInfo_JunkAuthHeaderWithCookie_FailsSafe(t *testing.T) {
	e := setupOIDCRouter(t)
	// Grant openid only — email must never appear in a correct response.
	accessToken, _, _ := oidcFullGrant(t, e, "openid offline_access")

	// Build the userinfo request: the real token goes in the session cookie;
	// the Authorization header is a Basic scheme that must be ignored.
	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Basic anVuaw==") // base64("junk")
	req.AddCookie(&http.Cookie{
		Name:  client.AccessCookieName(e.app.ID),
		Value: accessToken,
	})
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	// With the fix the cookie fallback fires, the real token is resolved, and
	// scope enforcement returns sub-only (openid grant → no email). A 401 would
	// also be acceptable here, but the fixed code returns 200 + sub-only
	// because GetSession successfully authenticates via the cookie.
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 (cookie auth succeeded), got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if sub, _ := resp["sub"].(string); sub == "" {
		t.Errorf("expected sub claim, got body=%s", rr.Body.String())
	}
	if _, hasEmail := resp["email"]; hasEmail {
		// Pre-fix bug: junk header was used as rawToken → scope="" → full claims leaked.
		t.Errorf("email must be absent: junk Basic header must not grant full claims, got body=%s", rr.Body.String())
	}
}

// TestOIDCUserInfo_CombinedScopes verifies that an access token granted with
// "openid email profile" returns sub + email + preferred_username all present.
func TestOIDCUserInfo_CombinedScopes(t *testing.T) {
	e := setupOIDCRouter(t)
	accessToken, _, _ := oidcFullGrant(t, e, "openid email profile offline_access")

	rr := oidcUserinfoGET(e, accessToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("userinfo: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if sub, _ := resp["sub"].(string); sub == "" {
		t.Errorf("expected sub claim, got body=%s", rr.Body.String())
	}
	if _, hasEmail := resp["email"]; !hasEmail {
		t.Errorf("email must be present for email scope, got body=%s", rr.Body.String())
	}
	if _, hasUN := resp["preferred_username"]; !hasUN {
		t.Errorf("preferred_username must be present for profile scope, got body=%s", rr.Body.String())
	}
}

// TestOIDCRefresh_LegacyEmptyRow_DefaultsOpenidEmail verifies that a refresh
// token row with an empty oidc_scope (pre-migration legacy row) falls back to
// the historical "openid email" scope in the response.
func TestOIDCRefresh_LegacyEmptyRow_DefaultsOpenidEmail(t *testing.T) {
	e := setupOIDCRouter(t)
	_, refreshToken, sessionID := oidcFullGrant(t, e, "openid email offline_access")

	// Simulate a legacy row by blanking out the stored scope.
	_, err := testEnv.DB.Pool().Exec(context.Background(),
		`UPDATE client_refresh_tokens SET oidc_scope = '' WHERE session_id = $1`,
		sessionID,
	)
	if err != nil {
		t.Fatalf("blank oidc_scope: %v", err)
	}

	rr := oidcPostForm(e, "/oidc/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {e.app.ID.String()},
		// no scope field
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh grant: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Scope string `json:"scope"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Scope != "openid email" {
		t.Errorf("legacy row response scope = %q, want %q", resp.Scope, "openid email")
	}
}
