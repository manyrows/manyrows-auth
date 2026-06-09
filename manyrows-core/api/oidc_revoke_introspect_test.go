package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// getOIDCTokensPublic runs the full auth-code flow (with offline_access) on a
// public client and returns a live access token + refresh token.
func getOIDCTokensPublic(t *testing.T, e *oidcTestEnv) (accessToken, refreshToken string) {
	t.Helper()
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")
	_, accessJWT := e.seedSessionForApp(t)
	verifier, challenge := makePKCE()
	q := url.Values{
		"response_type": {"code"}, "client_id": {e.app.ID.String()}, "redirect_uri": {redirect},
		"scope": {"openid email offline_access"}, "state": {"s"}, "nonce": {"n"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/authorize?"+q.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+accessJWT)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	loc, _ := url.Parse(rr.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code from authorize (rr=%d %s)", rr.Code, rr.Body.String())
	}
	tr := oidcPostForm(e, "/oidc/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"code_verifier": {verifier}, "client_id": {e.app.ID.String()},
	})
	if tr.Code != http.StatusOK {
		t.Fatalf("token exchange: %d %s", tr.Code, tr.Body.String())
	}
	var m map[string]any
	_ = json.Unmarshal(tr.Body.Bytes(), &m)
	accessToken, _ = m["access_token"].(string)
	refreshToken, _ = m["refresh_token"].(string)
	if accessToken == "" || refreshToken == "" {
		t.Fatalf("missing tokens: %s", tr.Body.String())
	}
	return accessToken, refreshToken
}

func oidcPostForm(e *oidcTestEnv, path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	return rr
}

// Revoking a refresh token kills the session, so it can no longer be refreshed.
func TestOIDCRevoke_RefreshTokenKillsSession(t *testing.T) {
	e := setupOIDCRouter(t)
	_, refresh := getOIDCTokensPublic(t, e)

	rr := oidcPostForm(e, "/oidc/revoke", url.Values{"token": {refresh}, "client_id": {e.app.ID.String()}})
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke: expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	again := oidcPostForm(e, "/oidc/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {e.app.ID.String()},
	})
	if again.Code == http.StatusOK {
		t.Errorf("refresh after revoke must fail, got 200 (%s)", again.Body.String())
	}
}

// Introspection reports an access token active, then inactive after the
// session is revoked.
func TestOIDCIntrospect_ActiveThenRevoked(t *testing.T) {
	e := setupOIDCRouter(t)
	access, refresh := getOIDCTokensPublic(t, e)

	rr := oidcPostForm(e, "/oidc/introspect", url.Values{"token": {access}, "client_id": {e.app.ID.String()}})
	if rr.Code != http.StatusOK {
		t.Fatalf("introspect: expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var m map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	if m["active"] != true {
		t.Errorf("expected active=true, got %v", m["active"])
	}
	if s, _ := m["sub"].(string); s == "" {
		t.Error("active introspection should include sub")
	}

	oidcPostForm(e, "/oidc/revoke", url.Values{"token": {refresh}, "client_id": {e.app.ID.String()}})

	rr2 := oidcPostForm(e, "/oidc/introspect", url.Values{"token": {access}, "client_id": {e.app.ID.String()}})
	var m2 map[string]any
	_ = json.Unmarshal(rr2.Body.Bytes(), &m2)
	if m2["active"] != false {
		t.Errorf("expected active=false after revoke, got %v", m2["active"])
	}
}

// An unknown token introspects as inactive (200, not an error).
func TestOIDCIntrospect_GarbageInactive(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDC(t, []string{"https://customer.example/cb"}, nil, "")
	rr := oidcPostForm(e, "/oidc/introspect", url.Values{"token": {"not-a-real-token"}, "client_id": {e.app.ID.String()}})
	if rr.Code != http.StatusOK {
		t.Fatalf("introspect garbage: expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var m map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	if m["active"] != false {
		t.Errorf("garbage token must be inactive, got %v", m["active"])
	}
}

// The discovery document advertises the new endpoints so RP libraries
// discover them automatically.
func TestOIDCDiscovery_AdvertisesRevocationAndIntrospection(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDC(t, []string{"https://customer.example/cb"}, nil, "")
	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("discovery: expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var doc map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &doc)
	if s, _ := doc["revocation_endpoint"].(string); !strings.HasSuffix(s, "/oidc/revoke") {
		t.Errorf("revocation_endpoint = %q, want .../oidc/revoke", s)
	}
	if s, _ := doc["introspection_endpoint"].(string); !strings.HasSuffix(s, "/oidc/introspect") {
		t.Errorf("introspection_endpoint = %q, want .../oidc/introspect", s)
	}
}

// Both endpoints require client authentication (a confidential client with no
// secret presented → 401).
func TestOIDCRevokeIntrospect_RequireClientAuth(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDC(t, []string{"https://customer.example/cb"}, nil, "confidential-secret-32-bytes-long!!")

	if rr := oidcPostForm(e, "/oidc/revoke", url.Values{"token": {"x"}, "client_id": {e.app.ID.String()}}); rr.Code != http.StatusUnauthorized {
		t.Errorf("revoke without secret: expected 401, got %d", rr.Code)
	}
	if rr := oidcPostForm(e, "/oidc/introspect", url.Values{"token": {"x"}, "client_id": {e.app.ID.String()}}); rr.Code != http.StatusUnauthorized {
		t.Errorf("introspect without secret: expected 401, got %d", rr.Code)
	}
}
