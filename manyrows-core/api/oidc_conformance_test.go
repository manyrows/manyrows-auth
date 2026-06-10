package api_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func decodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a 3-part JWT, got %d parts", len(parts))
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode jwt payload: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal jwt payload: %v", err)
	}
	return m
}

// authorizeGET issues a GET /oidc/authorize with the given query, optionally
// carrying a session (Bearer access JWT).
func authorizeGET(e *oidcTestEnv, q url.Values, accessJWT string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/authorize?"+q.Encode(), nil)
	if accessJWT != "" {
		req.Header.Set("Authorization", "Bearer "+accessJWT)
	}
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	return rr
}

func baseAuthorizeQuery(e *oidcTestEnv, redirect, challenge string) url.Values {
	return url.Values{
		"response_type": {"code"}, "client_id": {e.app.ID.String()}, "redirect_uri": {redirect},
		"scope": {"openid email"}, "state": {"s"}, "nonce": {"n"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
}

// The id_token carries at_hash (bound to the access_token) and azp (client_id).
func TestOIDCToken_IDTokenHasAtHashAndAzp(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")
	_, accessJWT := e.seedSessionForApp(t)
	verifier, challenge := makePKCE()

	rr := authorizeGET(e, baseAuthorizeQuery(e, redirect, challenge), accessJWT)
	loc, _ := url.Parse(rr.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code (rr=%d %s)", rr.Code, rr.Body.String())
	}
	tok := oidcPostForm(e, "/oidc/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"code_verifier": {verifier}, "client_id": {e.app.ID.String()},
	})
	if tok.Code != http.StatusOK {
		t.Fatalf("token: %d %s", tok.Code, tok.Body.String())
	}
	var resp struct {
		IDToken string `json:"id_token"`
	}
	_ = json.Unmarshal(tok.Body.Bytes(), &resp)
	payload := decodeJWTPayload(t, resp.IDToken)
	if s, _ := payload["at_hash"].(string); s == "" {
		t.Error("id_token missing at_hash")
	}
	if payload["azp"] != e.app.ID.String() {
		t.Errorf("azp = %v, want %s", payload["azp"], e.app.ID.String())
	}
}

// prompt=none with no session must error (login_required), not redirect to login.
func TestOIDCAuthorize_PromptNone_NoSession_LoginRequired(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")
	_, challenge := makePKCE()

	q := baseAuthorizeQuery(e, redirect, challenge)
	q.Set("prompt", "none")
	rr := authorizeGET(e, q, "") // no session

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d (%s)", rr.Code, rr.Body.String())
	}
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if loc.Query().Get("error") != "login_required" {
		t.Errorf("error = %q, want login_required (Location=%s)", loc.Query().Get("error"), rr.Header().Get("Location"))
	}
}

// prompt=login forces re-auth even with a live session (routes to login
// instead of silently minting a code).
func TestOIDCAuthorize_PromptLogin_ForcesReauth(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")
	_, accessJWT := e.seedSessionForApp(t)
	_, challenge := makePKCE()

	// Sanity: without prompt, a live session mints a code immediately.
	base := authorizeGET(e, baseAuthorizeQuery(e, redirect, challenge), accessJWT)
	if loc, _ := url.Parse(base.Header().Get("Location")); loc.Query().Get("code") == "" {
		t.Fatalf("precondition: live session should mint a code, got %s", base.Header().Get("Location"))
	}

	q := baseAuthorizeQuery(e, redirect, challenge)
	q.Set("prompt", "login")
	rr := authorizeGET(e, q, accessJWT)
	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "/oidc/login") {
		t.Errorf("prompt=login should route to login, got %s", loc)
	}
}

// login_hint on /authorize threads through the pending row into the
// AppKit login shim's init options (prefill only). Hints over 254 chars
// are dropped entirely.
func TestOIDCAuthorize_LoginHint_ThreadsToShim(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")
	_, challenge := makePKCE()

	loginPageFor := func(t *testing.T, hint string) string {
		t.Helper()
		q := baseAuthorizeQuery(e, redirect, challenge)
		q.Set("login_hint", hint)
		rr := authorizeGET(e, q, "") // no session → login shim
		if rr.Code != http.StatusFound {
			t.Fatalf("authorize: expected 302, got %d (%s)", rr.Code, rr.Body.String())
		}
		loc := rr.Header().Get("Location")
		if !strings.Contains(loc, "/oidc/login?req=") {
			t.Fatalf("expected redirect to oidc/login, got %q", loc)
		}
		req := httptest.NewRequest("GET", loc, nil)
		page := httptest.NewRecorder()
		e.router.ServeHTTP(page, req)
		if page.Code != http.StatusOK {
			t.Fatalf("login page: expected 200, got %d (%s)", page.Code, page.Body.String())
		}
		return page.Body.String()
	}

	t.Run("hint reaches AppKit init options", func(t *testing.T) {
		body := loginPageFor(t, "hint@example.com")
		if !strings.Contains(body, `var loginHint = "hint@example.com";`) {
			t.Errorf("login page missing rendered loginHint value:\n%s", body)
		}
	})

	t.Run("over-length hint is dropped", func(t *testing.T) {
		long := strings.Repeat("a", 250) + "@example.com" // > 254 chars
		body := loginPageFor(t, long)
		if !strings.Contains(body, `var loginHint = "";`) {
			t.Errorf("over-length login_hint should render as empty string")
		}
		if strings.Contains(body, long) || strings.Contains(body, strings.Repeat("a", 250)) {
			t.Errorf("over-length login_hint should be dropped, but appears on page")
		}
	})

	t.Run("script-closing hint cannot break out of the inline script", func(t *testing.T) {
		body := loginPageFor(t, "</script><script>alert(1)</script>@x.com")
		if strings.Contains(body, "<script>alert(1)</script>") {
			t.Errorf("raw script payload leaked into the page:\n%s", body)
		}
	})
}

// The login shim's resumeURL must be a clean JS string literal whose query
// key is literally `req`. With the old `{{ .ResumeURL | js }}` pipeline the
// value was double-escaped (text/template JSEscaper + html/template
// jsValEscaper), rendering `req\u003d` — the browser then sent a query key
// literally named `req\u003d...` and resume broke.
func TestOIDCLoginShim_ResumeURLNotMangled(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")
	_, challenge := makePKCE()

	rr := authorizeGET(e, baseAuthorizeQuery(e, redirect, challenge), "") // no session → login shim
	if rr.Code != http.StatusFound {
		t.Fatalf("authorize: expected 302, got %d (%s)", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/oidc/login?req=") {
		t.Fatalf("expected redirect to oidc/login, got %q", loc)
	}
	req := httptest.NewRequest("GET", loc, nil)
	page := httptest.NewRecorder()
	e.router.ServeHTTP(page, req)
	if page.Code != http.StatusOK {
		t.Fatalf("login page: expected 200, got %d (%s)", page.Code, page.Body.String())
	}
	body := page.Body.String()

	// Pull out the rendered `var resumeURL = ...;` line.
	var line string
	for _, l := range strings.Split(body, "\n") {
		if strings.Contains(l, "var resumeURL") {
			line = strings.TrimSpace(l)
			break
		}
	}
	if line == "" {
		t.Fatalf("login page missing `var resumeURL` line:\n%s", body)
	}
	if strings.Contains(strings.ToLower(line), `\u003d`) {
		t.Errorf("resumeURL is double-escaped (contains \\u003d): %s", line)
	}
	if !strings.Contains(line, "req=") {
		t.Errorf("resumeURL missing literal `req=` query key: %s", line)
	}
}

// max_age=0 forces re-auth: the existing session is always "too old".
func TestOIDCAuthorize_MaxAgeZero_ForcesReauth(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")
	_, accessJWT := e.seedSessionForApp(t)
	_, challenge := makePKCE()

	q := baseAuthorizeQuery(e, redirect, challenge)
	q.Set("max_age", "0")
	rr := authorizeGET(e, q, accessJWT)
	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "/oidc/login") {
		t.Errorf("max_age=0 should route to login, got %s", loc)
	}
}
