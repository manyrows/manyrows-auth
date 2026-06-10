package api_test

import (
	"context"
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

// resumeGET issues a GET /oidc/authorize/resume?req=<id>, optionally
// carrying a session (Bearer access JWT).
func resumeGET(e *oidcTestEnv, reqID string, accessJWT string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET",
		"/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/authorize/resume?req="+reqID, nil)
	if accessJWT != "" {
		req.Header.Set("Authorization", "Bearer "+accessJWT)
	}
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	return rr
}

// promptLoginReqID starts a prompt=login authorize (carrying the given
// session, if any) and returns the pending req id from the login redirect.
func promptLoginReqID(t *testing.T, e *oidcTestEnv, redirect, accessJWT string) string {
	t.Helper()
	_, challenge := makePKCE()
	q := baseAuthorizeQuery(e, redirect, challenge)
	q.Set("prompt", "login")
	rr := authorizeGET(e, q, accessJWT)
	if rr.Code != http.StatusFound {
		t.Fatalf("authorize: expected 302, got %d (%s)", rr.Code, rr.Body.String())
	}
	u, _ := url.Parse(rr.Header().Get("Location"))
	if !strings.Contains(u.Path, "/oidc/login") || u.Query().Get("req") == "" {
		t.Fatalf("expected login redirect with req, got %s", rr.Header().Get("Location"))
	}
	return u.Query().Get("req")
}

// prompt=login must still be in force at /authorize/resume: a session
// created BEFORE the pending authorize row predates the forced re-auth
// (the holder skipped the login shim, e.g. by hitting the resume URL
// directly), so it must NOT satisfy prompt=login. The error surface must
// be byte-identical to the unauthenticated-resume case (no new oracle).
// A session created after the row (a real re-login) passes.
func TestOIDCAuthorizeResume_PromptLogin_RequiresFreshSession(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "") // consent toggle off
	staleSes, staleJWT := e.seedSessionForApp(t)

	// Backdate the pre-existing session so it is unambiguously older
	// than any pending row minted below (no same-millisecond flakiness).
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`update client_sessions set created_at = created_at - interval '1 minute' where id = $1`,
		staleSes.ID); err != nil {
		t.Fatalf("backdate session: %v", err)
	}

	// --- negative: resume with the PRE-EXISTING (stale) session ---
	req1 := promptLoginReqID(t, e, redirect, staleJWT)
	staleRes := resumeGET(e, req1, staleJWT)
	if staleRes.Code != http.StatusFound {
		t.Fatalf("stale resume: expected 302, got %d (%s)", staleRes.Code, staleRes.Body.String())
	}
	staleLoc, _ := url.Parse(staleRes.Header().Get("Location"))
	if staleLoc.Query().Get("code") != "" {
		t.Fatalf("stale session must NOT satisfy prompt=login at resume, got code in %s",
			staleRes.Header().Get("Location"))
	}
	if got := staleLoc.Query().Get("error"); got != "access_denied" {
		t.Errorf("stale resume error = %q, want access_denied (Location=%s)",
			got, staleRes.Header().Get("Location"))
	}

	// --- no-oracle: identical surface to the unauthenticated resume ---
	req2 := promptLoginReqID(t, e, redirect, staleJWT)
	anonRes := resumeGET(e, req2, "")
	if anonRes.Code != staleRes.Code {
		t.Errorf("stale-session resume status %d != unauthenticated resume status %d",
			staleRes.Code, anonRes.Code)
	}
	if anonRes.Header().Get("Location") != staleRes.Header().Get("Location") {
		t.Errorf("stale-session resume surface differs from unauthenticated:\n stale: %s\n anon:  %s",
			staleRes.Header().Get("Location"), anonRes.Header().Get("Location"))
	}

	// --- positive: a session minted AFTER the pending row passes ---
	req3 := promptLoginReqID(t, e, redirect, staleJWT)
	_, freshJWT := e.seedSessionForApp(t) // created after the pending row
	freshRes := resumeGET(e, req3, freshJWT)
	if freshRes.Code != http.StatusFound {
		t.Fatalf("fresh resume: expected 302, got %d (%s)", freshRes.Code, freshRes.Body.String())
	}
	freshLoc, _ := url.Parse(freshRes.Header().Get("Location"))
	if freshLoc.Query().Get("code") == "" {
		t.Errorf("fresh session should satisfy prompt=login and mint a code, got %s",
			freshRes.Header().Get("Location"))
	}
	if freshLoc.Query().Get("error") != "" {
		t.Errorf("fresh resume unexpectedly errored: %s", freshRes.Header().Get("Location"))
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

// max_age must still be in force at /authorize/resume: the demand was
// made at /authorize, so a session older than the RP allows cannot
// satisfy it at Resume either (the holder skipped the login shim, e.g.
// by hitting the resume URL directly). Error surface is identical to
// sign-in not completing. A fresh session within max_age passes.
func TestOIDCAuthorizeResume_MaxAge_StaleSessionRejected(t *testing.T) {
	e := setupOIDCRouter(t)
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "") // consent toggle off
	staleSes, staleJWT := e.seedSessionForApp(t)

	// Backdate the session 10 minutes so it is unambiguously older than
	// the max_age=60 demanded below.
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`update client_sessions set created_at = created_at - interval '10 minutes' where id = $1`,
		staleSes.ID); err != nil {
		t.Fatalf("backdate session: %v", err)
	}

	// Authorize with max_age=60 (no prompt) holding the stale session:
	// the direct path forces re-auth and routes to the login shim.
	_, challenge := makePKCE()
	q := baseAuthorizeQuery(e, redirect, challenge)
	q.Set("max_age", "60")
	rr := authorizeGET(e, q, staleJWT)
	if rr.Code != http.StatusFound {
		t.Fatalf("authorize: expected 302, got %d (%s)", rr.Code, rr.Body.String())
	}
	u, _ := url.Parse(rr.Header().Get("Location"))
	if !strings.Contains(u.Path, "/oidc/login") || u.Query().Get("req") == "" {
		t.Fatalf("expected login redirect with req, got %s", rr.Header().Get("Location"))
	}

	// --- negative: hit the resume URL directly with the SAME stale session ---
	staleRes := resumeGET(e, u.Query().Get("req"), staleJWT)
	if staleRes.Code != http.StatusFound {
		t.Fatalf("stale resume: expected 302, got %d (%s)", staleRes.Code, staleRes.Body.String())
	}
	staleLoc, _ := url.Parse(staleRes.Header().Get("Location"))
	if staleLoc.Query().Get("code") != "" {
		t.Fatalf("stale session must NOT satisfy max_age at resume, got code in %s",
			staleRes.Header().Get("Location"))
	}
	if got := staleLoc.Query().Get("error"); got != "access_denied" {
		t.Errorf("stale resume error = %q, want access_denied (Location=%s)",
			got, staleRes.Header().Get("Location"))
	}
	if desc := staleLoc.Query().Get("error_description"); !strings.Contains(desc, "sign-in did not complete") {
		t.Errorf("stale resume error_description = %q, want it to contain %q",
			desc, "sign-in did not complete")
	}

	// --- positive: unauthenticated authorize with max_age=300, then a
	// session minted mid-flow (fresh, well within max_age) resumes fine ---
	_, challenge2 := makePKCE()
	q2 := baseAuthorizeQuery(e, redirect, challenge2)
	q2.Set("max_age", "300")
	rr2 := authorizeGET(e, q2, "") // no session → login shim
	if rr2.Code != http.StatusFound {
		t.Fatalf("authorize (positive): expected 302, got %d (%s)", rr2.Code, rr2.Body.String())
	}
	u2, _ := url.Parse(rr2.Header().Get("Location"))
	if !strings.Contains(u2.Path, "/oidc/login") || u2.Query().Get("req") == "" {
		t.Fatalf("expected login redirect with req, got %s", rr2.Header().Get("Location"))
	}
	_, freshJWT := e.seedSessionForApp(t) // "signs in" mid-flow
	freshRes := resumeGET(e, u2.Query().Get("req"), freshJWT)
	if freshRes.Code != http.StatusFound {
		t.Fatalf("fresh resume: expected 302, got %d (%s)", freshRes.Code, freshRes.Body.String())
	}
	freshLoc, _ := url.Parse(freshRes.Header().Get("Location"))
	if freshLoc.Query().Get("code") == "" {
		t.Errorf("fresh session should satisfy max_age and mint a code, got %s",
			freshRes.Header().Get("Location"))
	}
	if freshLoc.Query().Get("error") != "" {
		t.Errorf("fresh resume unexpectedly errored: %s", freshRes.Header().Get("Location"))
	}

	// --- positive: max_age=0 ("always force fresh authentication") must
	// still be completable. Unauthenticated authorize routes to the login
	// shim; a session minted mid-flow is by definition the fresh sign-in
	// the RP demanded (it cannot predate the pending row), so resume must
	// mint a code even though time.Since(CreatedAt) > 0s. ---
	_, challenge3 := makePKCE()
	q3 := baseAuthorizeQuery(e, redirect, challenge3)
	q3.Set("max_age", "0")
	rr3 := authorizeGET(e, q3, "") // no session → login shim
	if rr3.Code != http.StatusFound {
		t.Fatalf("authorize (max_age=0): expected 302, got %d (%s)", rr3.Code, rr3.Body.String())
	}
	u3, _ := url.Parse(rr3.Header().Get("Location"))
	if !strings.Contains(u3.Path, "/oidc/login") || u3.Query().Get("req") == "" {
		t.Fatalf("expected login redirect with req, got %s", rr3.Header().Get("Location"))
	}
	_, zeroJWT := e.seedSessionForApp(t) // "signs in" mid-flow
	zeroRes := resumeGET(e, u3.Query().Get("req"), zeroJWT)
	if zeroRes.Code != http.StatusFound {
		t.Fatalf("max_age=0 resume: expected 302, got %d (%s)", zeroRes.Code, zeroRes.Body.String())
	}
	zeroLoc, _ := url.Parse(zeroRes.Header().Get("Location"))
	if zeroLoc.Query().Get("code") == "" {
		t.Errorf("fresh sign-in must satisfy max_age=0 at resume, got %s",
			zeroRes.Header().Get("Location"))
	}
	if zeroLoc.Query().Get("error") != "" {
		t.Errorf("max_age=0 resume unexpectedly errored: %s", zeroRes.Header().Get("Location"))
	}
}

// The session-freshness guards (prompt=login, max_age) at Resume must run
// BEFORE the consent interposition. The ordering is load-bearing: the
// consent POST endpoint deliberately has no freshness re-check — its
// pending row is supposed to be mintable only by a session that already
// passed the guards. If the consent interposition ran first, a stale
// session could get a consent-stage row minted and launder a code through
// POST /oidc/consent. So: with consent required and a stale session
// (max_age exceeded), Resume must reject outright — no consent hop
// offered, and no consent-stage pending row left in the database.
func TestOIDCAuthorizeResume_StaleSession_NoConsentRowMinted(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDCWithConsent(t, true) // consent required → interposition is live
	redirect := "https://customer.example/callback"
	staleSes, staleJWT := e.seedSessionForApp(t)

	// Backdate the session 10 minutes so it is unambiguously older than
	// the max_age=60 demanded below.
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`update client_sessions set created_at = created_at - interval '10 minutes' where id = $1`,
		staleSes.ID); err != nil {
		t.Fatalf("backdate session: %v", err)
	}

	// Authorize with max_age=60 (no prompt) holding the stale session:
	// freshness forces re-auth, routing to the login shim.
	_, challenge := makePKCE()
	q := baseAuthorizeQuery(e, redirect, challenge)
	q.Set("max_age", "60")
	rr := authorizeGET(e, q, staleJWT)
	if rr.Code != http.StatusFound {
		t.Fatalf("authorize: expected 302, got %d (%s)", rr.Code, rr.Body.String())
	}
	u, _ := url.Parse(rr.Header().Get("Location"))
	if !strings.Contains(u.Path, "/oidc/login") || u.Query().Get("req") == "" {
		t.Fatalf("expected login redirect with req, got %s", rr.Header().Get("Location"))
	}

	// Hit the resume URL directly with the SAME stale session. The
	// freshness guard must fire before the consent interposition gets a
	// chance to mint a consent-stage row.
	res := resumeGET(e, u.Query().Get("req"), staleJWT)
	if res.Code != http.StatusFound {
		t.Fatalf("stale resume: expected 302, got %d (%s)", res.Code, res.Body.String())
	}
	resLoc := res.Header().Get("Location")
	loc, _ := url.Parse(resLoc)
	if loc.Query().Get("code") != "" {
		t.Fatalf("stale session must NOT mint a code at resume, got %s", resLoc)
	}
	if got := loc.Query().Get("error"); got != "access_denied" {
		t.Errorf("stale resume error = %q, want access_denied (Location=%s)", got, resLoc)
	}
	if strings.Contains(resLoc, "/oidc/consent") {
		t.Errorf("stale session must not be offered the consent hop, got %s", resLoc)
	}

	// The teeth: no consent-stage pending row may have been minted for
	// this app. (ConsentStage serializes as `"consent_stage": true` in the
	// request_params jsonb; login-stage rows omit the key entirely.)
	var n int
	if err := testEnv.DB.Pool().QueryRow(context.Background(),
		`select count(*) from oidc_pending_authorize
		 where app_id = $1 and request_params->>'consent_stage' = 'true'`,
		e.app.ID).Scan(&n); err != nil {
		t.Fatalf("count consent-stage pending rows: %v", err)
	}
	if n != 0 {
		t.Errorf("stale session minted %d consent-stage pending row(s); freshness guards must run before the consent interposition", n)
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
