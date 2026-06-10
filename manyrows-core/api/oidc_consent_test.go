package api_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"

	"github.com/gofrs/uuid/v5"
)

// enableOIDCWithConsent calls UpdateAppOIDCConfig with RequireConsent set.
func (e *oidcTestEnv) enableOIDCWithConsent(t *testing.T, requireConsent bool) {
	t.Helper()
	empty := ""
	if err := testEnv.Repo.UpdateAppOIDCConfig(context.Background(), e.app.ID, repo.UpdateAppOIDCConfigParams{
		Enabled:                true,
		ClientSecretHash:       &empty,
		RedirectURIs:           []string{"https://customer.example/callback"},
		PostLogoutRedirectURIs: nil,
		RequireConsent:         requireConsent,
	}); err != nil {
		t.Fatalf("enableOIDCWithConsent: %v", err)
	}
}

// consentGET issues a GET /oidc/consent?req=<id> carrying an optional access JWT.
func consentGET(e *oidcTestEnv, reqID string, accessJWT string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET",
		"/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/consent?req="+reqID,
		nil)
	if accessJWT != "" {
		req.Header.Set("Authorization", "Bearer "+accessJWT)
	}
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	return rr
}

// consentPOST issues a POST /oidc/consent with the given decision and req.
func consentPOST(e *oidcTestEnv, reqID, decision, accessJWT string) *httptest.ResponseRecorder {
	form := url.Values{"req": {reqID}, "decision": {decision}}
	req := httptest.NewRequest("POST",
		"/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/consent",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if accessJWT != "" {
		req.Header.Set("Authorization", "Bearer "+accessJWT)
	}
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	return rr
}

// =============================================================================
// 1. TestOIDCConsent_ToggleOff_NoScreen
// =============================================================================

// When RequireConsent is off, an authenticated authorize goes straight to the
// redirect_uri with a code — no consent hop.
func TestOIDCConsent_ToggleOff_NoScreen(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDCWithConsent(t, false)
	_, accessJWT := e.seedSessionForApp(t)
	_, challenge := makePKCE()

	redirect := "https://customer.example/callback"
	rr := authorizeGET(e, baseAuthorizeQuery(e, redirect, challenge), accessJWT)
	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d (%s)", rr.Code, rr.Body.String())
	}
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Errorf("expected code in redirect when consent is off, got Location=%s", rr.Header().Get("Location"))
	}
	if strings.Contains(rr.Header().Get("Location"), "/oidc/consent") {
		t.Errorf("consent is off but redirected to consent page: %s", rr.Header().Get("Location"))
	}
}

// =============================================================================
// 2. TestOIDCConsent_FirstAuthorize_ShowsScreen
// =============================================================================

// With consent on and no remembered grant, authorize → consent page.
// GET the consent page → 200 with app name + scope description.
func TestOIDCConsent_FirstAuthorize_ShowsScreen(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDCWithConsent(t, true)
	_, accessJWT := e.seedSessionForApp(t)
	_, challenge := makePKCE()

	redirect := "https://customer.example/callback"
	rr := authorizeGET(e, baseAuthorizeQuery(e, redirect, challenge), accessJWT)
	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 to consent page, got %d (%s)", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/oidc/consent?req=") {
		t.Fatalf("expected redirect to /oidc/consent, got %s", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	reqID := u.Query().Get("req")
	if reqID == "" {
		t.Fatal("consent redirect has no req parameter")
	}

	// GET the consent page.
	getRR := consentGET(e, reqID, accessJWT)
	if getRR.Code != http.StatusOK {
		t.Fatalf("GET consent page expected 200, got %d (%s)", getRR.Code, getRR.Body.String())
	}
	body := getRR.Body.String()
	// Must contain app display name.
	if !strings.Contains(body, e.app.DisplayName()) {
		t.Errorf("consent page missing app display name %q; body starts: %.200s", e.app.DisplayName(), body)
	}
	// Must contain the scope bullet for "email".
	if !strings.Contains(body, "View your email address") {
		t.Errorf("consent page missing email scope description; body starts: %.200s", body)
	}
}

// =============================================================================
// 3. TestOIDCConsent_Allow_MintsAndRemembers
// =============================================================================

// POST decision=allow → code at redirect_uri; row in oidc_consents; second
// authorize goes straight through (no consent hop).
func TestOIDCConsent_Allow_MintsAndRemembers(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDCWithConsent(t, true)
	ses, accessJWT := e.seedSessionForApp(t)
	_, challenge := makePKCE()

	redirect := "https://customer.example/callback"
	rr := authorizeGET(e, baseAuthorizeQuery(e, redirect, challenge), accessJWT)
	u, _ := url.Parse(rr.Header().Get("Location"))
	reqID := u.Query().Get("req")
	if reqID == "" {
		t.Fatalf("expected redirect to consent, got %s", rr.Header().Get("Location"))
	}

	// Allow.
	postRR := consentPOST(e, reqID, "allow", accessJWT)
	if postRR.Code != http.StatusFound {
		t.Fatalf("consent allow expected 302, got %d (%s)", postRR.Code, postRR.Body.String())
	}
	postLoc, _ := url.Parse(postRR.Header().Get("Location"))
	code := postLoc.Query().Get("code")
	if code == "" {
		t.Fatalf("expected code in redirect after allow, got %s", postRR.Header().Get("Location"))
	}
	if postLoc.Query().Get("error") != "" {
		t.Errorf("unexpected error in redirect: %s", postRR.Header().Get("Location"))
	}

	// Verify oidc_consents row was written.
	scope, found, err := testEnv.Repo.GetOIDCConsent(context.Background(), ses.UserID, e.app.ID)
	if err != nil {
		t.Fatalf("GetOIDCConsent: %v", err)
	}
	if !found {
		t.Fatal("expected consent row after allow")
	}
	if !strings.Contains(scope, "openid") {
		t.Errorf("consent row scope %q missing openid", scope)
	}

	// Second authorize — should skip consent entirely.
	_, challenge2 := makePKCE()
	rr2 := authorizeGET(e, baseAuthorizeQuery(e, redirect, challenge2), accessJWT)
	if rr2.Code != http.StatusFound {
		t.Fatalf("second authorize expected 302, got %d (%s)", rr2.Code, rr2.Body.String())
	}
	loc2, _ := url.Parse(rr2.Header().Get("Location"))
	if loc2.Query().Get("code") == "" {
		t.Errorf("second authorize should skip consent and mint code, got %s", rr2.Header().Get("Location"))
	}
}

// =============================================================================
// 4. TestOIDCConsent_BroaderScope_RePrompts
// =============================================================================

// After allowing "openid", authorizing "openid email" re-prompts; after
// allowing again the row holds the union.
func TestOIDCConsent_BroaderScope_RePrompts(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDCWithConsent(t, true)
	ses, accessJWT := e.seedSessionForApp(t)
	_, challenge := makePKCE()

	redirect := "https://customer.example/callback"

	// First: authorize openid only.
	q1 := baseAuthorizeQuery(e, redirect, challenge)
	q1.Set("scope", "openid")
	rr1 := authorizeGET(e, q1, accessJWT)
	u1, _ := url.Parse(rr1.Header().Get("Location"))
	reqID1 := u1.Query().Get("req")
	if reqID1 == "" {
		t.Fatalf("expected consent redirect for first authorize, got %s", rr1.Header().Get("Location"))
	}
	// Allow the first consent.
	ar1 := consentPOST(e, reqID1, "allow", accessJWT)
	if ar1.Code != http.StatusFound || ar1.Header().Get("Location") == "" {
		t.Fatalf("first consent allow: %d %s", ar1.Code, ar1.Body.String())
	}

	// Verify row has "openid".
	scope, found, _ := testEnv.Repo.GetOIDCConsent(context.Background(), ses.UserID, e.app.ID)
	if !found || !strings.Contains(scope, "openid") {
		t.Fatalf("after first consent: found=%v scope=%q", found, scope)
	}

	// Second: authorize openid email — should re-prompt (email not in grant).
	_, challenge2 := makePKCE()
	q2 := baseAuthorizeQuery(e, redirect, challenge2)
	q2.Set("scope", "openid email")
	rr2 := authorizeGET(e, q2, accessJWT)
	if rr2.Code != http.StatusFound {
		t.Fatalf("broader scope authorize expected 302, got %d (%s)", rr2.Code, rr2.Body.String())
	}
	u2, _ := url.Parse(rr2.Header().Get("Location"))
	reqID2 := u2.Query().Get("req")
	if reqID2 == "" {
		t.Errorf("expected consent re-prompt for broader scope, got %s", rr2.Header().Get("Location"))
		// Not fatal — let's still check code absence.
	}
	if u2.Query().Get("code") != "" {
		t.Fatalf("broader scope should re-prompt, not mint code directly")
	}

	// Allow the second consent.
	ar2 := consentPOST(e, reqID2, "allow", accessJWT)
	if ar2.Code != http.StatusFound {
		t.Fatalf("second consent allow: %d %s", ar2.Code, ar2.Body.String())
	}
	loc2, _ := url.Parse(ar2.Header().Get("Location"))
	if loc2.Query().Get("code") == "" {
		t.Fatalf("second consent allow should mint code, got %s", ar2.Header().Get("Location"))
	}

	// Verify the row now holds the union.
	scope2, found2, _ := testEnv.Repo.GetOIDCConsent(context.Background(), ses.UserID, e.app.ID)
	if !found2 {
		t.Fatal("no consent row after broader scope allow")
	}
	if !strings.Contains(scope2, "openid") || !strings.Contains(scope2, "email") {
		t.Errorf("consent row should be union of openid+email, got %q", scope2)
	}
}

// =============================================================================
// 5. TestOIDCConsent_Deny_AccessDenied
// =============================================================================

// POST decision=deny → access_denied redirect; no consent row.
func TestOIDCConsent_Deny_AccessDenied(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDCWithConsent(t, true)
	ses, accessJWT := e.seedSessionForApp(t)
	_, challenge := makePKCE()

	redirect := "https://customer.example/callback"
	rr := authorizeGET(e, baseAuthorizeQuery(e, redirect, challenge), accessJWT)
	u, _ := url.Parse(rr.Header().Get("Location"))
	reqID := u.Query().Get("req")
	if reqID == "" {
		t.Fatalf("expected consent redirect, got %s", rr.Header().Get("Location"))
	}

	postRR := consentPOST(e, reqID, "deny", accessJWT)
	if postRR.Code != http.StatusFound {
		t.Fatalf("consent deny expected 302, got %d (%s)", postRR.Code, postRR.Body.String())
	}
	postLoc, _ := url.Parse(postRR.Header().Get("Location"))
	if postLoc.Query().Get("error") != "access_denied" {
		t.Errorf("expected error=access_denied, got %s", postRR.Header().Get("Location"))
	}
	if postLoc.Query().Get("code") != "" {
		t.Errorf("deny must not return a code")
	}

	// No consent row.
	_, found, err := testEnv.Repo.GetOIDCConsent(context.Background(), ses.UserID, e.app.ID)
	if err != nil {
		t.Fatalf("GetOIDCConsent: %v", err)
	}
	if found {
		t.Error("consent row must NOT exist after deny")
	}
}

// =============================================================================
// 6. TestOIDCConsent_PromptConsent_Forces
// =============================================================================

// prompt=consent forces the consent hop regardless of the toggle or an
// existing grant.
func TestOIDCConsent_PromptConsent_Forces(t *testing.T) {
	e := setupOIDCRouter(t)

	redirect := "https://customer.example/callback"

	// --- sub-test A: toggle OFF + prompt=consent → hop ---
	t.Run("toggle-off-prompt-consent", func(t *testing.T) {
		e.enableOIDCWithConsent(t, false)
		_, accessJWT := e.seedSessionForApp(t)
		_, challenge := makePKCE()

		q := baseAuthorizeQuery(e, redirect, challenge)
		q.Set("prompt", "consent")
		rr := authorizeGET(e, q, accessJWT)
		if rr.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d (%s)", rr.Code, rr.Body.String())
		}
		u, _ := url.Parse(rr.Header().Get("Location"))
		if u.Query().Get("req") == "" || !strings.Contains(rr.Header().Get("Location"), "/oidc/consent") {
			t.Errorf("prompt=consent should force hop even when toggle is off, got %s", rr.Header().Get("Location"))
		}
	})

	// --- sub-test B: toggle ON + remembered grant + prompt=consent → hop ---
	t.Run("remembered-grant-prompt-consent", func(t *testing.T) {
		e.enableOIDCWithConsent(t, true)
		ses, accessJWT := e.seedSessionForApp(t)

		// Write a remembered grant.
		if err := testEnv.Repo.UpsertOIDCConsent(context.Background(), ses.UserID, e.app.ID, "openid email"); err != nil {
			t.Fatalf("seed consent: %v", err)
		}

		_, challenge := makePKCE()
		q := baseAuthorizeQuery(e, redirect, challenge)
		q.Set("prompt", "consent")
		rr := authorizeGET(e, q, accessJWT)
		if rr.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d (%s)", rr.Code, rr.Body.String())
		}
		u, _ := url.Parse(rr.Header().Get("Location"))
		if u.Query().Get("req") == "" || !strings.Contains(rr.Header().Get("Location"), "/oidc/consent") {
			t.Errorf("prompt=consent should force hop despite existing grant, got %s", rr.Header().Get("Location"))
		}
	})
}

// =============================================================================
// 7. TestOIDCConsent_PromptNone_ConsentRequired
// =============================================================================

// prompt=none with consent required (and no grant) → consent_required error.
func TestOIDCConsent_PromptNone_ConsentRequired(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDCWithConsent(t, true)
	_, accessJWT := e.seedSessionForApp(t)
	_, challenge := makePKCE()

	redirect := "https://customer.example/callback"
	q := baseAuthorizeQuery(e, redirect, challenge)
	q.Set("prompt", "none")

	rr := authorizeGET(e, q, accessJWT)
	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d (%s)", rr.Code, rr.Body.String())
	}
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if loc.Query().Get("error") != "consent_required" {
		t.Errorf("expected error=consent_required, got Location=%s", rr.Header().Get("Location"))
	}
}

// =============================================================================
// 8. TestOIDCConsent_PendingSingleUse
// =============================================================================

// POSTing the same req twice: second POST hits the consumed/expired surface.
func TestOIDCConsent_PendingSingleUse(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDCWithConsent(t, true)
	_, accessJWT := e.seedSessionForApp(t)
	_, challenge := makePKCE()

	redirect := "https://customer.example/callback"
	rr := authorizeGET(e, baseAuthorizeQuery(e, redirect, challenge), accessJWT)
	u, _ := url.Parse(rr.Header().Get("Location"))
	reqID := u.Query().Get("req")
	if reqID == "" {
		t.Fatalf("expected consent redirect, got %s", rr.Header().Get("Location"))
	}

	// First POST — should succeed.
	post1 := consentPOST(e, reqID, "allow", accessJWT)
	if post1.Code != http.StatusFound {
		t.Fatalf("first consent POST expected 302, got %d (%s)", post1.Code, post1.Body.String())
	}
	if loc1, _ := url.Parse(post1.Header().Get("Location")); loc1.Query().Get("code") == "" {
		t.Fatalf("first POST should mint code, got %s", post1.Header().Get("Location"))
	}

	// Second POST with same req — should signal consumed/expired.
	post2 := consentPOST(e, reqID, "allow", accessJWT)
	// The handler renders the page-error (400) for an expired/consumed pending row.
	if post2.Code != http.StatusBadRequest {
		t.Errorf("second POST with consumed req expected 400, got %d (%s)", post2.Code, post2.Body.String())
	}
	body2 := post2.Body.String()
	if !strings.Contains(body2, "expired") && !strings.Contains(body2, "consumed") && !strings.Contains(body2, "already") {
		t.Errorf("consumed req error surface should mention expiry/consumed, body=%.300s", body2)
	}
}

// =============================================================================
// 9. Wrong-app binding — pending rows must be bound to their app
// =============================================================================

// setupSecondOIDCApp creates a second cookie-mode app in the same workspace
// with OIDC + consent enabled, plus a signed-in session (and access JWT)
// bound to it. Mirrors setupOIDCRouter's app fixture + seedSessionForApp.
func setupSecondOIDCApp(t *testing.T, e *oidcTestEnv) (*core.App, *core.ClientSession, string) {
	t.Helper()
	ctx := context.Background()

	accB := testEnv.CreateTestAccount(t, fmt.Sprintf("oidc-b-%s@test.example", GenerateUniqueSlug("u")))
	appB := testEnv.CreateTestApp(t, e.ws, accB)
	if _, err := testEnv.DB.Pool().Exec(ctx,
		`update apps set transport_mode = 'cookie' where id = $1`, appB.ID); err != nil {
		t.Fatalf("set transport_mode=cookie for app B: %v", err)
	}
	appB.TransportMode = core.TransportModeCookie

	empty := ""
	if err := testEnv.Repo.UpdateAppOIDCConfig(ctx, appB.ID, repo.UpdateAppOIDCConfigParams{
		Enabled:          true,
		ClientSecretHash: &empty,
		RedirectURIs:     []string{"https://customer.example/callback"},
		RequireConsent:   true,
	}); err != nil {
		t.Fatalf("enable OIDC for app B: %v", err)
	}

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx,
		fmt.Sprintf("user-b-%s@test.example", GenerateUniqueSlug("u")), appB, core.UserSourceRegistered)
	if err != nil {
		t.Fatalf("GetOrCreateUserWithMembership (app B): %v", err)
	}
	now := time.Now().UTC()
	appBID := appB.ID
	ses := &core.ClientSession{
		ID:         uuid.Must(uuid.NewV4()),
		UserID:     user.ID,
		AppID:      &appBID,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}
	if err := testEnv.Repo.InsertClientSession(ctx, ses); err != nil {
		t.Fatalf("InsertClientSession (app B): %v", err)
	}
	issuer := "http://localhost:8080/x/" + e.ws.Slug + "/apps/" + appB.ID.String()
	access, _, err := e.cas.IssueAccessToken(ses, 15*time.Minute, issuer)
	if err != nil {
		t.Fatalf("IssueAccessToken (app B): %v", err)
	}
	return appB, ses, access
}

// A pending req id minted for app A must not be presentable at app B's
// consent endpoints, even with a valid app B session. Both GET and POST
// must show the same expired/invalid surface (no wrong-app oracle) and
// no consent row may be written for app B.
func TestOIDCConsent_WrongApp_Rejected(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDCWithConsent(t, true)
	_, accessJWT := e.seedSessionForApp(t)
	_, challenge := makePKCE()

	// Start a consent flow at app A → pending req id.
	redirect := "https://customer.example/callback"
	rr := authorizeGET(e, baseAuthorizeQuery(e, redirect, challenge), accessJWT)
	u, _ := url.Parse(rr.Header().Get("Location"))
	reqID := u.Query().Get("req")
	if reqID == "" {
		t.Fatalf("expected consent redirect at app A, got %s", rr.Header().Get("Location"))
	}

	appB, sesB, accessJWTB := setupSecondOIDCApp(t, e)

	// GET app B's consent page with app A's req id + valid app B session.
	getReq := httptest.NewRequest("GET",
		"/x/"+e.ws.Slug+"/apps/"+appB.ID.String()+"/oidc/consent?req="+reqID, nil)
	getReq.Header.Set("Authorization", "Bearer "+accessJWTB)
	getRR := httptest.NewRecorder()
	e.router.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusBadRequest {
		t.Errorf("GET wrong-app consent expected 400, got %d (%s)", getRR.Code, getRR.Body.String())
	}
	getBody := getRR.Body.String()
	if !strings.Contains(getBody, "expired") && !strings.Contains(getBody, "consumed") && !strings.Contains(getBody, "already") {
		t.Errorf("wrong-app GET should show the expired/consumed surface, body=%.300s", getBody)
	}

	// POST decision=allow at app B with app A's req id.
	form := url.Values{"req": {reqID}, "decision": {"allow"}}
	postReq := httptest.NewRequest("POST",
		"/x/"+e.ws.Slug+"/apps/"+appB.ID.String()+"/oidc/consent",
		strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Authorization", "Bearer "+accessJWTB)
	postRR := httptest.NewRecorder()
	e.router.ServeHTTP(postRR, postReq)
	if postRR.Code != http.StatusBadRequest {
		t.Errorf("POST wrong-app consent expected 400, got %d (%s)", postRR.Code, postRR.Body.String())
	}
	postBody := postRR.Body.String()
	if !strings.Contains(postBody, "expired") && !strings.Contains(postBody, "consumed") && !strings.Contains(postBody, "already") {
		t.Errorf("wrong-app POST should show the expired/consumed surface, body=%.300s", postBody)
	}

	// No consent row may exist for app B.
	_, found, err := testEnv.Repo.GetOIDCConsent(context.Background(), sesB.UserID, appB.ID)
	if err != nil {
		t.Fatalf("GetOIDCConsent (app B): %v", err)
	}
	if found {
		t.Error("consent row must NOT be written for app B from a wrong-app req")
	}
}

// =============================================================================
// 10. TestOIDCConsent_ResumeInterposition_EndToEnd
// =============================================================================

// Pins the full unauthenticated path through the consent seam:
// authorize (login_hint) → login shim (hint survives) → sign-in →
// resume → consent hop → consent page → allow → code at redirect_uri.
func TestOIDCConsent_ResumeInterposition_EndToEnd(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDCWithConsent(t, true)
	_, challenge := makePKCE()

	// 1. Unauthenticated authorize with login_hint → 302 to login shim.
	redirect := "https://customer.example/callback"
	q := baseAuthorizeQuery(e, redirect, challenge)
	q.Set("login_hint", "hint@example.com")
	rr := authorizeGET(e, q, "")
	if rr.Code != http.StatusFound {
		t.Fatalf("unauthenticated authorize expected 302, got %d (%s)", rr.Code, rr.Body.String())
	}
	loginLoc := rr.Header().Get("Location")
	loginURL, _ := url.Parse(loginLoc)
	reqID := loginURL.Query().Get("req")
	if reqID == "" || !strings.Contains(loginURL.Path, "/oidc/login") {
		t.Fatalf("expected login redirect with req, got %s", loginLoc)
	}

	// 2. GET the shim — login_hint must survive into the page.
	shimReq := httptest.NewRequest("GET", loginLoc, nil)
	shimRR := httptest.NewRecorder()
	e.router.ServeHTTP(shimRR, shimReq)
	if shimRR.Code != http.StatusOK {
		t.Fatalf("login shim expected 200, got %d (%s)", shimRR.Code, shimRR.Body.String())
	}
	if !strings.Contains(shimRR.Body.String(), "hint@example.com") {
		t.Errorf("login shim lost login_hint; body starts: %.300s", shimRR.Body.String())
	}

	// 3. Simulate sign-in (same way other resume tests authenticate).
	ses, accessJWT := e.seedSessionForApp(t)

	// 4. Resume → must interpose the consent hop, not mint a code.
	resReq := httptest.NewRequest("GET",
		"/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/authorize/resume?req="+reqID, nil)
	resReq.Header.Set("Authorization", "Bearer "+accessJWT)
	resRR := httptest.NewRecorder()
	e.router.ServeHTTP(resRR, resReq)
	if resRR.Code != http.StatusFound {
		t.Fatalf("resume expected 302, got %d (%s)", resRR.Code, resRR.Body.String())
	}
	consentLoc, _ := url.Parse(resRR.Header().Get("Location"))
	if !strings.Contains(consentLoc.Path, "/oidc/consent") {
		t.Fatalf("resume should redirect to consent, got %s", resRR.Header().Get("Location"))
	}
	consentReqID := consentLoc.Query().Get("req")
	if consentReqID == "" {
		t.Fatal("consent redirect from resume has no req parameter")
	}

	// 5. GET the consent page: 200 with app name + scope bullets.
	getRR := consentGET(e, consentReqID, accessJWT)
	if getRR.Code != http.StatusOK {
		t.Fatalf("consent page expected 200, got %d (%s)", getRR.Code, getRR.Body.String())
	}
	body := getRR.Body.String()
	if !strings.Contains(body, e.app.DisplayName()) {
		t.Errorf("consent page missing app display name %q; body starts: %.300s", e.app.DisplayName(), body)
	}
	if !strings.Contains(body, "View your email address") {
		t.Errorf("consent page missing email scope bullet; body starts: %.300s", body)
	}

	// 6. POST allow → 302 to redirect_uri with code.
	postRR := consentPOST(e, consentReqID, "allow", accessJWT)
	if postRR.Code != http.StatusFound {
		t.Fatalf("consent allow expected 302, got %d (%s)", postRR.Code, postRR.Body.String())
	}
	postLoc, _ := url.Parse(postRR.Header().Get("Location"))
	if !strings.HasPrefix(postRR.Header().Get("Location"), redirect) {
		t.Errorf("allow should land on redirect_uri, got %s", postRR.Header().Get("Location"))
	}
	if postLoc.Query().Get("code") == "" {
		t.Fatalf("expected code after allow, got %s", postRR.Header().Get("Location"))
	}

	// 7. Consent row was written for the signed-in user.
	scope, found, err := testEnv.Repo.GetOIDCConsent(context.Background(), ses.UserID, e.app.ID)
	if err != nil {
		t.Fatalf("GetOIDCConsent: %v", err)
	}
	if !found {
		t.Fatal("expected consent row after end-to-end allow")
	}
	if !strings.Contains(scope, "openid") {
		t.Errorf("consent row scope %q missing openid", scope)
	}
}

// =============================================================================
// 11. TestOIDCConsent_Unauthenticated_NoOracle
// =============================================================================

// Unauthenticated callers must not be able to probe pending-req liveness
// via the consent endpoints: GET and POST without a session must return
// byte-identical responses for a LIVE req id and a random one (the
// login_required surface), pinning the session-before-peek ordering.
func TestOIDCConsent_Unauthenticated_NoOracle(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDCWithConsent(t, true)
	_, accessJWT := e.seedSessionForApp(t)
	_, challenge := makePKCE()

	// Mint a LIVE pending req via an authenticated authorize → consent hop.
	redirect := "https://customer.example/callback"
	rr := authorizeGET(e, baseAuthorizeQuery(e, redirect, challenge), accessJWT)
	u, _ := url.Parse(rr.Header().Get("Location"))
	liveReq := u.Query().Get("req")
	if liveReq == "" || !strings.Contains(u.Path, "/oidc/consent") {
		t.Fatalf("expected consent redirect with live req, got %s", rr.Header().Get("Location"))
	}
	deadReq := uuid.Must(uuid.NewV4()).String()

	// GET without a session: live vs random must be indistinguishable.
	liveGET := consentGET(e, liveReq, "")
	deadGET := consentGET(e, deadReq, "")
	if liveGET.Code != deadGET.Code {
		t.Errorf("GET status oracle: live=%d dead=%d", liveGET.Code, deadGET.Code)
	}
	if liveGET.Body.String() != deadGET.Body.String() {
		t.Errorf("GET body oracle:\n live: %.300s\n dead: %.300s", liveGET.Body.String(), deadGET.Body.String())
	}
	if !strings.Contains(liveGET.Body.String(), "login_required") {
		t.Errorf("unauthenticated GET should show the login_required surface, body=%.300s", liveGET.Body.String())
	}

	// POST without a session: same property.
	livePOST := consentPOST(e, liveReq, "allow", "")
	deadPOST := consentPOST(e, deadReq, "allow", "")
	if livePOST.Code != deadPOST.Code {
		t.Errorf("POST status oracle: live=%d dead=%d", livePOST.Code, deadPOST.Code)
	}
	if livePOST.Body.String() != deadPOST.Body.String() {
		t.Errorf("POST body oracle:\n live: %.300s\n dead: %.300s", livePOST.Body.String(), deadPOST.Body.String())
	}
	if !strings.Contains(livePOST.Body.String(), "login_required") {
		t.Errorf("unauthenticated POST should show the login_required surface, body=%.300s", livePOST.Body.String())
	}

	// The unauthenticated probes must not have consumed the live row:
	// the legitimate, authenticated POST still succeeds.
	allowRR := consentPOST(e, liveReq, "allow", accessJWT)
	if allowRR.Code != http.StatusFound {
		t.Fatalf("authenticated allow after probes expected 302, got %d (%s)", allowRR.Code, allowRR.Body.String())
	}
	if loc, _ := url.Parse(allowRR.Header().Get("Location")); loc.Query().Get("code") == "" {
		t.Errorf("authenticated allow should still mint a code, got %s", allowRR.Header().Get("Location"))
	}
}

// =============================================================================
// 12. Stage binding — login-stage reqs must not be spendable at /oidc/consent
// =============================================================================

// A LOGIN-stage pending req (minted because prompt=login forced
// re-authentication) must not be presentable at the consent endpoints.
// Otherwise a user holding a stale-but-valid session can lift the req id
// from the login-shim redirect and POST it straight to
// /oidc/consent?decision=allow, minting a code without ever
// re-authenticating. Both GET and POST must show the same
// expired/already-handled surface as a dead req (no stage oracle), the
// POST must not mint a code, and no consent row may be written.
func TestOIDCConsent_LoginStageReq_RejectedAtConsent(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDCWithConsent(t, true)
	ses, accessJWT := e.seedSessionForApp(t)
	_, challenge := makePKCE()

	// prompt=login while holding a valid session → forced re-auth path →
	// 302 to the login shim carrying a LOGIN-stage req id.
	redirect := "https://customer.example/callback"
	q := baseAuthorizeQuery(e, redirect, challenge)
	q.Set("prompt", "login")
	rr := authorizeGET(e, q, accessJWT)
	if rr.Code != http.StatusFound {
		t.Fatalf("prompt=login authorize expected 302, got %d (%s)", rr.Code, rr.Body.String())
	}
	u, _ := url.Parse(rr.Header().Get("Location"))
	reqID := u.Query().Get("req")
	if reqID == "" || !strings.Contains(u.Path, "/oidc/login") {
		t.Fatalf("expected login-shim redirect with req, got %s", rr.Header().Get("Location"))
	}

	// GET the consent page with the login-stage req (still holding the
	// valid session) — must hit the expired/already-handled surface.
	getRR := consentGET(e, reqID, accessJWT)
	if getRR.Code != http.StatusBadRequest {
		t.Errorf("GET consent with login-stage req expected 400, got %d (%s)", getRR.Code, getRR.Body.String())
	}
	getBody := getRR.Body.String()
	if !strings.Contains(getBody, "expired") && !strings.Contains(getBody, "already") {
		t.Errorf("login-stage GET should show the expired/already-handled surface, body=%.300s", getBody)
	}

	// POST decision=allow with the login-stage req — this is the bypass.
	postRR := consentPOST(e, reqID, "allow", accessJWT)
	if postRR.Code != http.StatusBadRequest {
		t.Errorf("POST consent with login-stage req expected 400, got %d (%s)", postRR.Code, postRR.Body.String())
	}
	if loc := postRR.Header().Get("Location"); loc != "" {
		if pu, _ := url.Parse(loc); pu != nil && pu.Query().Get("code") != "" {
			t.Errorf("login-stage req must NOT mint a code, got %s", loc)
		}
	}
	postBody := postRR.Body.String()
	if !strings.Contains(postBody, "expired") && !strings.Contains(postBody, "already") {
		t.Errorf("login-stage POST should show the expired/already-handled surface, body=%.300s", postBody)
	}

	// No consent row may have been written.
	_, found, err := testEnv.Repo.GetOIDCConsent(context.Background(), ses.UserID, e.app.ID)
	if err != nil {
		t.Fatalf("GetOIDCConsent: %v", err)
	}
	if found {
		t.Error("consent row must NOT exist after rejected login-stage POST")
	}
}

// =============================================================================
// 13. Stage binding — consent-stage reqs must not be spendable at /resume
// =============================================================================

// A CONSENT-stage pending req (minted at the consent interposition point)
// must not be presentable at /oidc/authorize/resume: Resume would skip the
// pending consent decision entirely. Expect Resume's expired/consumed
// surface, not a code or a fresh consent hop.
func TestOIDCAuthorizeResume_ConsentStageReq_Rejected(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDCWithConsent(t, true)
	_, accessJWT := e.seedSessionForApp(t)
	_, challenge := makePKCE()

	// Authenticated authorize with the toggle on → 302 to the consent
	// page carrying a CONSENT-stage req id.
	redirect := "https://customer.example/callback"
	rr := authorizeGET(e, baseAuthorizeQuery(e, redirect, challenge), accessJWT)
	if rr.Code != http.StatusFound {
		t.Fatalf("authenticated authorize expected 302, got %d (%s)", rr.Code, rr.Body.String())
	}
	u, _ := url.Parse(rr.Header().Get("Location"))
	reqID := u.Query().Get("req")
	if reqID == "" || !strings.Contains(u.Path, "/oidc/consent") {
		t.Fatalf("expected consent redirect with req, got %s", rr.Header().Get("Location"))
	}

	// Feed the consent-stage req to RESUME.
	resReq := httptest.NewRequest("GET",
		"/x/"+e.ws.Slug+"/apps/"+e.app.ID.String()+"/oidc/authorize/resume?req="+reqID, nil)
	resReq.Header.Set("Authorization", "Bearer "+accessJWT)
	resRR := httptest.NewRecorder()
	e.router.ServeHTTP(resRR, resReq)
	if resRR.Code != http.StatusBadRequest {
		t.Errorf("resume with consent-stage req expected 400, got %d (%s)", resRR.Code, resRR.Body.String())
	}
	if loc := resRR.Header().Get("Location"); loc != "" {
		if pu, _ := url.Parse(loc); pu != nil && pu.Query().Get("code") != "" {
			t.Errorf("consent-stage req at resume must NOT mint a code, got %s", loc)
		}
	}
	resBody := resRR.Body.String()
	if !strings.Contains(resBody, "expired") && !strings.Contains(resBody, "consumed") && !strings.Contains(resBody, "already") {
		t.Errorf("consent-stage resume should show the expired/consumed surface, body=%.300s", resBody)
	}
}

// =============================================================================
// 14. User binding — consent-stage reqs are bound to the rendering user
// =============================================================================

// A CONSENT-stage pending req minted while user A was signed in must not be
// presentable by user B's session (same app), GET or POST. Otherwise a
// cross-site form POST riding B's cookies could approve A's pending consent
// (CSRF defense-in-depth beyond SameSite=Lax). Both endpoints must show the
// same expired/already-handled surface as a dead req (no oracle), the POST
// must not mint a code, and no consent row may be written for either user.
//
// Note: B's POST consumes (burns) the row — an acceptable self-DoS-equivalent,
// consistent with the wrong-app burn — so this test does NOT try to complete
// user A's flow afterward.
func TestOIDCConsent_BoundUser_OtherUserRejected(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDCWithConsent(t, true)
	sesA, accessJWTA := e.seedSessionForApp(t)
	_, challenge := makePKCE()

	// User A: authenticated authorize → 302 to consent page with req id.
	redirect := "https://customer.example/callback"
	rr := authorizeGET(e, baseAuthorizeQuery(e, redirect, challenge), accessJWTA)
	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 to consent page, got %d (%s)", rr.Code, rr.Body.String())
	}
	u, _ := url.Parse(rr.Header().Get("Location"))
	reqID := u.Query().Get("req")
	if reqID == "" || !strings.Contains(u.Path, "/oidc/consent") {
		t.Fatalf("expected consent redirect with req, got %s", rr.Header().Get("Location"))
	}

	// User B: a second seedSessionForApp call mints a DISTINCT user with
	// its own session in the same app.
	sesB, accessJWTB := e.seedSessionForApp(t)
	if sesB.UserID == sesA.UserID {
		t.Fatal("fixture error: expected two distinct users")
	}

	// GET the consent page as user B — must hit the dead-req surface.
	getRR := consentGET(e, reqID, accessJWTB)
	if getRR.Code != http.StatusBadRequest {
		t.Errorf("GET consent as other user expected 400, got %d (%s)", getRR.Code, getRR.Body.String())
	}
	getBody := getRR.Body.String()
	if !strings.Contains(getBody, "expired") && !strings.Contains(getBody, "consumed") && !strings.Contains(getBody, "already") {
		t.Errorf("other-user GET should show the expired/already-handled surface, body=%.300s", getBody)
	}

	// POST decision=allow as user B — must not mint a code.
	postRR := consentPOST(e, reqID, "allow", accessJWTB)
	if postRR.Code != http.StatusBadRequest {
		t.Errorf("POST consent as other user expected 400, got %d (%s)", postRR.Code, postRR.Body.String())
	}
	if loc := postRR.Header().Get("Location"); loc != "" {
		if pu, _ := url.Parse(loc); pu != nil && pu.Query().Get("code") != "" {
			t.Errorf("other-user POST must NOT mint a code, got %s", loc)
		}
	}
	postBody := postRR.Body.String()
	if !strings.Contains(postBody, "expired") && !strings.Contains(postBody, "consumed") && !strings.Contains(postBody, "already") {
		t.Errorf("other-user POST should show the expired/already-handled surface, body=%.300s", postBody)
	}

	// No consent row may exist for EITHER user.
	_, foundB, err := testEnv.Repo.GetOIDCConsent(context.Background(), sesB.UserID, e.app.ID)
	if err != nil {
		t.Fatalf("GetOIDCConsent (user B): %v", err)
	}
	if foundB {
		t.Error("consent row must NOT be written for user B")
	}
	_, foundA, err := testEnv.Repo.GetOIDCConsent(context.Background(), sesA.UserID, e.app.ID)
	if err != nil {
		t.Fatalf("GetOIDCConsent (user A): %v", err)
	}
	if foundA {
		t.Error("consent row must NOT be written for user A")
	}
}

// A pending req id minted at app A's /authorize (unauthenticated path) must
// not be resumable at app B's /authorize/resume, even with a valid app B
// session. Same expired/consumed surface as a dead req id.
func TestOIDCAuthorizeResume_WrongApp_Rejected(t *testing.T) {
	e := setupOIDCRouter(t)
	e.enableOIDCWithConsent(t, true)
	_, challenge := makePKCE()

	// Unauthenticated authorize at app A → login redirect carrying req id.
	redirect := "https://customer.example/callback"
	rr := authorizeGET(e, baseAuthorizeQuery(e, redirect, challenge), "")
	if rr.Code != http.StatusFound {
		t.Fatalf("unauthenticated authorize expected 302, got %d (%s)", rr.Code, rr.Body.String())
	}
	u, _ := url.Parse(rr.Header().Get("Location"))
	reqID := u.Query().Get("req")
	if reqID == "" || !strings.Contains(u.Path, "/oidc/login") {
		t.Fatalf("expected login redirect with req at app A, got %s", rr.Header().Get("Location"))
	}

	appB, _, accessJWTB := setupSecondOIDCApp(t, e)

	// Resume at app B with app A's req id and a valid app B session.
	resReq := httptest.NewRequest("GET",
		"/x/"+e.ws.Slug+"/apps/"+appB.ID.String()+"/oidc/authorize/resume?req="+reqID, nil)
	resReq.Header.Set("Authorization", "Bearer "+accessJWTB)
	resRR := httptest.NewRecorder()
	e.router.ServeHTTP(resRR, resReq)
	if resRR.Code != http.StatusBadRequest {
		t.Errorf("wrong-app resume expected 400, got %d (%s)", resRR.Code, resRR.Body.String())
	}
	resBody := resRR.Body.String()
	if !strings.Contains(resBody, "expired") && !strings.Contains(resBody, "consumed") && !strings.Contains(resBody, "already") {
		t.Errorf("wrong-app resume should show the expired/consumed surface, body=%.300s", resBody)
	}
}
