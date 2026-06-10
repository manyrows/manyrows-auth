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
