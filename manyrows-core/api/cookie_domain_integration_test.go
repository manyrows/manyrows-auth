package api_test

// Round-trip tests for the workspace + per-app cookie-domain admin
// handlers: PUT /admin/workspace/{ws}/cookie-domain and
// PUT /admin/workspace/{ws}/projects/{p}/apps/{a}/cookie-domain.
//
// Verifies persistence, public-suffix rejection, and the inheritance
// model (app override beats workspace; clearing falls back to ws).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/core"
)

func putCookieDomain(t *testing.T, router http.Handler, url string, claims core.TokenClaims, body any) *httptest.ResponseRecorder {
	t.Helper()
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func wsCookieDomainURL(wsID string) string {
	return "/admin/workspace/" + wsID + "/cookie-domain"
}

func appCookieDomainURL(wsID, projID, appID string) string {
	return "/admin/workspace/" + wsID + "/projects/" + projID + "/apps/" + appID + "/cookie-domain"
}

// =====================
// Workspace cookie domain
// =====================

func TestWorkspaceCookieDomain_PersistsAndClears(t *testing.T) {
	svc := NewTestServices(t)
	router, wsRouter := NewAdminWorkspaceRouter(t, svc)
	wsRouter.Put("/cookie-domain", svc.Handler.HandleUpdateWorkspaceCookieDomain)

	acc := testEnv.CreateTestAccount(t, "wsdom-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	// Set
	rr := putCookieDomain(t, router, wsCookieDomainURL(ws.ID.String()), claims,
		map[string]any{"cookieDomain": ".acme.com"})
	if rr.Code != http.StatusOK {
		t.Fatalf("set: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	got, _, err := testEnv.Repo.GetWorkspaceByID(context.Background(), ws.ID)
	if err != nil {
		t.Fatalf("reload workspace: %v", err)
	}
	if got.CookieDomain == nil || *got.CookieDomain != ".acme.com" {
		t.Errorf("cookie domain not persisted: got %v", got.CookieDomain)
	}

	// Clear (empty string should null the column out)
	rr = putCookieDomain(t, router, wsCookieDomainURL(ws.ID.String()), claims,
		map[string]any{"cookieDomain": ""})
	if rr.Code != http.StatusOK {
		t.Fatalf("clear: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	got2, _, _ := testEnv.Repo.GetWorkspaceByID(context.Background(), ws.ID)
	if got2.CookieDomain != nil {
		t.Errorf("cookie domain not cleared: got %v", got2.CookieDomain)
	}
}

func TestWorkspaceCookieDomain_RejectsPublicSuffix(t *testing.T) {
	svc := NewTestServices(t)
	router, wsRouter := NewAdminWorkspaceRouter(t, svc)
	wsRouter.Put("/cookie-domain", svc.Handler.HandleUpdateWorkspaceCookieDomain)

	acc := testEnv.CreateTestAccount(t, "wsdom-bad-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	bad := []string{".github.io", "vercel.app", "netlify.app", "pages.dev", "herokuapp.com"}
	for _, v := range bad {
		t.Run(v, func(t *testing.T) {
			rr := putCookieDomain(t, router, wsCookieDomainURL(ws.ID.String()), claims,
				map[string]any{"cookieDomain": v})
			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400 for %q, got %d", v, rr.Code)
			}
		})
	}
}

// =====================
// App cookie domain (override)
// =====================

func TestAppCookieDomain_OverridesWorkspace(t *testing.T) {
	svc := NewTestServices(t)
	router, wsRouter := NewAdminWorkspaceRouter(t, svc)
	wsRouter.Put("/cookie-domain", svc.Handler.HandleUpdateWorkspaceCookieDomain)
	wsRouter.Put("/projects/{projectId}/apps/{appId}/cookie-domain", svc.Handler.HandleUpdateAppCookieDomain)

	acc := testEnv.CreateTestAccount(t, "appdom-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	// Set workspace value first.
	if rr := putCookieDomain(t, router, wsCookieDomainURL(ws.ID.String()), claims,
		map[string]any{"cookieDomain": ".acme.com"}); rr.Code != http.StatusOK {
		t.Fatalf("workspace set: %d", rr.Code)
	}

	// Set app override.
	rr := putCookieDomain(t, router, appCookieDomainURL(ws.ID.String(), app.ProjectID.String(), app.ID.String()), claims,
		map[string]any{"cookieDomain": ".widgets.io"})
	if rr.Code != http.StatusOK {
		t.Fatalf("app set: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	got, err := testEnv.Repo.GetAppByID(context.Background(), app.ID)
	if err != nil {
		t.Fatalf("reload app: %v", err)
	}
	if got.CookieDomain == nil || *got.CookieDomain != ".widgets.io" {
		t.Errorf("app cookie domain not persisted: got %v", got.CookieDomain)
	}

	// Clear app override → falls back to workspace.
	rr = putCookieDomain(t, router, appCookieDomainURL(ws.ID.String(), app.ProjectID.String(), app.ID.String()), claims,
		map[string]any{"cookieDomain": ""})
	if rr.Code != http.StatusOK {
		t.Fatalf("clear app: %d", rr.Code)
	}
	got2, _ := testEnv.Repo.GetAppByID(context.Background(), app.ID)
	if got2.CookieDomain != nil {
		t.Errorf("app cookie domain not cleared: got %v", got2.CookieDomain)
	}
}

func TestAppCookieDomain_RejectsPublicSuffix(t *testing.T) {
	svc := NewTestServices(t)
	router, wsRouter := NewAdminWorkspaceRouter(t, svc)
	wsRouter.Put("/projects/{projectId}/apps/{appId}/cookie-domain", svc.Handler.HandleUpdateAppCookieDomain)

	acc := testEnv.CreateTestAccount(t, "appdom-bad-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	rr := putCookieDomain(t, router, appCookieDomainURL(ws.ID.String(), app.ProjectID.String(), app.ID.String()), claims,
		map[string]any{"cookieDomain": ".github.io"})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for github.io, got %d: %s", rr.Code, rr.Body.String())
	}
}
