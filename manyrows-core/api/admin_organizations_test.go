package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/core"

	"github.com/go-chi/chi/v5"
)

func setupAdminOrgRouter(t *testing.T) (*chi.Mux, *TestServices) {
	t.Helper()
	svc := NewTestServices(t)
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)
	wsRouter.Put("/projects/{projectId}/apps/{appId}/organizations-enabled", svc.Handler.HandleUpdateAppOrganizationsEnabled)
	return r, svc
}

func adminAppOrgBase(ws *core.Workspace, app *core.App) string {
	return "/admin/workspace/" + ws.ID.String() + "/projects/" + app.ProjectID.String() + "/apps/" + app.ID.String()
}

func TestAdminOrgs_EnableToggle(t *testing.T) {
	ctx := context.Background()
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "aoe-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	put := func(enabled bool) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"organizationsEnabled": enabled})
		req := httptest.NewRequest(http.MethodPut, adminAppOrgBase(ws, app)+"/organizations-enabled", bytes.NewReader(body))
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	rr := put(true)
	if rr.Code != http.StatusOK {
		t.Fatalf("enable: expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		OrganizationsEnabled bool `json:"organizationsEnabled"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if !resp.OrganizationsEnabled {
		t.Fatalf("expected organizationsEnabled=true in response")
	}
	reloaded, err := testEnv.Repo.GetAppByID(ctx, app.ID)
	if err != nil || !reloaded.OrganizationsEnabled {
		t.Fatalf("expected DB flag true, err=%v", err)
	}

	rr = put(false)
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if rr.Code != http.StatusOK || resp.OrganizationsEnabled {
		t.Fatalf("disable: expected 200 + false, got %d %v", rr.Code, resp.OrganizationsEnabled)
	}
}

func TestAdminOrgs_EnableMissingField_400(t *testing.T) {
	router, _ := setupAdminOrgRouter(t)
	acc := testEnv.CreateTestAccount(t, "aoe2-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	req := httptest.NewRequest(http.MethodPut, adminAppOrgBase(ws, app)+"/organizations-enabled", bytes.NewReader([]byte(`{}`)))
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing field, got %d (%s)", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("error.badRequest")) {
		t.Fatalf("expected error.badRequest, got %s", rr.Body.String())
	}
}
