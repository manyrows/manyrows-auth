package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/core"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

func setupBFPAdminRouter(t *testing.T) *chi.Mux {
	t.Helper()
	svc := NewTestServices(t)
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)
	wsRouter.Put("/projects/{projectId}/apps/{appId}/brute-force-protection-config", svc.Handler.HandleUpdateAppBruteForceProtectionConfig)
	return r
}

func putBFPConfig(t *testing.T, router *chi.Mux, ws *core.Workspace, project *core.Project, appID uuid.UUID, claims core.TokenClaims, body any) *httptest.ResponseRecorder {
	t.Helper()
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPut,
		"/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/brute-force-protection-config",
		bytes.NewReader(bodyBytes))
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func TestAdminBFPConfig_Disable(t *testing.T) {
	router := setupBFPAdminRouter(t)
	acc := testEnv.CreateTestAccount(t, "bfp-adm-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "BFP Adm WS", GenerateUniqueSlug("ws"))
	proj := testEnv.CreateTestProject(t, ws, acc, "Test", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, proj.ID, uuid.Nil, "BFP Adm App")
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	rr := putBFPConfig(t, router, ws, proj, appID, claims, map[string]any{"enabled": false})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		BruteForceProtectionEnabled bool `json:"bruteForceProtectionEnabled"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.BruteForceProtectionEnabled {
		t.Fatalf("expected bruteForceProtectionEnabled=false after disable")
	}

	rr = putBFPConfig(t, router, ws, proj, appID, claims, map[string]any{"enabled": true})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on re-enable, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal re-enable: %v", err)
	}
	if !resp.BruteForceProtectionEnabled {
		t.Fatalf("expected bruteForceProtectionEnabled=true after re-enable")
	}
}

func TestAdminBFPConfig_MissingEnabled(t *testing.T) {
	router := setupBFPAdminRouter(t)
	acc := testEnv.CreateTestAccount(t, "bfp-adm2-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "BFP Adm WS2", GenerateUniqueSlug("ws"))
	proj := testEnv.CreateTestProject(t, ws, acc, "Test", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, proj.ID, uuid.Nil, "BFP Adm App2")
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	rr := putBFPConfig(t, router, ws, proj, appID, claims, map[string]any{})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing enabled, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("invalidRequest")) {
		t.Fatalf("expected invalidRequest error key, got %s", rr.Body.String())
	}
}

func TestAdminBFPConfig_UnknownApp(t *testing.T) {
	router := setupBFPAdminRouter(t)
	acc := testEnv.CreateTestAccount(t, "bfp-adm3-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "BFP Adm WS3", GenerateUniqueSlug("ws"))
	proj := testEnv.CreateTestProject(t, ws, acc, "Test", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	rr := putBFPConfig(t, router, ws, proj, uuid.Must(uuid.NewV4()), claims, map[string]any{"enabled": false})
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown app, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("appNotFound")) {
		t.Fatalf("expected appNotFound error key, got %s", rr.Body.String())
	}
}
