package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"manyrows-core/core"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// =====================
// Admin /qr-sign-in-config tests
// =====================

func setupQRAdminRouter(t *testing.T) *chi.Mux {
	t.Helper()
	svc := NewTestServices(t)
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)
	wsRouter.Put("/products/{productId}/apps/{appId}/qr-sign-in-config", svc.Handler.HandleUpdateAppQRSignInConfig)
	return r
}

func createQRAppFixture(t *testing.T) (*core.Account, *core.Workspace, *core.Product, uuid.UUID, *core.Session, core.TokenClaims) {
	t.Helper()
	acc := testEnv.CreateTestAccount(t, "qr-admin-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "QR Admin WS", GenerateUniqueSlug("ws"))
	proj := testEnv.CreateTestProduct(t, ws, acc, "Test", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, proj.ID, uuid.Nil, "QR Admin App")
	sess, claims := testEnv.CreateTestSession(t, acc)
	return acc, ws, proj, appID, sess, claims
}

func putQRConfig(t *testing.T, router *chi.Mux, ws *core.Workspace, project *core.Product, appID uuid.UUID, claims core.TokenClaims, body any) *httptest.ResponseRecorder {
	t.Helper()
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPut,
		"/admin/workspace/"+ws.ID.String()+"/products/"+project.ID.String()+"/apps/"+appID.String()+"/qr-sign-in-config",
		bytes.NewReader(bodyBytes))
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func TestAdminQRConfig_RejectsEnableWithoutAppURL(t *testing.T) {
	router := setupQRAdminRouter(t)
	_, ws, project, appID, _, claims := createQRAppFixture(t)

	rr := putQRConfig(t, router, ws, project, appID, claims, map[string]any{"enabled": true})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without app_url, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("qrSignInRequiresAppURL")) {
		t.Fatalf("expected qrSignInRequiresAppURL error, got %s", rr.Body.String())
	}
}

func TestAdminQRConfig_EnableSucceedsWithAppURL(t *testing.T) {
	router := setupQRAdminRouter(t)
	_, ws, project, appID, _, claims := createQRAppFixture(t)

	// Set app_url first.
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`update apps set app_url = $2 where id = $1`,
		appID, "https://customer.example"); err != nil {
		t.Fatalf("set app_url: %v", err)
	}

	rr := putQRConfig(t, router, ws, project, appID, claims, map[string]any{"enabled": true})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		QRSignInEnabled bool   `json:"qrSignInEnabled"`
		QRSignInURL     string `json:"qrSignInUrl"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.QRSignInEnabled {
		t.Fatalf("expected qrSignInEnabled=true")
	}
	if resp.QRSignInURL == "" {
		t.Fatalf("qrSignInUrl should be populated when enabled")
	}
}

// TestAdminQRConfig_DisableAlwaysAllowed proves the guard only fires
// on enable — admin can flip OFF regardless of app_url state, even
// after the field is cleared.
func TestAdminQRConfig_DisableAlwaysAllowed(t *testing.T) {
	router := setupQRAdminRouter(t)
	_, ws, project, appID, _, claims := createQRAppFixture(t)

	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`update apps set app_url = $2 where id = $1`,
		appID, "https://customer.example"); err != nil {
		t.Fatalf("set app_url: %v", err)
	}

	// Enable first.
	if rr := putQRConfig(t, router, ws, project, appID, claims, map[string]any{"enabled": true}); rr.Code != http.StatusOK {
		t.Fatalf("enable: %d", rr.Code)
	}

	// Clear app_url — disabling should still work.
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`update apps set app_url = null where id = $1`, appID); err != nil {
		t.Fatalf("clear app_url: %v", err)
	}

	rr := putQRConfig(t, router, ws, project, appID, claims, map[string]any{"enabled": false})
	if rr.Code != http.StatusOK {
		t.Fatalf("disable should still work with no app_url, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		QRSignInEnabled bool `json:"qrSignInEnabled"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.QRSignInEnabled {
		t.Fatalf("expected qrSignInEnabled=false after disable")
	}
}
