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
// Admin /oidc-config tests
// =====================

func setupOIDCAdminRouter(t *testing.T) *chi.Mux {
	t.Helper()
	svc := NewTestServices(t)
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)
	wsRouter.Get("/projects/{projectId}/apps/{appId}/oidc-config", svc.Handler.HandleGetAppOIDCConfig)
	wsRouter.Put("/projects/{projectId}/apps/{appId}/oidc-config", svc.Handler.HandleUpdateAppOIDCConfig)
	return r
}

// createOIDCAppFixture creates an account, workspace, app already in
// cookie transport mode (the OIDC pre-req) and returns everything the
// caller needs to drive admin requests.
func createOIDCAppFixture(t *testing.T) (*core.Account, *core.Workspace, *core.Project, uuid.UUID, *core.Session, core.TokenClaims) {
	t.Helper()
	acc := testEnv.CreateTestAccount(t, "oidc-admin-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "OIDC Admin WS", GenerateUniqueSlug("ws"))
	proj := testEnv.CreateTestProject(t, ws, acc, "Test", GenerateUniqueSlug("proj"))

	// Build app + flip to cookie mode for OIDC.
	appID := createTestApp(t, ws.ID, proj.ID, uuid.Nil, "OIDC Admin App")
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`update apps set transport_mode = 'cookie' where id = $1`, appID); err != nil {
		t.Fatalf("set transport_mode=cookie: %v", err)
	}

	sess, claims := testEnv.CreateTestSession(t, acc)
	return acc, ws, proj, appID, sess, claims
}

func putOIDCConfig(t *testing.T, router *chi.Mux, ws *core.Workspace, project *core.Project, appID uuid.UUID, claims core.TokenClaims, body any) *httptest.ResponseRecorder {
	t.Helper()
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPut,
		"/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/oidc-config",
		bytes.NewReader(bodyBytes))
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func TestAdminOIDCConfig_EnableAndGenerateSecret(t *testing.T) {
	router := setupOIDCAdminRouter(t)
	_, ws, project, appID, _, claims := createOIDCAppFixture(t)

	body := map[string]any{
		"enabled":          true,
		"redirectUris":     []string{"https://customer.example/cb"},
		"regenerateSecret": true,
	}
	rr := putOIDCConfig(t, router, ws, project, appID, claims, body)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		OIDCEnabled         bool   `json:"oidcEnabled"`
		HasOIDCClientSecret bool   `json:"hasOIDCClientSecret"`
		OIDCClientSecret    string `json:"oidcClientSecret"`
		OIDCClientID        string `json:"oidcClientId"`
		OIDCDiscoveryURL    string `json:"oidcDiscoveryUrl"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.OIDCEnabled {
		t.Fatalf("expected oidcEnabled=true")
	}
	if !resp.HasOIDCClientSecret {
		t.Fatalf("expected hasOIDCClientSecret=true after regenerate")
	}
	if resp.OIDCClientSecret == "" {
		t.Fatalf("raw client_secret should be returned exactly once on regenerate")
	}
	if resp.OIDCClientID != appID.String() {
		t.Fatalf("client_id should be app UUID, got %q", resp.OIDCClientID)
	}
	if resp.OIDCDiscoveryURL == "" {
		t.Fatalf("discovery URL should be populated")
	}

	// Subsequent fetch must NOT leak the raw secret.
	getReq := httptest.NewRequest(http.MethodGet,
		"/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/apps/"+appID.String()+"/oidc-config", nil)
	testEnv.SetSessionCookie(t, getReq, claims)
	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("GET expected 200, got %d", getRR.Code)
	}
	var got struct {
		OIDCClientSecret    string `json:"oidcClientSecret"`
		HasOIDCClientSecret bool   `json:"hasOIDCClientSecret"`
	}
	_ = json.Unmarshal(getRR.Body.Bytes(), &got)
	if got.OIDCClientSecret != "" {
		t.Fatalf("GET must not expose the raw secret; got %q", got.OIDCClientSecret)
	}
	if !got.HasOIDCClientSecret {
		t.Fatalf("GET should report hasOIDCClientSecret=true")
	}
}

func TestAdminOIDCConfig_RejectsLocalTransportMode(t *testing.T) {
	router := setupOIDCAdminRouter(t)
	_, ws, project, appID, _, claims := createOIDCAppFixture(t)
	// Flip BACK to local mode to exercise the guard.
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`update apps set transport_mode = 'local' where id = $1`, appID); err != nil {
		t.Fatalf("set transport_mode=local: %v", err)
	}

	body := map[string]any{
		"enabled":      true,
		"redirectUris": []string{"https://customer.example/cb"},
	}
	rr := putOIDCConfig(t, router, ws, project, appID, claims, body)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("oidcRequiresCookieTransport")) {
		t.Fatalf("expected oidcRequiresCookieTransport error, got %s", rr.Body.String())
	}
}

func TestAdminOIDCConfig_RejectsEnableWithoutRedirectURIs(t *testing.T) {
	router := setupOIDCAdminRouter(t)
	_, ws, project, appID, _, claims := createOIDCAppFixture(t)

	body := map[string]any{
		"enabled":      true,
		"redirectUris": []string{},
	}
	rr := putOIDCConfig(t, router, ws, project, appID, claims, body)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("oidcRedirectUrisRequired")) {
		t.Fatalf("expected oidcRedirectUrisRequired error, got %s", rr.Body.String())
	}
}

func TestAdminOIDCConfig_RotateSecretReturnsFreshValue(t *testing.T) {
	router := setupOIDCAdminRouter(t)
	_, ws, project, appID, _, claims := createOIDCAppFixture(t)

	// First enable + generate.
	rr1 := putOIDCConfig(t, router, ws, project, appID, claims, map[string]any{
		"enabled":          true,
		"redirectUris":     []string{"https://customer.example/cb"},
		"regenerateSecret": true,
	})
	if rr1.Code != http.StatusOK {
		t.Fatalf("first put: %d (body=%s)", rr1.Code, rr1.Body.String())
	}
	var first struct {
		OIDCClientSecret string `json:"oidcClientSecret"`
	}
	_ = json.Unmarshal(rr1.Body.Bytes(), &first)

	// Rotate.
	rr2 := putOIDCConfig(t, router, ws, project, appID, claims, map[string]any{
		"regenerateSecret": true,
	})
	if rr2.Code != http.StatusOK {
		t.Fatalf("rotate put: %d (body=%s)", rr2.Code, rr2.Body.String())
	}
	var second struct {
		OIDCClientSecret string `json:"oidcClientSecret"`
	}
	_ = json.Unmarshal(rr2.Body.Bytes(), &second)

	if first.OIDCClientSecret == "" || second.OIDCClientSecret == "" {
		t.Fatalf("both secrets must be non-empty")
	}
	if first.OIDCClientSecret == second.OIDCClientSecret {
		t.Fatalf("rotated secret should differ from original")
	}
}

func TestAdminOIDCConfig_ClearSecretDowngradesToPublic(t *testing.T) {
	router := setupOIDCAdminRouter(t)
	_, ws, project, appID, _, claims := createOIDCAppFixture(t)

	// Enable + generate.
	rr1 := putOIDCConfig(t, router, ws, project, appID, claims, map[string]any{
		"enabled":          true,
		"redirectUris":     []string{"https://customer.example/cb"},
		"regenerateSecret": true,
	})
	if rr1.Code != http.StatusOK {
		t.Fatalf("enable: %d", rr1.Code)
	}

	// Clear.
	rr2 := putOIDCConfig(t, router, ws, project, appID, claims, map[string]any{
		"clearSecret": true,
	})
	if rr2.Code != http.StatusOK {
		t.Fatalf("clear: %d (body=%s)", rr2.Code, rr2.Body.String())
	}
	var resp struct {
		HasOIDCClientSecret bool `json:"hasOIDCClientSecret"`
	}
	_ = json.Unmarshal(rr2.Body.Bytes(), &resp)
	if resp.HasOIDCClientSecret {
		t.Fatalf("after clearSecret, hasOIDCClientSecret should be false")
	}
}

func TestAdminOIDCConfig_RegenerateAndClearMutuallyExclusive(t *testing.T) {
	router := setupOIDCAdminRouter(t)
	_, ws, project, appID, _, claims := createOIDCAppFixture(t)

	rr := putOIDCConfig(t, router, ws, project, appID, claims, map[string]any{
		"regenerateSecret": true,
		"clearSecret":      true,
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (body=%s)", rr.Code, rr.Body.String())
	}
}

// TestAdminOIDCConfig_DisableAfterEnable proves the standard "turn it
// off" path: an enabled+secret-configured app can be flipped back to
// disabled, and the secret hash survives so re-enabling later does
// not need a new client_secret roundtrip.
func TestAdminOIDCConfig_DisableAfterEnable(t *testing.T) {
	router := setupOIDCAdminRouter(t)
	_, ws, project, appID, _, claims := createOIDCAppFixture(t)

	// Enable with secret.
	rr1 := putOIDCConfig(t, router, ws, project, appID, claims, map[string]any{
		"enabled":          true,
		"redirectUris":     []string{"https://customer.example/cb"},
		"regenerateSecret": true,
	})
	if rr1.Code != http.StatusOK {
		t.Fatalf("enable: %d (body=%s)", rr1.Code, rr1.Body.String())
	}

	// Disable (no other changes).
	rr2 := putOIDCConfig(t, router, ws, project, appID, claims, map[string]any{
		"enabled": false,
	})
	if rr2.Code != http.StatusOK {
		t.Fatalf("disable: %d (body=%s)", rr2.Code, rr2.Body.String())
	}
	var disabled struct {
		OIDCEnabled         bool     `json:"oidcEnabled"`
		HasOIDCClientSecret bool     `json:"hasOIDCClientSecret"`
		OIDCRedirectURIs    []string `json:"oidcRedirectUris"`
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &disabled); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if disabled.OIDCEnabled {
		t.Fatalf("expected oidcEnabled=false after disable")
	}
	// Secret hash + URIs should survive — the admin can re-enable
	// later without re-running secret distribution.
	if !disabled.HasOIDCClientSecret {
		t.Fatalf("client_secret hash should survive disable; HasOIDCClientSecret=false")
	}
	if len(disabled.OIDCRedirectURIs) != 1 || disabled.OIDCRedirectURIs[0] != "https://customer.example/cb" {
		t.Fatalf("redirect URIs should survive disable, got %v", disabled.OIDCRedirectURIs)
	}
}
