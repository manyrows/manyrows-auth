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
	"github.com/gofrs/uuid/v5"
)

func setupExternalIDPAdminRouter(t *testing.T) (*chi.Mux, *core.Workspace, *core.Product, uuid.UUID, core.TokenClaims) {
	t.Helper()
	svc := NewTestServices(t)
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)
	base := "/products/{productId}/apps/{appId}/external-idps"
	wsRouter.Get(base, svc.Handler.HandleListExternalIDPs)
	wsRouter.Post(base, svc.Handler.HandleCreateExternalIDP)
	wsRouter.Post(base+"/validate-discovery", svc.Handler.HandleValidateExternalIDPDiscovery)
	wsRouter.Put(base+"/{idpId}", svc.Handler.HandleUpdateExternalIDP)
	wsRouter.Delete(base+"/{idpId}", svc.Handler.HandleDeleteExternalIDP)

	acc := testEnv.CreateTestAccount(t, "extidp-admin-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "ExtIDP Admin WS", GenerateUniqueSlug("ws"))
	proj := testEnv.CreateTestProduct(t, ws, acc, "Test", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, proj.ID, uuid.Nil, "ExtIDP Admin App")
	_, claims := testEnv.CreateTestSession(t, acc)
	return r, ws, proj, appID, claims
}

func doExtIDPReq(t *testing.T, router *chi.Mux, method, path string, claims core.TokenClaims, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func extIDPBase(ws *core.Workspace, proj *core.Product, appID uuid.UUID) string {
	return "/admin/workspace/" + ws.ID.String() + "/products/" + proj.ID.String() + "/apps/" + appID.String() + "/external-idps"
}

// TestExternalIDPAdmin_CRUDAndSecretMerge covers the create→list→update→
// delete lifecycle and, crucially, that an update with an empty
// clientSecret PRESERVES the stored ciphertext (the full-overwrite
// hazard the audit flagged), while a non-empty one rotates it.
func TestExternalIDPAdmin_CRUDAndSecretMerge(t *testing.T) {
	router, ws, proj, appID, claims := setupExternalIDPAdminRouter(t)
	base := extIDPBase(ws, proj, appID)

	create := map[string]any{
		"slug": "acme-okta", "displayName": "Acme Okta", "enabled": true,
		"mode": "oidc", "issuerUrl": "https://acme.okta.com",
		"clientId": "client-1", "clientSecret": "super-secret-1",
	}
	rr := doExtIDPReq(t, router, http.MethodPost, base, claims, create)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d (%s)", rr.Code, rr.Body.String())
	}
	var created externalIDPResp
	mustJSON(t, rr, &created)
	if created.ID == "" || !created.HasClientSecret {
		t.Fatalf("create response missing id/hasClientSecret: %+v", created)
	}
	if bytes.Contains(rr.Body.Bytes(), []byte("super-secret-1")) {
		t.Fatal("the plaintext client secret must never appear in a response")
	}
	idpID := uuid.Must(uuid.FromString(created.ID))

	secret0 := readSecretBytes(t, idpID)
	if len(secret0) == 0 {
		t.Fatal("client secret was not stored")
	}

	// List shows it.
	rr = doExtIDPReq(t, router, http.MethodGet, base, claims, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d (%s)", rr.Code, rr.Body.String())
	}
	var listResp struct {
		ExternalIdps []externalIDPResp `json:"externalIdps"`
	}
	mustJSON(t, rr, &listResp)
	if len(listResp.ExternalIdps) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(listResp.ExternalIdps))
	}

	// Update WITHOUT a secret → ciphertext must be byte-identical.
	upd := map[string]any{
		"slug": "acme-okta", "displayName": "Acme Okta (prod)", "enabled": false,
		"mode": "oidc", "issuerUrl": "https://acme.okta.com",
		"clientId": "client-1", "clientSecret": "",
	}
	rr = doExtIDPReq(t, router, http.MethodPut, base+"/"+idpID.String(), claims, upd)
	if rr.Code != http.StatusOK {
		t.Fatalf("update(no secret): %d (%s)", rr.Code, rr.Body.String())
	}
	if !bytes.Equal(secret0, readSecretBytes(t, idpID)) {
		t.Fatal("empty-secret update must PRESERVE the stored ciphertext (regression: full-overwrite wipe)")
	}

	// Update WITH a new secret → ciphertext must change.
	upd["clientSecret"] = "rotated-secret-2"
	rr = doExtIDPReq(t, router, http.MethodPut, base+"/"+idpID.String(), claims, upd)
	if rr.Code != http.StatusOK {
		t.Fatalf("update(new secret): %d (%s)", rr.Code, rr.Body.String())
	}
	if bytes.Equal(secret0, readSecretBytes(t, idpID)) {
		t.Fatal("a non-empty secret must rotate the stored ciphertext")
	}

	// Delete.
	rr = doExtIDPReq(t, router, http.MethodDelete, base+"/"+idpID.String(), claims, nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d (%s)", rr.Code, rr.Body.String())
	}
	rr = doExtIDPReq(t, router, http.MethodDelete, base+"/"+idpID.String(), claims, nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("delete again should 404, got %d", rr.Code)
	}
}

func TestExternalIDPAdmin_Validation(t *testing.T) {
	router, ws, proj, appID, claims := setupExternalIDPAdminRouter(t)
	base := extIDPBase(ws, proj, appID)

	cases := []struct {
		name string
		body map[string]any
	}{
		{"bad slug", map[string]any{"slug": "Bad Slug!", "displayName": "x", "mode": "oidc", "issuerUrl": "https://x.example", "clientId": "c", "clientSecret": "s"}},
		{"missing secret on create", map[string]any{"slug": "p1", "displayName": "x", "mode": "oidc", "issuerUrl": "https://x.example", "clientId": "c"}},
		{"insecure issuer", map[string]any{"slug": "p2", "displayName": "x", "mode": "oidc", "issuerUrl": "http://evil.example", "clientId": "c", "clientSecret": "s"}},
		{"oauth2 missing endpoints", map[string]any{"slug": "p3", "displayName": "x", "mode": "oauth2", "clientId": "c", "clientSecret": "s"}},
		{"bad mode", map[string]any{"slug": "p4", "displayName": "x", "mode": "saml", "clientId": "c", "clientSecret": "s"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := doExtIDPReq(t, router, http.MethodPost, base, claims, c.body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("%s: expected 400, got %d (%s)", c.name, rr.Code, rr.Body.String())
			}
			// The error code must be translated to a human message
			// (message != code), or the admin UI would surface the raw
			// "error.externalIdp*" key.
			var body struct{ Error, Message string }
			_ = json.Unmarshal(rr.Body.Bytes(), &body)
			if body.Message == "" || body.Message == body.Error {
				t.Errorf("%s: error %q lacks a translated message (got %q)", c.name, body.Error, body.Message)
			}
		})
	}

	// Duplicate slug → 409.
	ok := map[string]any{"slug": "dup", "displayName": "x", "mode": "oidc", "issuerUrl": "https://x.example", "clientId": "c", "clientSecret": "s"}
	if rr := doExtIDPReq(t, router, http.MethodPost, base, claims, ok); rr.Code != http.StatusCreated {
		t.Fatalf("first create: %d (%s)", rr.Code, rr.Body.String())
	}
	if rr := doExtIDPReq(t, router, http.MethodPost, base, claims, ok); rr.Code != http.StatusConflict {
		t.Fatalf("duplicate slug should 409, got %d", rr.Code)
	}
}

func TestExternalIDPAdmin_ValidateDiscovery(t *testing.T) {
	router, ws, proj, appID, claims := setupExternalIDPAdminRouter(t)
	base := extIDPBase(ws, proj, appID)

	// Minimal mock issuer serving a well-known doc (loopback http is
	// allowed by RequireSecureURL).
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"userinfo_endpoint":      srv.URL + "/userinfo",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	rr := doExtIDPReq(t, router, http.MethodPost, base+"/validate-discovery", claims, map[string]any{"issuerUrl": srv.URL})
	if rr.Code != http.StatusOK {
		t.Fatalf("validate-discovery: %d (%s)", rr.Code, rr.Body.String())
	}
	var disc struct {
		Issuer, AuthorizeURL, TokenURL, JWKSURL string
	}
	mustJSON(t, rr, &disc)
	if disc.Issuer != srv.URL || disc.TokenURL != srv.URL+"/token" {
		t.Fatalf("discovery did not resolve endpoints: %+v", disc)
	}

	// A bad issuer → 400, not 500.
	rr = doExtIDPReq(t, router, http.MethodPost, base+"/validate-discovery", claims, map[string]any{"issuerUrl": "http://evil.example"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("insecure issuer should 400, got %d", rr.Code)
	}
}

// externalIDPResp mirrors the handler's response shape for unmarshaling.
type externalIDPResp struct {
	ID              string `json:"id"`
	Slug            string `json:"slug"`
	DisplayName     string `json:"displayName"`
	Enabled         bool   `json:"enabled"`
	Mode            string `json:"mode"`
	HasClientSecret bool   `json:"hasClientSecret"`
}

func mustJSON(t *testing.T, rr *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rr.Body.Bytes(), v); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, rr.Body.String())
	}
}

func readSecretBytes(t *testing.T, idpID uuid.UUID) []byte {
	t.Helper()
	var b []byte
	if err := testEnv.DB.Pool().QueryRow(context.Background(),
		`select client_secret_encrypted from external_idps where id=$1`, idpID).Scan(&b); err != nil {
		t.Fatalf("read secret bytes: %v", err)
	}
	return b
}
