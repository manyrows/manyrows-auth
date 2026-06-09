package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"manyrows-core/core"
)

func apiKeysCleanup(t *testing.T, wsID interface{ String() string }) {
	t.Helper()
	_, _ = testEnv.DB.Pool().Exec(context.Background(),
		"DELETE FROM api_keys WHERE workspace_id = $1", wsID)
}

func postJSON(t *testing.T, router http.Handler, claims core.TokenClaims, path string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func getKey(t *testing.T, router http.Handler, claims core.TokenClaims, wsID, keyID string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+wsID+"/apiKeys/"+keyID, nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("getKey: %d %s", rr.Code, rr.Body.String())
	}
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("getKey decode: %v", err)
	}
	return m
}

func TestCreateApiKey_WithScopeAndExpiry(t *testing.T) {
	router := setupAPIKeysRouter(t)
	acc := testEnv.CreateTestAccount(t, "ak-scope-"+GenerateUniqueSlug("t")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})
	defer apiKeysCleanup(t, ws.ID)

	rr := postJSON(t, router, claims, "/admin/workspace/"+ws.ID.String()+"/apiKeys",
		map[string]any{"name": "scoped", "scope": "read", "expiresInDays": 7})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		ID        string     `json:"id"`
		Scope     string     `json:"scope"`
		ExpiresAt *time.Time `json:"expiresAt"`
		Key       string     `json:"key"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Scope != "read" {
		t.Errorf("response scope: got %q, want read", resp.Scope)
	}
	if resp.ExpiresAt == nil {
		t.Error("response expiresAt: got nil, want ~7 days out")
	}
	if resp.Key == "" {
		t.Error("response key empty")
	}

	got := getKey(t, router, claims, ws.ID.String(), resp.ID)
	if got["scope"] != "read" {
		t.Errorf("persisted scope: got %v, want read", got["scope"])
	}
	if got["expiresAt"] == nil {
		t.Error("persisted expiresAt: got nil")
	}
}

func TestCreateApiKey_InvalidScope(t *testing.T) {
	router := setupAPIKeysRouter(t)
	acc := testEnv.CreateTestAccount(t, "ak-bad-"+GenerateUniqueSlug("t")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})
	defer apiKeysCleanup(t, ws.ID)

	rr := postJSON(t, router, claims, "/admin/workspace/"+ws.ID.String()+"/apiKeys",
		map[string]any{"name": "bad", "scope": "admin"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid scope, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestRotateApiKey_PreservesMetadata(t *testing.T) {
	router := setupAPIKeysRouter(t)
	acc := testEnv.CreateTestAccount(t, "ak-rot-"+GenerateUniqueSlug("t")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})
	defer apiKeysCleanup(t, ws.ID)

	// Create a read-scoped key with an expiry.
	rr := postJSON(t, router, claims, "/admin/workspace/"+ws.ID.String()+"/apiKeys",
		map[string]any{"name": "rotate-me", "scope": "read", "expiresInDays": 30})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var created struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	before := getKey(t, router, claims, ws.ID.String(), created.ID)
	prefixBefore := before["prefix"]

	// Rotate.
	rotRR := postJSON(t, router, claims, "/admin/workspace/"+ws.ID.String()+"/apiKeys/"+created.ID+"/rotate", nil)
	if rotRR.Code != http.StatusOK {
		t.Fatalf("rotate: expected 200, got %d %s", rotRR.Code, rotRR.Body.String())
	}
	var rotated struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	_ = json.Unmarshal(rotRR.Body.Bytes(), &rotated)
	if rotated.Key == "" || rotated.Key == created.Key {
		t.Errorf("rotate must return a NEW key (got %q, original %q)", rotated.Key, created.Key)
	}
	if rotated.ID != created.ID {
		t.Errorf("rotate must keep the same key id (got %q, want %q)", rotated.ID, created.ID)
	}

	after := getKey(t, router, claims, ws.ID.String(), created.ID)
	if after["prefix"] == prefixBefore {
		t.Error("rotate must change the stored prefix (the old secret must stop working)")
	}
	if after["scope"] != "read" {
		t.Errorf("rotate must preserve scope: got %v, want read", after["scope"])
	}
	if after["expiresAt"] == nil {
		t.Error("rotate must preserve expiry")
	}
}
