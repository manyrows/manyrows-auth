package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func setupHealthSplitRouter(t *testing.T) *chi.Mux {
	t.Helper()
	svc := NewTestServices(t)
	r := chi.NewRouter()
	r.Get("/livez", svc.Handler.HandleLivez)
	r.Get("/readyz", svc.Handler.HandleReadyz)
	return r
}

// /livez is a pure liveness probe: 200 with status "alive", no DB check.
func TestLivez_Success(t *testing.T) {
	router := setupHealthSplitRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["status"] != "alive" {
		t.Errorf("expected status=alive, got %q", body["status"])
	}
}

// /readyz reports readiness: 200 with status "ready" when the DB is reachable.
func TestReadyz_Success(t *testing.T) {
	router := setupHealthSplitRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["status"] != "ready" {
		t.Errorf("expected status=ready, got %q", body["status"])
	}
}
