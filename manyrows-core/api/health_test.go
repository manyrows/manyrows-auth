package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func setupHealthRouter(t *testing.T) *chi.Mux {
	t.Helper()
	svc := NewTestServices(t)
	r := chi.NewRouter()
	r.Get("/health", svc.Handler.HandleHealth)
	return r
}

func TestHealth_Success(t *testing.T) {
	router := setupHealthRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if body["status"] != "healthy" {
		t.Errorf("expected status=healthy, got %q", body["status"])
	}

	// /health is the UI's source for the binary version. The default
	// is "dev"; release builds replace it via -ldflags at link time.
	if body["version"] == "" {
		t.Errorf("expected version field in /health response, got empty")
	}

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

func TestHealth_NoAuthRequired(t *testing.T) {
	router := setupHealthRouter(t)

	// No cookies, no Authorization header — should still succeed
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 without auth, got %d", rr.Code)
	}
}

func TestHealth_MethodNotAllowed(t *testing.T) {
	router := setupHealthRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", rr.Code)
	}
}
