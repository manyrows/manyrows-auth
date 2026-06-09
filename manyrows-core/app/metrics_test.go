package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func scrapeMetrics(h http.Handler, authHeader string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// The HTTP middleware records each request and the registry exposes it,
// including build-info labelled with the version.
func TestMetrics_MiddlewareRecordsAndExposes(t *testing.T) {
	m := newMetrics("test-version")

	r := chi.NewRouter()
	r.Use(m.middleware)
	r.Get("/widgets/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/widgets/42", nil))

	rr := scrapeMetrics(m.handler(""), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("scrape: expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "manyrows_http_requests_total") {
		t.Errorf("expected manyrows_http_requests_total in /metrics output")
	}
	if !strings.Contains(body, `manyrows_build_info{version="test-version"}`) {
		t.Errorf("expected build_info with version label")
	}
}

// /metrics is open when no token is set, and bearer-gated when one is.
func TestMetrics_TokenGate(t *testing.T) {
	m := newMetrics("test")

	if rr := scrapeMetrics(m.handler(""), ""); rr.Code != http.StatusOK {
		t.Errorf("no token configured: expected 200, got %d", rr.Code)
	}

	h := m.handler("s3cret")
	if rr := scrapeMetrics(h, ""); rr.Code != http.StatusUnauthorized {
		t.Errorf("missing token: expected 401, got %d", rr.Code)
	}
	if rr := scrapeMetrics(h, "Bearer wrong"); rr.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: expected 401, got %d", rr.Code)
	}
	if rr := scrapeMetrics(h, "Bearer s3cret"); rr.Code != http.StatusOK {
		t.Errorf("correct token: expected 200, got %d", rr.Code)
	}
}
