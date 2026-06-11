package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func TestEchoRequestIDHeader(t *testing.T) {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(echoRequestIDHeader)
	r.Get("/x", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Header().Get("X-Request-Id") == "" {
		t.Fatal("expected X-Request-Id on response")
	}

	rec2 := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-Request-Id", "abc123")
	r.ServeHTTP(rec2, req)
	if got := rec2.Header().Get("X-Request-Id"); got != "abc123" {
		t.Fatalf("inbound id not echoed: got %q", got)
	}
}
