package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"manyrows-core/core"
)

// TestClientAuthRequestIDCorrelation proves the feature's core value: a log line
// emitted from inside a handler carries the SAME request_id that the
// clientAuthAccessLog middleware seeded — i.e. the seeded request-scoped logger
// reaches handler code, end-to-end.
//
// Why this asserts reqLog's behavior even though reqLog lives in package api:
// reqLog(ctx) is defined as `return log.Ctx(ctx)`, and zerolog aliases
// log.Ctx == zerolog.Ctx — both return the *Logger stashed in the context by
// the middleware's `lg.WithContext(...)` call (falling back to the global logger
// when none was seeded). The handler below calls zerolog.Ctx(r.Context()) — the
// EXACT mechanism reqLog uses — so asserting "a zerolog.Ctx line from a handler
// carries the seeded request_id" is asserting reqLog's contract directly. The
// real api-package handlers were migrated from the global `log.` to
// `reqLog(ctx).`, and this is the seeding↔reqLog link that migration relies on.
//
// Uses the same in-isolation harness as client_auth_access_log_test.go /
// serverAccessLog_test.go (no DB): RequestID + echoRequestIDHeader seed a
// request id, an upstream middleware resolves app+workspace into context, and
// the /auth group mounts clientAuthAccessLog().
func TestClientAuthRequestIDCorrelation(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Logger
	log.Logger = zerolog.New(&buf)
	defer func() { log.Logger = orig }()

	appID := uuid.Must(uuid.NewV4())
	wsID := uuid.Must(uuid.NewV4())
	app := &core.App{ID: appID, WorkspaceID: wsID}
	ws := &core.Workspace{ID: wsID, Slug: "acme"}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(echoRequestIDHeader)

	r.Route("/apps/{appId}", func(ar chi.Router) {
		// Stand-in for workspaceMiddleware + appFromURLMiddleware: resolve
		// app + workspace into context above the /auth group.
		ar.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				ctx := core.WithWorkspace(req.Context(), ws)
				ctx = core.WithApp(ctx, app)
				next.ServeHTTP(w, req.WithContext(ctx))
			})
		})

		ar.Route("/auth", func(auth chi.Router) {
			auth.Use(clientAuthAccessLog())
			// The mock handler emits a HANDLER-OWNED line through the
			// context logger seeded by the middleware. zerolog.Ctx is what
			// reqLog wraps, so this stands in for the migrated handler logs.
			auth.Post("/password", func(w http.ResponseWriter, req *http.Request) {
				zerolog.Ctx(req.Context()).Info().Msg("handler-line")
				w.WriteHeader(http.StatusOK)
			})
		})
	})

	req := httptest.NewRequest(http.MethodPost, "/apps/"+appID.String()+"/auth/password", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// The request id the client sees on the wire.
	reqID := rr.Header().Get(middleware.RequestIDHeader)
	if reqID == "" {
		t.Fatalf("expected a non-empty %s response header", middleware.RequestIDHeader)
	}

	// Find the HANDLER line (Msg "handler-line"), which must NOT be the
	// access line (component=client_auth). It proves the seeded logger
	// reaches handler code rather than only being used by the middleware.
	handlerLine := findHandlerLine(t, buf.String())
	if strings.Contains(handlerLine, `"component":"client_auth"`) {
		t.Fatalf("handler line should not carry component=client_auth: %s", handlerLine)
	}

	// The crux: the handler-emitted line carries the SAME request_id that the
	// middleware seeded (and that the client got back in the header).
	if got := extractField(t, handlerLine, "request_id"); got != reqID {
		t.Fatalf("handler line request_id %q != response header request_id %q\nline: %s",
			got, reqID, handlerLine)
	}

	// Sanity: the access line for the same request also carries that request_id,
	// confirming both frames share one id (true end-to-end correlation).
	accessLine := lastClientAuthLine(t, buf.String())
	if got := extractField(t, accessLine, "request_id"); got != reqID {
		t.Fatalf("access line request_id %q != %q\nline: %s", got, reqID, accessLine)
	}
}

// findHandlerLine returns the JSON log line whose message is "handler-line".
func findHandlerLine(t *testing.T, out string) string {
	t.Helper()
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.Contains(ln, `"message":"handler-line"`) {
			return ln
		}
	}
	t.Fatalf("no handler-line emitted; got: %s", out)
	return ""
}

// extractField returns the string value of key from a JSON log line.
func extractField(t *testing.T, line, key string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("log line is not valid JSON: %v\nline: %s", err, line)
	}
	s, _ := m[key].(string)
	return s
}
