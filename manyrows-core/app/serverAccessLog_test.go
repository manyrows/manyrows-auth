package app

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// TestServerAccessLog_CapturesIdentityFromInnerMiddleware guards the holder
// pattern: the access log runs OUTERMOST, but the identity it logs is
// resolved by inner middlewares that hand a child request down via
// r.WithContext. Reading the outer request's context after the fact misses
// those values (the original bug), so the inner middlewares write through a
// pointer the outer frame seeded. This test populates the holder the way
// apiKeyMiddleware/appMiddleware do and asserts the fields reach the log line
// — and would fail if the middleware reverted to reading context getters.
func TestServerAccessLog_CapturesIdentityFromInnerMiddleware(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Logger
	log.Logger = zerolog.New(&buf)
	defer func() { log.Logger = orig }()

	inner := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if f := serverAccessLogFieldsFrom(r.Context()); f != nil {
				f.apiKeyID = "key-123"
				f.apiKeyName = "ci-bot"
				f.workspaceID = "ws-1"
				f.appID = "app-1"
			}
			// Hand a fresh request down, like the real middlewares do — this
			// is what hides context values from the outer frame.
			next.ServeHTTP(w, r.WithContext(r.Context()))
		})
	}

	final := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	h := serverAccessLogMiddleware()(inner(final))
	req := httptest.NewRequest(http.MethodGet, "/x/acme/api/v1/apps/app-1/users?id=u1", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()
	for _, want := range []string{
		`"component":"server_api"`,
		`"status":200`,
		`"api_key_id":"key-123"`,
		`"api_key_name":"ci-bot"`,
		`"workspace_id":"ws-1"`,
		`"app_id":"app-1"`,
		`"query":"id=u1"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("access log line missing %s\ngot: %s", want, out)
		}
	}
}

// TestServerAccessLog_OmitsIdentityWhenUnauthenticated confirms a request that
// never resolves a key (e.g. a 401) still logs the request line without
// inventing identity fields.
func TestServerAccessLog_OmitsIdentityWhenUnauthenticated(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Logger
	log.Logger = zerolog.New(&buf)
	defer func() { log.Logger = orig }()

	final := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	h := serverAccessLogMiddleware()(final)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x/acme/api/v1/apps/app-1/", nil))

	out := buf.String()
	if !strings.Contains(out, `"status":401`) {
		t.Fatalf("expected status 401 logged; got: %s", out)
	}
	if strings.Contains(out, "api_key_id") {
		t.Fatalf("unauthenticated request should not log an api_key_id; got: %s", out)
	}
}
