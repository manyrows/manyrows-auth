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

// buildClientAuthAccessLogTestRouter mirrors the real external router's /auth
// wiring just enough to exercise clientAuthAccessLog end-to-end without a DB:
//
//   - RequestID + echoRequestIDHeader seed a request id (as the base router does)
//   - an upstream middleware resolves app + workspace into context (as
//     workspaceMiddleware + appFromURLMiddleware do on /apps/{appId})
//   - the /auth group mounts clientAuthAccessLog(), then POST /auth/password
//
// The two handlers stand in for WorkspaceLoginPassword's outcomes: the success
// handler calls core.SetAuthLogUser (exactly the call Task 2 adds to the real
// handler) and returns 200; the bad-cred handler returns 401 without recording
// a subject. This is the same isolation style as serverAccessLog_test.go, which
// is the in-package precedent for testing an unexported access-log middleware.
func buildClientAuthAccessLogTestRouter(app *core.App, ws *core.Workspace, userID uuid.UUID) *chi.Mux {
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
			auth.Post("/password", func(w http.ResponseWriter, req *http.Request) {
				var body struct {
					Password string `json:"password"`
				}
				_ = json.NewDecoder(req.Body).Decode(&body)
				if body.Password == "correcthorse123" {
					core.SetAuthLogUser(req.Context(), userID)
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
			})
		})
	})
	return r
}

func postPasswordForAccessLog(t *testing.T, router *chi.Mux, app *core.App, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"password": password})
	req := httptest.NewRequest(http.MethodPost,
		"/apps/"+app.ID.String()+"/auth/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// TestClientAuthAccessLog_SuccessRecordsUserID drives a successful /auth/password
// request and asserts the single access line carries component=client_auth, a
// non-empty request_id/app_id, a status, the /auth/password route pattern, and
// the resolved user_id.
func TestClientAuthAccessLog_SuccessRecordsUserID(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Logger
	log.Logger = zerolog.New(&buf)
	defer func() { log.Logger = orig }()

	appID := uuid.Must(uuid.NewV4())
	wsID := uuid.Must(uuid.NewV4())
	userID := uuid.Must(uuid.NewV4())
	app := &core.App{ID: appID, WorkspaceID: wsID}
	ws := &core.Workspace{ID: wsID, Slug: "acme"}

	router := buildClientAuthAccessLogTestRouter(app, ws, userID)
	rr := postPasswordForAccessLog(t, router, app, "correcthorse123")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	line := lastClientAuthLine(t, buf.String())
	assertContains(t, line, `"component":"client_auth"`)
	assertContains(t, line, `"status":200`)
	assertContains(t, line, `"app_id":"`+appID.String()+`"`)
	assertContains(t, line, `"workspace_id":"`+wsID.String()+`"`)
	assertContains(t, line, `"user_id":"`+userID.String()+`"`)
	assertContains(t, line, `/auth/password`) // route pattern

	if reqID := extractString(t, line, "request_id"); reqID == "" {
		t.Fatalf("expected a non-empty request_id; got line: %s", line)
	}
}

// TestClientAuthAccessLog_FailureOmitsUserID drives a bad-credential request and
// asserts the access line has the request metadata but NO user_id (the handler
// never recorded a subject).
func TestClientAuthAccessLog_FailureOmitsUserID(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Logger
	log.Logger = zerolog.New(&buf)
	defer func() { log.Logger = orig }()

	appID := uuid.Must(uuid.NewV4())
	wsID := uuid.Must(uuid.NewV4())
	userID := uuid.Must(uuid.NewV4())
	app := &core.App{ID: appID, WorkspaceID: wsID}
	ws := &core.Workspace{ID: wsID, Slug: "acme"}

	router := buildClientAuthAccessLogTestRouter(app, ws, userID)
	rr := postPasswordForAccessLog(t, router, app, "wrong-password")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}

	line := lastClientAuthLine(t, buf.String())
	assertContains(t, line, `"component":"client_auth"`)
	assertContains(t, line, `"status":401`)
	assertContains(t, line, `"app_id":"`+appID.String()+`"`)
	assertContains(t, line, `/auth/password`)
	if strings.Contains(line, "user_id") {
		t.Fatalf("bad-cred request should not log a user_id; got line: %s", line)
	}
}

// lastClientAuthLine returns the last JSON log line whose component is
// client_auth (the access line, emitted after the handler returns).
func lastClientAuthLine(t *testing.T, out string) string {
	t.Helper()
	var found string
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.Contains(ln, `"component":"client_auth"`) {
			found = ln
		}
	}
	if found == "" {
		t.Fatalf("no client_auth access line emitted; got: %s", out)
	}
	return found
}

func assertContains(t *testing.T, line, want string) {
	t.Helper()
	if !strings.Contains(line, want) {
		t.Fatalf("access line missing %s\ngot: %s", want, line)
	}
}

func extractString(t *testing.T, line, key string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("access line is not valid JSON: %v\nline: %s", err, line)
	}
	s, _ := m[key].(string)
	return s
}
