package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"manyrows-core/api"
	"manyrows-core/auth"
	"manyrows-core/auth/client"
	"manyrows-core/core"
	"manyrows-core/email"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// ---------------------------------------------------------------------------
// Shared constructor
// ---------------------------------------------------------------------------

// newTestRequestHandler constructs a RequestHandler using the shared testEnv,
// mirroring the setup in setupServerAPIRouter.
func newTestRequestHandler(t *testing.T) *api.RequestHandler {
	t.Helper()
	cfg := GetTestConfig()
	adminSvc, err := auth.NewAuthService(cfg, testEnv.Repo)
	if err != nil {
		t.Fatalf("auth.NewAuthService: %v", err)
	}
	clientSvc, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("client.NewAuthService: %v", err)
	}
	return api.NewRequestHandler(testEnv.Repo, adminSvc, clientSvc, email.NewEmailService(true, nil), cfg, nil, nil)
}

// ---------------------------------------------------------------------------
// Router builders
// ---------------------------------------------------------------------------

// lookupRouter builds a minimal chi router that wires the users:batch and
// users:lookup routes under the standard /x/{workspaceSlug}/api/v1/apps/{appId}
// prefix, using the supplied workspace and app for context injection.
func lookupRouter(t *testing.T, rh *api.RequestHandler, ws *core.Workspace, appID uuid.UUID) *chi.Mux {
	t.Helper()
	wsMiddleware := makeWSMiddleware(ws)
	appMiddleware := makeAppMiddleware(t, appID, ws)

	r := chi.NewRouter()
	r.Route("/x/{workspaceSlug}/api/v1/apps/{appId}", func(appR chi.Router) {
		appR.Use(wsMiddleware)
		appR.Use(appMiddleware)
		appR.Post("/users:batch", rh.ServerBatchCreateUsers)
		appR.Post("/users:lookup", rh.ServerUsersLookup)
	})
	return r
}

// scopeGatedLookupRouter wraps lookupRouter with an inline scope gate, so
// TestServerUsersLookup_ReadScopedKeyAllowed can verify that :lookup is
// reachable with a read key while :batch is not.
func scopeGatedLookupRouter(t *testing.T, rh *api.RequestHandler, ws *core.Workspace, appID uuid.UUID, keyScope string) *chi.Mux {
	t.Helper()

	// wsMiddleware that also injects a synthetic API key with the given scope.
	wsGateMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := core.WithWorkspace(r.Context(), ws)
			syntheticKey := &core.APIKey{Scope: keyScope}
			if ws.CreatedBy != nil {
				syntheticKey.CreatedBy = *ws.CreatedBy
			}
			ctx = core.WithAPIKey(ctx, syntheticKey)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	// Scope gate: mirrors the logic in app/routerExternal.go, including the
	// isReadOnlyCustomMethod exception for :lookup.
	scopeGate := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key, ok := core.APIKeyFromContext(r.Context())
			if !ok || key == nil {
				api.WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
				return
			}
			if !key.AllowsWrite() &&
				r.Method != http.MethodGet &&
				r.Method != http.MethodHead &&
				!strings.HasSuffix(r.URL.Path, ":lookup") {
				api.WriteError(w, r, "error.forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	appMiddleware := makeAppMiddleware(t, appID, ws)

	r := chi.NewRouter()
	r.Route("/x/{workspaceSlug}/api/v1/apps/{appId}", func(appR chi.Router) {
		appR.Use(wsGateMiddleware)
		appR.Use(scopeGate)
		appR.Use(appMiddleware)
		appR.Post("/users:batch", rh.ServerBatchCreateUsers)
		appR.Post("/users:lookup", rh.ServerUsersLookup)
	})
	return r
}

// makeWSMiddleware returns a middleware that injects a workspace into context.
func makeWSMiddleware(ws *core.Workspace) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := core.WithWorkspace(r.Context(), ws)
			if ws.CreatedBy != nil {
				ctx = core.WithAPIKey(ctx, &core.APIKey{CreatedBy: *ws.CreatedBy})
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// makeAppMiddleware returns a middleware that resolves app + project from the
// DB and injects them into context, mirroring the test app-middleware in
// setupServerAPIRouter.
func makeAppMiddleware(t *testing.T, appID uuid.UUID, ws *core.Workspace) func(http.Handler) http.Handler {
	t.Helper()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			app, err := testEnv.Repo.GetAppByID(ctx, appID)
			if err != nil {
				http.Error(w, "app not found", http.StatusForbidden)
				return
			}
			ctx = core.WithApp(ctx, &app)
			project, err := testEnv.Repo.GetProject(ctx, app.ProjectID, ws.ID)
			if err != nil || project == nil {
				http.Error(w, "project not found", http.StatusForbidden)
				return
			}
			ctx = core.WithProject(ctx, project)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestServerUsersLookup_FoundAndMissing: 2 created users + 1 ghost → 200,
// users has 2 entries, missing has the ghost address.
func TestServerUsersLookup_FoundAndMissing(t *testing.T) {
	rh := newTestRequestHandler(t)

	acc := testEnv.CreateTestAccount(t, "srv-lk-fm-"+GenerateUniqueSlug("a")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Lookup WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Lookup Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Lookup App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}}
	defer testEnv.CleanupTestData(t, fixtures)

	e1 := "lk-u1-" + GenerateUniqueSlug("u") + "@example.com"
	e2 := "lk-u2-" + GenerateUniqueSlug("u") + "@example.com"
	ghost := "lk-ghost-" + GenerateUniqueSlug("g") + "@example.com"

	defer func() {
		pool := testEnv.DB.Pool()
		ctx := context.Background()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE lower(email) = lower($1) OR lower(email) = lower($2)", e1, e2)
		_, _ = pool.Exec(ctx, "DELETE FROM apps WHERE id = $1", appID)
	}()

	router := lookupRouter(t, rh, ws, appID)
	base := "/x/" + ws.Slug + "/api/v1/apps/" + appID.String()

	// Provision two users via :batch.
	batchBody, _ := json.Marshal(api.ServerBatchCreateUsersRequest{Emails: []string{e1, e2}})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, base+"/users:batch", bytes.NewReader(batchBody)))
	if rr.Code != http.StatusOK {
		t.Fatalf("provision :batch: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Lookup 2 known + 1 ghost.
	lookupBody, _ := json.Marshal(api.ServerUsersLookupRequest{Emails: []string{e1, e2, ghost}})
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, base+"/users:lookup", bytes.NewReader(lookupBody)))
	if rr.Code != http.StatusOK {
		t.Fatalf("lookup: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp api.ServerUsersLookupResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp.Users) != 2 {
		t.Fatalf("users: expected 2, got %d: %+v", len(resp.Users), resp.Users)
	}
	for _, u := range resp.Users {
		if u.ID == (uuid.UUID{}) {
			t.Errorf("user.id is zero UUID")
		}
		if u.Email == "" {
			t.Errorf("user.email is empty")
		}
	}
	if len(resp.Missing) != 1 || resp.Missing[0] != ghost {
		t.Fatalf("missing: expected [%q], got %v", ghost, resp.Missing)
	}
}

// TestServerUsersLookup_CapEnforced: 1001 emails → 400.
func TestServerUsersLookup_CapEnforced(t *testing.T) {
	rh := newTestRequestHandler(t)

	acc := testEnv.CreateTestAccount(t, "srv-lk-cap-"+GenerateUniqueSlug("a")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Cap WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Cap Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Cap App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		_, _ = testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	router := lookupRouter(t, rh, ws, appID)
	base := "/x/" + ws.Slug + "/api/v1/apps/" + appID.String()

	emails := make([]string, 1001)
	for i := range emails {
		emails[i] = "cap-" + GenerateUniqueSlug("u") + "@example.com"
	}

	body, _ := json.Marshal(api.ServerUsersLookupRequest{Emails: emails})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, base+"/users:lookup", bytes.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("cap: expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestServerUsersLookup_NormalizesEmails: user stored as lowercase; lookup with
// mixed-case variant → found; missing empty.
func TestServerUsersLookup_NormalizesEmails(t *testing.T) {
	rh := newTestRequestHandler(t)

	acc := testEnv.CreateTestAccount(t, "srv-lk-norm-"+GenerateUniqueSlug("a")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Norm WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Norm Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Norm App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}}
	defer testEnv.CleanupTestData(t, fixtures)

	canonicalEmail := "lk-norm-" + GenerateUniqueSlug("u") + "@example.com"
	defer func() {
		pool := testEnv.DB.Pool()
		ctx := context.Background()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE lower(email) = lower($1)", canonicalEmail)
		_, _ = pool.Exec(ctx, "DELETE FROM apps WHERE id = $1", appID)
	}()

	router := lookupRouter(t, rh, ws, appID)
	base := "/x/" + ws.Slug + "/api/v1/apps/" + appID.String()

	// Provision using the lowercase canonical form.
	batchBody, _ := json.Marshal(api.ServerBatchCreateUsersRequest{Emails: []string{canonicalEmail}})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, base+"/users:batch", bytes.NewReader(batchBody)))
	if rr.Code != http.StatusOK {
		t.Fatalf("provision :batch: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Lookup using a mixed-case variant of the same address.
	mixedEmail := strings.ToUpper(canonicalEmail[:3]) + canonicalEmail[3:]
	lookupBody, _ := json.Marshal(api.ServerUsersLookupRequest{Emails: []string{mixedEmail}})
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, base+"/users:lookup", bytes.NewReader(lookupBody)))
	if rr.Code != http.StatusOK {
		t.Fatalf("lookup: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp api.ServerUsersLookupResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp.Users) != 1 {
		t.Fatalf("users: expected 1, got %d: %+v", len(resp.Users), resp.Users)
	}
	if len(resp.Missing) != 0 {
		t.Fatalf("missing: expected empty, got %v", resp.Missing)
	}
}

// TestServerUsersLookup_ReadScopedKeyAllowed: a READ-scoped key must be allowed
// to call :lookup (200) but must be rejected for :batch (403).
func TestServerUsersLookup_ReadScopedKeyAllowed(t *testing.T) {
	rh := newTestRequestHandler(t)

	acc := testEnv.CreateTestAccount(t, "srv-lk-scope-"+GenerateUniqueSlug("a")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Scope WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Scope Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Scope App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		_, _ = testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	// Router with a read-scoped key and the scope gate.
	router := scopeGatedLookupRouter(t, rh, ws, appID, core.APIKeyScopeRead)
	base := "/x/" + ws.Slug + "/api/v1/apps/" + appID.String()

	// 1. :lookup with read-scoped key → 200.
	lookupBody, _ := json.Marshal(api.ServerUsersLookupRequest{Emails: []string{"nobody-" + GenerateUniqueSlug("u") + "@example.com"}})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, base+"/users:lookup", bytes.NewReader(lookupBody)))
	if rr.Code != http.StatusOK {
		t.Fatalf("read key + :lookup: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// 2. :batch with read-scoped key → 403.
	batchBody, _ := json.Marshal(api.ServerBatchCreateUsersRequest{Emails: []string{"nobody2@example.com"}})
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, base+"/users:batch", bytes.NewReader(batchBody)))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("read key + :batch: expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}
