package api_test

import (
	"context"
	"io"
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

// TestAdminWorkspaceAccount_CrossTenantScoping is the regression test for the
// cross-tenant IDOR fix: the flat /accounts/{accountId} admin handlers must
// refuse to read or mutate a user who belongs to another workspace's pool
// (users carry no workspace_id, so the handlers must scope via
// user_pool_id -> user_pools.workspace_id).
func TestAdminWorkspaceAccount_CrossTenantScoping(t *testing.T) {
	cfg := GetTestConfig()
	adminAuthService, err := auth.NewAuthService(cfg, testEnv.Repo)
	if err != nil {
		t.Fatalf("admin auth service: %v", err)
	}
	clientAuthService, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("client auth service: %v", err)
	}
	requestHandler := api.NewRequestHandler(testEnv.Repo, adminAuthService, clientAuthService, email.NewEmailService(true, nil), cfg, nil, nil)

	ctx := context.Background()

	// Workspace A — the caller — with a user in its pool.
	accA := testEnv.CreateTestAccount(t, "idor-a-"+GenerateUniqueSlug("t")+"@example.com")
	wsA := testEnv.CreateTestWorkspace(t, accA, "WS A", GenerateUniqueSlug("wsa"))
	projA := testEnv.CreateTestProduct(t, wsA, accA, "Prod A", GenerateUniqueSlug("pa"))
	appA := createTestApp(t, wsA.ID, projA.ID, uuid.Nil, "App A")
	userA, _, err := testEnv.GetOrCreateUserWithMembership(ctx, "ua-"+GenerateUniqueSlug("u")+"@example.com", &core.App{ID: appA}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user A: %v", err)
	}

	// Workspace B — a different tenant — with a user in ITS pool.
	accB := testEnv.CreateTestAccount(t, "idor-b-"+GenerateUniqueSlug("t")+"@example.com")
	wsB := testEnv.CreateTestWorkspace(t, accB, "WS B", GenerateUniqueSlug("wsb"))
	projB := testEnv.CreateTestProduct(t, wsB, accB, "Prod B", GenerateUniqueSlug("pb"))
	appB := createTestApp(t, wsB.ID, projB.ID, uuid.Nil, "App B")
	userB, _, err := testEnv.GetOrCreateUserWithMembership(ctx, "ub-"+GenerateUniqueSlug("u")+"@example.com", &core.App{ID: appB}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user B: %v", err)
	}

	defer func() {
		p := testEnv.DB.Pool()
		_, _ = p.Exec(ctx, "DELETE FROM app_users WHERE user_id = $1 OR user_id = $2", userA.ID, userB.ID)
		_, _ = p.Exec(ctx, "DELETE FROM users WHERE id = $1 OR id = $2", userA.ID, userB.ID)
		_, _ = p.Exec(ctx, "DELETE FROM apps WHERE id = $1 OR id = $2", appA, appB)
		_, _ = p.Exec(ctx, "DELETE FROM user_pools WHERE workspace_id = $1 OR workspace_id = $2", wsA.ID, wsB.ID)
	}()

	// Router: every request runs as an owner of workspace A.
	r := chi.NewRouter()
	r.Route("/admin/workspace/{workspaceId}/accounts", func(sub chi.Router) {
		sub.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				c := core.WithWorkspace(req.Context(), wsA)
				c = core.WithWorkspaceRole(c, "owner")
				c = core.WithAdminAccount(c, accA)
				next.ServeHTTP(w, req.WithContext(c))
			})
		})
		sub.Get("/{accountId}", requestHandler.HandleGetWorkspaceAccount)
		sub.Patch("/{accountId}/status", requestHandler.HandleSetWorkspaceAccountStatus)
		sub.Delete("/{accountId}/password", requestHandler.HandleClearUserPassword)
		sub.Delete("/{accountId}", requestHandler.HandleDeleteWorkspaceAccount)
	})

	base := "/admin/workspace/" + wsA.ID.String() + "/accounts/"
	send := func(method, path, body string) int {
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(method, path, rdr))
		return rr.Code
	}

	// In-tenant: workspace A's admin can read workspace A's user.
	if code := send(http.MethodGet, base+userA.ID.String(), ""); code != http.StatusOK {
		t.Fatalf("in-tenant GET user A: want 200, got %d", code)
	}

	// Cross-tenant: every op on workspace B's user must be 404.
	for _, tc := range []struct {
		name, method, path, body string
	}{
		{"get", http.MethodGet, base + userB.ID.String(), ""},
		{"set-status", http.MethodPatch, base + userB.ID.String() + "/status", `{"enabled":false}`},
		{"clear-password", http.MethodDelete, base + userB.ID.String() + "/password", ""},
		{"delete", http.MethodDelete, base + userB.ID.String(), ""},
	} {
		if code := send(tc.method, tc.path, tc.body); code != http.StatusNotFound {
			t.Fatalf("cross-tenant %s on user B: want 404, got %d", tc.name, code)
		}
	}

	// User B must be untouched (not disabled, not deleted).
	if u, _ := testEnv.Repo.GetUserByID(ctx, userB.ID); u == nil || !u.Enabled {
		t.Fatalf("user B should be untouched after blocked cross-tenant ops, got %+v", u)
	}
}
