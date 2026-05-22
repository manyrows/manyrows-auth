package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"manyrows-core/api"
	"manyrows-core/auth"
	"manyrows-core/auth/client"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/crypto/passwordhash"
	"manyrows-core/email"
	"manyrows-core/utils"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// setupClientAPIRouter creates a router for client-facing API tests (/x/{workspaceSlug})
func setupClientAPIRouter(t *testing.T) *chi.Mux {
	t.Helper()

	cfg := GetTestConfig()
	adminAuthService, err := auth.NewAuthService(cfg, testEnv.Repo)
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}

	clientAuthService, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("failed to create client auth service: %v", err)
	}

	emailService := email.NewEmailService(true, nil)

	requestHandler := api.NewRequestHandler(
		testEnv.Repo,
		adminAuthService,
		clientAuthService,
		emailService,
		cfg,
		nil,
		nil,
	)

	r := chi.NewRouter()

	// Mount at /x/{workspaceSlug} to mirror the real router
	wsRouter := chi.NewRouter()

	// Workspace middleware
	wsRouter.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			workspaceSlug := chi.URLParam(r, "workspaceSlug")
			if workspaceSlug == "" {
				http.Error(w, "missing workspace slug", http.StatusBadRequest)
				return
			}
			ws, ok, err := testEnv.Repo.GetWorkspaceBySlug(r.Context(), workspaceSlug)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if !ok {
				http.Error(w, "workspace not found", http.StatusForbidden)
				return
			}
			ctx := core.WithWorkspace(r.Context(), ws)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	// All client routes under /apps/{appId}
	wsRouter.Route("/apps/{appId}", func(ar chi.Router) {
		// appFromURLMiddleware: resolve app from URL param
		ar.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := r.Context()
				ws, ok := core.WorkspaceFromContext(ctx)
				if !ok || ws == nil {
					next.ServeHTTP(w, r)
					return
				}
				appIDStr := chi.URLParam(r, "appId")
				appID, err := uuid.FromString(appIDStr)
				if err != nil {
					http.Error(w, "invalid app id", http.StatusBadRequest)
					return
				}
				app, err := testEnv.Repo.GetAppByID(ctx, appID)
				if err != nil {
					http.Error(w, "app not found", http.StatusNotFound)
					return
				}
				if app.WorkspaceID != ws.ID || !app.Enabled {
					http.Error(w, "app not found", http.StatusNotFound)
					return
				}
				ctx = core.WithApp(ctx, &app)
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		})

		// Public app config
		ar.Get("/", requestHandler.HandleGetAppForAppKit)

		// Auth routes
		ar.Route("/auth", func(authR chi.Router) {
			authR.Post("/", requestHandler.WorkspaceLoginRequest)
			authR.Post("/verify", requestHandler.WorkspaceLogin)
			authR.Post("/refresh", requestHandler.WorkspaceRefresh)
			authR.Post("/logout", requestHandler.WorkspacePublicLogout)
			authR.Post("/register", requestHandler.WorkspaceRegister)
			authR.Post("/password", requestHandler.WorkspaceLoginPassword)
			authR.Post("/forgot-password", requestHandler.WorkspaceForgotPassword)
			authR.Post("/reset-password", requestHandler.WorkspaceResetPassword)
			authR.Post("/request-magic-link", requestHandler.WorkspaceLoginRequestMagicLink)
			authR.Get("/magic-link", requestHandler.WorkspaceConsumeMagicLink)
			authR.Post("/totp/setup-init", requestHandler.HandleWorkspaceTOTPSetupInit)
			authR.Post("/totp/setup-complete", requestHandler.HandleWorkspaceTOTPSetupComplete)
		})

		// Authed endpoints
		ar.Route("/a", func(authed chi.Router) {
			authed.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					ws, ok := core.WorkspaceFromContext(r.Context())
					if !ok || ws == nil {
						http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
						return
					}
					app, _ := core.AppFromContext(r.Context())
					if app == nil {
						http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
						return
					}
					loggedIn, ses, err := clientAuthService.IsLoggedIntoApp(r, app.ID)
					if err != nil {
						http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
						return
					}
					if !loggedIn || ses == nil {
						http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
						return
					}
					ctx := core.WithClientSessionContext(r.Context(), ses)
					next.ServeHTTP(w, r.WithContext(ctx))
				})
			})
			// Production flattened the formerly /app-nested authed
			// endpoints into /a directly, and routes /me to GetAppMe
			// (not GetWorkspaceMe). Mirror that so /a/me, /a/check-permission,
			// /a/runtime resolve to the production handlers. Product is
			// loaded here so app-scoped handlers can read it from context.
			authed.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					ctx := r.Context()
					ws, ok := core.WorkspaceFromContext(ctx)
					if !ok || ws == nil {
						http.Error(w, "invalid workspace", http.StatusUnauthorized)
						return
					}
					app, appOk := core.AppFromContext(ctx)
					if !appOk || app == nil {
						http.Error(w, "app not in context", http.StatusForbidden)
						return
					}
					project, err := testEnv.Repo.GetProduct(ctx, app.ProductID, ws.ID)
					if err != nil || project == nil {
						http.Error(w, "project not found", http.StatusForbidden)
						return
					}
					ctx = core.WithProduct(ctx, project)
					next.ServeHTTP(w, r.WithContext(ctx))
				})
			})
			authed.Post("/logout", requestHandler.WorkspaceLogout)
			authed.Get("/me", requestHandler.GetAppMe)
			authed.Get("/check-permission", requestHandler.CheckPermission)
			authed.Get("/runtime", requestHandler.GetAppData)
			authed.Post("/profile/display-name", requestHandler.WorkspaceUpdateDisplayName)
			authed.Post("/set-password", requestHandler.WorkspaceSetPassword)
			authed.Get("/me/sessions", requestHandler.GetMySessions)
			authed.Delete("/me/sessions/{sessionId}", requestHandler.DeleteMySession)
			authed.Post("/me/request-email-change", requestHandler.ClientRequestEmailChange)
			authed.Post("/me/verify-email-change", requestHandler.ClientVerifyEmailChange)
			// Sensitive-op routes — gated by requireSensitivePasswordOrCodeReauth.
			// Wired here so the re-auth-contract integration tests below
			// can exercise the body shape end-to-end.
			authed.Post("/totp/setup", requestHandler.HandleWorkspaceTOTPSetup)
			authed.Post("/totp/disable", requestHandler.HandleWorkspaceTOTPDisable)
			authed.Delete("/passkeys/{passkeyId}", requestHandler.WorkspaceDeletePasskey)
		})
	})

	r.Mount("/x/{workspaceSlug}", wsRouter)

	return r
}

// setupServerAPIRouter creates a router for server-to-server API tests (/x/{workspaceSlug}/api)
func setupServerAPIRouter(t *testing.T) *chi.Mux {
	t.Helper()

	cfg := GetTestConfig()
	adminAuthService, err := auth.NewAuthService(cfg, testEnv.Repo)
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}

	clientAuthService, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("failed to create client auth service: %v", err)
	}

	emailService := email.NewEmailService(true, nil)

	requestHandler := api.NewRequestHandler(
		testEnv.Repo,
		adminAuthService,
		clientAuthService,
		emailService,
		cfg,
		nil,
		nil,
	)

	r := chi.NewRouter()

	// Workspace middleware (inline for tests)
	wsMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			workspaceSlug := chi.URLParam(r, "workspaceSlug")
			if workspaceSlug == "" {
				http.Error(w, "missing workspace slug", http.StatusBadRequest)
				return
			}
			ws, ok, err := testEnv.Repo.GetWorkspaceBySlug(ctx, workspaceSlug)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if !ok {
				http.Error(w, "workspace not found", http.StatusForbidden)
				return
			}
			ctx = core.WithWorkspace(ctx, ws)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	// App middleware (inline for tests — resolves app + project + env)
	testAppMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ws, ok := core.WorkspaceFromContext(ctx)
			if !ok || ws == nil {
				http.Error(w, "invalid workspace", http.StatusUnauthorized)
				return
			}
			appID, err := uuid.FromString(chi.URLParam(r, "appId"))
			if err != nil {
				http.Error(w, "invalid app id", http.StatusBadRequest)
				return
			}
			app, err := testEnv.Repo.GetAppByID(ctx, appID)
			if err != nil {
				http.Error(w, "app not found", http.StatusForbidden)
				return
			}
			if app.WorkspaceID != ws.ID {
				http.Error(w, "app not found", http.StatusForbidden)
				return
			}
			if !app.Enabled {
				http.Error(w, "app is disabled", http.StatusForbidden)
				return
			}
			ctx = core.WithApp(ctx, &app)

			project, err := testEnv.Repo.GetProduct(ctx, app.ProductID, ws.ID)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if project == nil {
				http.Error(w, "project not found", http.StatusForbidden)
				return
			}
			ctx = core.WithProduct(ctx, project)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	// Server API router: /x/{workspaceSlug}/api/v1/apps/{appId}/...
	serverRouter := chi.NewRouter()
	serverRouter.Use(wsMiddleware)

	appRouter := chi.NewRouter()
	appRouter.Use(testAppMiddleware)
	appRouter.Get("/", requestHandler.GetDeliveryForServer)
	appRouter.Get("/check-permission", requestHandler.ServerCheckPermission)
	appRouter.Get("/roles", requestHandler.ServerListRoles)
	appRouter.Get("/permissions", requestHandler.ServerListPermissions)
	appRouter.Get("/users", requestHandler.HandleServerGetUser)
	appRouter.Get("/users/{userId}", requestHandler.ServerGetUserByID)
	appRouter.Post("/users", requestHandler.ServerCreateUser)
	appRouter.Patch("/users/{userId}", requestHandler.ServerSetUserStatus)
	appRouter.Post("/users/{userId}/magic-link", requestHandler.ServerCreateMagicLink)
	appRouter.Get("/user-fields", requestHandler.HandleServerGetUserFields)
	appRouter.Get("/user-fields/users/{userId}", requestHandler.HandleServerGetUserFieldValues)
	appRouter.Put("/user-fields/{userFieldId}/users/{userId}", requestHandler.ServerUpsertUserFieldValue)
	appRouter.Delete("/user-fields/{userFieldId}/users/{userId}", requestHandler.ServerDeleteUserFieldValue)
	appRouter.Delete("/users/{userId}/sessions", requestHandler.ServerRevokeUserSessions)
	appRouter.Put("/users/{userId}/roles", requestHandler.ServerReplaceUserRoles)
	appRouter.Delete("/users/{userId}", requestHandler.ServerRemoveUser)

	serverRouter.Mount("/v1/apps/{appId}", appRouter)
	r.Mount("/x/{workspaceSlug}/api", serverRouter)

	return r
}

// createTestClientSessionForApp creates a client session tied to a specific app.
func createTestClientSessionForApp(t *testing.T, ws *core.Workspace, acc *core.Account, app *core.App) (*core.ClientSession, string) {
	t.Helper()
	ctx := context.Background()

	cfg := GetTestConfig()
	clientAuthService, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("failed to create client auth service: %v", err)
	}

	// Create or get user for app
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	ses, err := clientAuthService.CreateSession(ctx, user.ID, app.ID, "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to create client session: %v", err)
	}

	tokenPair, err := clientAuthService.IssueTokenPair(ctx, ses, "test-agent", "127.0.0.1", 0, 0, "", "")
	if err != nil {
		t.Fatalf("failed to issue token pair: %v", err)
	}

	return ses, tokenPair.AccessToken
}

// =====================
// Token Refresh Tests
// =====================

func TestWorkspaceRefresh_Success(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "refresh-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_refresh_tokens WHERE session_id IN (SELECT id FROM client_sessions WHERE workspace_id = $1)", ws.ID)
	}()

	// Create a client session and get a refresh token
	cfg := GetTestConfig()
	clientAuthService, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("failed to create client auth service: %v", err)
	}

	// Create user first
	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	ses, err := clientAuthService.CreateSession(ctx, user.ID, app.ID, "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to create client session: %v", err)
	}

	tokenPair, err := clientAuthService.IssueTokenPair(ctx, ses, "test-agent", "127.0.0.1", 0, 0, "", "")
	if err != nil {
		t.Fatalf("failed to issue token pair: %v", err)
	}

	body := map[string]any{
		"refreshToken": tokenPair.RefreshToken,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/refresh", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["accessToken"] == nil || resp["accessToken"] == "" {
		t.Error("expected accessToken in response")
	}
	if resp["refreshToken"] == nil || resp["refreshToken"] == "" {
		t.Error("expected refreshToken in response")
	}
}

func TestWorkspaceRefresh_InvalidToken(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "refresh-invalid-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"refreshToken": "invalid-token",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/refresh", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d: %s", http.StatusUnauthorized, rr.Code, rr.Body.String())
	}
}

func TestWorkspaceRefresh_MissingToken(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "refresh-missing-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/refresh", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

func TestWorkspaceRefresh_RateLimitedByIP(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "refresh-rl-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM attempts WHERE purpose = 'workspace_refresh'")
	}()

	body, _ := json.Marshal(map[string]any{"refreshToken": "invalid-token"})
	url := "/x/" + ws.Slug + "/apps/" + app.ID.String() + "/auth/refresh"
	ip := "203.0.113.42"

	for i := 0; i < 30; i++ {
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", ip)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401 before rate limit, got %d: %s", i, rr.Code, rr.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after %d failures, got %d: %s", 30, rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Retry-After"); got == "" {
		t.Error("expected Retry-After header on rate-limit response")
	}
}

// =====================
// Workspace Me Tests
// =====================

func TestGetWorkspaceMe_Success(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "ws-me-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_refresh_tokens WHERE session_id IN (SELECT id FROM client_sessions WHERE workspace_id = $1)", ws.ID)
	}()

	_, accessToken := createTestClientSessionForApp(t, ws, acc, app)

	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["user"] == nil {
		t.Error("expected user in response")
	}
	if resp["workspaceName"] == nil {
		t.Error("expected workspaceName in response")
	}
}

func TestGetWorkspaceMe_Unauthenticated(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "ws-me-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/me", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d: %s", http.StatusUnauthorized, rr.Code, rr.Body.String())
	}
}

// =====================
// Workspace Logout Tests
// =====================

func TestWorkspaceLogout_Success(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "ws-logout-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_refresh_tokens WHERE session_id IN (SELECT id FROM client_sessions WHERE workspace_id = $1)", ws.ID)
	}()

	_, accessToken := createTestClientSessionForApp(t, ws, acc, app)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/logout", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["ok"] != true {
		t.Error("expected ok: true in response")
	}
}

func TestWorkspaceLogout_Unauthenticated(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "ws-logout-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/logout", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d: %s", http.StatusUnauthorized, rr.Code, rr.Body.String())
	}
}

// =====================
// Product Me Tests
// =====================

// =====================
// GetAppMe Tests
// =====================

func TestGetAppMe_WithRolesAndPermissions(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "app-me-rp-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM user_roles WHERE app_id IN (SELECT id FROM apps WHERE product_id = $1)", project.ID)
	}()

	ctx := context.Background()
	now := time.Now().UTC()

	// Create user
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create a permission
	perm := core.Permission{
		ID:        utils.NewUUID(),
		ProductID: project.ID,
		Name:      "Read Posts",
		Slug:      "posts:read",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := testEnv.Repo.CreatePermission(ctx, perm); err != nil {
		t.Fatalf("failed to create permission: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM permissions WHERE id = $1", perm.ID)
	}()

	// Create a role
	role, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{
		ProductID: project.ID,
		Name:      "Editor",
		Slug:      GenerateUniqueSlug("editor"),
		Now:       now,
	})
	if err != nil {
		t.Fatalf("failed to create role: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM role_permissions WHERE role_id = $1", role.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM roles WHERE id = $1", role.ID)
	}()

	// Attach permission to role
	if err := testEnv.Repo.ReplaceRolePermissions(ctx, repo.ReplaceRolePermissionsParams{
		ProductID:     project.ID,
		RoleID:        role.ID,
		PermissionIDs: []uuid.UUID{perm.ID},
		Now:           now,
	}); err != nil {
		t.Fatalf("failed to attach permission to role: %v", err)
	}

	// Assign role to workspace account
	if err := testEnv.Repo.ReplaceUserRoles(ctx, repo.ReplaceUserRolesParams{
		ProductID: project.ID,
		UserID:    user.ID,
		AppID:     appID,
		RoleIDs:   []uuid.UUID{role.ID},
		Now:       now,
	}); err != nil {
		t.Fatalf("failed to assign role: %v", err)
	}

	_, accessToken := createTestClientSessionForApp(t, ws, acc, &core.App{ID: appID})

	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+appID.String()+"/a/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp api.AppMeResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(resp.App.Roles) != 1 || resp.App.Roles[0] != role.Slug {
		t.Errorf("expected roles [%q], got %v", role.Slug, resp.App.Roles)
	}
	if len(resp.App.Permissions) != 1 || resp.App.Permissions[0] != "posts:read" {
		t.Errorf("expected permissions [\"posts:read\"], got %v", resp.App.Permissions)
	}
}

func TestGetAppMe_NoRoles(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "app-me-nr-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
	}()

	_, accessToken := createTestClientSessionForApp(t, ws, acc, &core.App{ID: appID})

	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+appID.String()+"/a/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp api.AppMeResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(resp.App.Roles) != 0 {
		t.Errorf("expected empty roles, got %v", resp.App.Roles)
	}
	if len(resp.App.Permissions) != 0 {
		t.Errorf("expected empty permissions, got %v", resp.App.Permissions)
	}
}

// =====================
// CheckPermission Tests
// =====================

func TestCheckPermission_Allowed(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "chk-perm-ok-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM user_roles WHERE app_id IN (SELECT id FROM apps WHERE product_id = $1)", project.ID)
	}()

	ctx := context.Background()
	now := time.Now().UTC()

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	perm := core.Permission{
		ID:        utils.NewUUID(),
		ProductID: project.ID,
		Name:      "Read Posts",
		Slug:      "posts:read",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := testEnv.Repo.CreatePermission(ctx, perm); err != nil {
		t.Fatalf("failed to create permission: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM permissions WHERE id = $1", perm.ID)
	}()

	role, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{
		ProductID: project.ID,
		Name:      "Editor",
		Slug:      GenerateUniqueSlug("editor"),
		Now:       now,
	})
	if err != nil {
		t.Fatalf("failed to create role: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM role_permissions WHERE role_id = $1", role.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM roles WHERE id = $1", role.ID)
	}()

	if err := testEnv.Repo.ReplaceRolePermissions(ctx, repo.ReplaceRolePermissionsParams{
		ProductID:     project.ID,
		RoleID:        role.ID,
		PermissionIDs: []uuid.UUID{perm.ID},
		Now:           now,
	}); err != nil {
		t.Fatalf("failed to attach permission to role: %v", err)
	}

	if err := testEnv.Repo.ReplaceUserRoles(ctx, repo.ReplaceUserRolesParams{
		ProductID: project.ID,
		UserID:    user.ID,
		AppID:     appID,
		RoleIDs:   []uuid.UUID{role.ID},
		Now:       now,
	}); err != nil {
		t.Fatalf("failed to assign role: %v", err)
	}

	_, accessToken := createTestClientSessionForApp(t, ws, acc, &core.App{ID: appID})

	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+appID.String()+"/a/check-permission?permission=posts:read", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp api.CheckPermissionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if !resp.Allowed {
		t.Error("expected allowed to be true")
	}
	if resp.Permission != "posts:read" {
		t.Errorf("expected permission \"posts:read\", got %q", resp.Permission)
	}
}

func TestCheckPermission_Denied(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "chk-perm-no-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
	}()

	_, accessToken := createTestClientSessionForApp(t, ws, acc, &core.App{ID: appID})

	// No roles assigned, so user should NOT have posts:read
	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+appID.String()+"/a/check-permission?permission=posts:read", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp api.CheckPermissionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Allowed {
		t.Error("expected allowed to be false")
	}
}

func TestCheckPermission_MissingParam(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "chk-perm-mp-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
	}()

	_, accessToken := createTestClientSessionForApp(t, ws, acc, &core.App{ID: appID})

	// No ?permission= param
	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+appID.String()+"/a/check-permission", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

func TestCheckPermission_Unauthorized(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "chk-perm-ua-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	// No auth header
	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+appID.String()+"/a/check-permission?permission=posts:read", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d: %s", http.StatusUnauthorized, rr.Code, rr.Body.String())
	}
}

// =====================
// App Data Tests
// =====================

func TestGetAppData_Success(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "app-data-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_refresh_tokens WHERE session_id IN (SELECT id FROM client_sessions WHERE workspace_id = $1)", ws.ID)
	}()

	_, accessToken := createTestClientSessionForApp(t, ws, acc, &core.App{ID: appID})

	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+appID.String()+"/a/runtime", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["featureFlags"] == nil {
		t.Error("expected featureFlags in response")
	}
	if resp["config"] == nil {
		t.Error("expected config in response")
	}
}

func TestGetAppData_Unauthenticated(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "app-data-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+appID.String()+"/a/runtime", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d: %s", http.StatusUnauthorized, rr.Code, rr.Body.String())
	}
}

// =====================
// Server Delivery Tests
// =====================

func TestGetDeliveryForServer_Success(t *testing.T) {
	router := setupServerAPIRouter(t)

	emailAddr := "delivery-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	// Note: This test doesn't include API key auth middleware for simplicity
	// In production, this endpoint requires API key authentication
	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["workspaceId"] == nil {
		t.Error("expected workspaceId in response")
	}
	if resp["productId"] == nil {
		t.Error("expected productId in response")
	}
	if resp["appId"] == nil {
		t.Error("expected appId in response")
	}
	if resp["config"] == nil {
		t.Error("expected config in response")
	}
	if resp["flags"] == nil {
		t.Error("expected flags in response")
	}
}

func TestGetDeliveryForServer_InvalidApp(t *testing.T) {
	router := setupServerAPIRouter(t)

	emailAddr := "delivery-invalid-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	fakeAppID := uuid.Must(uuid.NewV4())

	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/api/v1/apps/"+fakeAppID.String()+"/", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d: %s", http.StatusForbidden, rr.Code, rr.Body.String())
	}
}

// =====================
// Server Check Permission Tests
// =====================

func TestServerCheckPermission_Allowed(t *testing.T) {
	router := setupServerAPIRouter(t)

	emailAddr := "srv-chk-ok-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM user_roles WHERE app_id IN (SELECT id FROM apps WHERE product_id = $1)", project.ID)
	}()

	ctx := context.Background()
	now := time.Now().UTC()

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	perm := core.Permission{
		ID:        utils.NewUUID(),
		ProductID: project.ID,
		Name:      "Read Posts",
		Slug:      "posts:read",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := testEnv.Repo.CreatePermission(ctx, perm); err != nil {
		t.Fatalf("failed to create permission: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM permissions WHERE id = $1", perm.ID)
	}()

	role, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{
		ProductID: project.ID,
		Name:      "Editor",
		Slug:      GenerateUniqueSlug("editor"),
		Now:       now,
	})
	if err != nil {
		t.Fatalf("failed to create role: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM role_permissions WHERE role_id = $1", role.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM roles WHERE id = $1", role.ID)
	}()

	if err := testEnv.Repo.ReplaceRolePermissions(ctx, repo.ReplaceRolePermissionsParams{
		ProductID:     project.ID,
		RoleID:        role.ID,
		PermissionIDs: []uuid.UUID{perm.ID},
		Now:           now,
	}); err != nil {
		t.Fatalf("failed to attach permission to role: %v", err)
	}

	if err := testEnv.Repo.ReplaceUserRoles(ctx, repo.ReplaceUserRolesParams{
		ProductID: project.ID,
		UserID:    user.ID,
		AppID:     appID,
		RoleIDs:   []uuid.UUID{role.ID},
		Now:       now,
	}); err != nil {
		t.Fatalf("failed to assign role: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/check-permission?accountId="+user.ID.String()+"&permission=posts:read", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp api.ServerCheckPermissionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if !resp.Allowed {
		t.Error("expected allowed to be true")
	}
	if resp.Permission != "posts:read" {
		t.Errorf("expected permission \"posts:read\", got %q", resp.Permission)
	}
	if resp.AccountID != user.ID.String() {
		t.Errorf("expected accountId %q, got %q", user.ID.String(), resp.AccountID)
	}
}

func TestServerCheckPermission_Denied(t *testing.T) {
	router := setupServerAPIRouter(t)

	emailAddr := "srv-chk-no-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	req := httptest.NewRequest(http.MethodGet,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/check-permission?accountId="+user.ID.String()+"&permission=posts:write", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp api.ServerCheckPermissionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Allowed {
		t.Error("expected allowed to be false")
	}
}

func TestServerCheckPermission_MissingPermission(t *testing.T) {
	router := setupServerAPIRouter(t)

	emailAddr := "srv-chk-mp-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	accountID := uuid.Must(uuid.NewV4())
	req := httptest.NewRequest(http.MethodGet,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/check-permission?accountId="+accountID.String(), nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

func TestServerCheckPermission_MissingAccountId(t *testing.T) {
	router := setupServerAPIRouter(t)

	emailAddr := "srv-chk-ma-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	req := httptest.NewRequest(http.MethodGet,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/check-permission?permission=posts:read", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

func TestServerCheckPermission_AccountNotFound(t *testing.T) {
	router := setupServerAPIRouter(t)

	emailAddr := "srv-chk-anf-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	fakeAccountID := uuid.Must(uuid.NewV4())
	req := httptest.NewRequest(http.MethodGet,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/check-permission?accountId="+fakeAccountID.String()+"&permission=posts:read", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d: %s", http.StatusNotFound, rr.Code, rr.Body.String())
	}
}

// TestServerGetUser_SamePool confirms the happy path: looking up a user by ID
// through an app whose pool the user belongs to returns the user.
func TestServerGetUser_SamePool(t *testing.T) {
	router := setupServerAPIRouter(t)

	emailAddr := "srv-getuser-ok-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	req := httptest.NewRequest(http.MethodGet,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users/"+user.ID.String(), nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp api.ServerUserResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.User == nil || resp.User.ID != user.ID {
		t.Fatalf("expected user %s in response, got %+v", user.ID, resp.User)
	}
}

// TestServerGetUser_ByEmail covers the GET /users?email= dispatch branch (a
// deep single-user lookup by the unique pool email).
func TestServerGetUser_ByEmail(t *testing.T) {
	router := setupServerAPIRouter(t)

	emailAddr := "srv-getuser-email-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users?email="+acc.Email, nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp api.ServerUserResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.User == nil || resp.User.ID != user.ID {
		t.Fatalf("expected user %s by email, got %+v", user.ID, resp.User)
	}
}

// TestServerGetUser_CrossPoolDenied is the regression guard for the IDOR fix:
// GetUserByID is global, so without the pool scope check an API key for one
// app could read any user on the install by ID. The user here lives in a
// different app's pool, so the lookup must 404 rather than leak the record.
func TestServerGetUser_CrossPoolDenied(t *testing.T) {
	router := setupServerAPIRouter(t)

	emailAddr := "srv-getuser-xpool-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))

	// Two products, one app each, so the apps land in distinct user pools
	// (a single product allows only one app per type).
	callerProject := testEnv.CreateTestProduct(t, ws, acc, "Caller Product", GenerateUniqueSlug("proj"))
	otherProject := testEnv.CreateTestProduct(t, ws, acc, "Other Product", GenerateUniqueSlug("proj"))
	callerApp := createTestApp(t, ws.ID, callerProject.ID, uuid.Nil, "Caller App")
	otherApp := createTestApp(t, ws.ID, otherProject.ID, uuid.Nil, "Other App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*callerProject, *otherProject}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id IN ($1, $2)", callerApp, otherApp)
	}()

	ctx := context.Background()
	// User belongs to otherApp's pool, not callerApp's.
	foreignUser, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: otherApp}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", foreignUser.ID)
	}()

	// Look the foreign user up by ID through callerApp — must not leak.
	req := httptest.NewRequest(http.MethodGet,
		"/x/"+ws.Slug+"/api/v1/apps/"+callerApp.String()+"/users/"+foreignUser.ID.String(), nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected status %d (cross-pool lookup must not leak), got %d: %s",
			http.StatusNotFound, rr.Code, rr.Body.String())
	}
}

// TestServerGetUser_PoolMemberNotInApp_Denied locks in the scoping rule: the
// server API gates on app_users membership, not the pool. A user who exists in
// the app's pool but never joined the app must 404 (the pool only shares
// credentials, it is not an access boundary).
func TestServerGetUser_PoolMemberNotInApp_Denied(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-getuser-nm-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	ctx := context.Background()
	appRow, err := testEnv.Repo.GetAppByID(ctx, appID)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}

	// Create the user in the app's pool but DO NOT add app membership.
	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, acc.Email, &appRow, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	req := httptest.NewRequest(http.MethodGet,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users/"+user.ID.String(), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a pool user who isn't an app member, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =====================
// Server API write tests
// =====================

func TestServerReplaceUserRoles_NotMember(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-roles-nm-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	ctx := context.Background()
	appRow, err := testEnv.Repo.GetAppByID(ctx, appID)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}
	// Pool user, not an app member.
	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, acc.Email, &appRow, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	body, _ := json.Marshal(api.ServerReplaceRolesRequest{Roles: []string{"anything"}})
	req := httptest.NewRequest(http.MethodPut,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users/"+user.ID.String()+"/roles", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 assigning roles to a non-member, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestServerRevokeUserSessions_Success(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-revoke-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM client_sessions WHERE user_id = $1", user.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	now := time.Now().UTC()
	aID := appID
	for i := 0; i < 2; i++ {
		ses := &core.ClientSession{
			ID:         uuid.Must(uuid.NewV4()),
			UserID:     user.ID,
			AppID:      &aID,
			CreatedAt:  now,
			LastSeenAt: now,
			ExpiresAt:  now.Add(24 * time.Hour),
		}
		if err := testEnv.Repo.InsertClientSession(ctx, ses); err != nil {
			t.Fatalf("InsertClientSession: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodDelete,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users/"+user.ID.String()+"/sessions", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp api.ServerRevokeSessionsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Revoked != 2 {
		t.Fatalf("expected 2 sessions revoked, got %d", resp.Revoked)
	}

	remaining, err := testEnv.Repo.GetActiveClientSessionsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetActiveClientSessionsByUserID: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("expected no sessions after revoke, got %d", len(remaining))
	}
}

func TestServerRevokeUserSessions_NotMember(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-revoke-nm-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	// Random user that is not a member of the app.
	req := httptest.NewRequest(http.MethodDelete,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users/"+uuid.Must(uuid.NewV4()).String()+"/sessions", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for non-member, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestServerReplaceUserRoles_Success(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-roles-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM user_roles WHERE app_id = $1", appID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	slug := GenerateUniqueSlug("editor")
	role, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{
		ProductID: project.ID, Name: "Editor", Slug: slug, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM roles WHERE id = $1", role.ID)
	}()

	body, _ := json.Marshal(api.ServerReplaceRolesRequest{Roles: []string{slug}})
	req := httptest.NewRequest(http.MethodPut,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users/"+user.ID.String()+"/roles", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp api.ServerRolesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(resp.Roles) != 1 || resp.Roles[0] != slug {
		t.Fatalf("expected roles [%s], got %v", slug, resp.Roles)
	}
}

func TestServerReplaceUserRoles_UnknownSlug(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-roles-bad-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	body, _ := json.Marshal(api.ServerReplaceRolesRequest{Roles: []string{"does-not-exist"}})
	req := httptest.NewRequest(http.MethodPut,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users/"+user.ID.String()+"/roles", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown slug, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestServerUpsertAndDeleteUserFieldValue(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-field-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	ctx := context.Background()
	appRow, err := testEnv.Repo.GetAppByID(ctx, appID)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}

	now := time.Now().UTC()
	field, err := testEnv.Repo.CreateUserField(ctx, core.UserField{
		UserPoolID: appRow.UserPoolID,
		Key:        "nickname",
		ValueType:  core.UserFieldValueTypeString,
		Visibility: core.UserFieldVisibilityServer,
		Label:      "Nickname",
		Status:     "active",
		CreatedAt:  now,
		UpdatedAt:  now,
		CreatedBy:  acc.ID,
	})
	if err != nil {
		t.Fatalf("CreateUserField: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM user_field_values WHERE user_field_id = $1", field.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM user_fields WHERE id = $1", field.ID)
	}()

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	base := "/x/" + ws.Slug + "/api/v1/apps/" + appID.String() +
		"/user-fields/" + field.ID.String() + "/users/" + user.ID.String()

	// Wrong type → 400.
	bad := httptest.NewRequest(http.MethodPut, base, strings.NewReader(`{"value": true}`))
	badRR := httptest.NewRecorder()
	router.ServeHTTP(badRR, bad)
	if badRR.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong-typed value, got %d: %s", badRR.Code, badRR.Body.String())
	}

	// Valid upsert → 200 and persisted.
	put := httptest.NewRequest(http.MethodPut, base, strings.NewReader(`{"value": "ace"}`))
	putRR := httptest.NewRecorder()
	router.ServeHTTP(putRR, put)
	if putRR.Code != http.StatusOK {
		t.Fatalf("expected 200 for upsert, got %d: %s", putRR.Code, putRR.Body.String())
	}
	values, err := testEnv.Repo.GetUserFieldValuesByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserFieldValuesByUser: %v", err)
	}
	if len(values) != 1 || string(values[0].ValueJSON) != `"ace"` {
		t.Fatalf("expected stored value \"ace\", got %+v", values)
	}

	// Delete → 204 and gone.
	del := httptest.NewRequest(http.MethodDelete, base, nil)
	delRR := httptest.NewRecorder()
	router.ServeHTTP(delRR, del)
	if delRR.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for delete, got %d: %s", delRR.Code, delRR.Body.String())
	}
	values, err = testEnv.Repo.GetUserFieldValuesByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserFieldValuesByUser after delete: %v", err)
	}
	if len(values) != 0 {
		t.Fatalf("expected no values after delete, got %d", len(values))
	}
}

// =====================
// Server API provisioning tests
// =====================

func TestServerCreateUser_NewAndIdempotent(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-prov-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	ctx := context.Background()
	emailAddr := "provisioned-" + GenerateUniqueSlug("u") + "@example.com"
	base := "/x/" + ws.Slug + "/api/v1/apps/" + appID.String() + "/users"

	body, _ := json.Marshal(api.ServerCreateUserRequest{Email: emailAddr, EmailVerified: true})

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, base, bytes.NewReader(body)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 on first create, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp api.ServerCreateUserResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !resp.Created || resp.User == nil {
		t.Fatalf("expected created=true with a user, got %+v", resp)
	}
	uid := resp.User.ID
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", uid)
	}()

	// Membership was created and email marked verified.
	if m, _ := testEnv.Repo.GetAppUser(ctx, appID, uid); m == nil {
		t.Fatal("created user should be a member of the app")
	}
	if u, _ := testEnv.Repo.GetUserByID(ctx, uid); u == nil || u.EmailVerifiedAt == nil {
		t.Fatal("user should exist and be email-verified")
	}

	// Second call with the same email is idempotent: reuse, created=false.
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, httptest.NewRequest(http.MethodPost, base, bytes.NewReader(body)))
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200 on idempotent re-create, got %d: %s", rr2.Code, rr2.Body.String())
	}
	var resp2 api.ServerCreateUserResponse
	if err := json.Unmarshal(rr2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp2.Created || resp2.User == nil || resp2.User.ID != uid {
		t.Fatalf("expected created=false reusing %s, got %+v", uid, resp2)
	}
}

func TestServerCreateUser_WithRoles(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-prov-roles-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM user_roles WHERE app_id = $1", appID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	ctx := context.Background()
	slug := GenerateUniqueSlug("editor")
	role, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{
		ProductID: project.ID, Name: "Editor", Slug: slug, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM roles WHERE id = $1", role.ID)
	}()

	emailAddr := "provisioned-roles-" + GenerateUniqueSlug("u") + "@example.com"
	body, _ := json.Marshal(api.ServerCreateUserRequest{Email: emailAddr, Roles: []string{slug}})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users", bytes.NewReader(body)))

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp api.ServerCreateUserResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", resp.User.ID)
	}()
	if len(resp.Roles) != 1 || resp.Roles[0] != slug {
		t.Fatalf("expected roles [%s], got %v", slug, resp.Roles)
	}
}

func TestServerCreateUser_InvalidEmail(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-prov-bad-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	body, _ := json.Marshal(api.ServerCreateUserRequest{Email: "not-an-email"})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users", bytes.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid email, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestServerRemoveUser_PrunesOrphan(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-rm-orphan-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users/"+user.ID.String(), nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp api.ServerRemoveUserResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !resp.RemovedFromApp || !resp.IdentityDeleted {
		t.Fatalf("expected removedFromApp+identityDeleted for a sole-app member, got %+v", resp)
	}
	if u, _ := testEnv.Repo.GetUserByID(ctx, user.ID); u != nil {
		t.Fatal("orphaned identity should have been deleted from the pool")
	}
}

func TestServerRemoveUser_KeepsIdentityWhenInOtherApp(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-rm-keep-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	prodA := testEnv.CreateTestProduct(t, ws, acc, "Product A", GenerateUniqueSlug("proj"))
	prodB := testEnv.CreateTestProduct(t, ws, acc, "Product B", GenerateUniqueSlug("proj"))
	appA := createTestApp(t, ws.ID, prodA.ID, uuid.Nil, "App A")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*prodA, *prodB}}
	defer testEnv.CleanupTestData(t, fixtures)

	ctx := context.Background()
	appARow, err := testEnv.Repo.GetAppByID(ctx, appA)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}

	// App B shares App A's pool (the SSO case), in a different product so it
	// doesn't hit the product/type uniqueness constraint.
	appB := uuid.Must(uuid.NewV4())
	if _, err := testEnv.DB.Pool().Exec(ctx, `
		INSERT INTO apps (id, workspace_id, product_id, user_pool_id, type, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'dev', true, NOW(), NOW())`,
		appB, ws.ID, prodB.ID, appARow.UserPoolID); err != nil {
		t.Fatalf("insert app B: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM apps WHERE id IN ($1, $2)", appA, appB)
	}()

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &appARow, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()
	if _, _, err := testEnv.Repo.EnsureAppMember(ctx, appB, user.ID, core.UserSourceInvited); err != nil {
		t.Fatalf("add member to app B: %v", err)
	}

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete,
		"/x/"+ws.Slug+"/api/v1/apps/"+appA.String()+"/users/"+user.ID.String(), nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp api.ServerRemoveUserResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !resp.RemovedFromApp || resp.IdentityDeleted {
		t.Fatalf("identity must be kept while user is still in App B, got %+v", resp)
	}
	if u, _ := testEnv.Repo.GetUserByID(ctx, user.ID); u == nil {
		t.Fatal("identity should still exist (member of App B)")
	}
	if m, _ := testEnv.Repo.GetAppUser(ctx, appA, user.ID); m != nil {
		t.Fatal("should no longer be a member of App A")
	}
	if m, _ := testEnv.Repo.GetAppUser(ctx, appB, user.ID); m == nil {
		t.Fatal("should still be a member of App B")
	}
}

func TestServerRemoveUser_NotMember(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-rm-nm-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users/"+uuid.Must(uuid.NewV4()).String(), nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 removing a non-member, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =====================
// Server API catalog + status tests
// =====================

func TestServerListRolesAndPermissions(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-catalog-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	ctx := context.Background()
	now := time.Now().UTC()
	perm := core.Permission{ID: utils.NewUUID(), ProductID: project.ID, Name: "Read", Slug: "posts:read", CreatedAt: now, UpdatedAt: now}
	if err := testEnv.Repo.CreatePermission(ctx, perm); err != nil {
		t.Fatalf("CreatePermission: %v", err)
	}
	roleSlug := GenerateUniqueSlug("editor")
	role, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{ProductID: project.ID, Name: "Editor", Slug: roleSlug, Now: now})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := testEnv.Repo.ReplaceRolePermissions(ctx, repo.ReplaceRolePermissionsParams{
		ProductID: project.ID, RoleID: role.ID, PermissionIDs: []uuid.UUID{perm.ID}, Now: now,
	}); err != nil {
		t.Fatalf("ReplaceRolePermissions: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM role_permissions WHERE role_id = $1", role.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM roles WHERE id = $1", role.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM permissions WHERE id = $1", perm.ID)
	}()

	base := "/x/" + ws.Slug + "/api/v1/apps/" + appID.String()

	// Roles
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, base+"/roles", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /roles: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var rolesResp api.ServerRolesListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &rolesResp); err != nil {
		t.Fatalf("parse roles: %v", err)
	}
	found := false
	for _, role := range rolesResp.Roles {
		if role.Slug == roleSlug {
			found = true
			if len(role.Permissions) != 1 || role.Permissions[0] != "posts:read" {
				t.Fatalf("expected role %s to grant [posts:read], got %v", roleSlug, role.Permissions)
			}
		}
	}
	if !found {
		t.Fatalf("expected role %s in catalog, got %+v", roleSlug, rolesResp.Roles)
	}

	// Permissions
	pr := httptest.NewRecorder()
	router.ServeHTTP(pr, httptest.NewRequest(http.MethodGet, base+"/permissions", nil))
	if pr.Code != http.StatusOK {
		t.Fatalf("GET /permissions: expected 200, got %d: %s", pr.Code, pr.Body.String())
	}
	var permsResp api.ServerPermissionsListResponse
	if err := json.Unmarshal(pr.Body.Bytes(), &permsResp); err != nil {
		t.Fatalf("parse permissions: %v", err)
	}
	permFound := false
	for _, p := range permsResp.Permissions {
		if p.Slug == "posts:read" {
			permFound = true
		}
	}
	if !permFound {
		t.Fatalf("expected permission posts:read in catalog, got %+v", permsResp.Permissions)
	}
}

func TestServerSetUserStatus_DisableThenEnable(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-status-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM client_sessions WHERE user_id = $1", user.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	// Live session that should be revoked on disable.
	now := time.Now().UTC()
	aID := appID
	if err := testEnv.Repo.InsertClientSession(ctx, &core.ClientSession{
		ID: uuid.Must(uuid.NewV4()), UserID: user.ID, AppID: &aID, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("InsertClientSession: %v", err)
	}

	base := "/x/" + ws.Slug + "/api/v1/apps/" + appID.String() + "/users/" + user.ID.String()

	// Disable
	body, _ := json.Marshal(api.ServerSetUserStatusRequest{Status: "disabled"})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPatch, base, bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("disable: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp api.ServerUserStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Status != "disabled" {
		t.Fatalf("expected status disabled, got %q", resp.Status)
	}
	if m, _ := testEnv.Repo.GetAppUser(ctx, appID, user.ID); m == nil || m.Status != core.AppUserStatusDisabled {
		t.Fatalf("membership should be disabled, got %+v", m)
	}
	if sessions, _ := testEnv.Repo.GetActiveClientSessionsByUserID(ctx, user.ID); len(sessions) != 0 {
		t.Fatalf("disable should revoke the app's sessions, %d remain", len(sessions))
	}

	// Re-enable
	body, _ = json.Marshal(api.ServerSetUserStatusRequest{Status: "active"})
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPatch, base, bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("enable: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if m, _ := testEnv.Repo.GetAppUser(ctx, appID, user.ID); m == nil || m.Status != core.AppUserStatusActive {
		t.Fatalf("membership should be active again, got %+v", m)
	}
}

func TestServerSetUserStatus_NotMemberAndInvalid(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-status-nm-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	base := "/x/" + ws.Slug + "/api/v1/apps/" + appID.String() + "/users/"

	// Invalid status on a real (member) user → 400 before any membership work.
	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()
	bad, _ := json.Marshal(api.ServerSetUserStatusRequest{Status: "frozen"})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPatch, base+user.ID.String(), bytes.NewReader(bad)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid status: expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	// Valid status on a non-member → 404.
	ok, _ := json.Marshal(api.ServerSetUserStatusRequest{Status: "disabled"})
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPatch, base+uuid.Must(uuid.NewV4()).String(), bytes.NewReader(ok)))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("non-member: expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =====================
// Server API magic-link tests
// =====================

func TestServerCreateMagicLink_Success(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-ml-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	appRow, err := testEnv.Repo.GetAppByID(context.Background(), appID)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}
	configureAppForMagicLink(t, &appRow)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM magic_links WHERE lower(email) = lower($1)", user.Email)
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users/"+user.ID.String()+"/magic-link", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp api.ServerMagicLinkResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !strings.Contains(resp.URL, "/auth/magic-link") || !strings.Contains(resp.URL, "token=") {
		t.Fatalf("expected a consumable magic-link URL, got %q", resp.URL)
	}
	if !resp.ExpiresAt.After(time.Now()) {
		t.Fatalf("expected a future expiry, got %v", resp.ExpiresAt)
	}
}

// TestServerCreateMagicLink_RoundTripLogsIn proves the issue→consume contract:
// a link minted by the S2S endpoint is actually redeemable at the public
// consume endpoint and logs the holder in (302 + session). This pins the
// otherwise-only-by-inspection guarantee that token/purpose/URL/TTL all line up.
func TestServerCreateMagicLink_RoundTripLogsIn(t *testing.T) {
	serverRouter := setupServerAPIRouter(t)
	clientRouter := setupClientAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-ml-rt-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	appRow, err := testEnv.Repo.GetAppByID(context.Background(), appID)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}
	configureAppForMagicLink(t, &appRow)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM magic_links WHERE lower(email) = lower($1)", user.Email)
		_, _ = pool.Exec(ctx, "DELETE FROM client_sessions WHERE user_id = $1", user.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	// Issue the link via the S2S endpoint.
	rr := httptest.NewRecorder()
	serverRouter.ServeHTTP(rr, httptest.NewRequest(http.MethodPost,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users/"+user.ID.String()+"/magic-link", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("issue: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp api.ServerMagicLinkResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	parsed, err := url.Parse(resp.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	token := parsed.Query().Get("token")
	if token == "" {
		t.Fatalf("no token in issued URL %q", resp.URL)
	}

	// Consume it at the public endpoint — should log the user in.
	cr := httptest.NewRecorder()
	clientRouter.ServeHTTP(cr, httptest.NewRequest(http.MethodGet,
		"/x/"+ws.Slug+"/apps/"+appID.String()+"/auth/magic-link?token="+token, nil))
	if cr.Code != http.StatusFound {
		t.Fatalf("consume: expected 302, got %d: %s", cr.Code, cr.Body.String())
	}
	if loc := cr.Header().Get("Location"); !strings.Contains(loc, "mr_session=") {
		t.Fatalf("consume redirect should carry a session, got %q", loc)
	}
}

func TestServerCreateMagicLink_AuthMethodDisabled(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-ml-off-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App") // password-primary by default

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users/"+uuid.Must(uuid.NewV4()).String()+"/magic-link", nil))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when app isn't magic-link primary, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestServerCreateMagicLink_NotMember(t *testing.T) {
	router := setupServerAPIRouter(t)

	acc := testEnv.CreateTestAccount(t, "srv-ml-nm-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	appRow, err := testEnv.Repo.GetAppByID(context.Background(), appID)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}
	configureAppForMagicLink(t, &appRow)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users/"+uuid.Must(uuid.NewV4()).String()+"/magic-link", nil))

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a non-member, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =====================
// OTP Login Tests
// =====================

func TestWorkspaceLoginRequest_Success(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "otp-req-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_otp_codes WHERE workspace_id = $1", ws.ID)
	}()

	body := map[string]any{
		"email": emailAddr,
		"appId": app.ID.String(),
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["ok"] != true {
		t.Error("expected ok: true in response")
	}
}

func TestWorkspaceLoginRequest_AnyEmailAllowed(t *testing.T) {
	// With workspace accounts, anyone can request an OTP code.
	// The workspace account is created on verification, not on request.
	router := setupClientAPIRouter(t)

	ownerEmail := "owner-otp-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, owner)

	// Use a random email that has no account
	newUserEmail := "newuser-otp-" + GenerateUniqueSlug("test") + "@example.com"

	fixtures := &TestFixtures{Account: owner, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"email": newUserEmail,
		"appId": app.ID.String(),
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Should succeed - anyone can request an OTP
	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
}

func TestWorkspaceLogin_InvalidCode(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "otp-verify-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"email": emailAddr,
		"code":  "000000", // Invalid code
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/verify", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d: %s", http.StatusUnauthorized, rr.Code, rr.Body.String())
	}
}

func TestWorkspaceLogin_InvalidCodeFormat(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "otp-format-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"email": emailAddr,
		"code":  "abc", // Invalid format
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/verify", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

// =====================
// Workspace Not Found Tests
// =====================

func TestClientAPI_WorkspaceNotFound(t *testing.T) {
	router := setupClientAPIRouter(t)

	fakeAppID := uuid.Must(uuid.NewV4())

	body := map[string]any{
		"email": "test@example.com",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/nonexistent-workspace-slug/apps/"+fakeAppID.String()+"/auth", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d: %s", http.StatusForbidden, rr.Code, rr.Body.String())
	}
}

// =====================
// Get App For AppKit Tests
// =====================

// setupAppKitRouter creates a router for AppKit tests
func setupAppKitRouter(t *testing.T) *chi.Mux {
	t.Helper()

	cfg := GetTestConfig()
	adminAuthService, err := auth.NewAuthService(cfg, testEnv.Repo)
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}

	clientAuthService, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("failed to create client auth service: %v", err)
	}

	emailService := email.NewEmailService(true, nil)

	requestHandler := api.NewRequestHandler(
		testEnv.Repo,
		adminAuthService,
		clientAuthService,
		emailService,
		cfg,
		nil,
		nil,
	)

	r := chi.NewRouter()

	// Mount at /x/{workspaceSlug} to mirror the real router
	wsRouter := chi.NewRouter()

	// Workspace middleware
	wsRouter.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			workspaceSlug := chi.URLParam(r, "workspaceSlug")
			if workspaceSlug == "" {
				http.Error(w, "missing workspace slug", http.StatusBadRequest)
				return
			}
			ws, ok, err := testEnv.Repo.GetWorkspaceBySlug(r.Context(), workspaceSlug)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if !ok {
				http.Error(w, "workspace not found", http.StatusForbidden)
				return
			}
			ctx := core.WithWorkspace(r.Context(), ws)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	// AppKit endpoint (public, no auth required) — app from URL
	wsRouter.Route("/apps/{appId}", func(ar chi.Router) {
		ar.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := r.Context()
				ws, ok := core.WorkspaceFromContext(ctx)
				if !ok || ws == nil {
					next.ServeHTTP(w, r)
					return
				}
				appIDStr := chi.URLParam(r, "appId")
				appID, err := uuid.FromString(appIDStr)
				if err != nil {
					http.Error(w, "invalid app id", http.StatusBadRequest)
					return
				}
				app, err := testEnv.Repo.GetAppByID(ctx, appID)
				if err != nil {
					http.Error(w, "app not found", http.StatusNotFound)
					return
				}
				if app.WorkspaceID != ws.ID || !app.Enabled {
					http.Error(w, "app not found", http.StatusNotFound)
					return
				}
				ctx = core.WithApp(ctx, &app)
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		})
		ar.Get("/", requestHandler.HandleGetAppForAppKit)
	})

	r.Mount("/x/{workspaceSlug}", wsRouter)

	return r
}

func createTestApp(t *testing.T, workspaceID, productID, _ uuid.UUID, name string) uuid.UUID {
	t.Helper()
	ctx := context.Background()

	userPool, err := testEnv.Repo.CreateUserPool(ctx, workspaceID, "Pool for "+name+" "+GenerateUniqueSlug("p"))
	if err != nil {
		t.Fatalf("failed to create user pool: %v", err)
	}

	appID := utils.NewUUID()
	pool := testEnv.DB.Pool()
	_, err = pool.Exec(ctx, `
		INSERT INTO apps (id, workspace_id, product_id, user_pool_id, type, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'dev', true, NOW(), NOW())
	`, appID, workspaceID, productID, userPool.ID)
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	return appID
}

func TestGetAppForAppKit_Success(t *testing.T) {
	router := setupAppKitRouter(t)

	emailAddr := "appkit-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+appID.String(), nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Response contains app resource directly (id, name, workspaceSlug, workspaceName, productId, appId)
	if resp["id"] == nil {
		t.Error("expected id in response")
	}
	if resp["name"] == nil {
		t.Error("expected name in response")
	}
	if resp["workspaceSlug"] == nil {
		t.Error("expected workspaceSlug in response")
	}
	if resp["workspaceName"] == nil {
		t.Error("expected workspaceName in response")
	}
	if resp["workspaceName"] != "Test WS" {
		t.Errorf("expected workspaceName to be 'Test WS', got %v", resp["workspaceName"])
	}
}

func TestGetAppForAppKit_NotFound(t *testing.T) {
	router := setupAppKitRouter(t)

	emailAddr := "appkit-nf-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	fakeAppID := uuid.Must(uuid.NewV4())
	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+fakeAppID.String(), nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d: %s", http.StatusNotFound, rr.Code, rr.Body.String())
	}
}

func TestGetAppForAppKit_InvalidAppID(t *testing.T) {
	router := setupAppKitRouter(t)

	emailAddr := "appkit-inv-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/invalid-uuid", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusNotFound {
		t.Errorf("expected status %d or %d, got %d: %s", http.StatusBadRequest, http.StatusNotFound, rr.Code, rr.Body.String())
	}
}

// =====================
// Workspace Registration Tests
// =====================

func TestWorkspaceRegister_Success(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	router := setupClientAPIRouter(t)

	emailAddr := "wsreg-owner-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	// Set workspace to a plan that supports registration
	testEnv.SetWorkspacePlan(t, ws.ID, "pro")

	// Enable registration for the app with a default role
	role := createTestRole(t, project.ID)
	ctx := context.Background()
	_, _ = testEnv.DB.Pool().Exec(ctx, "UPDATE apps SET allow_registration = true, default_role_id = $1 WHERE id = $2", role.ID, appID)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)

	newUserEmail := "newuser-" + GenerateUniqueSlug("test") + "@example.com"
	body := map[string]any{
		"appId": appID.String(),
		"email": newUserEmail,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+appID.String()+"/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["ok"] != true {
		t.Errorf("expected ok to be true")
	}
}

func TestWorkspaceRegister_AppNotFound(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "wsreg-nf-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	fakeAppID := uuid.Must(uuid.NewV4())
	body := map[string]any{
		"appId": fakeAppID.String(),
		"email": "newuser@example.com",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+fakeAppID.String()+"/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d: %s", http.StatusNotFound, rr.Code, rr.Body.String())
	}
}

func TestWorkspaceRegister_RegistrationDisabled(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "wsreg-disabled-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")
	// Note: registration is disabled by default

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"appId": appID.String(),
		"email": "newuser@example.com",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+appID.String()+"/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d: %s", http.StatusForbidden, rr.Code, rr.Body.String())
	}
}

// =====================
// Password Auth Tests
// =====================

func TestWorkspaceLoginPassword_Success(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	router := setupClientAPIRouter(t)

	emailAddr := "wspwlogin-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	// Create a user with password via the users table
	ctx := context.Background()
	password := "testpassword123"
	hash, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	now := time.Now().UTC()
	_, err = testEnv.DB.Pool().Exec(ctx, `
		UPDATE users SET password_hash = $1, password_set_at = $2, email_verified_at = $3 WHERE id = $4
	`, hash, now, now, user.ID)
	if err != nil {
		t.Fatalf("failed to set password on user: %v", err)
	}

	body := map[string]any{
		"email":    emailAddr,
		"password": password,
		"appId":    app.ID.String(),
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/password", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["accessToken"] == nil {
		t.Error("expected accessToken in response")
	}
	if resp["refreshToken"] == nil {
		t.Error("expected refreshToken in response")
	}
}

func TestWorkspaceLoginPassword_WrongPassword(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	router := setupClientAPIRouter(t)

	emailAddr := "wspwlogin-wrong-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	// Create a user with password via the users table
	ctx := context.Background()
	now := time.Now().UTC()
	password := "correctpassword123"
	hash, _ := passwordhash.Hash(password)

	user, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, core.UserSourceInvited)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()
	_, _ = testEnv.DB.Pool().Exec(ctx, `
		UPDATE users SET password_hash = $1, password_set_at = $2, email_verified_at = $3 WHERE id = $4
	`, hash, now, now, user.ID)

	body := map[string]any{
		"email":    emailAddr,
		"password": "wrongpassword",
		"appId":    app.ID.String(),
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/password", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d: %s", http.StatusUnauthorized, rr.Code, rr.Body.String())
	}
}

func TestWorkspaceLoginPassword_AccountNotFound(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	router := setupClientAPIRouter(t)

	emailAddr := "wspwlogin-nf-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"email":    "nonexistent@example.com",
		"password": "somepassword123",
		"appId":    app.ID.String(),
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/password", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d: %s", http.StatusUnauthorized, rr.Code, rr.Body.String())
	}
}

// =====================
// Forgot/Reset Password Tests
// =====================

func TestWorkspaceForgotPassword_Success(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	router := setupClientAPIRouter(t)

	emailAddr := "wsforgot-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	// Create a user with password via the users table
	ctx := context.Background()
	now := time.Now().UTC()
	password := "testpassword123"
	hash, _ := passwordhash.Hash(password)

	user, _, _ := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, core.UserSourceInvited)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()
	_, _ = testEnv.DB.Pool().Exec(ctx, `
		UPDATE users SET password_hash = $1, password_set_at = $2, email_verified_at = $3 WHERE id = $4
	`, hash, now, now, user.ID)

	body := map[string]any{
		"email": emailAddr,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/forgot-password", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Should always return OK to prevent email enumeration
	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
}

func TestWorkspaceForgotPassword_NonExistent(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	router := setupClientAPIRouter(t)

	emailAddr := "wsforgot-nf-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"email": "nonexistent@example.com",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/forgot-password", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Should still return OK to prevent email enumeration
	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
}

func TestWorkspaceResetPassword_InvalidCode(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	router := setupClientAPIRouter(t)

	emailAddr := "wsreset-inv-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"email":       emailAddr,
		"code":        "123456",
		// zxcvbn-strong password so the invalid-code path runs without
		// tripping the password-strength validator first.
		"newPassword": "Tr0ub4dor&3-correct-horse",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/reset-password", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d: %s", http.StatusUnauthorized, rr.Code, rr.Body.String())
	}
}

func TestWorkspaceResetPassword_ShortPassword(t *testing.T) {
	testEnv.ClearRateLimitAttempts(t)
	router := setupClientAPIRouter(t)

	emailAddr := "wsreset-short-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"email":       emailAddr,
		"code":        "123456",
		"newPassword": "short", // Too short
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/auth/reset-password", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

// =====================
// Profile Update Tests
// =====================

func TestWorkspaceUpdateDisplayName_Success(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "wsprofile-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	// Create a workspace account and session
	clientSes, accessToken := createTestClientSessionForApp(t, ws, acc, app)
	_ = clientSes

	body := map[string]any{
		"displayName": "New Display Name",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/profile/display-name", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["ok"] != true {
		t.Error("expected ok to be true")
	}
}

func TestWorkspaceUpdateDisplayName_Empty(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "wsprofile-empty-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	clientSes, accessToken := createTestClientSessionForApp(t, ws, acc, app)
	_ = clientSes

	body := map[string]any{
		"displayName": "",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/profile/display-name", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// The handler is a no-op that always returns ok (display name is now stored client-side)
	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
}

func TestWorkspaceUpdateDisplayName_Unauthenticated(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "wsprofile-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"displayName": "New Name",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/profile/display-name", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// =====================
// Set Password Tests
// =====================

func TestWorkspaceSetPassword_Success(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "wssetpw-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	clientSes, accessToken := createTestClientSessionForApp(t, ws, acc, app)

	// Setting a password on an account without an existing password now
	// requires either a recent OTP at this app or the change-password
	// path. Pre-seed a password hash so the test can hit the
	// change-password branch with currentPassword.
	currentPW := "Tr0ub4dor&3-current"
	hash, err := passwordhash.Hash(currentPW)
	if err != nil {
		t.Fatalf("hash current password: %v", err)
	}
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		"UPDATE users SET password_hash = $1 WHERE id = $2", hash, clientSes.UserID,
	); err != nil {
		t.Fatalf("seed password_hash: %v", err)
	}

	body := map[string]any{
		"currentPassword": currentPW,
		"password":        "Tr0ub4dor&3-new",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/set-password", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["ok"] != true {
		t.Error("expected ok to be true")
	}
}

func TestWorkspaceSetPassword_TooShort(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "wssetpw-short-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	clientSes, accessToken := createTestClientSessionForApp(t, ws, acc, app)
	_ = clientSes

	body := map[string]any{
		"password": "short", // Too short (< 10 chars)
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/set-password", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

func TestWorkspaceSetPassword_Unauthenticated(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "wssetpw-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body := map[string]any{
		"password": "newpassword123",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/set-password", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// =====================
// ServerGetAppMembers
// =====================

func TestServerGetAppMembers_Success(t *testing.T) {
	router := setupServerAPIRouter(t)

	emailAddr := "srv-members-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM user_roles WHERE app_id IN (SELECT id FROM apps WHERE product_id = $1)", project.ID)
	}()

	ctx := context.Background()
	now := time.Now().UTC()

	// Create workspace account and assign a role
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	role, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{
		ProductID: project.ID,
		Name:      "Editor",
		Slug:      GenerateUniqueSlug("editor"),
		Now:       now,
	})
	if err != nil {
		t.Fatalf("failed to create role: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM roles WHERE id = $1", role.ID)
	}()

	if err := testEnv.Repo.ReplaceUserRoles(ctx, repo.ReplaceUserRolesParams{
		ProductID: project.ID,
		UserID:    user.ID,
		AppID:     appID,
		RoleIDs:   []uuid.UUID{role.ID},
		Now:       now,
	}); err != nil {
		t.Fatalf("failed to assign role: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp struct {
		Members []struct {
			UserID string   `json:"userId"`
			Email  string   `json:"email"`
			Name   string   `json:"name"`
			Roles  []string `json:"roles"`
		} `json:"members"`
		Total    int `json:"total"`
		Page     int `json:"page"`
		PageSize int `json:"pageSize"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Total != 1 {
		t.Fatalf("expected total 1, got %d", resp.Total)
	}
	if len(resp.Members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(resp.Members))
	}
	if resp.Members[0].Email != acc.Email {
		t.Errorf("expected email %q, got %q", acc.Email, resp.Members[0].Email)
	}
	if len(resp.Members[0].Roles) != 1 || resp.Members[0].Roles[0] != role.Slug {
		t.Errorf("expected roles [%q], got %v", role.Slug, resp.Members[0].Roles)
	}
}

func TestServerGetAppMembers_Empty(t *testing.T) {
	router := setupServerAPIRouter(t)

	emailAddr := "srv-members-empty-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	req := httptest.NewRequest(http.MethodGet,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp struct {
		Members []any `json:"members"`
		Total   int   `json:"total"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Total != 0 {
		t.Errorf("expected total 0, got %d", resp.Total)
	}
	if len(resp.Members) != 0 {
		t.Errorf("expected 0 members, got %d", len(resp.Members))
	}
}

func TestServerGetAppMembers_EmailFilter(t *testing.T) {
	router := setupServerAPIRouter(t)

	slug := GenerateUniqueSlug("test")
	emailAddr := "srv-members-filter-" + slug + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM user_roles WHERE app_id IN (SELECT id FROM apps WHERE product_id = $1)", project.ID)
	}()

	ctx := context.Background()
	now := time.Now().UTC()

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	role, err := testEnv.Repo.CreateRole(ctx, repo.CreateRoleParams{
		ProductID: project.ID,
		Name:      "Viewer",
		Slug:      GenerateUniqueSlug("viewer"),
		Now:       now,
	})
	if err != nil {
		t.Fatalf("failed to create role: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM roles WHERE id = $1", role.ID)
	}()

	if err := testEnv.Repo.ReplaceUserRoles(ctx, repo.ReplaceUserRolesParams{
		ProductID: project.ID,
		UserID:    user.ID,
		AppID:     appID,
		RoleIDs:   []uuid.UUID{role.ID},
		Now:       now,
	}); err != nil {
		t.Fatalf("failed to assign role: %v", err)
	}

	// Search with matching email
	req := httptest.NewRequest(http.MethodGet,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users?search="+slug, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp struct {
		Members []any `json:"members"`
		Total   int   `json:"total"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Total != 1 {
		t.Errorf("expected total 1, got %d", resp.Total)
	}

	// Search with non-matching email
	req2 := httptest.NewRequest(http.MethodGet,
		"/x/"+ws.Slug+"/api/v1/apps/"+appID.String()+"/users?search=nonexistent-xyz", nil)
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr2.Code, rr2.Body.String())
	}

	var resp2 struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp2.Total != 0 {
		t.Errorf("expected total 0, got %d", resp2.Total)
	}
}

// TestIssueRefreshToken_DefaultTTL verifies that IssueRefreshToken with sessionTTL=0
// uses the default 7-day TTL.
func TestIssueRefreshToken_DefaultTTL(t *testing.T) {
	email := "rt-defttl-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	ctx := context.Background()
	cfg := GetTestConfig()
	clientAuthService, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("failed to create client auth service: %v", err)
	}

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	ses, err := clientAuthService.CreateSession(ctx, user.ID, app.ID, "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to create client session: %v", err)
	}

	before := time.Now()
	_, rt, err := clientAuthService.IssueRefreshToken(ctx, ses.ID, "test-agent", "127.0.0.1", 0, "")
	after := time.Now()
	if err != nil {
		t.Fatalf("failed to issue refresh token: %v", err)
	}

	// Default TTL is 7 days
	expectedMin := before.Add(7 * 24 * time.Hour)
	expectedMax := after.Add(7 * 24 * time.Hour)

	if rt.ExpiresAt.Before(expectedMin) || rt.ExpiresAt.After(expectedMax) {
		t.Errorf("expected ExpiresAt ~7 days from now, got %v (expected between %v and %v)",
			rt.ExpiresAt, expectedMin, expectedMax)
	}
}

// TestIssueRefreshToken_CustomTTL verifies that IssueRefreshToken with a custom sessionTTL
// uses that TTL instead of the default.
func TestIssueRefreshToken_CustomTTL(t *testing.T) {
	email := "rt-customttl-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	ctx := context.Background()
	cfg := GetTestConfig()
	clientAuthService, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("failed to create client auth service: %v", err)
	}

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	ses, err := clientAuthService.CreateSession(ctx, user.ID, app.ID, "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to create client session: %v", err)
	}

	customTTL := 30 * time.Minute
	before := time.Now()
	_, rt, err := clientAuthService.IssueRefreshToken(ctx, ses.ID, "test-agent", "127.0.0.1", customTTL, "")
	after := time.Now()
	if err != nil {
		t.Fatalf("failed to issue refresh token: %v", err)
	}

	expectedMin := before.Add(customTTL)
	expectedMax := after.Add(customTTL)

	if rt.ExpiresAt.Before(expectedMin) || rt.ExpiresAt.After(expectedMax) {
		t.Errorf("expected ExpiresAt ~30 min from now, got %v (expected between %v and %v)",
			rt.ExpiresAt, expectedMin, expectedMax)
	}
}

// =====================
// GetMySessions / DeleteMySession Tests
// =====================

// TestGetMySessions_Success tests that GET /me/sessions returns active sessions
// with the current session flagged as current=true.
func TestGetMySessions_Success(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "sessions-get-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_refresh_tokens WHERE session_id IN (SELECT id FROM client_sessions WHERE workspace_id = $1)", ws.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
	}()

	// Create a client session with a JWT access token
	ses, accessToken := createTestClientSessionForApp(t, ws, acc, app)
	_ = ses

	// Clean up the user created for the session
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM users WHERE id = $1", ses.UserID)
	}()

	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/me/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	sessions, ok := resp["sessions"].([]any)
	if !ok {
		t.Fatalf("expected sessions array, got %T", resp["sessions"])
	}

	if len(sessions) == 0 {
		t.Fatalf("expected at least one session, got 0")
	}

	// At least one session should have current=true
	foundCurrent := false
	for _, s := range sessions {
		entry, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if entry["current"] == true {
			foundCurrent = true
			// Verify other fields are present
			if entry["id"] == nil || entry["id"] == "" {
				t.Error("expected non-empty session id")
			}
			if entry["createdAt"] == nil || entry["createdAt"] == "" {
				t.Error("expected non-empty createdAt")
			}
			if entry["lastSeenAt"] == nil || entry["lastSeenAt"] == "" {
				t.Error("expected non-empty lastSeenAt")
			}
			break
		}
	}
	if !foundCurrent {
		t.Error("expected at least one session with current=true")
	}
}

// TestDeleteMySession_CannotRevokeCurrent tests that DELETE /me/sessions/{sessionId}
// returns 400 when trying to revoke the current session.
func TestDeleteMySession_CannotRevokeCurrent(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "sessions-del-cur-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_refresh_tokens WHERE session_id IN (SELECT id FROM client_sessions WHERE workspace_id = $1)", ws.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
	}()

	ses, accessToken := createTestClientSessionForApp(t, ws, acc, app)

	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM users WHERE id = $1", ses.UserID)
	}()

	// Try to revoke the current session
	req := httptest.NewRequest(http.MethodDelete, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/me/sessions/"+ses.ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

// TestDeleteMySession_Success tests that DELETE /me/sessions/{sessionId}
// successfully revokes a non-current session.
func TestDeleteMySession_Success(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "sessions-del-ok-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_refresh_tokens WHERE session_id IN (SELECT id FROM client_sessions WHERE workspace_id = $1)", ws.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
	}()

	ctx := context.Background()
	cfg := GetTestConfig()
	clientAuthService, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("failed to create client auth service: %v", err)
	}

	// Create a user for the app
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM users WHERE id = $1", user.ID)
	}()

	// Create first session (this will be our "current" session)
	ses1, err := clientAuthService.CreateSession(ctx, user.ID, app.ID, "test-agent-1", "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to create first session: %v", err)
	}
	tokenPair1, err := clientAuthService.IssueTokenPair(ctx, ses1, "test-agent-1", "127.0.0.1", 0, 0, "", "")
	if err != nil {
		t.Fatalf("failed to issue token pair for first session: %v", err)
	}

	// Create second session (this is the one we will revoke)
	ses2, err := clientAuthService.CreateSession(ctx, user.ID, app.ID, "test-agent-2", "127.0.0.2")
	if err != nil {
		t.Fatalf("failed to create second session: %v", err)
	}
	_, err = clientAuthService.IssueTokenPair(ctx, ses2, "test-agent-2", "127.0.0.2", 0, 0, "", "")
	if err != nil {
		t.Fatalf("failed to issue token pair for second session: %v", err)
	}

	// Delete the second session using the first session's token
	req := httptest.NewRequest(http.MethodDelete, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/me/sessions/"+ses2.ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+tokenPair1.AccessToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d: %s", http.StatusNoContent, rr.Code, rr.Body.String())
	}

	// Verify the revoked session is gone by listing sessions
	reqList := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/me/sessions", nil)
	reqList.Header.Set("Authorization", "Bearer "+tokenPair1.AccessToken)

	rrList := httptest.NewRecorder()
	router.ServeHTTP(rrList, reqList)

	if rrList.Code != http.StatusOK {
		t.Fatalf("expected status %d listing sessions, got %d: %s", http.StatusOK, rrList.Code, rrList.Body.String())
	}

	var listResp map[string]any
	if err := json.Unmarshal(rrList.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to parse list response: %v", err)
	}

	sessions, ok := listResp["sessions"].([]any)
	if !ok {
		t.Fatalf("expected sessions array, got %T", listResp["sessions"])
	}

	// The revoked session should NOT be in the list
	for _, s := range sessions {
		entry, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if entry["id"] == ses2.ID.String() {
			t.Errorf("revoked session %s should not appear in sessions list", ses2.ID.String())
		}
	}
}

// =====================
// Role-Targeted Feature Flag Delivery Tests
// =====================

// TestGetAppData_RoleTargetedFlag_UserHasRole verifies that a role-targeted flag
// is delivered as enabled to a user who has the matching role.
func TestGetAppData_RoleTargetedFlag_UserHasRole(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "ff-role-has-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM feature_flag_overrides WHERE feature_flag_id IN (SELECT id FROM feature_flags WHERE product_id = $1)", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM feature_flags WHERE product_id = $1", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM user_roles WHERE app_id IN (SELECT id FROM apps WHERE product_id = $1)", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM roles WHERE product_id = $1", project.ID)
	}()

	ctx := context.Background()
	now := time.Now().UTC()

	// Create feature flag via repo
	ff, err := testEnv.Repo.CreateFeatureFlag(ctx, core.FeatureFlag{
		ID:             utils.NewUUID(),
		ProductID:      project.ID,
		Key:            "role_targeted_flag",
		Scope:          core.FeatureFlagScopeClient,
		DefaultEnabled: false,
		Status:         "active",
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      acc.ID,
	})
	if err != nil {
		t.Fatalf("failed to create feature flag: %v", err)
	}

	// Create role
	role := createTestRole(t, project.ID)

	_, err = testEnv.Repo.UpsertFeatureFlagOverride(ctx, core.FeatureFlagOverride{
		ID:            utils.NewUUID(),
		ProductID:     project.ID,
		AppID:         appID,
		FeatureFlagID: ff.ID,
		Enabled:       true,
		RoleIDs:       []uuid.UUID{role.ID},
		Status:        "active",
		UpdatedAt:     now,
		UpdatedBy:     acc.ID,
	})
	if err != nil {
		t.Fatalf("failed to upsert feature flag: %v", err)
	}

	// Create user for the app
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Assign role to user
	if err := testEnv.Repo.ReplaceUserRoles(ctx, repo.ReplaceUserRolesParams{
		ProductID: project.ID,
		UserID:    user.ID,
		AppID:     appID,
		RoleIDs:   []uuid.UUID{role.ID},
		Now:       now,
	}); err != nil {
		t.Fatalf("failed to assign role to user: %v", err)
	}

	// Create client session
	_, accessToken := createTestClientSessionForApp(t, ws, acc, &core.App{ID: appID})

	// Call the delivery endpoint
	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+appID.String()+"/a/runtime", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	flags, ok := resp["featureFlags"].([]any)
	if !ok {
		t.Fatalf("expected featureFlags array in response")
	}

	// Find our flag
	found := false
	for _, f := range flags {
		flag := f.(map[string]any)
		if flag["key"] == "role_targeted_flag" {
			found = true
			if flag["enabled"] != true {
				t.Errorf("expected role_targeted_flag to be enabled for user with matching role, got %v", flag["enabled"])
			}
			break
		}
	}
	if !found {
		t.Error("expected role_targeted_flag in response")
	}
}

// TestGetAppData_RoleTargetedFlag_UserLacksRole verifies that a role-targeted flag
// is delivered as enabled:false to a user who does NOT have the matching role.
func TestGetAppData_RoleTargetedFlag_UserLacksRole(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "ff-role-lacks-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM feature_flag_overrides WHERE feature_flag_id IN (SELECT id FROM feature_flags WHERE product_id = $1)", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM feature_flags WHERE product_id = $1", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM user_roles WHERE app_id IN (SELECT id FROM apps WHERE product_id = $1)", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM roles WHERE product_id = $1", project.ID)
	}()

	ctx := context.Background()
	now := time.Now().UTC()

	// Create feature flag via repo
	ff, err := testEnv.Repo.CreateFeatureFlag(ctx, core.FeatureFlag{
		ID:             utils.NewUUID(),
		ProductID:      project.ID,
		Key:            "role_no_match_flag",
		Scope:          core.FeatureFlagScopeClient,
		DefaultEnabled: false,
		Status:         "active",
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      acc.ID,
	})
	if err != nil {
		t.Fatalf("failed to create feature flag: %v", err)
	}

	// Create role (but do NOT assign it to the user)
	role := createTestRole(t, project.ID)

	_, err = testEnv.Repo.UpsertFeatureFlagOverride(ctx, core.FeatureFlagOverride{
		ID:            utils.NewUUID(),
		ProductID:     project.ID,
		AppID:         appID,
		FeatureFlagID: ff.ID,
		Enabled:       true,
		RoleIDs:       []uuid.UUID{role.ID},
		Status:        "active",
		UpdatedAt:     now,
		UpdatedBy:     acc.ID,
	})
	if err != nil {
		t.Fatalf("failed to upsert feature flag: %v", err)
	}

	// Create client session (user does NOT have the role)
	_, accessToken := createTestClientSessionForApp(t, ws, acc, &core.App{ID: appID})

	// Call the delivery endpoint
	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+appID.String()+"/a/runtime", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	flags, ok := resp["featureFlags"].([]any)
	if !ok {
		t.Fatalf("expected featureFlags array in response")
	}

	// Find our flag — it should be delivered with enabled:false
	found := false
	for _, f := range flags {
		flag := f.(map[string]any)
		if flag["key"] == "role_no_match_flag" {
			found = true
			if flag["enabled"] != false {
				t.Errorf("expected role_no_match_flag to be disabled for user without role, got %v", flag["enabled"])
			}
			break
		}
	}
	if !found {
		t.Error("expected role_no_match_flag in response (with enabled:false)")
	}
}

// TestGetAppData_NoRoleTargeting verifies that a flag with no roleIds
// is delivered as enabled to all users.
func TestGetAppData_NoRoleTargeting(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "ff-no-role-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Test App")

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM feature_flag_overrides WHERE feature_flag_id IN (SELECT id FROM feature_flags WHERE product_id = $1)", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM feature_flags WHERE product_id = $1", project.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
	}()

	ctx := context.Background()
	now := time.Now().UTC()

	// Create feature flag via repo (no role targeting)
	ff, err := testEnv.Repo.CreateFeatureFlag(ctx, core.FeatureFlag{
		ID:             utils.NewUUID(),
		ProductID:      project.ID,
		Key:            "no_role_flag",
		Scope:          core.FeatureFlagScopeClient,
		DefaultEnabled: false,
		Status:         "active",
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      acc.ID,
	})
	if err != nil {
		t.Fatalf("failed to create feature flag: %v", err)
	}

	_, err = testEnv.Repo.UpsertFeatureFlagOverride(ctx, core.FeatureFlagOverride{
		ID:            utils.NewUUID(),
		ProductID:     project.ID,
		AppID:         appID,
		FeatureFlagID: ff.ID,
		Enabled:       true,
		RoleIDs:       []uuid.UUID{}, // empty = applies to everyone
		Status:        "active",
		UpdatedAt:     now,
		UpdatedBy:     acc.ID,
	})
	if err != nil {
		t.Fatalf("failed to upsert feature flag: %v", err)
	}

	// Create client session
	_, accessToken := createTestClientSessionForApp(t, ws, acc, &core.App{ID: appID})

	// Call the delivery endpoint
	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+appID.String()+"/a/runtime", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	flags, ok := resp["featureFlags"].([]any)
	if !ok {
		t.Fatalf("expected featureFlags array in response")
	}

	// Find our flag — it should be enabled for everyone (no role restriction)
	found := false
	for _, f := range flags {
		flag := f.(map[string]any)
		if flag["key"] == "no_role_flag" {
			found = true
			if flag["enabled"] != true {
				t.Errorf("expected no_role_flag to be enabled for all users, got %v", flag["enabled"])
			}
			break
		}
	}
	if !found {
		t.Error("expected no_role_flag in response")
	}
}

// =====================
// Sensitive-op re-auth gate (PR #3, commit 1fe493b)
// =====================
//
// The /a/totp/setup endpoint requires { password } or { code } in
// the body so a stolen access token alone can't bind an attacker-
// controlled authenticator. These tests exercise the wire contract
// directly: no body → error.reauthRequired; wrong password →
// error.invalidCredentials; right password → 200 with a TOTP secret.

func TestSensitiveReauth_TOTPSetup_RequiresBody(t *testing.T) {
	router := setupClientAPIRouter(t)
	ctx := context.Background()

	emailAddr := "reauth-setup-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	// Create a user with a password so the password gate is usable.
	const userPassword = "userpassword-correct-horse"
	hash, err := passwordhash.Hash(userPassword)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, "u-"+GenerateUniqueSlug("e")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	defer func() {
		_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()
	now := time.Now().UTC()
	if _, err := testEnv.DB.Pool().Exec(ctx, `UPDATE users SET password_hash=$1, password_set_at=$2, email_verified_at=$3 WHERE id=$4`, hash, now, now, user.ID); err != nil {
		t.Fatalf("set password: %v", err)
	}

	// Issue a session for this user.
	cfg := GetTestConfig()
	clientAuth, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("client auth service: %v", err)
	}
	ses, err := clientAuth.CreateSession(ctx, user.ID, app.ID, "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	tokens, err := clientAuth.IssueTokenPair(ctx, ses, "test-agent", "127.0.0.1", 0, 0, "", "")
	if err != nil {
		t.Fatalf("issue tokens: %v", err)
	}
	accessToken := tokens.AccessToken

	postSetup := func(body any) *httptest.ResponseRecorder {
		buf, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/totp/setup", bytes.NewReader(buf))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	t.Run("empty body returns reauthRequired", func(t *testing.T) {
		rr := postSetup(map[string]any{})
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body = %s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "reauthRequired") {
			t.Errorf("expected error.reauthRequired, got: %s", rr.Body.String())
		}
	})

	t.Run("wrong password returns invalidCredentials", func(t *testing.T) {
		rr := postSetup(map[string]any{"password": "not-the-password"})
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body = %s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "invalidCredentials") {
			t.Errorf("expected error.invalidCredentials, got: %s", rr.Body.String())
		}
	})

	t.Run("correct password returns secret + uri", func(t *testing.T) {
		rr := postSetup(map[string]any{"password": userPassword})
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
		}
		var resp struct {
			Secret string `json:"secret"`
			URI    string `json:"uri"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("parse response: %v", err)
		}
		if resp.Secret == "" {
			t.Error("response is missing secret")
		}
		if resp.URI == "" {
			t.Error("response is missing uri")
		}
	})
}

func TestSensitiveReauth_PasskeyDelete_RequiresBody(t *testing.T) {
	router := setupClientAPIRouter(t)
	ctx := context.Background()

	emailAddr := "reauth-pk-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	const userPassword = "passkey-test-pw"
	hash, err := passwordhash.Hash(userPassword)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, "u-"+GenerateUniqueSlug("e")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	defer func() {
		_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()
	now := time.Now().UTC()
	if _, err := testEnv.DB.Pool().Exec(ctx, `UPDATE users SET password_hash=$1, password_set_at=$2, email_verified_at=$3 WHERE id=$4`, hash, now, now, user.ID); err != nil {
		t.Fatalf("set password: %v", err)
	}

	cfg := GetTestConfig()
	clientAuth, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("client auth service: %v", err)
	}
	ses, err := clientAuth.CreateSession(ctx, user.ID, app.ID, "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	tokens, err := clientAuth.IssueTokenPair(ctx, ses, "test-agent", "127.0.0.1", 0, 0, "", "")
	if err != nil {
		t.Fatalf("issue tokens: %v", err)
	}
	accessToken := tokens.AccessToken

	// Try to delete a (nonexistent) passkey with no body — should
	// hit the re-auth gate FIRST and return reauthRequired, not
	// notFound. Order matters: an attacker who knows the body shape
	// would otherwise be able to enumerate passkey IDs by watching
	// which UUIDs return 404 vs 401.
	deletePasskey := func(body any) *httptest.ResponseRecorder {
		buf, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodDelete, "/x/"+ws.Slug+"/apps/"+app.ID.String()+"/a/passkeys/"+uuid.Must(uuid.NewV4()).String(), bytes.NewReader(buf))
		req.ContentLength = int64(len(buf))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	t.Run("empty body returns reauthRequired before passkey lookup", func(t *testing.T) {
		rr := deletePasskey(map[string]any{})
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body = %s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "reauthRequired") {
			t.Errorf("expected error.reauthRequired, got: %s", rr.Body.String())
		}
	})

	t.Run("correct password reaches the actual delete path (404 for unknown id)", func(t *testing.T) {
		rr := deletePasskey(map[string]any{"password": userPassword})
		// We passed the re-auth gate; the unknown UUID in the URL
		// now yields error.notFound from the repo. Either status is
		// fine — we just need to confirm we got past the 401 gate.
		if rr.Code == http.StatusUnauthorized {
			t.Fatalf("expected to pass the re-auth gate, but got 401: %s", rr.Body.String())
		}
	})
}
