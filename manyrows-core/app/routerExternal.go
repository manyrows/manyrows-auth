package app

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"manyrows-core/api"
	"manyrows-core/auth"
	"manyrows-core/auth/client"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// =====================
// CLIENT ROUTER (browser/mobile/etc)
// Mounted at: /x/{workspaceSlug}
// =====================
func (a *AppService) externalAPIRouter(h *api.RequestHandler, corsMiddleware func(next http.Handler) http.Handler) *chi.Mux {
	r := chi.NewRouter()

	// Workspace is required for auth/session
	r.Use(workspaceMiddleware(a.repo))

	// All external client routes live under /apps/{appId}.
	// This ensures every request has a resolved app in context,
	// so CORS and IP allowlist middleware always have per-app data.
	r.Route("/apps/{appId}", func(ar chi.Router) {
		// Per-app CORS runs FIRST so that CORS headers are present on
		// every response, including errors from downstream middleware.
		// It resolves the app from the URL param if not already in context.
		ar.Use(corsMiddleware)

		// Validate app (workspace ownership + enabled).
		// Skips re-loading if CORS middleware already resolved the app.
		ar.Use(appFromURLMiddleware(a.repo))

		// Per-app IP allowlist
		ar.Use(appIPAllowlistMiddleware(a.repo))

		// Public: app config for AppKit bootstrap
		ar.Get("/", h.HandleGetAppForAppKit)

		// Auth routes (public POST routes)
		ar.Route("/auth", func(auth chi.Router) {
			auth.Post("/", h.WorkspaceLoginRequest)
			auth.Post("/verify", h.WorkspaceLogin)
			auth.Post("/request-magic-link", h.WorkspaceLoginRequestMagicLink)
			auth.Get("/magic-link", h.WorkspaceConsumeMagicLink)
			auth.Post("/refresh", h.WorkspaceRefresh)
			auth.Post("/logout", h.WorkspacePublicLogout)
			auth.Post("/register", h.WorkspaceRegister)
			auth.Post("/password", h.WorkspaceLoginPassword)
			auth.Post("/forgot-password", h.WorkspaceForgotPassword)
			auth.Post("/reset-password", h.WorkspaceResetPassword)
			auth.Post("/google", h.WorkspaceLoginGoogle)
			auth.Get("/google/authorize", h.WorkspaceGoogleAuthorize)
			auth.Get("/google/callback", h.WorkspaceGoogleCallbackGET)
			auth.Post("/google/callback", h.WorkspaceGoogleCallback)
			auth.Get("/apple/authorize", h.WorkspaceAppleAuthorize)
			auth.Post("/apple/callback", h.WorkspaceAppleCallback)
			auth.Get("/microsoft/authorize", h.WorkspaceMicrosoftAuthorize)
			auth.Get("/microsoft/callback", h.WorkspaceMicrosoftCallback)
			auth.Get("/github/authorize", h.WorkspaceGithubAuthorize)
			auth.Get("/github/callback", h.WorkspaceGithubCallback)
			auth.Post("/totp/verify", h.HandleWorkspaceTOTPVerify)
			auth.Post("/totp/setup-init", h.HandleWorkspaceTOTPSetupInit)
			auth.Post("/totp/setup-complete", h.HandleWorkspaceTOTPSetupComplete)
			auth.Post("/passkey/login/begin", h.WorkspacePasskeyLoginBegin)
			auth.Post("/passkey/login/finish", h.WorkspacePasskeyLoginFinish)
		})

		// Authed routes (session JWT or cookie required).
		ar.Route("/a", func(authed chi.Router) {
			authed.Use(workspaceAuthMiddleware(a.clientAuthService, a.repo))
			registerAuthedAppRoutes(authed, h, a.repo)
		})

		// OIDC provider. Public surface (no workspaceAuthMiddleware) —
		// the spec endpoints either gate their own auth (userinfo via
		// bearer, token via client_secret + PKCE) or are intentionally
		// unauthenticated (discovery, authorize, end-session). The
		// existing per-app CORS + IP allowlist still apply.
		ar.Get("/.well-known/openid-configuration", h.OIDCDiscovery)
		ar.Route("/oidc", func(oidc chi.Router) {
			oidc.Get("/authorize", h.OIDCAuthorize)
			oidc.Get("/authorize/resume", h.OIDCAuthorizeResume)
			oidc.Get("/login", h.OIDCLoginPage)
			oidc.Post("/token", h.OIDCToken)
			oidc.Get("/userinfo", h.OIDCUserInfo)
			oidc.Post("/userinfo", h.OIDCUserInfo)
			oidc.Get("/end-session", h.OIDCEndSession)
			oidc.Post("/end-session", h.OIDCEndSession)
		})
	})

	return r
}

// =====================
// SERVER ROUTER (server-to-server)
// Mounted at: /x/{workspaceSlug}/api
// NOTE: do NOT mount "/api" again inside here, or you'll get /api/api.
// =====================
func (a *AppService) serverAPIRouter(h *api.RequestHandler) *chi.Mux {
	r := chi.NewRouter()

	r.Use(workspaceMiddleware(a.repo))
	r.Use(apiKeyMiddleware(a.repo))

	// App-scoped routes (resolves project+env from app, then CORS/IP)
	appRouter := chi.NewRouter()
	appRouter.Use(appMiddleware(a.repo))
	appRouter.Use(appIPAllowlistMiddleware(a.repo))
	appRouter.Get("/", h.GetDeliveryForServer)
	appRouter.Get("/check-permission", h.ServerCheckPermission)
	appRouter.Get("/members", h.ServerGetAppMembers)

	// User fields (read-only, app-scoped)
	appRouter.Get("/user-fields", h.HandleServerGetUserFields)

	// User lookup
	appRouter.Get("/users", h.HandleServerGetUser)

	r.Mount("/apps/{appId}", appRouter)

	return r
}

// =====================
// API KEY AUTH (machine clients)
// =====================
//
// Expects full key like: mr_<prefix>_<secret>
// - prefix: first 8 chars of secret (per your generator)
// - stored hash: sha256(fullKey) hex
//
// Header:
// - Prefer: X-API-Key: <fullKey>
// - Also allow: Authorization: Bearer <fullKey>
func apiKeyMiddleware(rpo *repo.Repo) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ws, ok := core.WorkspaceFromContext(r.Context())
			if !ok || ws == nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			raw := strings.TrimSpace(r.Header.Get("X-API-Key"))
			if raw == "" {
				authz := strings.TrimSpace(r.Header.Get("Authorization"))
				if len(authz) >= 7 && strings.EqualFold(authz[:7], "bearer ") {
					raw = strings.TrimSpace(authz[7:])
				}
			}
			if raw == "" {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			prefix, ok := parseAPIKeyPrefix(raw)
			if !ok {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			// NOTE: you must implement repo.GetAPIKeyByPrefix(ctx, ws.ID, prefix)
			key, found, err := rpo.GetAPIKeyByPrefix(r.Context(), ws.ID, prefix)
			if err != nil {
				log.Err(err).Msg("apiKeyMiddleware: GetAPIKeyByPrefix failed")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if !found || key == nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			// Hash *fullKey* exactly like generateApiKey()
			sum := sha256.Sum256([]byte(raw))
			presented := hex.EncodeToString(sum[:])

			// Constant-time compare
			if subtle.ConstantTimeCompare([]byte(key.Hash), []byte(presented)) != 1 {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			// If the key is scoped to an app, validate it matches the requested app
			if key.AppID != nil && *key.AppID != uuid.Nil {
				reqAppIDStr := chi.URLParam(r, "appId")
				if reqAppIDStr != "" {
					reqAppID, parseErr := uuid.FromString(reqAppIDStr)
					if parseErr != nil || *key.AppID != reqAppID {
						http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
						return
					}
				}
			}

			// Attach for handlers/auth logging
			ctx := core.WithAPIKey(r.Context(), key)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func parseAPIKeyPrefix(fullKey string) (string, bool) {
	// Expected: "mr_<prefix>_<secret>"
	if !strings.HasPrefix(fullKey, "mr_") {
		return "", false
	}
	parts := strings.Split(fullKey, "_")
	if len(parts) != 3 {
		return "", false
	}
	prefix := strings.TrimSpace(parts[1])
	if len(prefix) != 8 {
		return "", false
	}
	if strings.TrimSpace(parts[2]) == "" {
		return "", false
	}
	return prefix, true
}

// =====================
// SESSION JWT AUTH (human/mobile clients)
// =====================
func workspaceAuthMiddleware(authService *client.AuthService, rpo *repo.Repo) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ws, ok := core.WorkspaceFromContext(r.Context())
			if !ok || ws == nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			// JWT-only: resolve session from Authorization: Bearer <token>
			ses, err := authService.GetSession(r)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if ses == nil || !ses.IsActive(time.Now().UTC()) {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			// Enforce app-scoped sessions: reject if session is bound to a different app.
			if ses.AppID != nil && *ses.AppID != uuid.Nil {
				if ctxApp, appOk := core.AppFromContext(r.Context()); appOk && ctxApp != nil {
					if *ses.AppID != ctxApp.ID {
						http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
						return
					}
				}
			}

			// Require email verification for API access
			if ses.AppID != nil && *ses.AppID != uuid.Nil {
				user, err := rpo.GetUserByID(r.Context(), ses.UserID)
				if err != nil {
					log.Err(err).Msg("workspaceAuthMiddleware: failed to get user")
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				if user == nil {
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}
				if user.EmailVerifiedAt == nil {
					http.Error(w, "email verification required", http.StatusForbidden)
					return
				}
			}

			ctx := core.WithClientSessionContext(r.Context(), ses)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// =====================
// CORS (browser-only)
// =====================
func isBrowserCORSRequest(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}

	// Definite preflight signal.
	if r.Method == http.MethodOptions && strings.TrimSpace(r.Header.Get("Access-Control-Request-Method")) != "" {
		return true
	}

	// Modern browsers send these on navigation/fetch; non-browsers usually won't.
	if strings.TrimSpace(r.Header.Get("Sec-Fetch-Mode")) != "" {
		return true
	}
	if strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")) != "" {
		return true
	}

	// Some browsers (older / unusual contexts) may not send Sec-Fetch-*.
	if strings.TrimSpace(r.Header.Get("Access-Control-Request-Headers")) != "" {
		return true
	}

	return false
}

// =====================
// WORKSPACE / PROJECT / ENV RESOLUTION
// =====================

func workspaceMiddleware(rpo *repo.Repo) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			workspaceSlug := utils.GetPathString("workspaceSlug", r)
			if workspaceSlug == "" {
				http.Error(w, "missing workspace slug", http.StatusBadRequest)
				return
			}

			ws, ok, err := rpo.GetWorkspaceBySlug(ctx, workspaceSlug)
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
}

// appFromURLMiddleware resolves an App by {appId} from the URL path.
// Lightweight: validates workspace ownership + enabled, stores in context.
// If the app is already in context (e.g. set by CORS middleware), it only
// validates workspace ownership and enabled status.
func appFromURLMiddleware(rpo *repo.Repo) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			ws, ok := core.WorkspaceFromContext(ctx)
			if !ok || ws == nil {
				http.Error(w, "invalid workspace", http.StatusUnauthorized)
				return
			}

			// Check if app was already resolved (by CORS middleware for browser requests).
			app, appOk := core.AppFromContext(ctx)
			if appOk && app != nil {
				if app.WorkspaceID != ws.ID {
					http.Error(w, "app not found", http.StatusForbidden)
					return
				}
				if !app.Enabled {
					http.Error(w, "app is disabled", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Full resolution for non-browser requests (CORS middleware skipped).
			appID, err := utils.GetPathUUID("appId", r)
			if err != nil {
				http.Error(w, "invalid app id", http.StatusBadRequest)
				return
			}

			loaded, err := rpo.GetAppByID(ctx, appID)
			if err != nil {
				if errors.Is(err, repo.ErrNotFound) {
					http.Error(w, "app not found", http.StatusForbidden)
					return
				}
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			if loaded.WorkspaceID != ws.ID {
				http.Error(w, "app not found", http.StatusForbidden)
				return
			}

			if !loaded.Enabled {
				http.Error(w, "app is disabled", http.StatusForbidden)
				return
			}

			ctx = core.WithApp(ctx, &loaded)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// appMiddleware loads the project for an app already in context.
// If no app is in context yet, it resolves the app by {appId} from the URL.
func appMiddleware(rpo *repo.Repo) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			ws, ok := core.WorkspaceFromContext(ctx)
			if !ok || ws == nil {
				http.Error(w, "invalid workspace", http.StatusUnauthorized)
				return
			}

			// Use app from context if already resolved (by appFromURLMiddleware).
			app, appOk := core.AppFromContext(ctx)
			if !appOk || app == nil {
				// Fallback: resolve from URL (for server API routes that don't use appFromURLMiddleware)
				appID, err := utils.GetPathUUID("appId", r)
				if err != nil {
					http.Error(w, "invalid app id", http.StatusBadRequest)
					return
				}

				loaded, err := rpo.GetAppByID(ctx, appID)
				if err != nil {
					if errors.Is(err, repo.ErrNotFound) {
						http.Error(w, "app not found", http.StatusForbidden)
						return
					}
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}

				if loaded.WorkspaceID != ws.ID {
					http.Error(w, "app not found", http.StatusForbidden)
					return
				}

				if !loaded.Enabled {
					http.Error(w, "app is disabled", http.StatusForbidden)
					return
				}

				app = &loaded
				ctx = core.WithApp(ctx, app)
			}

			// Load project
			project, err := rpo.GetProduct(ctx, app.ProductID, ws.ID)
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
}

// =====================
// IP ALLOWLIST (app-scoped)
// =====================

// appIPAllowlistMiddleware checks if the client IP is in the app's allowlist.
// If the app has no allowlist entries, all IPs are allowed.
// Must be placed AFTER app is resolved into context.
func appIPAllowlistMiddleware(rpo *repo.Repo) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			app, ok := core.AppFromContext(ctx)
			if !ok || app == nil {
				// No app = can't check allowlist, let downstream handle
				next.ServeHTTP(w, r)
				return
			}

			// Check if app has any allowlist entries
			hasAllowlist, err := rpo.HasIPAllowlist(ctx, app.ID)
			if err != nil {
				log.Err(err).Str("app_id", app.ID.String()).Msg("appIPAllowlistMiddleware: failed to check allowlist")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			// If no allowlist configured, allow all
			if !hasAllowlist {
				next.ServeHTTP(w, r)
				return
			}

			// Get client IP
			clientIP := getClientIP(r)
			if clientIP == "" {
				http.Error(w, "could not determine client IP", http.StatusForbidden)
				return
			}

			// Get all allowlist entries
			entries, err := rpo.GetIPAllowlist(ctx, app.ID)
			if err != nil {
				log.Err(err).Str("app_id", app.ID.String()).Msg("appIPAllowlistMiddleware: failed to get allowlist")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			// Check if client IP matches any entry
			ip := net.ParseIP(clientIP)
			if ip == nil {
				http.Error(w, "IP address not allowed", http.StatusForbidden)
				return
			}

			allowed := false
			for _, entry := range entries {
				if ipMatchesRange(ip, entry.IPRange) {
					allowed = true
					break
				}
			}

			if !allowed {
				http.Error(w, "IP address not allowed", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getClientIP extracts the client IP from the request.
func getClientIP(r *http.Request) string {
	return auth.ClientIP(r)
}

// ipMatchesRange checks if an IP matches an IP range (single IP or CIDR).
func ipMatchesRange(ip net.IP, ipRange string) bool {
	// Try CIDR first
	if strings.Contains(ipRange, "/") {
		_, network, err := net.ParseCIDR(ipRange)
		if err != nil {
			return false
		}
		return network.Contains(ip)
	}

	// Plain IP comparison
	rangeIP := net.ParseIP(ipRange)
	if rangeIP == nil {
		return false
	}
	return ip.Equal(rangeIP)
}

// =====================
// API RATE LIMITING (monthly call limits)
// =====================

