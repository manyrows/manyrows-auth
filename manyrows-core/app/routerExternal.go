package app

import (
	"context"
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

		// Cross-device sign-in (QR) phone landing page. Browser opens
		// this when the user scans the desktop's QR code.
		ar.Get("/pair", h.HandlePairLandingPage)

		// Desktop-side hosted QR page. Customers link to this with
		// ?return_to=… to bootstrap the cross-device sign-in flow.
		ar.Get("/qr-sign-in", h.HandleQRSignInPage)

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
			// Generic external IdP (OIDC / OAuth2), one route pair for
			// every configured provider, keyed by {providerSlug}.
			auth.Get("/idp/{providerSlug}/authorize", h.WorkspaceExternalIDPAuthorize)
			auth.Get("/idp/{providerSlug}/callback", h.WorkspaceExternalIDPCallback)
			auth.Post("/totp/verify", h.HandleWorkspaceTOTPVerify)
			auth.Post("/totp/setup-init", h.HandleWorkspaceTOTPSetupInit)
			auth.Post("/totp/setup-complete", h.HandleWorkspaceTOTPSetupComplete)
			auth.Post("/passkey/login/begin", h.WorkspacePasskeyLoginBegin)
			auth.Post("/passkey/login/finish", h.WorkspacePasskeyLoginFinish)

			// Cross-device sign-in (QR pairing).
			// /start and /wait are anonymous (the desktop holds the
			// opaque pairing id from /start). /approve and /cancel
			// require the phone's app session, which the handlers
			// validate internally.
			auth.Post("/pair/start", h.HandleAuthPairStart)
			auth.Get("/pair/wait", h.HandleAuthPairWait)
			auth.Post("/pair/approve", h.HandleAuthPairApprove)
			auth.Post("/pair/cancel", h.HandleAuthPairCancel)
			auth.Get("/pair/qr", h.HandleAuthPairQR)
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
// Endpoints live under a /v1 version segment, so the full base is
// /x/{workspaceSlug}/api/v1/apps/{appId}. Bump to /v2 (mounted alongside
// /v1) for a future breaking change rather than mutating /v1 in place.
// NOTE: do NOT mount "/api" again inside here, or you'll get /api/api.
// =====================
func (a *AppService) serverAPIRouter(h *api.RequestHandler) *chi.Mux {
	r := chi.NewRouter()

	// Outermost: one structured audit line per request, including auth
	// failures and throttled requests (which never reach a handler).
	r.Use(serverAccessLogMiddleware())

	r.Use(workspaceMiddleware(a.repo))
	r.Use(apiKeyMiddleware(a.repo, newLastUsedThrottle(time.Minute)))

	// Per-key throttle, after auth so the key is in context. Created once
	// here (serverAPIRouter is built a single time at startup) so the
	// token buckets persist for the process lifetime.
	r.Use(apiKeyRateLimitMiddleware(newAPIKeyRateLimiter(a.config.GetAPIRateLimitPerMinute())))

	// App-scoped routes (resolves project+env from app, then CORS/IP)
	appRouter := chi.NewRouter()
	appRouter.Use(appMiddleware(a.repo))
	appRouter.Use(appIPAllowlistMiddleware(a.repo))
	appRouter.Get("/", h.GetDeliveryForServer)
	appRouter.Get("/check-permission", h.ServerCheckPermission)

	// Authorization catalog: the assignable role/permission slugs for the app.
	appRouter.Get("/roles", h.ServerListRoles)
	appRouter.Get("/permissions", h.ServerListPermissions)

	// Config-value + feature-flag management (read via the delivery endpoint).
	appRouter.Put("/config/{configKey}", h.ServerSetConfigValue)
	appRouter.Delete("/config/{configKey}", h.ServerDeleteConfigValue)
	appRouter.Put("/features/{flagKey}", h.ServerSetFeatureFlag)
	appRouter.Delete("/features/{flagKey}", h.ServerDeleteFeatureFlag)

	// User fields (app-scoped). Schema is read-only; values can be read
	// and written per user (handlers pool-scope every userId).
	appRouter.Get("/user-fields", h.HandleServerGetUserFields)
	appRouter.Get("/user-fields/users/{userId}", h.HandleServerGetUserFieldValues)
	appRouter.Put("/user-fields/{userFieldId}/users/{userId}", h.ServerUpsertUserFieldValue)
	appRouter.Delete("/user-fields/{userFieldId}/users/{userId}", h.ServerDeleteUserFieldValue)

	// Users: list app members (GET /users, ?search= filter) or look one up by
	// email (GET /users?email=); fetch one by id (GET /users/{userId});
	// provision (POST /users, create-or-find in pool + add to app).
	appRouter.Get("/users", h.HandleServerGetUser)
	appRouter.Get("/users/{userId}", h.ServerGetUserByID)
	appRouter.Post("/users", h.ServerCreateUser)
	appRouter.Post("/users:batch", h.ServerBatchCreateUsers)
	// Suspend / re-enable a user in this app (per-app membership status).
	appRouter.Patch("/users/{userId}", h.ServerSetUserStatus)
	// Generate a one-time passwordless sign-in link for a member.
	appRouter.Post("/users/{userId}/magic-link", h.ServerCreateMagicLink)

	// User mutations (force-logout, role assignment, removal), app/pool-scoped.
	appRouter.Get("/users/{userId}/sessions", h.ServerListUserSessions)
	appRouter.Delete("/users/{userId}/sessions", h.ServerRevokeUserSessions)
	appRouter.Delete("/users/{userId}/sessions/{sessionId}", h.ServerRevokeUserSession)
	appRouter.Put("/users/{userId}/roles", h.ServerReplaceUserRoles)
	// Direct per-user permission overrides (on top of role-granted permissions).
	appRouter.Get("/users/{userId}/permissions", h.ServerGetUserPermissions)
	appRouter.Put("/users/{userId}/permissions", h.ServerSetUserPermissions)
	// Authentication-event history for a member.
	appRouter.Get("/users/{userId}/auth-logs", h.ServerGetUserAuthLogs)
	// Password management.
	appRouter.Put("/users/{userId}/password", h.ServerSetUserPassword)
	appRouter.Delete("/users/{userId}/password", h.ServerClearUserPassword)
	// Email verification.
	appRouter.Put("/users/{userId}/email-verified", h.ServerSetUserEmailVerified)
	// Remove a user from this app; prunes the pool identity if the user is
	// left with no app memberships.
	appRouter.Delete("/users/{userId}", h.ServerRemoveUser)

	r.Mount("/v1/apps/{appId}", appRouter)

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
func apiKeyMiddleware(rpo *repo.Repo, touch *lastUsedThrottle) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ws, ok := core.WorkspaceFromContext(r.Context())
			if !ok || ws == nil {
				api.WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
				return
			}
			if f := serverAccessLogFieldsFrom(r.Context()); f != nil {
				f.workspaceID = ws.ID.String()
			}

			raw := strings.TrimSpace(r.Header.Get("X-API-Key"))
			if raw == "" {
				authz := strings.TrimSpace(r.Header.Get("Authorization"))
				if len(authz) >= 7 && strings.EqualFold(authz[:7], "bearer ") {
					raw = strings.TrimSpace(authz[7:])
				}
			}
			if raw == "" {
				api.WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
				return
			}

			prefix, ok := parseAPIKeyPrefix(raw)
			if !ok {
				api.WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
				return
			}

			// NOTE: you must implement repo.GetAPIKeyByPrefix(ctx, ws.ID, prefix)
			key, found, err := rpo.GetAPIKeyByPrefix(r.Context(), ws.ID, prefix)
			if err != nil {
				log.Err(err).Msg("apiKeyMiddleware: GetAPIKeyByPrefix failed")
				api.WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
			if !found || key == nil {
				api.WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
				return
			}

			// Hash *fullKey* exactly like generateApiKey()
			sum := sha256.Sum256([]byte(raw))
			presented := hex.EncodeToString(sum[:])

			// Constant-time compare
			if subtle.ConstantTimeCompare([]byte(key.Hash), []byte(presented)) != 1 {
				api.WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
				return
			}

			// If the key is scoped to an app, validate it matches the requested app
			if key.AppID != nil && *key.AppID != uuid.Nil {
				reqAppIDStr := chi.URLParam(r, "appId")
				if reqAppIDStr != "" {
					reqAppID, parseErr := uuid.FromString(reqAppIDStr)
					if parseErr != nil || *key.AppID != reqAppID {
						api.WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
						return
					}
				}
			}

			if f := serverAccessLogFieldsFrom(r.Context()); f != nil {
				f.apiKeyID = key.ID.String()
				f.apiKeyName = key.Name
			}

			// Record last use without blocking the request. The in-memory
			// throttle keeps this off the DB on the hot path (once per
			// interval per key); the repo's WHERE clause is the
			// multi-process backstop. Detached context so it outlives the
			// request.
			if touch.shouldWrite(key.ID) {
				go func(id uuid.UUID) {
					bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := rpo.TouchAPIKeyLastUsed(bgCtx, id); err != nil {
						log.Err(err).Msg("apiKeyMiddleware: TouchAPIKeyLastUsed failed")
					}
				}(key.ID)
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
				api.WriteError(w, r, "error.missingWorkspaceSlug", http.StatusBadRequest)
				return
			}

			ws, ok, err := rpo.GetWorkspaceBySlug(ctx, workspaceSlug)
			if err != nil {
				api.WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
			if !ok {
				api.WriteError(w, r, "error.workspaceNotFound", http.StatusForbidden)
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
				api.WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if app was already resolved (by CORS middleware for browser requests).
			app, appOk := core.AppFromContext(ctx)
			if appOk && app != nil {
				if app.WorkspaceID != ws.ID {
					api.WriteError(w, r, "error.appNotFound", http.StatusForbidden)
					return
				}
				if !app.Enabled {
					api.WriteError(w, r, "error.appDisabled", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Full resolution for non-browser requests (CORS middleware skipped).
			appID, err := utils.GetPathUUID("appId", r)
			if err != nil {
				api.WriteError(w, r, "error.invalidAppId", http.StatusBadRequest)
				return
			}

			loaded, err := rpo.GetAppByID(ctx, appID)
			if err != nil {
				if errors.Is(err, repo.ErrNotFound) {
					api.WriteError(w, r, "error.appNotFound", http.StatusForbidden)
					return
				}
				api.WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}

			if loaded.WorkspaceID != ws.ID {
				api.WriteError(w, r, "error.appNotFound", http.StatusForbidden)
				return
			}

			if !loaded.Enabled {
				api.WriteError(w, r, "error.appDisabled", http.StatusForbidden)
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
				api.WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
				return
			}

			// Use app from context if already resolved (by appFromURLMiddleware).
			app, appOk := core.AppFromContext(ctx)
			if !appOk || app == nil {
				// Fallback: resolve from URL (for server API routes that don't use appFromURLMiddleware)
				appID, err := utils.GetPathUUID("appId", r)
				if err != nil {
					api.WriteError(w, r, "error.invalidAppId", http.StatusBadRequest)
					return
				}

				loaded, err := rpo.GetAppByID(ctx, appID)
				if err != nil {
					if errors.Is(err, repo.ErrNotFound) {
						api.WriteError(w, r, "error.appNotFound", http.StatusForbidden)
						return
					}
					api.WriteError(w, r, "error.internalError", http.StatusInternalServerError)
					return
				}

				if loaded.WorkspaceID != ws.ID {
					api.WriteError(w, r, "error.appNotFound", http.StatusForbidden)
					return
				}

				if !loaded.Enabled {
					api.WriteError(w, r, "error.appDisabled", http.StatusForbidden)
					return
				}

				app = &loaded
				ctx = core.WithApp(ctx, app)
			}

			// Load project
			project, err := rpo.GetProduct(ctx, app.ProductID, ws.ID)
			if err != nil {
				api.WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
			if project == nil {
				api.WriteError(w, r, "error.projectNotFound", http.StatusForbidden)
				return
			}

			ctx = core.WithProduct(ctx, project)

			if f := serverAccessLogFieldsFrom(ctx); f != nil {
				f.appID = app.ID.String()
			}

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
				api.WriteError(w, r, "error.internalError", http.StatusInternalServerError)
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
				api.WriteError(w, r, "error.ipNotAllowed", http.StatusForbidden)
				return
			}

			// Get all allowlist entries
			entries, err := rpo.GetIPAllowlist(ctx, app.ID)
			if err != nil {
				log.Err(err).Str("app_id", app.ID.String()).Msg("appIPAllowlistMiddleware: failed to get allowlist")
				api.WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}

			// Check if client IP matches any entry
			ip := net.ParseIP(clientIP)
			if ip == nil {
				api.WriteError(w, r, "error.ipNotAllowed", http.StatusForbidden)
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
				api.WriteError(w, r, "error.ipNotAllowed", http.StatusForbidden)
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

