package app

import (
	"manyrows-core/appkit"
	"manyrows-core/auth"
	"manyrows-core/config"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"
	"manyrows-core/web"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

func (a *AppService) initRouter() error {
	useHTTPSOnly := a.config.GetProfile() != config.ProfileLocalDev

	// BASE_URL is no longer required at boot. The HTTPS-only middleware
	// reads it live each request (so first-/admin/register pinning kicks
	// in without a restart) and falls back to redirecting via the
	// request's own Host header when BASE_URL hasn't been pinned yet.
	// That keeps fresh self-hosted installs bootable with only
	// DATABASE_URL set.comm
	r := createBaseRouter(a.config.GetBaseURL, useHTTPSOnly)

	// Prometheus instrumentation: count + time every request, labelled by
	// matched route pattern. Registered before any route is added to r.
	m := newMetrics(a.config.GetVersion())
	m.registerDBPool(a.repo.DB().Pool())
	r.Use(m.middleware)

	// set robots.txt
	r.Get("/robots.txt", web.Robots)

	// -----------------------------
	// AppKit assets (PUBLIC CORS)
	// -----------------------------
	//
	// IMPORTANT:
	// AppKit assets are served outside /x/{workspaceSlug} and therefore DO NOT have workspace context.
	// Module scripts require CORS headers, so we must do "public" CORS here (NOT workspace-scoped).
	//
	fs := http.FileServer(http.FS(appkit.GetFS()))
	eTagHandler := etagMiddlewareForAppKit(fs)

	// Allow all origins for now (assets only).
	appkitCORSHandler := corsAppKitAssetsMiddlewareAllowAll()(eTagHandler)

	r.Handle("/appkit/*", appkitCORSHandler)
	r.Get("/appkit", appkit.HandleFrontendRouterPageIndex)
	r.Get("/appkit/app", appkit.HandleFrontendRouterPage)
	r.Get("/appkit/app/*", appkit.HandleFrontendRouterPage)

	// -----------------------------
	// Admin Console frontend
	// -----------------------------
	r.Handle("/*", securityHeadersMiddleware(http.FileServer(http.FS(web.GetFS()))))
	r.Get("/", web.HandleFrontendRouterPageIndex)
	r.Get("/app", securityHeadersHandlerFunc(web.HandleFrontendRouterPage))
	r.Get("/app/*", securityHeadersHandlerFunc(web.HandleFrontendRouterPage))

	adminRouter := chi.NewRouter()
	adminRouter.Use(adminMustBeAuthenticatedMiddleware(a.adminAuthService))

	requestHandler := a.GetRequestHandler()

	// health check (unauthenticated, for k8s probes)
	r.Get("/health", requestHandler.HandleHealth)
	r.Get("/livez", requestHandler.HandleLivez)   // liveness: process is up (no dependency check)
	r.Get("/readyz", requestHandler.HandleReadyz) // readiness: database is reachable

	// Prometheus metrics. Open by default; gated by a bearer token when
	// MANYROWS_METRICS_TOKEN is set (see metrics.handler).
	r.Handle("/metrics", m.handler(a.config.GetMetricsToken()))

	// JWKS — public, unauthenticated. Customer backends point
	// manyrows-go at this install's base URL; the SDK fetches here
	// to verify access-token signatures locally without a shared
	// secret. Cached client-side; we'd add an ETag here if traffic
	// ever warranted it.
	r.Get("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		doc, err := a.clientAuthService.JWKSDocument()
		if err != nil {
			log.Err(err).Msg("jwks: render document failed")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(doc)
	})

	// CORS middleware for API routes (app-scoped)
	cors := appCorsMiddleware(a.repo)

	// externalAPIRouter is for client app access
	clientAPIRouter := a.externalAPIRouter(requestHandler, cors)
	serverAPIRouter := a.serverAPIRouter(requestHandler)

	// A router that is mounted at /admin/workspace/{workspaceId}
	// so routes INSIDE it should NOT repeat /workspace/{workspaceId}
	adminWorkspaceRouter := chi.NewRouter()
	adminWorkspaceRouter.Use(adminWorkspaceMiddleware(a.repo))

	r.Get("/admin/auth", requestHandler.AdminProcessMagicLink)   // magic-link (invite, register, login)
	r.Get("/admin/auth/config", requestHandler.AdminAuthConfig)  // public: turnstile site key for login pages
	r.Post("/admin/auth/register", requestHandler.AdminRegister) // handles register
	r.Post("/admin/auth/login", requestHandler.AdminLogin)       // handles login
	r.Post("/admin/auth/forgot", requestHandler.AdminForgotPassword)
	r.Post("/admin/auth/reset", requestHandler.AdminResetPassword)
	r.Post("/admin/auth/totp/verify", requestHandler.AdminTOTPVerify)

	adminRouter.Post("/auth/validate", requestHandler.SendValidateEmail)
	adminRouter.Post("/auth/verify", requestHandler.VerifyValidationCode)

	// admin endpoints that are authenticated
	adminRouter.Post("/logout", requestHandler.AdminLogout)
	adminRouter.Get("/appdata", requestHandler.GetAdminAppData)

	// Install-wide security — super-admin only. Routes are flat under
	// /admin/security/ to leave room for future install-wide knobs
	// (rate-limit overrides, replay-cache nukes, etc.) without
	// reshuffling.
	adminRouter.Get("/security/signing-keys", requestHandler.GetSigningKeys)
	adminRouter.Post("/security/signing-keys/rotate", requestHandler.PostRotateSigningKey)
	adminRouter.Post("/security/signing-keys/retire-previous", requestHandler.PostRetirePreviousSigningKey)

	// profile endpoints
	adminRouter.Post("/profile/name", requestHandler.UpdateAccountName)
	adminRouter.Post("/profile/language", requestHandler.UpdateAccountLanguage)
	adminRouter.Post("/profile/email/change", requestHandler.RequestEmailChange)
	adminRouter.Post("/profile/email/verify", requestHandler.VerifyEmailChange)

	// TOTP 2FA
	adminRouter.Post("/totp/setup", requestHandler.AdminTOTPSetup)
	adminRouter.Post("/totp/enable", requestHandler.AdminTOTPEnable)
	adminRouter.Post("/totp/disable", requestHandler.AdminTOTPDisable)
	adminRouter.Post("/totp/backup-codes", requestHandler.AdminTOTPRegenerateBackupCodes)

	// create workspace
	adminRouter.Post("/workspace", requestHandler.CreateWorkspace)

	// =========================
	// Workspace-scoped endpoints
	// =========================
	adminWorkspaceRouter.Post("/", requestHandler.UpdateWorkspace)
	adminWorkspaceRouter.Put("/cookie-domain", requestHandler.HandleUpdateWorkspaceCookieDomain)

	// Workspace Encryption Key
	adminWorkspaceRouter.Get("/encryption-key", requestHandler.GetWorkspaceEncryptionKey)
	adminWorkspaceRouter.Post("/encryption-key", requestHandler.SetWorkspaceEncryptionKey)

	// workspace accounts (pre-registered users who can sign in)
	adminWorkspaceRouter.Get("/accounts", requestHandler.HandleGetWorkspaceAccounts)
	adminWorkspaceRouter.Post("/accounts", requestHandler.HandleCreateWorkspaceAccount)
	adminWorkspaceRouter.Post("/accounts/bulk-import", requestHandler.HandleBulkImportWorkspaceAccounts)
	adminWorkspaceRouter.Get("/accounts/{accountId}", requestHandler.HandleGetWorkspaceAccount)
	adminWorkspaceRouter.Patch("/accounts/{accountId}", requestHandler.HandleUpdateWorkspaceAccount)
	adminWorkspaceRouter.Patch("/accounts/{accountId}/status", requestHandler.HandleSetWorkspaceAccountStatus)
	adminWorkspaceRouter.Delete("/accounts/{accountId}/password", requestHandler.HandleClearUserPassword)
	adminWorkspaceRouter.Delete("/accounts/{accountId}", requestHandler.HandleDeleteWorkspaceAccount)

	// sessions
	adminWorkspaceRouter.Get("/sessions", requestHandler.HandleGetWorkspaceSessions)
	adminWorkspaceRouter.Post("/sessions/prune", requestHandler.HandlePruneExpiredSessions)
	adminWorkspaceRouter.Delete("/sessions", requestHandler.HandleDeleteWorkspaceSessionsByAccount)
	adminWorkspaceRouter.Delete("/sessions/{sessionId}", requestHandler.HandleDeleteWorkspaceSession)

	// user pools (workspace-scoped identity boundaries)
	adminWorkspaceRouter.Get("/userPools", requestHandler.HandleListUserPools)
	adminWorkspaceRouter.Post("/userPools", requestHandler.HandleCreateUserPool)
	adminWorkspaceRouter.Patch("/userPools/{poolId}", requestHandler.HandleUpdateUserPool)
	adminWorkspaceRouter.Delete("/userPools/{poolId}", requestHandler.HandleDeleteUserPool)
	adminWorkspaceRouter.Get("/userPools/{poolId}/apps", requestHandler.HandleListAppsByUserPool)
	adminWorkspaceRouter.Delete("/userPools/{poolId}/orphan-users", requestHandler.HandleDeletePoolOrphanUsers)
	adminWorkspaceRouter.Delete("/userPools/{poolId}/users/{userId}", requestHandler.HandleDeletePoolUser)

	// projects
	adminWorkspaceRouter.Get("/projects", requestHandler.GetProjects)
	adminWorkspaceRouter.Post("/projects", requestHandler.CreateProject)
	adminWorkspaceRouter.Get("/projects/{projectId}", requestHandler.GetProject)
	adminWorkspaceRouter.Put("/projects/{projectId}", requestHandler.UpdateProject)
	adminWorkspaceRouter.Delete("/projects/{projectId}", requestHandler.DeleteProject)

	// apiKeys
	adminWorkspaceRouter.Get("/apiKeys", requestHandler.HandleGetApiKeys)
	adminWorkspaceRouter.Get("/apiKeys/{id}", requestHandler.HandleGetApiKey)
	adminWorkspaceRouter.Patch("/apiKeys/{id}", requestHandler.HandleUpdateApiKey)
	adminWorkspaceRouter.Delete("/apiKeys/{id}", requestHandler.HandleDeleteApiKey)
	adminWorkspaceRouter.Post("/apiKeys", requestHandler.HandleCreateApiKey)
	adminWorkspaceRouter.Post("/apiKeys/{id}/rotate", requestHandler.HandleRotateApiKey)

	// team
	adminWorkspaceRouter.Get("/team", requestHandler.HandleListTeamMembers)
	adminWorkspaceRouter.Post("/team", requestHandler.HandleAddTeamMember)
	adminWorkspaceRouter.Delete("/team/{accountId}", requestHandler.HandleRemoveTeamMember)
	adminWorkspaceRouter.Delete("/team/{accountId}/totp", requestHandler.HandleResetTeamMemberTOTP)
	adminWorkspaceRouter.Get("/team/invites", requestHandler.HandleListTeamInvites)
	adminWorkspaceRouter.Delete("/team/invites/{inviteId}", requestHandler.HandleCancelTeamInvite)

	// smtp config
	adminWorkspaceRouter.Get("/smtp", requestHandler.HandleGetSMTPConfig)
	adminWorkspaceRouter.Post("/smtp", requestHandler.HandleUpsertSMTPConfig)
	adminWorkspaceRouter.Delete("/smtp", requestHandler.HandleDeleteSMTPConfig)
	adminWorkspaceRouter.Post("/smtp/test", requestHandler.HandleTestSMTPConfig)

	// first-boot setup checklist (dismiss only — completion timestamps
	// land on the workspace row from the actions that complete each
	// item, e.g. /smtp/test sets setup_test_email_sent_at).
	adminWorkspaceRouter.Post("/setup-checklist/dismiss", requestHandler.HandleDismissSetupChecklist)

	// permissions
	adminWorkspaceRouter.Get("/projects/{projectId}/permissions", requestHandler.HandleGetPermissions)
	adminWorkspaceRouter.Post("/projects/{projectId}/permissions", requestHandler.HandleCreatePermission)
	adminWorkspaceRouter.Patch("/projects/{projectId}/permissions/{permissionId}", requestHandler.HandleUpdatePermission)
	adminWorkspaceRouter.Delete("/projects/{projectId}/permissions/{permissionId}", requestHandler.HandleDeletePermission)

	// roles
	adminWorkspaceRouter.Get("/projects/{projectId}/roles", requestHandler.HandleGetRoles)
	adminWorkspaceRouter.Post("/projects/{projectId}/roles", requestHandler.HandleCreateRole)
	adminWorkspaceRouter.Patch("/projects/{projectId}/roles/{roleId}", requestHandler.HandleUpdateRole)
	adminWorkspaceRouter.Delete("/projects/{projectId}/roles/{roleId}", requestHandler.HandleDeleteRole)
	adminWorkspaceRouter.Patch("/projects/{projectId}/roles/{roleId}/permissions", requestHandler.HandleUpdateRolePermissions)

	// member roles (links users to project roles)
	adminWorkspaceRouter.Get("/projects/{projectId}/memberRoles", requestHandler.HandleGetMemberRoles)
	adminWorkspaceRouter.Put("/projects/{projectId}/memberRoles/{userId}", requestHandler.HandlerUpdateMemberRoles)
	adminWorkspaceRouter.Get("/projects/{projectId}/memberPermissions/{userId}", requestHandler.HandleGetMemberPermissions)
	adminWorkspaceRouter.Put("/projects/{projectId}/memberPermissions/{userId}", requestHandler.HandleSetMemberPermissions)
	adminWorkspaceRouter.Get("/projects/{projectId}/members", requestHandler.HandleGetProjectMembers)
	adminWorkspaceRouter.Delete("/projects/{projectId}/members/{userId}", requestHandler.HandleRemoveProjectMember)

	// feature flags (project-level)
	adminWorkspaceRouter.Get("/projects/{projectId}/featureFlags", requestHandler.HandleGetFeatureFlags)
	adminWorkspaceRouter.Post("/projects/{projectId}/featureFlags", requestHandler.HandleCreateFeatureFlag)
	adminWorkspaceRouter.Get("/projects/{projectId}/featureFlags/{featureFlagId}", requestHandler.HandleGetFeatureFlag)
	adminWorkspaceRouter.Patch("/projects/{projectId}/featureFlags/{featureFlagId}", requestHandler.HandleUpdateFeatureFlag)
	adminWorkspaceRouter.Delete("/projects/{projectId}/featureFlags/{featureFlagId}", requestHandler.HandleDeleteFeatureFlag)

	adminWorkspaceRouter.Get("/projects/{projectId}/featureFlags/apps", requestHandler.HandleGetFeatureFlagOverrides)
	adminWorkspaceRouter.Put("/projects/{projectId}/featureFlags/{featureFlagId}/apps/{appId}", requestHandler.HandleUpsertFeatureFlagOverride)
	adminWorkspaceRouter.Delete("/projects/{projectId}/featureFlags/{featureFlagId}/apps/{appId}", requestHandler.HandleDeleteFeatureFlagOverride)

	// config keys (project-level)
	adminWorkspaceRouter.Get("/projects/{projectId}/configKeys", requestHandler.HandleGetConfigKeys)
	adminWorkspaceRouter.Post("/projects/{projectId}/configKeys", requestHandler.HandleCreateConfigKey)
	adminWorkspaceRouter.Get("/projects/{projectId}/configKeys/{configKeyId}", requestHandler.HandleGetConfigKey)
	adminWorkspaceRouter.Patch("/projects/{projectId}/configKeys/{configKeyId}", requestHandler.HandleUpdateConfigKey)
	adminWorkspaceRouter.Delete("/projects/{projectId}/configKeys/{configKeyId}", requestHandler.HandleDeleteConfigKey)

	// config values (bulk list for UI)
	adminWorkspaceRouter.Get("/projects/{projectId}/configValues", requestHandler.HandleGetConfigValues)
	adminWorkspaceRouter.Put("/projects/{projectId}/configKeys/{configKeyId}/apps/{appId}", requestHandler.HandleUpsertConfigValue)
	adminWorkspaceRouter.Delete("/projects/{projectId}/configKeys/{configKeyId}/apps/{appId}", requestHandler.HandleDeleteConfigValue)

	// user fields (project-level schema for user metadata)
	// User fields are pool-scoped: schema lives on the pool, values
	// key on (user_id, field_id), and user_id implies the pool.
	adminWorkspaceRouter.Get("/userPools/{poolId}/userFields", requestHandler.HandleGetUserFields)
	adminWorkspaceRouter.Post("/userPools/{poolId}/userFields", requestHandler.HandleCreateUserField)
	adminWorkspaceRouter.Get("/userPools/{poolId}/userFields/{userFieldId}", requestHandler.HandleGetUserField)
	adminWorkspaceRouter.Patch("/userPools/{poolId}/userFields/{userFieldId}", requestHandler.HandleUpdateUserField)
	adminWorkspaceRouter.Delete("/userPools/{poolId}/userFields/{userFieldId}", requestHandler.HandleDeleteUserField)

	// user field values (per-user)
	adminWorkspaceRouter.Get("/userPools/{poolId}/userFields/values", requestHandler.HandleGetUserFieldValues)
	adminWorkspaceRouter.Put("/userPools/{poolId}/userFields/{userFieldId}/users/{userId}", requestHandler.HandleUpsertUserFieldValue)
	adminWorkspaceRouter.Delete("/userPools/{poolId}/userFields/{userFieldId}/users/{userId}", requestHandler.HandleDeleteUserFieldValue)

	// webhooks (app-scoped)
	adminWorkspaceRouter.Get("/projects/{projectId}/apps/{appId}/webhooks", requestHandler.HandleListWebhooks)
	adminWorkspaceRouter.Post("/projects/{projectId}/apps/{appId}/webhooks", requestHandler.HandleCreateWebhook)
	adminWorkspaceRouter.Get("/projects/{projectId}/apps/{appId}/webhooks/health", requestHandler.HandleGetAppWebhookHealth)
	adminWorkspaceRouter.Get("/projects/{projectId}/apps/{appId}/webhooks/{webhookId}", requestHandler.HandleGetWebhook)
	adminWorkspaceRouter.Patch("/projects/{projectId}/apps/{appId}/webhooks/{webhookId}", requestHandler.HandleUpdateWebhook)
	adminWorkspaceRouter.Delete("/projects/{projectId}/apps/{appId}/webhooks/{webhookId}", requestHandler.HandleDeleteWebhook)
	adminWorkspaceRouter.Get("/projects/{projectId}/apps/{appId}/webhooks/{webhookId}/deliveries", requestHandler.HandleListWebhookDeliveries)
	adminWorkspaceRouter.Post("/projects/{projectId}/apps/{appId}/webhooks/{webhookId}/deliveries/{deliveryId}/retry", requestHandler.HandleRetryWebhookDelivery)

	// Apps (under projects)
	adminWorkspaceRouter.Route("/projects/{projectId}/apps", func(r chi.Router) {
		r.Get("/", requestHandler.HandleGetApps)
		r.Post("/", requestHandler.HandleCreateApp)
		r.Route("/{appId}", func(r chi.Router) {
			r.Get("/", requestHandler.HandleGetApp)
			r.Patch("/", requestHandler.HandleUpdateApp)
			r.Delete("/", requestHandler.HandleDeleteApp)
			r.Put("/registration", requestHandler.HandleUpdateAppRegistration)
			r.Put("/auth-method-config", requestHandler.HandleUpdateAppAuthMethodConfig)
			r.Put("/google-config", requestHandler.HandleUpdateAppGoogleConfig)
			r.Put("/apple-config", requestHandler.HandleUpdateAppAppleConfig)
			r.Put("/microsoft-config", requestHandler.HandleUpdateAppMicrosoftConfig)
			r.Put("/github-config", requestHandler.HandleUpdateAppGithubConfig)
			r.Put("/kakao-config", requestHandler.HandleUpdateAppKakaoConfig)
			r.Put("/naver-config", requestHandler.HandleUpdateAppNaverConfig)
			r.Get("/oidc-config", requestHandler.HandleGetAppOIDCConfig)
			r.Put("/oidc-config", requestHandler.HandleUpdateAppOIDCConfig)
			r.Put("/qr-sign-in-config", requestHandler.HandleUpdateAppQRSignInConfig)
			r.Put("/brute-force-protection-config", requestHandler.HandleUpdateAppBruteForceProtectionConfig)
			// Generic external IdP (OIDC / OAuth2) CRUD sub-resource.
			r.Get("/external-idps", requestHandler.HandleListExternalIDPs)
			r.Post("/external-idps", requestHandler.HandleCreateExternalIDP)
			r.Post("/external-idps/validate-discovery", requestHandler.HandleValidateExternalIDPDiscovery)
			r.Put("/external-idps/{idpId}", requestHandler.HandleUpdateExternalIDP)
			r.Delete("/external-idps/{idpId}", requestHandler.HandleDeleteExternalIDP)
			r.Put("/password-policy", requestHandler.HandleUpdateAppPasswordPolicy)
			r.Put("/cookie-domain", requestHandler.HandleUpdateAppCookieDomain)
			r.Put("/transport-mode", requestHandler.HandleUpdateAppTransportMode)
			r.Put("/session-cookie-samesite", requestHandler.HandleUpdateAppSessionCookieSameSite)

			// Organizations (admin oversight: enable flag + list/manage
			// app-scoped tenants from the admin panel).
			r.Put("/organizations-enabled", requestHandler.HandleUpdateAppOrganizationsEnabled)
			r.Put("/organizations-creation-policy", requestHandler.HandleUpdateAppOrgCreationPolicy)
			r.Get("/organizations", requestHandler.HandleListAppOrganizations)
			r.Post("/organizations", requestHandler.HandleCreateAppOrganization)
			r.Get("/organizations/{orgId}/members", requestHandler.HandleListAppOrganizationMembers)
			r.Post("/organizations/{orgId}/members", requestHandler.HandleAddAppOrganizationMember)
			r.Put("/organizations/{orgId}/members/{userId}/roles", requestHandler.HandleSetAppOrganizationMemberRoles)
			r.Patch("/organizations/{orgId}/members/{userId}", requestHandler.HandleSetAppOrganizationMemberTier)
			r.Patch("/organizations/{orgId}/members/{userId}/status", requestHandler.HandleSetAppOrganizationMemberStatus)
			r.Delete("/organizations/{orgId}/members/{userId}", requestHandler.HandleRemoveAppOrganizationMember)
			r.Get("/organizations/{orgId}/invites", requestHandler.HandleListAppOrganizationInvites)
			r.Post("/organizations/{orgId}/invites", requestHandler.HandleCreateAppOrganizationInvite)
			r.Delete("/organizations/{orgId}/invites/{inviteId}", requestHandler.HandleRevokeAppOrganizationInvite)
			r.Patch("/organizations/{orgId}", requestHandler.HandleRenameAppOrganization)
			r.Delete("/organizations/{orgId}", requestHandler.HandleArchiveAppOrganization)
			r.Post("/organizations/{orgId}/restore", requestHandler.HandleRestoreAppOrganization)
			r.Delete("/organizations/{orgId}/permanent", requestHandler.HandleDeleteAppOrganization)

			// Repoint the app at a different user pool. Refuses when
			// the app has any members; merge-on-repoint is a follow-up.
			r.Post("/userPool", requestHandler.HandleRepointAppUserPool)

			// CORS origins (app-scoped)
			r.Get("/corsOrigins", requestHandler.HandleGetCorsOrigins)
			r.Post("/corsOrigins", requestHandler.HandleCreateCorsOrigin)
			r.Patch("/corsOrigins/{id}", requestHandler.HandleUpdateCorsOrigin)
			r.Delete("/corsOrigins/{id}", requestHandler.HandleDeleteCorsOrigin)

			// IP allowlist (app-scoped)
			r.Get("/ipAllowlist", requestHandler.HandleGetIPAllowlist)
			r.Post("/ipAllowlist", requestHandler.HandleCreateIPAllowlistEntry)
			r.Patch("/ipAllowlist/{id}", requestHandler.HandleUpdateIPAllowlistEntry)
			r.Delete("/ipAllowlist/{id}", requestHandler.HandleDeleteIPAllowlistEntry)

			// Insights / analytics (app-scoped)
			r.Get("/insights/summary", requestHandler.HandleGetAppInsightsSummary)
			r.Get("/insights/timeseries", requestHandler.HandleGetAppInsightsTimeseries)
			r.Get("/insights/activity", requestHandler.HandleGetAppInsightsActivity)
			r.Get("/insights/sources", requestHandler.HandleGetAppInsightsSourceBreakdown)
			r.Get("/users/{userId}/activity", requestHandler.HandleGetAppUserActivity)
			r.Get("/users/{userId}/tags", requestHandler.HandleListUserTags)
			r.Put("/users/{userId}/tags", requestHandler.HandleReplaceUserTags)
			r.Get("/tags", requestHandler.HandleListAppTags)

			// Passkeys / WebAuthn (app-scoped)
			r.Get("/webauthn-rpid", requestHandler.HandleGetAppWebAuthnRPID)
			r.Put("/webauthn-rpid", requestHandler.HandleSetAppWebAuthnRPID)
			r.Get("/users/{userId}/passkeys", requestHandler.HandleAdminListUserPasskeys)
			r.Delete("/users/{userId}/passkeys/{passkeyId}", requestHandler.HandleAdminDeleteUserPasskey)

			// Organizations (app-scoped, display-only for user-detail)
			r.Get("/users/{userId}/organizations", requestHandler.HandleAdminUserOrganizations)

			// Social-account identities (Google/Apple/Microsoft/GitHub)
			r.Get("/users/{userId}/identities", requestHandler.HandleAdminListUserIdentities)
			r.Delete("/users/{userId}/identities/{provider}", requestHandler.HandleAdminDeleteUserIdentity)

			// Account recovery (support ops)
			r.Delete("/users/{userId}/totp", requestHandler.HandleAdminResetUserTOTP)
			r.Post("/users/{userId}/unlock", requestHandler.HandleAdminUnlockUser)

			// Bulk recovery: fan one action out over many users.
			r.Post("/users:bulk", requestHandler.HandleAdminBulkUserAction)

			// Parity with the S2S API for support operations on a user.
			r.Post("/users/{userId}/magic-link", requestHandler.HandleAdminCreateMagicLink)
			r.Put("/users/{userId}/password", requestHandler.HandleAdminSetUserPassword)
			r.Put("/users/{userId}/email-verified", requestHandler.HandleAdminSetUserEmailVerified)
			r.Get("/users/{userId}/check-permission", requestHandler.HandleAdminCheckUserPermission)
		})
	})

	// ==========================
	// Auth logs (workspace-scoped). Per-user variant powers the
	// "Auth activity" tab on the user detail dialog.
	// ==========================
	adminWorkspaceRouter.Get("/auth/logs", requestHandler.HandleListAuthLogs)
	adminWorkspaceRouter.Get("/projects/{projectId}/apps/{appId}/users/{userId}/auth-logs", requestHandler.HandleListAuthLogsForUser)

	// mounts
	adminRouter.Mount("/workspace/{workspaceId}", adminWorkspaceRouter)
	r.Mount("/admin", adminRouter)
	r.Mount("/x/{workspaceSlug}/api", serverAPIRouter)
	r.Mount("/x/{workspaceSlug}", clientAPIRouter)

	a.router = r

	err := chi.Walk(a.router, func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		log.Debug().Str("method", method).Str("route", route).Msg("registered route")
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func createBaseRouter(getBaseURL func() string, useHTTPSOnly bool) *chi.Mux {
	r := chi.NewRouter()
	if useHTTPSOnly {
		r.Use(httpsOnly(getBaseURL))
	}
	r.Use(commonSecurityHeaders(useHTTPSOnly))
	r.Use(middleware.StripSlashes)
	r.Use(middleware.RequestID)
	// NOTE: do NOT add chi's middleware.RealIP here. It overwrites
	// r.RemoteAddr from client-supplied headers (True-Client-IP /
	// X-Real-IP / X-Forwarded-For) BEFORE any trusted-proxy check runs,
	// which lets a direct caller spoof the client IP and defeat the
	// per-app IP allowlist, per-IP rate limiting, and audit-log IPs.
	// Client-IP resolution is owned by auth.ClientIP, which only honours
	// forwarding headers when the real kernel-set peer (r.RemoteAddr) is
	// in the operator's MANYROWS_TRUSTED_PROXIES allow-list. Leaving
	// RemoteAddr untouched is exactly what that logic requires.
	r.Use(middleware.GetHead)
	r.Use(middleware.Heartbeat("/ping"))
	r.Use(smartCache)
	r.Use(middleware.Compress(5))
	r.Use(middleware.CleanPath)
	r.Use(safeRecoverer)
	r.Use(maxBodySize(1 << 20)) // 1 MB
	r.Use(middleware.Timeout(60 * time.Second))
	return r
}

// smartCache sets caching headers based on the request path.
// Hashed static assets (under /assets/) are immutable and cached for 1 year.
// Everything else (HTML, API) gets no-cache to ensure fresh responses.
func smartCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-store, no-cache, max-age=0, must-revalidate, value")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "Thu, 01 Jan 1970 00:00:00 GMT")
		}
		next.ServeHTTP(w, r)
	})
}

// httpsOnly redirects plain-HTTP requests to HTTPS. Reads the live
// BASE_URL on every request (cheap — getBaseURL is a thin env read)
// so first-/admin/register pinning takes effect without a restart.
//
// When BASE_URL hasn't been pinned yet, fall back to upgrading the
// request's own Host header. That keeps the install bootable with no
// pre-configured hostname and means the very first /admin/register
// hit (which does the pinning) still gets redirected to HTTPS if
// it arrived over plain HTTP via a TLS-terminating proxy.
func httpsOnly(getBaseURL func() string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Forwarded-Proto") != "http" {
				next.ServeHTTP(w, r)
				return
			}
			target := getBaseURL()
			if target == "" {
				if r.Host == "" {
					// Nothing to redirect to — let it through rather
					// than emit an open redirect.
					next.ServeHTTP(w, r)
					return
				}
				target = "https://" + r.Host
			}
			http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusTemporaryRedirect)
		})
	}
}

func commonSecurityHeaders(useHTTPSOnly bool) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			if useHTTPSOnly {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

func adminMustBeAuthenticatedMiddleware(authService *auth.Service) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			acc, _, err := authService.GetLoggedInAccount(r)
			if err != nil {
				authService.ClearSessionCookie(w)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if acc == nil {
				authService.ClearSessionCookie(w)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			ctx := core.WithAdminAccount(r.Context(), acc)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func adminWorkspaceMiddleware(rpo *repo.Repo) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			acc, ok := core.AdminAccountFromContext(ctx)
			if !ok || acc == nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			wsID, err := utils.GetPathUUID("workspaceId", r)
			if err != nil {
				log.Err(err).Msg("Could not get workspaceId from request")
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
			ws, found, err := rpo.GetWorkspaceByID(ctx, wsID)
			if err != nil {
				log.Err(err).Msgf("Could not get workspace by ID: %s", wsID)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if !found {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}
			// Check workspace_admins table for access
			role, isMember, roleErr := rpo.GetWorkspaceAdminRole(ctx, wsID, acc.ID)
			if roleErr != nil {
				log.Err(roleErr).Msgf("Could not check workspace admin role: %s", wsID)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if !isMember {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			ctx = core.WithWorkspace(ctx, ws)
			ctx = core.WithWorkspaceRole(ctx, role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func etagMiddlewareForAppKit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		etag := appkit.GetVersion()
		if match := r.Header.Get("If-None-Match"); match != "" {
			if match == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		w.Header().Set("ETag", etag)
		next.ServeHTTP(w, r)
	})
}

// corsAppKitAssetsMiddlewareAllowAll allows all origins for AppKit *static assets only*.
// This is safe for now because:
// - AppKit assets are public (JS/CSS) and do not use cookies/credentials.
// - ESM module scripts REQUIRE CORS headers.
// Later you can tighten this by using a configured allowlist.
func corsAppKitAssetsMiddlewareAllowAll() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only do CORS work for browser-like requests.
			if !isBrowserCORSRequest(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Always allow for AppKit assets.
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Add("Vary", "Origin")
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")

			w.Header().Set("Access-Control-Allow-Methods", "GET,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
			w.Header().Set("Access-Control-Max-Age", "3600")

			acrm := strings.TrimSpace(r.Header.Get("Access-Control-Request-Method"))
			isPreflight := r.Method == http.MethodOptions && acrm != ""
			if isPreflight {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func maxBodySize(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// safeRecoverer recovers from panics and returns a generic 500 without leaking stack traces.
func safeRecoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rv := recover(); rv != nil {
				log.Error().Interface("panic", rv).Msg("recovered from panic")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware wraps an http.Handler to add X-Frame-Options and CSP headers.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// securityHeadersHandlerFunc wraps an http.HandlerFunc to add X-Frame-Options and CSP headers.
func securityHeadersHandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		next(w, r)
	}
}

func appCorsMiddleware(rpo *repo.Repo) func(next http.Handler) http.Handler {
	type corsCacheEntry struct {
		origins   []core.CorsOrigin
		fetchedAt time.Time
	}
	var mu sync.RWMutex
	cache := map[string]corsCacheEntry{}
	// 10s TTL — keeps the cache absorbing preflight bursts but caps
	// the multi-instance drift window after a CORS-origin edit at
	// ~10s rather than 30s. The underlying SELECT is indexed
	// (idx_app_cors_origins_app), so a wider cache window optimises
	// microseconds at the cost of correctness during allowlist
	// changes.
	const cacheTTL = 10 * time.Second
	const maxCacheSize = 1000

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only do CORS work for browser-like requests.
			if !isBrowserCORSRequest(r) {
				next.ServeHTTP(w, r)
				return
			}

			origin := strings.TrimSpace(r.Header.Get("Origin"))
			acrm := strings.TrimSpace(r.Header.Get("Access-Control-Request-Method"))
			isPreflight := r.Method == http.MethodOptions && acrm != ""

			// Resolve app: check context first, then URL param.
			// This middleware runs BEFORE appFromURLMiddleware so that CORS
			// headers are present even when downstream middleware returns errors.
			app, _ := core.AppFromContext(r.Context())
			if app == nil {
				appIDStr := chi.URLParam(r, "appId")
				if appIDStr != "" {
					appID, err := uuid.FromString(appIDStr)
					if err == nil {
						loaded, loadErr := rpo.GetAppByID(r.Context(), appID)
						if loadErr == nil {
							app = &loaded
							r = r.WithContext(core.WithApp(r.Context(), app))
						}
					}
				}
			}

			if app == nil {
				if isPreflight {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			cacheKey := "app:" + app.ID.String()
			var origins []core.CorsOrigin

			mu.RLock()
			ce, cacheHit := cache[cacheKey]
			mu.RUnlock()

			if cacheHit && time.Since(ce.fetchedAt) < cacheTTL {
				origins = ce.origins
			} else {
				var err error
				origins, err = rpo.GetCorsOrigins(r.Context(), app.ID)
				if err != nil {
					log.Err(err).Msg("appCorsMiddleware: GetCorsOrigins failed")
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				mu.Lock()
				if len(cache) >= maxCacheSize {
					cache = map[string]corsCacheEntry{}
				}
				cache[cacheKey] = corsCacheEntry{origins: origins, fetchedAt: time.Now()}
				mu.Unlock()
			}

			allowed := false
			for i := range origins {
				if strings.EqualFold(strings.TrimSpace(origins[i].Origin), origin) {
					allowed = true
					break
				}
			}

			// If disallowed: emit no CORS headers.
			// Browser blocks. Non-browsers never reach here (gated above).
			if !allowed {
				if isPreflight {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Allowed origin — emit CORS headers.
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")

			// Credentials allowed: lets the SDK opt into cookie mode by
			// setting withCredentials: true. The per-app CORS allowlist
			// (above) still gates which origins can do this. Bearer-mode
			// clients ignore this header — it costs them nothing.
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, DPoP")
			w.Header().Set("Access-Control-Expose-Headers", "Link")
			w.Header().Set("Access-Control-Max-Age", "3600")

			if isPreflight {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
