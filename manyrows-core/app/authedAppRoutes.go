package app

import (
	"manyrows-core/api"
	"manyrows-core/core/repo"

	"github.com/go-chi/chi/v5"
)

// registerAuthedAppRoutes mounts the post-authentication AppKit
// surface under /apps/{appId}/a/*, gated by workspaceAuthMiddleware
// (Bearer JWT or HttpOnly mr_at cookie).
//
// appMiddleware (loads project from the app already in context) runs
// at this level — every authed AppKit endpoint either needs project
// directly (GetMe, CheckPermission, user fields) or accepts the small
// DB-load cost without needing the data.
// Previously /me, /check-permission, /me/fields lived under a /app
// sub-route to scope appMiddleware narrowly; that prefix leaked the
// "this needs middleware-X" implementation detail into URLs and
// the AppKit page paid for it with /a/app/me-style ugliness.
func registerAuthedAppRoutes(r chi.Router, h *api.RequestHandler, rpo *repo.Repo) {
	r.Use(appMiddleware(rpo))

	r.Post("/logout", h.WorkspaceLogout)
	r.Post("/profile/display-name", h.WorkspaceUpdateDisplayName)
	r.Post("/set-password", h.WorkspaceSetPassword)
	r.Post("/totp/setup", h.HandleWorkspaceTOTPSetup)
	r.Post("/totp/enable", h.HandleWorkspaceTOTPEnable)
	r.Post("/totp/disable", h.HandleWorkspaceTOTPDisable)
	r.Post("/totp/backup-codes", h.HandleWorkspaceTOTPRegenerateBackupCodes)
	r.Post("/passkey/register/begin", h.WorkspacePasskeyRegisterBegin)
	r.Post("/passkey/register/finish", h.WorkspacePasskeyRegisterFinish)
	r.Get("/passkeys", h.WorkspaceListMyPasskeys)
	r.Patch("/passkeys/{passkeyId}", h.WorkspaceRenamePasskey)
	r.Delete("/passkeys/{passkeyId}", h.WorkspaceDeletePasskey)

	// User-info / app-scoped routes (formerly under /app/).
	r.Get("/me", h.GetAppMe)
	r.Get("/me/fields", h.GetMyUserFields)
	r.Patch("/me/fields", h.UpdateMyUserFields)
	r.Get("/check-permission", h.CheckPermission)
	r.Get("/runtime", h.GetAppData) // config keys + feature flags

	// User-account ops.
	r.Get("/me/sessions", h.GetMySessions)
	r.Delete("/me/sessions/{sessionId}", h.DeleteMySession)
	r.Get("/me/identities", h.GetMyIdentities)
	r.Delete("/me/identities/{provider}", h.DeleteMyIdentity)
	r.Post("/me/delete", h.DeleteMyAccount)
	r.Post("/me/request-email-change", h.ClientRequestEmailChange)
	r.Post("/me/verify-email-change", h.ClientVerifyEmailChange)
}
