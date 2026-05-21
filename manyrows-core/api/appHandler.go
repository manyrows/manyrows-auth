package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	microsoftauth "manyrows-core/auth/microsoft"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

type AppsResponse struct {
	Apps []core.App `json:"apps"`
}

// adminAppResponse wraps core.App for admin endpoints, adding computed fields
// like the OAuth redirect URIs that admins need for configuration.
type adminAppResponse struct {
	core.App
	GoogleOAuthRedirectURI    string `json:"googleOAuthRedirectUri,omitempty"`
	HasGoogleClientSecret     bool   `json:"hasGoogleClientSecret"`
	AppleOAuthRedirectURI     string `json:"appleOAuthRedirectUri,omitempty"`
	HasApplePrivateKey        bool   `json:"hasApplePrivateKey"`
	MicrosoftOAuthRedirectURI string `json:"microsoftOAuthRedirectUri,omitempty"`
	HasMicrosoftClientSecret  bool   `json:"hasMicrosoftClientSecret"`
	GithubOAuthRedirectURI    string `json:"githubOAuthRedirectUri,omitempty"`
	HasGithubClientSecret     bool   `json:"hasGithubClientSecret"`
	// QRSignInURL is the customer-facing /qr-sign-in entry-point.
	// Server-computed (AppBaseURL + workspace.Slug + app.ID) so the
	// admin UI doesn't have to build it client-side. Empty when the
	// install BASE_URL isn't pinned yet.
	QRSignInURL string `json:"qrSignInUrl,omitempty"`
}

// AppBaseURL returns the base URL the OAuth providers should redirect to
// for this app. Prefers App.AuthDomain (per-app custom auth hostname, e.g.
// "auth.drumkingdom.com") so each app on a multi-app install can wear its
// own customer-branded host; falls back to the install-wide
// MANYROWS_BASE_URL when no custom domain is configured.
//
// Used both by the admin UI (so the value displayed for the customer to
// paste into Google Cloud Console matches the OAuth flow) and by the
// /authorize + token-exchange paths (so the redirect_uri they send to the
// provider is byte-identical with what's registered).
func (handler *RequestHandler) AppBaseURL(a *core.App) string {
	if a != nil && a.AuthDomain != nil {
		if d := strings.TrimSpace(*a.AuthDomain); d != "" {
			return "https://" + strings.TrimRight(d, "/")
		}
	}
	return strings.TrimRight(handler.config.GetBaseURL(), "/")
}

func (handler *RequestHandler) toAdminAppResponse(a core.App, ws *core.Workspace) adminAppResponse {
	resp := adminAppResponse{
		App:                      a,
		HasGoogleClientSecret:    len(a.GoogleOAuthClientSecretEncrypted) > 0,
		HasApplePrivateKey:       len(a.ApplePrivateKeyEncrypted) > 0,
		HasMicrosoftClientSecret: len(a.MicrosoftClientSecretEncrypted) > 0,
		HasGithubClientSecret:    len(a.GithubClientSecretEncrypted) > 0,
	}
	baseURL := handler.AppBaseURL(&a)
	if baseURL != "" && ws != nil {
		resp.GoogleOAuthRedirectURI = baseURL + "/x/" + ws.Slug + "/apps/" + a.ID.String() + "/auth/google/callback"
		resp.AppleOAuthRedirectURI = baseURL + "/x/" + ws.Slug + "/apps/" + a.ID.String() + "/auth/apple/callback"
		resp.MicrosoftOAuthRedirectURI = baseURL + "/x/" + ws.Slug + "/apps/" + a.ID.String() + "/auth/microsoft/callback"
		resp.GithubOAuthRedirectURI = baseURL + "/x/" + ws.Slug + "/apps/" + a.ID.String() + "/auth/github/callback"
		resp.QRSignInURL = baseURL + "/x/" + ws.Slug + "/apps/" + a.ID.String() + "/qr-sign-in"
	}
	return resp
}

type createAppRequest struct {
	Type              string  `json:"type"` // prod | staging | dev
	Description       *string `json:"description,omitempty"`
	Enabled           *bool   `json:"enabled,omitempty"`
	AppURL            *string `json:"appUrl,omitempty"`
	PrimaryAuthMethod *string `json:"primaryAuthMethod,omitempty"`
	// UserPoolID is optional. When set, the new app shares users with
	// every other app pointing at that pool. When unset, a fresh pool
	// is auto-created (1:1 with the app).
	UserPoolID *uuid.UUID `json:"userPoolId,omitempty"`
}

type updateAppRequest struct {
	Description           *string `json:"description,omitempty"`
	Enabled               *bool   `json:"enabled,omitempty"`
	AppURL                *string `json:"appUrl,omitempty"`
	AuthDomain            *string `json:"authDomain,omitempty"`
	SessionTTLMinutes     *int    `json:"sessionTtlMinutes,omitempty"`
	IdleTimeoutMinutes    *int    `json:"idleTimeoutMinutes,omitempty"`
	RememberMeTTLMinutes  *int    `json:"rememberMeTtlMinutes,omitempty"`
	AccessTokenTTLMinutes *int    `json:"accessTokenTtlMinutes,omitempty"`
	MaxSessionsPerUser    *int    `json:"maxSessionsPerUser,omitempty"`
}

// Self-registration + the cross-cutting require-2FA policy. 2FA isn't
// per-provider — it applies to every sign-in method on the app — so it
// rides along with the registration "policy" surface rather than living
// in any provider's endpoint.
type updateAppRegistrationRequest struct {
	AllowRegistration    *bool      `json:"allowRegistration"`
	AllowAccountDeletion *bool      `json:"allowAccountDeletion,omitempty"`
	AllowEmailChange     *bool      `json:"allowEmailChange,omitempty"`
	DefaultRoleID        *uuid.UUID `json:"defaultRoleId,omitempty"`
	AllowedEmailDomains  []string   `json:"allowedEmailDomains,omitempty"`
	Require2FA           *bool      `json:"require2fa,omitempty"`
}

// Email-form mode for the sign-in screen. Tri-state: "password",
// "code", or "none" — see core.PrimaryAuthMethod* constants. password
// and code are mutually exclusive (we only show one email form); "none"
// hides the email form entirely (OAuth-only mode).
type updateAppAuthMethodConfigRequest struct {
	PrimaryAuthMethod *string `json:"primaryAuthMethod,omitempty"`
}

// Per-app cookie domain override. Empty string / null clears the
// override and falls back to the workspace-level cookie_domain.
type updateAppCookieDomainRequest struct {
	CookieDomain *string `json:"cookieDomain"`
}

// Per-app transport-mode selector — one of "local" / "cookie".
// Drives how AppKit delivers the session token. See core.TransportMode*
// constants; the DB CHECK constraint enforces the same enum.
type updateAppTransportModeRequest struct {
	TransportMode string `json:"transportMode"`
}

// Per-app session-cookie SameSite attribute — one of "lax" / "strict".
// Strict is only valid when no inbound cross-site GET ever needs to
// carry the session (no magic links, no OAuth, no link-based reset).
type updateAppSessionCookieSameSiteRequest struct {
	SessionCookieSameSite string `json:"sessionCookieSameSite"`
}

// Per-app password-strength policy. Both fields validated server-side
// to the same ranges enforced by the DB CHECK constraints (1..256 for
// length, 0..4 for the zxcvbn score).
type updateAppPasswordPolicyRequest struct {
	MinLength      *int `json:"passwordMinLength,omitempty"`
	MinZxcvbnScore *int `json:"passwordMinZxcvbnScore,omitempty"`
}

func (handler *RequestHandler) HandleGetApps(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	productID, err := utils.GetPathUUID("productId", r)
	if err != nil || productID == uuid.Nil {
		log.Err(err).Msg("failed to parse project id")
		WriteError(w, r, "error.invalidProductId", http.StatusBadRequest)
		return
	}

	// safer multi-tenant list
	apps, err := handler.repo.GetAppsByWorkspaceAndProductID(r.Context(), ws.ID, productID)
	if err != nil {
		log.Err(err).Msg("failed to load apps")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, AppsResponse{Apps: apps}, http.StatusOK)
}

// maxAppsPerWorkspace is a hard server-side cap. Plan-based limits
// were removed; this guards against runaway creation.
const maxAppsPerWorkspace = 100

func (handler *RequestHandler) HandleCreateApp(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	productID, err := utils.GetPathUUID("productId", r)
	if err != nil || productID == uuid.Nil {
		log.Err(err).Msg("failed to parse project id")
		WriteError(w, r, "error.invalidProductId", http.StatusBadRequest)
		return
	}

	count, err := handler.repo.CountAppsByWorkspaceID(r.Context(), ws.ID)
	if err != nil {
		log.Err(err).Msg("HandleCreateApp: count failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if count >= maxAppsPerWorkspace {
		WriteErrorf(w, r, "error.limitReached", http.StatusForbidden, "Apps", maxAppsPerWorkspace)
		return
	}

	var req createAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode json")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	req.Type = strings.TrimSpace(strings.ToLower(req.Type))
	if req.Type == "" {
		req.Type = "dev"
	}
	if req.Type != "prod" && req.Type != "staging" && req.Type != "dev" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	enabled := false
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	var description *string
	if req.Description != nil {
		s := strings.TrimSpace(*req.Description)
		if s != "" {
			description = &s
		}
	}

	var appURL *string
	if req.AppURL != nil {
		s := strings.TrimSpace(*req.AppURL)
		if s != "" {
			appURL = &s
		}
	}

	primaryAuthMethod := core.PrimaryAuthMethodPassword
	if req.PrimaryAuthMethod != nil {
		m := strings.TrimSpace(*req.PrimaryAuthMethod)
		if m != core.PrimaryAuthMethodPassword &&
			m != core.PrimaryAuthMethodCode &&
			m != core.PrimaryAuthMethodMagicLink &&
			m != core.PrimaryAuthMethodNone {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		primaryAuthMethod = m
	}

	// Magic-link mode is unusable without an app URL — same constraint
	// the PATCH/auth-method-config endpoints enforce.
	if primaryAuthMethod == core.PrimaryAuthMethodMagicLink && appURL == nil {
		WriteError(w, r, "error.magicLinkRequiresAppUrl", http.StatusBadRequest)
		return
	}

	// Resolve the user pool. If the caller picked an existing one
	// ("share users with app X"), validate it belongs to this
	// workspace. Otherwise auto-create a 1:1 pool named after the app -
	// the safe default for unrelated apps.
	var pool *core.UserPool
	if req.UserPoolID != nil && *req.UserPoolID != uuid.Nil {
		existing, err := handler.repo.GetUserPoolByID(r.Context(), *req.UserPoolID)
		if err != nil || existing == nil || existing.WorkspaceID != ws.ID {
			WriteError(w, r, "error.userPoolNotFound", http.StatusBadRequest)
			return
		}
		pool = existing
	} else {
		// Auto-pool naming derives from the parent product so the admin
		// sees something recognizable in the pools list. Load the product
		// for its name; the new app inherits the product's identity surface.
		product, err := handler.repo.GetProduct(r.Context(), productID, ws.ID)
		if err != nil || product == nil {
			log.Err(err).Msg("failed to load product for pool auto-naming")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		created, err := handler.repo.CreateUserPoolWithUniqueName(r.Context(), ws.ID, product.Name)
		if err != nil {
			log.Err(err).Msg("failed to create user pool for app")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		pool = created
	}

	a := core.App{
		ID:                   utils.NewUUID(),
		WorkspaceID:          ws.ID,
		ProductID:            productID,
		UserPoolID:           pool.ID,
		Type:                 req.Type,
		Description:          description,
		Enabled:              enabled,
		AppURL:               appURL,
		PrimaryAuthMethod:    primaryAuthMethod,
		AllowAccountDeletion: true,  // safe default, users can self-serve
		AllowEmailChange:     false, // advanced; opt-in per app (see admin UI)
	}

	out, err := handler.repo.InsertApp(r.Context(), a)
	if err != nil {
		// (product_id, type) is unique - one app per env per product.
		// Surface as 409 so the UI can render a real message instead
		// of a generic "internal error".
		if repo.IsUniqueViolation(err) {
			utils.WriteJsonWithStatusCode(w, map[string]any{
				"error": "this product already has a " + req.Type + " environment",
				"code":  "appTypeAlreadyExists",
				"type":  req.Type,
			}, http.StatusConflict)
			return
		}
		log.Err(err).Msg("failed to create app")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Seed a CORS origin from the App URL so the operator doesn't have
	// to add it manually before the first cross-origin request from
	// their app works. Best-effort: a malformed URL or a duplicate
	// shouldn't fail the create. Operator can edit/remove it later from
	// App → Security → CORS Origins.
	if appURL != nil {
		if origin := normalizeOrigin(*appURL); origin != "" {
			seed := core.CorsOrigin{
				ID:        utils.NewUUID(),
				AppID:     out.ID,
				Origin:    origin,
				CreatedAt: time.Now().UTC(),
			}
			if err := handler.repo.InsertCorsOrigin(r.Context(), seed); err != nil {
				log.Err(err).Str("appId", out.ID.String()).Str("origin", origin).
					Msg("seed CORS origin from appUrl failed (non-fatal)")
			}
		}
	}

	utils.WriteJsonWithStatusCode(w, out, http.StatusCreated)
}

// normalizeOrigin reduces a URL string to its canonical
// "scheme://host[:port]" form, which is what the CORS allowlist
// stores. Returns "" when the input isn't a usable HTTP(S) URL —
// callers treat that as "skip the seed, don't fail the request."
func normalizeOrigin(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u == nil {
		return ""
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

type AppResource struct {
	ID                        uuid.UUID `json:"id"`
	Name                      string    `json:"name"`
	WorkspaceSlug             string    `json:"workspaceSlug"`
	WorkspaceName             string    `json:"workspaceName"`
	AllowRegistration         bool      `json:"allowRegistration"`
	AllowAccountDeletion      bool      `json:"allowAccountDeletion"`
	AllowEmailChange          bool      `json:"allowEmailChange"`
	GoogleOAuthClientID       string    `json:"googleOAuthClientId,omitempty"`
	GoogleAuthCodeFlowEnabled bool      `json:"googleAuthCodeFlowEnabled,omitempty"`
	PrimaryAuthMethod         string    `json:"primaryAuthMethod"`
	AppleEnabled              bool      `json:"appleEnabled,omitempty"`
	MicrosoftEnabled          bool      `json:"microsoftEnabled,omitempty"`
	GithubEnabled             bool      `json:"githubEnabled,omitempty"`
	Require2FA                bool      `json:"require2fa"`
	HideBranding              bool      `json:"hideBranding,omitempty"`
	PasskeyEnabled            bool      `json:"passkeyEnabled,omitempty"`
	// QRSignInEnabled gates the "Sign in with phone" button on
	// AppKit's login screen. Read from app.QRSignInEnabled.
	QRSignInEnabled bool `json:"qrSignInEnabled,omitempty"`
	// TransportMode is the explicit selector for how the session token
	// is delivered ("local" / "cookie"). AppKit reads this on boot and
	// configures fetch / storage behaviour accordingly — no client-side
	// prop needed.
	TransportMode string `json:"transportMode"`
}

func (handler *RequestHandler) HandleGetAppForAppKit(w http.ResponseWriter, r *http.Request) {
	// App is already in context (resolved by appFromURLMiddleware).
	a, ok := core.AppFromContext(r.Context())
	if !ok || a == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	ws, wsOk := core.WorkspaceFromContext(r.Context())
	if !wsOk || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	googleClientID := ""
	if a.AuthMethodGoogle && a.GoogleOAuthClientID != nil {
		googleClientID = *a.GoogleOAuthClientID
	}
	googleAuthCodeFlow := googleClientID != "" && len(a.GoogleOAuthClientSecretEncrypted) > 0

	// Apple is "enabled" when the toggle is on and all required config is present.
	appleEnabled := a.AuthMethodApple &&
		a.AppleServicesID != nil && *a.AppleServicesID != "" &&
		a.AppleTeamID != nil && *a.AppleTeamID != "" &&
		a.AppleKeyID != nil && *a.AppleKeyID != "" &&
		len(a.ApplePrivateKeyEncrypted) > 0

	// Microsoft is "enabled" when the toggle is on, client ID + secret
	// are set, and the tenant config is one of the four valid values.
	microsoftEnabled := a.AuthMethodMicrosoft &&
		a.MicrosoftClientID != nil && *a.MicrosoftClientID != "" &&
		len(a.MicrosoftClientSecretEncrypted) > 0 &&
		microsoftauth.IsValidTenant(a.MicrosoftTenant)

	// GitHub is "enabled" when the toggle is on and both creds set.
	githubEnabled := a.AuthMethodGithub &&
		a.GithubClientID != nil && *a.GithubClientID != "" &&
		len(a.GithubClientSecretEncrypted) > 0

	// Self-hosted: branding-removal toggle no longer gated by a plan tier.
	// All apps treated as if branding is removable; fold this into a UI
	// preference if the operator wants to keep the badge.
	hideBranding := true

	passkeyEnabled := false
	if rpid, err := handler.repo.GetAppWebAuthnRPID(r.Context(), a.ID); err == nil && rpid != nil && *rpid != "" {
		passkeyEnabled = true
	}

	transportMode := a.TransportMode
	if transportMode == "" {
		transportMode = core.TransportModeLocal
	}

	ap := AppResource{
		ID:                        a.ID,
		Name:                      a.DisplayName(),
		WorkspaceSlug:             ws.Slug,
		WorkspaceName:             ws.Name,
		AllowRegistration:         a.AllowRegistration,
		AllowAccountDeletion:      a.AllowAccountDeletion,
		AllowEmailChange:          a.AllowEmailChange,
		GoogleOAuthClientID:       googleClientID,
		GoogleAuthCodeFlowEnabled: googleAuthCodeFlow,
		PrimaryAuthMethod:         a.PrimaryAuthMethod,
		AppleEnabled:              appleEnabled,
		MicrosoftEnabled:          microsoftEnabled,
		GithubEnabled:             githubEnabled,
		Require2FA:                a.Require2FA,
		HideBranding:              hideBranding,
		PasskeyEnabled:            passkeyEnabled,
		QRSignInEnabled:           a.QRSignInEnabled,
		TransportMode:             transportMode,
	}

	utils.WriteJsonWithStatusCode(w, ap, http.StatusOK)
}

func (handler *RequestHandler) HandleGetApp(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	productID, err := utils.GetPathUUID("productId", r)
	if err != nil || productID == uuid.Nil {
		log.Err(err).Msg("failed to parse project id")
		WriteError(w, r, "error.invalidProductId", http.StatusBadRequest)
		return
	}

	appID, err := utils.GetPathUUID("appId", r)
	if err != nil || appID == uuid.Nil {
		log.Err(err).Msg("failed to parse app id")
		WriteError(w, r, "error.invalidAppId", http.StatusBadRequest)
		return
	}

	a, err := handler.repo.GetAppByIDForProduct(r.Context(), ws.ID, productID, appID)
	if err != nil {
		log.Err(err).Msg("failed to load app")
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(a, ws), http.StatusOK)
}

func (handler *RequestHandler) HandleUpdateApp(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	productID, err := utils.GetPathUUID("productId", r)
	if err != nil || productID == uuid.Nil {
		log.Err(err).Msg("failed to parse project id")
		WriteError(w, r, "error.invalidProductId", http.StatusBadRequest)
		return
	}

	appID, err := utils.GetPathUUID("appId", r)
	if err != nil || appID == uuid.Nil {
		log.Err(err).Msg("failed to parse app id")
		WriteError(w, r, "error.invalidAppId", http.StatusBadRequest)
		return
	}

	var req updateAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode json")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if req.Description == nil && req.Enabled == nil && req.AppURL == nil && req.AuthDomain == nil && req.SessionTTLMinutes == nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Patch semantics: read current, then write back with merged values.
	cur, err := handler.repo.GetAppByIDForProduct(r.Context(), ws.ID, productID, appID)
	if err != nil {
		log.Err(err).Msg("failed to load app")
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	newEnabled := cur.Enabled
	if req.Enabled != nil {
		newEnabled = *req.Enabled
	}

	newAppURL := cur.AppURL
	if req.AppURL != nil {
		trimmed := strings.TrimSpace(*req.AppURL)
		if trimmed == "" {
			newAppURL = nil
		} else {
			newAppURL = &trimmed
		}
	}

	newAuthDomain := cur.AuthDomain
	if req.AuthDomain != nil {
		trimmed := strings.TrimSpace(*req.AuthDomain)
		if trimmed == "" {
			newAuthDomain = nil
		} else {
			// Strip any accidental scheme / path the user pasted in —
			// downstream redirect-URI construction prepends "https://"
			// and the apps path itself.
			trimmed = strings.TrimPrefix(trimmed, "https://")
			trimmed = strings.TrimPrefix(trimmed, "http://")
			trimmed = strings.TrimSuffix(trimmed, "/")
			if strings.ContainsAny(trimmed, " /") || !strings.Contains(trimmed, ".") {
				WriteError(w, r, "error.invalidAuthDomain", http.StatusBadRequest)
				return
			}
			newAuthDomain = &trimmed
		}
	}

	// Block clearing the app URL while magic-link mode is on — the
	// magic-link request handler short-circuits without an app URL,
	// so the app would silently break for end users.
	if cur.PrimaryAuthMethod == core.PrimaryAuthMethodMagicLink && (newAppURL == nil || strings.TrimSpace(*newAppURL) == "") {
		WriteError(w, r, "error.magicLinkRequiresAppUrl", http.StatusBadRequest)
		return
	}

	// merge applies the "0 / negative clears, positive overrides,
	// nil leaves alone" rule that all four duration knobs follow.
	merge := func(req *int, cur *int) *int {
		if req == nil {
			return cur
		}
		if *req <= 0 {
			return nil
		}
		return req
	}
	newSessionTTL := merge(req.SessionTTLMinutes, cur.SessionTTLMinutes)
	newIdleTimeout := merge(req.IdleTimeoutMinutes, cur.IdleTimeoutMinutes)
	newRememberMeTTL := merge(req.RememberMeTTLMinutes, cur.RememberMeTTLMinutes)
	newAccessTokenTTL := merge(req.AccessTokenTTLMinutes, cur.AccessTokenTTLMinutes)
	newMaxSessions := merge(req.MaxSessionsPerUser, cur.MaxSessionsPerUser)

	newDescription := cur.Description
	if req.Description != nil {
		trimmed := strings.TrimSpace(*req.Description)
		if trimmed == "" {
			newDescription = nil
		} else {
			newDescription = &trimmed
		}
	}

	out, err := handler.repo.UpdateAppEnabled(r.Context(), ws.ID, productID, appID, newEnabled, repo.AppCoreUpdate{
		AppURL:                newAppURL,
		AuthDomain:            newAuthDomain,
		SessionTTLMinutes:     newSessionTTL,
		IdleTimeoutMinutes:    newIdleTimeout,
		RememberMeTTLMinutes:  newRememberMeTTL,
		AccessTokenTTLMinutes: newAccessTokenTTL,
		MaxSessionsPerUser:    newMaxSessions,
		Description:           newDescription,
	})
	if err != nil {
		log.Err(err).Msg("failed to update app")
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, ws), http.StatusOK)
}

func (handler *RequestHandler) HandleDeleteApp(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	productID, err := utils.GetPathUUID("productId", r)
	if err != nil || productID == uuid.Nil {
		log.Err(err).Msg("failed to parse project id")
		WriteError(w, r, "error.invalidProductId", http.StatusBadRequest)
		return
	}

	// Note: your route is /apps/{appId}
	appIDStr := chi.URLParam(r, "appId")
	appID, err := uuid.FromString(appIDStr)
	if err != nil || appID == uuid.Nil {
		log.Err(err).Msg("failed to parse app id")
		WriteError(w, r, "error.invalidAppId", http.StatusBadRequest)
		return
	}

	if err := handler.repo.DeleteAppByID(r.Context(), ws.ID, productID, appID); err != nil {
		log.Err(err).Msg("failed to delete app")
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// resolvePathIDs reads productId + appId from the URL, writing the
// appropriate error response and returning ok=false on failure. Used by
// every per-app PUT handler in this file to keep the boilerplate from
// dominating the actual logic.
func (handler *RequestHandler) resolvePathIDs(w http.ResponseWriter, r *http.Request) (productID, appID uuid.UUID, ok bool) {
	productID, err := utils.GetPathUUID("productId", r)
	if err != nil || productID == uuid.Nil {
		log.Err(err).Msg("failed to parse project id")
		WriteError(w, r, "error.invalidProductId", http.StatusBadRequest)
		return uuid.Nil, uuid.Nil, false
	}
	appID, err = utils.GetPathUUID("appId", r)
	if err != nil || appID == uuid.Nil {
		log.Err(err).Msg("failed to parse app id")
		WriteError(w, r, "error.invalidAppId", http.StatusBadRequest)
		return uuid.Nil, uuid.Nil, false
	}
	return productID, appID, true
}

// requireAtLeastOneSignInMethod rejects sign-in configurations that
// would leave the app with no working sign-in path. Called from any
// handler that may flip a method off — primary email mode, Google,
// Apple, Microsoft, GitHub — with the prospective post-save state of
// all five.
//
// Rules:
//   - "password" mode: always OK (email + password, with OTP fallback
//     for users without a password — emails go via custom SMTP if
//     configured, otherwise via the default mailer).
//   - "code" mode: always OK (passwordless OTP — same email path).
//   - "none" mode: requires at least one OAuth provider, since there
//     is no email path at all.
func (handler *RequestHandler) requireAtLeastOneSignInMethod(ctx context.Context, ws *core.Workspace, isSuper bool, primaryAuthMethod string, google, apple, microsoft, github bool) bool {
	switch primaryAuthMethod {
	case core.PrimaryAuthMethodPassword, core.PrimaryAuthMethodCode, core.PrimaryAuthMethodMagicLink:
		return true
	case core.PrimaryAuthMethodNone:
		return google || apple || microsoft || github
	}
	return false
}

// HandleUpdateAppRegistration updates self-registration settings + the
// require-2FA flag (cross-cutting policy that applies to every sign-in
// method). Provider toggles + credentials are configured separately.
func (handler *RequestHandler) HandleUpdateAppRegistration(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	productID, appID, ok := handler.resolvePathIDs(w, r)
	if !ok {
		return
	}

	var req updateAppRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode json")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	if req.AllowRegistration == nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	// DefaultRoleID is optional. Self-registered users without a default
	// role land with zero roles; the customer backend decides whether a
	// roleless token has any access.
	if req.DefaultRoleID != nil && *req.DefaultRoleID != uuid.Nil {
		if _, err := handler.repo.GetRoleByID(r.Context(), productID, *req.DefaultRoleID); err != nil {
			log.Err(err).Msg("failed to load role")
			if errors.Is(err, repo.ErrNotFound) {
				WriteError(w, r, "error.roleNotFound", http.StatusBadRequest)
				return
			}
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
	}

	allowedDomains := make([]string, 0, len(req.AllowedEmailDomains))
	for _, d := range req.AllowedEmailDomains {
		d = strings.TrimSpace(strings.ToLower(d))
		if d != "" {
			allowedDomains = append(allowedDomains, d)
		}
	}

	curApp, curAppErr := handler.repo.GetAppByIDForProduct(r.Context(), ws.ID, productID, appID)

	require2FA := false
	if curAppErr == nil {
		require2FA = curApp.Require2FA
	}
	if req.Require2FA != nil {
		require2FA = *req.Require2FA
	}

	// Default to keeping the existing AllowAccountDeletion value if the
	// caller didn't include the field — backwards-compatible for older
	// clients that haven't been updated to send it. Falls back to true
	// (the migration default) if curApp lookup failed for any reason.
	allowAccountDeletion := true
	if curAppErr == nil {
		allowAccountDeletion = curApp.AllowAccountDeletion
	}
	if req.AllowAccountDeletion != nil {
		allowAccountDeletion = *req.AllowAccountDeletion
	}

	allowEmailChange := true
	if curAppErr == nil {
		allowEmailChange = curApp.AllowEmailChange
	}
	if req.AllowEmailChange != nil {
		allowEmailChange = *req.AllowEmailChange
	}

	out, err := handler.repo.UpdateAppRegistration(r.Context(), ws.ID, productID, appID, repo.AppRegistrationUpdate{
		AllowRegistration:    *req.AllowRegistration,
		AllowAccountDeletion: allowAccountDeletion,
		AllowEmailChange:     allowEmailChange,
		DefaultRoleID:        req.DefaultRoleID,
		AllowedEmailDomains:  allowedDomains,
		Require2FA:           require2FA,
	})
	if err != nil {
		log.Err(err).Msg("failed to update app registration")
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if curAppErr == nil {
	}

	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, ws), http.StatusOK)
}

// HandleUpdateAppAuthMethodConfig sets the email-form mode for the
// sign-in screen — "password", "code", or "none". Validation depends
// on the chosen mode (see requireAtLeastOneSignInMethod):
//   - "password": always allowed.
//   - "code": always allowed (OTP delivery falls back to the default
//     mailer when no custom SMTP is configured).
//   - "none": requires at least one OAuth provider on (no email path).
func (handler *RequestHandler) HandleUpdateAppAuthMethodConfig(w http.ResponseWriter, r *http.Request) {
	acc, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	productID, appID, ok := handler.resolvePathIDs(w, r)
	if !ok {
		return
	}

	var req updateAppAuthMethodConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode json")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if req.PrimaryAuthMethod == nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	method := *req.PrimaryAuthMethod
	if method != core.PrimaryAuthMethodPassword &&
		method != core.PrimaryAuthMethodCode &&
		method != core.PrimaryAuthMethodMagicLink &&
		method != core.PrimaryAuthMethodNone {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	curApp, curAppErr := handler.repo.GetAppByIDForProduct(r.Context(), ws.ID, productID, appID)
	if curAppErr != nil {
		if errors.Is(curAppErr, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		log.Err(curAppErr).Msg("failed to load app for auth-method-config update")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if !handler.requireAtLeastOneSignInMethod(r.Context(), ws, acc.IsSuper(), method, curApp.AuthMethodGoogle, curApp.AuthMethodApple, curApp.AuthMethodMicrosoft, curApp.AuthMethodGithub) {
		WriteError(w, r, "error.noSignInMethodEnabled", http.StatusBadRequest)
		return
	}

	// Magic-link mode requires an app URL — the email contains a link
	// that has to point somewhere. Without it the link is dead.
	if method == core.PrimaryAuthMethodMagicLink {
		if curApp.AppURL == nil || strings.TrimSpace(*curApp.AppURL) == "" {
			WriteError(w, r, "error.magicLinkRequiresAppUrl", http.StatusBadRequest)
			return
		}
	}

	out, err := handler.repo.UpdateAppPrimaryAuthMethod(r.Context(), ws.ID, productID, appID, method)
	if err != nil {
		log.Err(err).Msg("failed to update auth-method config")
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, ws), http.StatusOK)
}

// HandleUpdateAppPasswordPolicy sets the per-app password-strength
// policy: a length floor and a zxcvbn score threshold. Both are
// optional in the request — omitted fields keep their current value.
func (handler *RequestHandler) HandleUpdateAppPasswordPolicy(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	productID, appID, ok := handler.resolvePathIDs(w, r)
	if !ok {
		return
	}

	var req updateAppPasswordPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode json")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	curApp, curAppErr := handler.repo.GetAppByIDForProduct(r.Context(), ws.ID, productID, appID)
	if curAppErr != nil {
		if errors.Is(curAppErr, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		log.Err(curAppErr).Msg("failed to load app for password-policy update")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	minLength := curApp.PasswordMinLength
	if req.MinLength != nil {
		minLength = *req.MinLength
	}
	minScore := curApp.PasswordMinZxcvbnScore
	if req.MinZxcvbnScore != nil {
		minScore = *req.MinZxcvbnScore
	}
	if minLength < 1 || minLength > 256 {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if minScore < 0 || minScore > 4 {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	out, err := handler.repo.UpdateAppPasswordPolicy(r.Context(), ws.ID, productID, appID, minLength, minScore)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to update password policy")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, ws), http.StatusOK)
}

// HandleUpdateAppCookieDomain sets the per-app override for the
// session cookie Domain attribute. Empty string clears the override
// (app then inherits the workspace-level cookie domain). Format
// rules + public-suffix rejection match the workspace handler — see
// validateCookieDomain in updateWorkspace.go.
func (handler *RequestHandler) HandleUpdateAppCookieDomain(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	productID, appID, ok := handler.resolvePathIDs(w, r)
	if !ok {
		return
	}

	var req updateAppCookieDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode json")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	var stored *string
	if req.CookieDomain != nil {
		v := strings.TrimSpace(*req.CookieDomain)
		if v == "" {
			stored = nil
		} else {
			if err := validateCookieDomain(v); err != nil {
				WriteError(w, r, "error.invalidCookieDomain", http.StatusBadRequest)
				return
			}
			stored = &v
		}
	}

	out, err := handler.repo.UpdateAppCookieDomain(r.Context(), ws.ID, productID, appID, stored)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to update app cookie domain")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, ws), http.StatusOK)
}

// HandleUpdateAppTransportMode sets the per-app session-transport
// selector. Validates the value is one of the allowed enum constants
// (local / cookie). Switching modes does NOT auto-clear the per-mode
// config (e.g. cookie_domain) — it stays dormant when the mode is
// off, so flipping back doesn't lose it.
func (handler *RequestHandler) HandleUpdateAppTransportMode(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	productID, appID, ok := handler.resolvePathIDs(w, r)
	if !ok {
		return
	}

	var req updateAppTransportModeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode json")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	mode := strings.TrimSpace(req.TransportMode)
	switch mode {
	case core.TransportModeLocal, core.TransportModeCookie:
		// ok
	default:
		WriteError(w, r, "error.invalidTransportMode", http.StatusBadRequest)
		return
	}

	out, err := handler.repo.UpdateAppTransportMode(r.Context(), ws.ID, productID, appID, mode)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to update app transport mode")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, ws), http.StatusOK)
}

// HandleUpdateAppSessionCookieSameSite sets the per-app SameSite
// attribute on the session cookies. Strict is only valid when the
// app has no inbound cross-site GET that needs to carry the session
// — magic links, any OAuth provider, or the (unimplemented) link-
// based reset/verify flows would all break under Strict because the
// cookie wouldn't ride along on the top-level navigation back to
// this app.
//
// The handler enforces the precondition; the inverse direction
// (enabling magic links / OAuth while Strict is set) isn't checked
// here — the operator will notice the broken flow on first use and
// flip back to Lax. Documenting the trade-off in the admin UI is
// the simplest belt-and-braces.
func (handler *RequestHandler) HandleUpdateAppSessionCookieSameSite(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	productID, appID, ok := handler.resolvePathIDs(w, r)
	if !ok {
		return
	}

	var req updateAppSessionCookieSameSiteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode json")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	mode := strings.TrimSpace(req.SessionCookieSameSite)
	switch mode {
	case core.SessionCookieSameSiteLax, core.SessionCookieSameSiteStrict:
		// ok
	default:
		WriteError(w, r, "error.invalidSameSiteMode", http.StatusBadRequest)
		return
	}

	// Strict-mode precondition check: refuse if any link-based flow is
	// active. Lax has no preconditions.
	//
	// Use the workspace+project-scoped lookup so a workspace-A admin
	// probing arbitrary UUIDs can't infer the auth-method config of
	// an app in workspace B via the branch errors below (strict /
	// magic-link / OAuth). The UPDATE below was already scoped — this
	// closes the matching information-disclosure hole on the read
	// path.
	if mode == core.SessionCookieSameSiteStrict {
		cur, err := handler.repo.GetAppByIDForProduct(r.Context(), ws.ID, productID, appID)
		if err != nil {
			if errors.Is(err, repo.ErrNotFound) {
				WriteError(w, r, "error.appNotFound", http.StatusNotFound)
				return
			}
			log.Err(err).Msg("failed to load app for SameSite precondition check")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if cur.PrimaryAuthMethod == core.PrimaryAuthMethodMagicLink {
			WriteError(w, r, "error.strictRequiresNoMagicLinks", http.StatusBadRequest)
			return
		}
		if cur.AuthMethodGoogle || cur.AuthMethodApple || cur.AuthMethodMicrosoft || cur.AuthMethodGithub {
			WriteError(w, r, "error.strictRequiresNoOAuth", http.StatusBadRequest)
			return
		}
	}

	out, err := handler.repo.UpdateAppSessionCookieSameSite(r.Context(), ws.ID, productID, appID, mode)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to update app SameSite mode")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, ws), http.StatusOK)
}

