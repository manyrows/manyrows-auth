package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"manyrows-core/auth"
	"manyrows-core/auth/oidc"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/crypto"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// =====================
// Generic external IdP sign-in (Authorization Code Flow)
// =====================
//
// One pair of handlers serves every configured external IdP, keyed by
// the {providerSlug} path segment. OIDC-mode providers are verified via
// id_token + JWKS; OAuth2-mode providers via the userinfo endpoint. The
// heavy lifting lives in auth/oidc; this file is the HTTP/session glue
// that mirrors the bespoke Tier-1 providers (state, opener-origin,
// popup postMessage wrapper, shared login completion).

// externalIDPStateTTL bounds the authorize→callback round trip.
const externalIDPStateTTL = 10 * time.Minute

// externalIDPProviderConfig builds the auth/oidc config (primitives)
// from a stored row + its decrypted client secret.
func externalIDPProviderConfig(e *core.ExternalIDP, clientSecret string) oidc.ProviderConfig {
	return oidc.ProviderConfig{
		Mode:               string(e.Mode),
		IssuerURL:          e.IssuerURL,
		AuthorizeURL:       e.AuthorizeURL,
		TokenURL:           e.TokenURL,
		UserinfoURL:        e.UserinfoURL,
		JWKSURL:            e.JWKSURL,
		ClientID:           e.ClientID,
		ClientSecret:       clientSecret,
		Scopes:             e.Scopes,
		SubjectField:       e.SubjectField,
		EmailField:         e.EmailField,
		EmailVerifiedField: e.EmailVerifiedField,
		NameField:          e.NameField,
	}
}

// derivePKCE derives the PKCE verifier+challenge deterministically from
// the signed state and the server HMAC key. We deliberately do NOT
// persist per-flow PKCE: the state row already enforces single-use +
// expiry, and because the verifier is HMAC(serverKey, state) the public
// `state` value alone can't reveal it. The verifier is 43 url-safe chars
// (32 HMAC bytes), within RFC 7636's 43–128 range.
func derivePKCE(state string, key []byte) (verifier, challenge string) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(state))
	mac.Write([]byte(":pkce"))
	verifier = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

// deriveNonce derives the OIDC nonce from the signed state + server key
// (same rationale as derivePKCE): unpredictable to anyone without the
// key, and bound one-shot to the single-use state.
func deriveNonce(state string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(state))
	mac.Write([]byte(":nonce"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// loadEnabledExternalIDP resolves {providerSlug} to an enabled config for
// the context app. On any miss it writes a 404 (don't distinguish "no
// such provider" from "disabled") and returns ok=false.
func (handler *RequestHandler) loadEnabledExternalIDP(w http.ResponseWriter, r *http.Request) (*core.App, *core.ExternalIDP, bool) {
	app, ok := core.AppFromContext(r.Context())
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return nil, nil, false
	}
	slug := strings.TrimSpace(utils.GetPathString("providerSlug", r))
	if slug == "" {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return nil, nil, false
	}
	idp, err := handler.repo.GetExternalIDPByAppAndSlug(r.Context(), app.ID, slug)
	if err != nil {
		if errors.Is(err, repo.ErrExternalIDPNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return nil, nil, false
		}
		log.Err(err).Str("app_id", app.ID.String()).Str("slug", slug).Msg("loadEnabledExternalIDP: lookup failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return nil, nil, false
	}
	if !idp.Enabled {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return nil, nil, false
	}
	return app, idp, true
}

// pkceAndNonce derives the per-flow PKCE challenge + nonce for a config.
// nonce only applies to OIDC mode (OAuth2 has no id_token to bind).
func (handler *RequestHandler) pkceAndNonce(idp *core.ExternalIDP, state string) (challenge, nonce string) {
	_, challenge = derivePKCE(state, handler.totpKey)
	if idp.Mode == core.ExternalIDPModeOIDC {
		nonce = deriveNonce(state, handler.totpKey)
	}
	return challenge, nonce
}

// WorkspaceExternalIDPAuthorize returns the provider authorization URL.
// GET /x/{slug}/apps/{appId}/auth/idp/{providerSlug}/authorize?openerOrigin=…
func (handler *RequestHandler) WorkspaceExternalIDPAuthorize(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}
	app, idp, ok := handler.loadEnabledExternalIDP(w, r)
	if !ok {
		return
	}

	openerOrigin := strings.TrimSpace(r.URL.Query().Get("openerOrigin"))
	if openerOrigin == "" {
		openerOrigin = strings.TrimSpace(r.Header.Get("Origin"))
	}
	// The popup flow needs an opener origin to scope the postMessage.
	if openerOrigin == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	allowed, err := handler.isOpenerOriginAllowed(r.Context(), app, openerOrigin)
	if err != nil {
		log.Err(err).Msg("external idp authorize: GetCorsOrigins failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !allowed {
		WriteError(w, r, "error.invalidOrigin", http.StatusBadRequest)
		return
	}

	// Ride an existing session along on the state row (bearer flow: the
	// top-level callback redirect carries no token of its own).
	var preloginSessionID *uuid.UUID
	if loggedIn, ses, lerr := handler.clientAuthService.IsLoggedIntoApp(r, app.ID); lerr == nil && loggedIn && ses != nil {
		sid := ses.ID
		preloginSessionID = &sid
	}

	state, err := auth.SignOAuthState(r.Context(), handler.repo, handler.totpKey, app.ID, idp.ProviderKey(), openerOrigin, preloginSessionID, externalIDPStateTTL)
	if err != nil {
		log.Err(err).Msg("external idp authorize: sign state failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	baseURL := handler.AppBaseURL(app)
	if baseURL == "" {
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	redirectURI := baseURL + "/x/" + ws.Slug + "/apps/" + app.ID.String() + "/auth/idp/" + idp.Slug + "/callback"

	challenge, nonce := handler.pkceAndNonce(idp, state)
	authorizeURL, err := oidc.AuthorizeURL(r.Context(), externalIDPProviderConfig(idp, ""), redirectURI, state, challenge, nonce)
	if err != nil {
		log.Err(err).Str("slug", idp.Slug).Msg("external idp authorize: build URL failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{"url": authorizeURL, "state": state})
}

// WorkspaceExternalIDPCallback handles the provider's GET redirect with
// code + state. Same buffered-then-postMessage-wrap pattern as the
// bespoke providers.
// GET /x/{slug}/apps/{appId}/auth/idp/{providerSlug}/callback?code=…&state=…
func (handler *RequestHandler) WorkspaceExternalIDPCallback(w http.ResponseWriter, r *http.Request) {
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	targetOrigin := sanitizeTargetOrigin(auth.PeekOAuthStateOpenerOriginAny(r.Context(), handler.repo, handler.tokenVerifyKeys(), state))

	buf := newBufferedResponse()
	handler.processExternalIDPCallback(buf, r)
	writeOAuthCallbackHTML(w, buf, targetOrigin, "external-idp-oauth-callback")
}

func (handler *RequestHandler) processExternalIDPCallback(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}
	app, idp, ok := handler.loadEnabledExternalIDP(w, r)
	if !ok {
		return
	}

	// Forbid OAuth completion when a session is already active for this
	// app (cookie mode shows it on the callback redirect) — same
	// forced-linking guard as the bespoke providers.
	loggedIn, _, sesErr := handler.clientAuthService.IsLoggedIntoApp(r, app.ID)
	if sesErr != nil {
		log.Err(sesErr).Msg("external idp callback: session resolve failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if loggedIn {
		WriteError(w, r, "error.alreadyLoggedIn", http.StatusForbidden)
		return
	}

	if e := strings.TrimSpace(r.URL.Query().Get("error")); e != "" {
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if code == "" || state == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	stateAppID, _, preloginSesID, err := auth.VerifyOAuthStateAny(r.Context(), handler.repo, handler.tokenVerifyKeys(), state, idp.ProviderKey())
	if err != nil || stateAppID != app.ID {
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	ip := auth.ClientIP(r)
	if !handler.checkAttemptRateLimit(w, r, "external_idp_oauth", ip, "", "external idp oauth callback", nil) {
		return
	}

	clientSecret, err := handler.encryptor.DecryptFromBytesWithAAD(
		idp.ClientSecretEncrypted,
		crypto.AAD("external_idps", "client_secret_encrypted", idp.ID),
	)
	if err != nil {
		log.Err(err).Str("slug", idp.Slug).Msg("external idp callback: decrypt secret failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	baseURL := handler.AppBaseURL(app)
	redirectURI := baseURL + "/x/" + ws.Slug + "/apps/" + app.ID.String() + "/auth/idp/" + idp.Slug + "/callback"

	verifier, _ := derivePKCE(state, handler.totpKey)
	nonce := ""
	if idp.Mode == core.ExternalIDPModeOIDC {
		nonce = deriveNonce(state, handler.totpKey)
	}

	info, err := oidc.Authenticate(r.Context(), externalIDPProviderConfig(idp, string(clientSecret)), code, redirectURI, verifier, nonce)
	if err != nil {
		_ = handler.repo.InsertAttempt(r.Context(), "external_idp_oauth", "external_idp_code_failed", ip)
		log.Warn().Err(err).Str("slug", idp.Slug).Msg("external idp callback: authenticate failed")
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:   ws.ID,
			AppID:         &app.ID,
			Event:         core.AuthEventLoginFailed,
			Method:        core.AuthMethodExternalIDP,
			Outcome:       core.AuthOutcomeFailed,
			FailureReason: core.AuthFailProviderExchangeFail,
			ActorType:     core.AuthActorSelf,
		})
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	if info.Email == "" {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:   ws.ID,
			AppID:         &app.ID,
			Event:         core.AuthEventLoginFailed,
			Method:        core.AuthMethodExternalIDP,
			Outcome:       core.AuthOutcomeFailed,
			FailureReason: core.AuthFailEmailNotProvided,
			ActorType:     core.AuthActorSelf,
		})
		WriteError(w, r, "error.emailNotProvided", http.StatusBadRequest)
		return
	}

	// Require a verified email — same bar as every bespoke provider
	// (Google/Apple verify, GitHub filters to verified, Microsoft uses
	// xms_edov), and the contract completeTier1OAuthLogin documents.
	// Without this an external IdP that lets a user assert an arbitrary
	// unverified email could hijack an existing account through the
	// email-fallback link in ResolveOAuthSignInIdentity. An admin can
	// opt a trusted IdP out via TrustUnverifiedEmail (e.g. a corporate
	// Okta that verifies emails but omits the email_verified claim).
	if !idp.TrustUnverifiedEmail && !info.EmailVerified {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:   ws.ID,
			AppID:         &app.ID,
			Event:         core.AuthEventLoginFailed,
			Method:        core.AuthMethodExternalIDP,
			Outcome:       core.AuthOutcomeFailed,
			FailureReason: core.AuthFailEmailNotVerified,
			ActorType:     core.AuthActorSelf,
		})
		WriteError(w, r, "error.emailNotVerified", http.StatusForbidden)
		return
	}

	handler.completeTier1OAuthLogin(w, r, ws, app, info.Email, ip, false, tier1OAuthLoginOpts{
		AuthMethod:        core.AuthMethodExternalIDP,
		UserSource:        core.UserSourceExternalIDP,
		ProviderKey:       idp.ProviderKey(),
		ProviderSubject:   info.Subject,
		AttemptPurpose:    "external_idp_oauth",
		WebhookMethod:     idp.Slug,
		PreloginSessionID: preloginSesID,
	})
}
