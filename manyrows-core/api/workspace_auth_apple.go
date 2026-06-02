package api

import (
	"bytes"
	"fmt"
	"manyrows-core/auth"
	appleauth "manyrows-core/auth/apple"
	"manyrows-core/core"
	"manyrows-core/crypto"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// =====================
// Sign in with Apple (Authorization Code Flow)
// =====================
//
// Apple uses response_mode=form_post when the name/email scopes are
// requested, so the callback handler accepts POST application/x-www-form-
// urlencoded rather than JSON. The "client secret" sent to Apple's token
// endpoint is itself an ES256 JWT minted from the customer's .p8 key.

const oauthStateTTL = 10 * time.Minute
const appleClientSecretTTL = 5 * time.Minute

// Backward-compat alias used by the original Apple handler. Apple was
// the first popup-callback provider; the same TTL fits Microsoft too.
const appleOAuthStateTTL = oauthStateTTL

func (handler *RequestHandler) appleConfigured(a *core.App) bool {
	return a != nil &&
		a.AppleServicesID != nil && *a.AppleServicesID != "" &&
		a.AppleTeamID != nil && *a.AppleTeamID != "" &&
		a.AppleKeyID != nil && *a.AppleKeyID != "" &&
		len(a.ApplePrivateKeyEncrypted) > 0
}

// WorkspaceAppleAuthorize returns the Apple authorization URL. Requires
// `openerOrigin` (query param or Origin header) so the callback HTML can
// postMessage tokens to a specific origin rather than "*". The origin
// must match one of the app's configured CORS origins; this is the same
// allowlist that gates AppKit's API access.
//
// GET /x/{slug}/apps/{appId}/auth/apple/authorize?openerOrigin=https://...
func (handler *RequestHandler) WorkspaceAppleAuthorize(w http.ResponseWriter, r *http.Request) {
	handler.workspaceOAuthAuthorize(w, r, tier1OAuthAuthorizeOpts{
		Provider:             "apple",
		AuthMethodEnabled:    func(a *core.App) bool { return a.AuthMethodApple },
		Configured:           handler.appleConfigured,
		NotConfiguredCode:    "error.appleNotConfigured",
		OpenerOriginRequired: true,
		StateTTL:             appleOAuthStateTTL,
		CallbackPath:         "auth/apple/callback",
		BuildAuthorizeURL: func(a *core.App, redirectURI, state string) string {
			return appleauth.BuildAuthorizeURL(*a.AppleServicesID, redirectURI, state)
		},
	})
}

// bufferedResponse captures the body and status code written by a handler
// chain so the Apple callback can wrap downstream JSON in an HTML page.
// The popup that Apple form_posts into needs to relay tokens to the
// opener via postMessage; everything that writes via WriteError or
// utils.WriteJson stays portable this way.
type bufferedResponse struct {
	header http.Header
	body   bytes.Buffer
	code   int
}

func newBufferedResponse() *bufferedResponse {
	return &bufferedResponse{header: http.Header{}, code: http.StatusOK}
}
func (b *bufferedResponse) Header() http.Header         { return b.header }
func (b *bufferedResponse) WriteHeader(code int)        { b.code = code }
func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }

// writeOAuthCallbackHTML serves a tiny page that posts the captured
// JSON payload to the opener window and closes the popup. messageType
// is the postMessage `type` field the AppKit listener filters on
// (e.g. "apple-oauth-callback", "microsoft-oauth-callback").
// targetOrigin scopes the postMessage to the AppKit window's origin
// (validated upstream against the app's CORS origins) so tokens never
// leak to a window that has navigated away. If the state token is
// unknown (replayed, expired, never minted), targetOrigin will be
// empty and we render a plain message rather than blasting tokens to "*".
//
// Forwards any Set-Cookie headers the buffered handler wrote
// (setSessionCookies → mr_at_<appID>, mr_rt_<appID>) onto the real
// ResponseWriter. Without this the popup flow returns tokens in the
// postMessage payload but no HttpOnly cookies — the next page reload
// loses the in-memory session and /auth/refresh 400s because there's
// no mr_rt cookie to refresh from.
func writeOAuthCallbackHTML(w http.ResponseWriter, buf *bufferedResponse, targetOrigin, messageType string) {
	for _, c := range buf.header.Values("Set-Cookie") {
		w.Header().Add("Set-Cookie", c)
	}
	statusCode := buf.code
	payload := buf.body.Bytes()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Completing sign-in…</title></head>
<body>
<p>Completing sign-in…</p>
<script>
(function() {
  var status = %d;
  var targetOrigin = %q;
  var messageType = %q;
  var data;
  try { data = JSON.parse(%q); } catch (_) { data = {error: "invalid response"}; }
  if (window.opener && targetOrigin) {
    window.opener.postMessage({type:messageType, status:status, payload:data}, targetOrigin);
    window.close();
  } else {
    document.body.innerHTML = "<p>Sign-in cannot be completed in this context.</p>";
  }
})();
</script>
</body>
</html>`, statusCode, targetOrigin, messageType, string(payload))
}

// WorkspaceAppleCallback handles Apple's form_post callback. Apple posts
// `code`, `state`, optionally `user` (first sign-in only), and on failure
// `error`. Content-Type is application/x-www-form-urlencoded.
//
// The browser arrives here via Apple's auto-submitting form, so the
// response must be HTML that hands tokens back to window.opener. We run
// the existing JSON-emitting handler against a bufferedResponse and then
// wrap whatever it produced in the postMessage page.
//
// POST /x/{slug}/apps/{appId}/auth/apple/callback
func (handler *RequestHandler) WorkspaceAppleCallback(w http.ResponseWriter, r *http.Request) {
	// Pull the opener origin off the state token *before* running the
	// processor so we have it for the HTML wrapper even on early errors.
	// The state is in the form body — peek without consuming any other
	// state machinery. ParseForm is idempotent so the processor can call
	// it again.
	_ = r.ParseForm()
	state := strings.TrimSpace(r.PostFormValue("state"))

	// Peek opener_origin from the state row WITHOUT consuming — the inner
	// processor will atomically consume via VerifyOAuthState. The peek
	// returns "" if the token is invalid/expired/already-consumed; in
	// that case the HTML wrapper will render without a postMessage
	// target, which is the right fail-closed behaviour.
	rawOrigin := auth.PeekOAuthStateOpenerOrigin(r.Context(), handler.repo, handler.totpKey, state)
	targetOrigin := sanitizeTargetOrigin(rawOrigin)

	buf := newBufferedResponse()
	handler.processAppleCallback(buf, r)
	writeOAuthCallbackHTML(w, buf, targetOrigin, "apple-oauth-callback")
}

// sanitizeTargetOrigin parses an origin string and returns it rebuilt
// from the scheme + host components, dropping anything else. Defense in
// depth before the value lands inside a <script> string literal:
// `%q` (strconv.Quote) escapes control chars and quotes but not `<`
// or `>`, so a malformed CORS-origin entry like `https://x</script>`
// would otherwise break the surrounding script tag. Returns "" if the
// input doesn't parse as an http(s) origin.
func sanitizeTargetOrigin(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	// Reject any character not legal in a URL host. The whitelist covers
	// hostnames (letters/digits/./-), ports (:), and IPv6 literals ([]).
	// Anything outside that set — quotes, null bytes, '<', '>' — could
	// break out of the surrounding <script> string when the value is
	// emitted via %q (which doesn't escape '<' or '>').
	for i := 0; i < len(u.Host); i++ {
		c := u.Host[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '.', c == '-', c == ':', c == '[', c == ']':
			// allowed
		default:
			return ""
		}
	}
	return u.Scheme + "://" + u.Host
}

func (handler *RequestHandler) processAppleCallback(w http.ResponseWriter, r *http.Request) {
	ws, ctxApp, ok := handler.requireOAuthAppContext(w, r,
		func(a *core.App) bool { return a.AuthMethodApple },
		handler.appleConfigured,
		"error.appleNotConfigured")
	if !ok {
		return
	}

	// Forbid OAuth completion when a session for this app is already
	// active. Without this, a user who's already logged in but tricked
	// into completing an Apple OAuth flow would get their session
	// silently swapped for whoever owns the Apple identity that came
	// back — i.e. forced account-linking / takeover.
	loggedIn, _, sesErr := handler.clientAuthService.IsLoggedIntoApp(r, ctxApp.ID)
	if sesErr != nil {
		log.Err(sesErr).Msg("Could not resolve client session for apple callback")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if loggedIn {
		WriteError(w, r, "error.alreadyLoggedIn", http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	if e := strings.TrimSpace(r.PostFormValue("error")); e != "" {
		// User cancelled / consent denied. Surface as 401.
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	code := strings.TrimSpace(r.PostFormValue("code"))
	state := strings.TrimSpace(r.PostFormValue("state"))
	if code == "" || state == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	stateAppID, _, preloginSesID, err := auth.VerifyOAuthState(r.Context(), handler.repo, handler.totpKey, state, "apple")
	if err != nil || stateAppID != ctxApp.ID {
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	ip := auth.ClientIP(r)

	appleCBFail := func(reason core.AuthLogFailureReason, email string) {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:    ws.ID,
			AppID:          &ctxApp.ID,
			Event:          core.AuthEventLoginFailed,
			Method:         core.AuthMethodApple,
			Outcome:        core.AuthOutcomeFailed,
			FailureReason:  reason,
			EmailAttempted: email,
			ActorType:      core.AuthActorSelf,
		})
	}

	if !handler.checkAttemptRateLimit(w, r, "apple_oauth", ip, "", "apple oauth callback",
		func() { appleCBFail(core.AuthFailRateLimited, "") }) {
		return
	}

	privateKey, err := handler.encryptor.DecryptFromBytesWithAAD(
		ctxApp.ApplePrivateKeyEncrypted,
		crypto.AAD("apps", "apple_private_key_encrypted", ctxApp.ID),
	)
	if err != nil {
		log.Err(err).Msg("failed to decrypt apple private key")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	clientSecret, err := appleauth.GenerateClientSecret(
		*ctxApp.AppleTeamID,
		*ctxApp.AppleServicesID,
		*ctxApp.AppleKeyID,
		privateKey,
		appleClientSecretTTL,
	)
	if err != nil {
		log.Err(err).Msg("failed to generate apple client secret")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	baseURL := handler.AppBaseURL(ctxApp)
	redirectURI := baseURL + "/x/" + ws.Slug + "/apps/" + ctxApp.ID.String() + "/auth/apple/callback"

	tokenInfo, err := appleauth.ExchangeAuthCode(r.Context(), code, *ctxApp.AppleServicesID, clientSecret, redirectURI)
	if err != nil {
		_ = handler.repo.InsertAttempt(r.Context(), "apple_oauth", "apple_oauth_code_failed", ip)
		appleCBFail(core.AuthFailProviderExchangeFail, "")
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	// Apple omits email when the user has signed in before with a different
	// app and chose private relay; in that case we have no way to identify
	// the user without the sub-based lookup, which we don't yet implement.
	if tokenInfo.Email == "" {
		appleCBFail(core.AuthFailEmailNotProvided, "")
		WriteError(w, r, "error.emailNotProvided", http.StatusBadRequest)
		return
	}

	// Apple sets is_private_email for relay addresses; treat both verified
	// and private-relay as trusted (Apple guarantees deliverability for
	// private relay).
	if !tokenInfo.EmailVerified && !tokenInfo.IsPrivateEmail {
		appleCBFail(core.AuthFailEmailNotVerified, tokenInfo.Email)
		WriteError(w, r, "error.emailNotVerified", http.StatusForbidden)
		return
	}

	handler.completeAppleLogin(w, r, ws, ctxApp, tokenInfo, ip, false, preloginSesID)
}

// completeAppleLogin mirrors completeGoogleLogin: lookup-or-create user,
// 2FA gate, session issuance, JSON response. Kept separate rather than
// generalized because the audit/event metadata strings differ and a
// shared helper would obscure the per-provider differences.
func (handler *RequestHandler) completeAppleLogin(
	w http.ResponseWriter, r *http.Request,
	ws *core.Workspace, ctxApp *core.App,
	tokenInfo *appleauth.TokenInfo, ip string, rememberMe bool,
	preloginSessionID *uuid.UUID,
) {
	// Apple's private-relay addresses are always @privaterelay.appleid.com;
	// they can never match a customer's AllowedEmailDomains, so skip that
	// check when the token says the user opted into relay.
	skipDomain := tokenInfo.IsPrivateEmail
	handler.completeTier1OAuthLogin(w, r, ws, ctxApp, tokenInfo.Email, ip, rememberMe, tier1OAuthLoginOpts{
		AuthMethod:        core.AuthMethodApple,
		UserSource:        core.UserSourceApple,
		ProviderSubject:   tokenInfo.Sub,
		AttemptPurpose:    "apple_oauth",
		WebhookMethod:     "apple",
		SkipDomainCheck:   func() bool { return skipDomain },
		PreloginSessionID: preloginSessionID,
	})
}
