package api

import (
	"net/http"
	"time"

	clientauth "manyrows-core/auth/client"
	"manyrows-core/core"
)

// resolveCookieDomain returns the Domain attribute to put on session
// cookies for an end-user session in the given workspace + app. Order
// of precedence: app-level override → workspace-level setting →
// empty (browser scopes the cookie to the exact host that set it).
func resolveCookieDomain(ws *core.Workspace, app *core.App) string {
	if app != nil && app.CookieDomain != nil {
		v := *app.CookieDomain
		if v != "" {
			return v
		}
	}
	if ws != nil && ws.CookieDomain != nil {
		return *ws.CookieDomain
	}
	return ""
}

// resolveSameSite picks the http.SameSite value for the session
// cookies. Defaults to Lax (the column's default and the safe value
// for every flow). Strict only kicks in when the operator has flipped
// the per-app field to "strict" via the admin UI; the handler that
// flips it guards the precondition (no link-based auth flows).
func resolveSameSite(app *core.App) http.SameSite {
	if app != nil && app.SessionCookieSameSite == core.SessionCookieSameSiteStrict {
		return http.SameSiteStrictMode
	}
	return http.SameSiteLaxMode
}

// setSessionCookies writes HttpOnly access + refresh cookies for the
// given token pair. Cookie mode is same-site only: AppKit and
// ManyRows must share an origin (or sit on subdomains of a shared
// registrable domain reached via top-level navigation). Cross-origin
// XHR is not supported on the cookie path — those clients use Bearer
// mode. Bearer-mode clients (AppKit-direct localStorage, native apps)
// ignore these cookies and keep reading tokens from the JSON response
// body.
//
// SameSite defaults to Lax — works for every flow including magic
// links, OAuth redirects, and the bookmark/typed-URL cases. Apps
// that opt into Strict (Security → Sessions → Lifetime → Cookie
// strictness) get http.SameSiteStrictMode; the handler that flips
// that field guards against incompatible auth methods so cookies
// can't go silently undeliverable on a top-level cross-site GET.
func (handler *RequestHandler) setSessionCookies(
	w http.ResponseWriter,
	r *http.Request,
	ws *core.Workspace,
	app *core.App,
	tp *clientauth.TokenPair,
	refreshTTL time.Duration,
) {
	if tp == nil {
		return
	}
	domain := resolveCookieDomain(ws, app)
	secure := !handler.config.IsDevMode()
	sameSite := resolveSameSite(app)

	// Access cookie expires with the access token.
	accessMaxAge := tp.ExpiresIn
	if accessMaxAge <= 0 {
		accessMaxAge = int(time.Until(tp.ExpiresAt).Seconds())
	}
	if accessMaxAge < 0 {
		accessMaxAge = 0
	}

	http.SetCookie(w, &http.Cookie{
		Name:     clientauth.AccessCookieName(app.ID),
		Value:    tp.AccessToken,
		Path:     "/",
		Domain:   domain,
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
		MaxAge:   accessMaxAge,
	})

	// Refresh cookie tracks the refresh token's actual lifetime — the
	// caller passes effectiveSessionTTL(app, rememberMe) so the cookie
	// doesn't expire before the server-side token does.
	refreshMaxAge := int(refreshTTL.Seconds())
	if refreshMaxAge <= 0 {
		refreshMaxAge = 7 * 24 * 60 * 60
	}

	http.SetCookie(w, &http.Cookie{
		Name:     clientauth.RefreshCookieName(app.ID),
		Value:    tp.RefreshToken,
		Path:     "/",
		Domain:   domain,
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
		MaxAge:   refreshMaxAge,
	})

	_ = r // reserved for future use (per-request domain detection)
}

// clearSessionCookies expires the access + refresh cookies. Used by
// logout. The Domain must match what we set them with, otherwise the
// browser won't clear them.
func (handler *RequestHandler) clearSessionCookies(
	w http.ResponseWriter,
	ws *core.Workspace,
	app *core.App,
) {
	domain := resolveCookieDomain(ws, app)
	secure := !handler.config.IsDevMode()
	sameSite := resolveSameSite(app)
	for _, name := range []string{clientauth.AccessCookieName(app.ID), clientauth.RefreshCookieName(app.ID)} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			Domain:   domain,
			HttpOnly: true,
			Secure:   secure,
			SameSite: sameSite,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
		})
	}
}
