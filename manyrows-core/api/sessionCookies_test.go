package api

// Internal-package tests for setSessionCookies / clearSessionCookies /
// resolveCookieDomain — pure, no DB. Validates that the cookies we
// hand to the browser carry the right Domain / HttpOnly / SameSite /
// MaxAge attributes for every (workspace cookie_domain, app override)
// permutation, plus the rememberMe TTL plumbing through to the
// refresh-cookie MaxAge.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	clientauth "manyrows-core/auth/client"
	"manyrows-core/config"
	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
)

// testAppID is a stable UUID used by the cookie tests so the per-app
// cookie names (mr_at_<uuid>, mr_rt_<uuid>) are predictable and
// every assertion lines up against the same string.
var testAppID = uuid.Must(uuid.NewV4())

func testApp(extra ...func(*core.App)) *core.App {
	a := &core.App{ID: testAppID}
	for _, fn := range extra {
		fn(a)
	}
	return a
}

func strp(s string) *string { return &s }

func TestResolveCookieDomain(t *testing.T) {
	cases := []struct {
		name string
		ws   *core.Workspace
		app  *core.App
		want string
	}{
		{name: "both nil", ws: nil, app: nil, want: ""},
		{name: "ws + app both unset", ws: &core.Workspace{}, app: &core.App{}, want: ""},
		{name: "ws set, no app override", ws: &core.Workspace{CookieDomain: strp(".acme.com")}, app: &core.App{}, want: ".acme.com"},
		{name: "app override beats ws", ws: &core.Workspace{CookieDomain: strp(".acme.com")}, app: &core.App{CookieDomain: strp(".widgets.io")}, want: ".widgets.io"},
		{name: "app override empty string falls through to ws", ws: &core.Workspace{CookieDomain: strp(".acme.com")}, app: &core.App{CookieDomain: strp("")}, want: ".acme.com"},
		{name: "ws empty string returns empty", ws: &core.Workspace{CookieDomain: strp("")}, app: &core.App{}, want: ""},
		{name: "nil ws, app set", ws: nil, app: &core.App{CookieDomain: strp(".acme.com")}, want: ".acme.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveCookieDomain(c.ws, c.app); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// devModeHandler builds a minimal RequestHandler whose config defaults
// to dev profile (IsDevMode() == true), so the Secure flag is false
// and we don't need a real env. We use an env-prefix that no test
// touches so PROFILE never resolves to a non-dev value.
func devModeHandler(t *testing.T) *RequestHandler {
	t.Helper()
	return &RequestHandler{config: config.NewConfig("SESSIONCOOKIES_TEST_")}
}

func cookieByName(cs []*http.Cookie, name string) *http.Cookie {
	for _, c := range cs {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestSetSessionCookies_BothCookiesWritten(t *testing.T) {
	h := devModeHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/verify", nil)

	tp := &clientauth.TokenPair{
		AccessToken:  "at_value",
		RefreshToken: "rt_value",
		ExpiresAt:    time.Now().Add(15 * time.Minute),
		ExpiresIn:    900,
	}
	h.setSessionCookies(w, r, &core.Workspace{}, testApp(), tp, 7*24*time.Hour)

	cs := w.Result().Cookies()
	at := cookieByName(cs, clientauth.AccessCookieName(testAppID))
	rt := cookieByName(cs, clientauth.RefreshCookieName(testAppID))
	if at == nil {
		t.Fatalf("access cookie %q missing", clientauth.AccessCookieName(testAppID))
	}
	if rt == nil {
		t.Fatalf("refresh cookie %q missing", clientauth.RefreshCookieName(testAppID))
	}
	if at.Value != "at_value" || rt.Value != "rt_value" {
		t.Errorf("cookie values not propagated: at=%q rt=%q", at.Value, rt.Value)
	}
	for _, c := range []*http.Cookie{at, rt} {
		if !c.HttpOnly {
			t.Errorf("%s should be HttpOnly", c.Name)
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Errorf("%s SameSite = %v, want Lax", c.Name, c.SameSite)
		}
		if c.Path != "/" {
			t.Errorf("%s Path = %q, want /", c.Name, c.Path)
		}
		if c.Domain != "" {
			t.Errorf("%s Domain = %q, want empty (host-scoped)", c.Name, c.Domain)
		}
	}
	if at.MaxAge != 900 {
		t.Errorf("access MaxAge = %d, want 900 (TokenPair.ExpiresIn)", at.MaxAge)
	}
	if rt.MaxAge != int((7 * 24 * time.Hour).Seconds()) {
		t.Errorf("refresh MaxAge = %d, want %d", rt.MaxAge, int((7 * 24 * time.Hour).Seconds()))
	}
}

func TestSetSessionCookies_DomainPrecedence(t *testing.T) {
	h := devModeHandler(t)
	tp := &clientauth.TokenPair{AccessToken: "a", RefreshToken: "r", ExpiresIn: 900, ExpiresAt: time.Now().Add(15 * time.Minute)}

	cases := []struct {
		name       string
		ws         *core.Workspace
		app        *core.App
		wantDomain string
	}{
		// Go's net/http (per RFC 6265) strips the leading dot from
		// Domain when parsing Set-Cookie back via Result().Cookies(),
		// even though the raw header still contains it. We assert on
		// the parsed value, so the wantDomain is dot-less.
		{"empty resolves to host-only", &core.Workspace{}, testApp(), ""},
		{"ws domain used when app absent", &core.Workspace{CookieDomain: strp(".acme.com")}, testApp(), "acme.com"},
		{"app override wins", &core.Workspace{CookieDomain: strp(".acme.com")}, testApp(func(a *core.App) { a.CookieDomain = strp(".widgets.io") }), "widgets.io"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/auth/verify", nil)
			h.setSessionCookies(w, r, c.ws, c.app, tp, time.Hour)

			for _, name := range []string{clientauth.AccessCookieName(testAppID), clientauth.RefreshCookieName(testAppID)} {
				got := cookieByName(w.Result().Cookies(), name)
				if got == nil {
					t.Fatalf("cookie %q not set", name)
				}
				if got.Domain != c.wantDomain {
					t.Errorf("%s Domain = %q, want %q", name, got.Domain, c.wantDomain)
				}
			}
		})
	}
}

func TestSetSessionCookies_RefreshTTLTracksRememberMe(t *testing.T) {
	// Regression for the rememberMe bug: refresh-cookie MaxAge must
	// match the TTL the caller used at IssueTokenPair time, not the
	// app's base session TTL.
	h := devModeHandler(t)
	tp := &clientauth.TokenPair{AccessToken: "a", RefreshToken: "r", ExpiresIn: 900, ExpiresAt: time.Now().Add(15 * time.Minute)}

	cases := []struct {
		name       string
		refreshTTL time.Duration
		wantMaxAge int
	}{
		{"short app TTL (no rememberMe)", time.Hour, 3600},
		{"30-day rememberMe extension", clientauth.RememberMeTTL, int(clientauth.RememberMeTTL.Seconds())},
		{"zero TTL falls back to 7d default", 0, 7 * 24 * 60 * 60},
		{"negative TTL falls back to 7d default", -time.Hour, 7 * 24 * 60 * 60},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/auth/verify", nil)
			h.setSessionCookies(w, r, &core.Workspace{}, testApp(), tp, c.refreshTTL)
			rt := cookieByName(w.Result().Cookies(), clientauth.RefreshCookieName(testAppID))
			if rt == nil {
				t.Fatal("refresh cookie missing")
			}
			if rt.MaxAge != c.wantMaxAge {
				t.Errorf("refresh MaxAge = %d, want %d", rt.MaxAge, c.wantMaxAge)
			}
		})
	}
}

func TestSetSessionCookies_SecureRespectsProfile(t *testing.T) {
	// Non-dev profile must emit cookies with Secure=true.
	t.Setenv("SESSIONCOOKIES_PROD_TEST_PROFILE", "prod")
	h := &RequestHandler{config: config.NewConfig("SESSIONCOOKIES_PROD_TEST_")}
	if h.config.IsDevMode() {
		t.Fatal("test setup wrong: expected non-dev profile")
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/verify", nil)
	tp := &clientauth.TokenPair{AccessToken: "a", RefreshToken: "r", ExpiresIn: 900, ExpiresAt: time.Now().Add(15 * time.Minute)}
	h.setSessionCookies(w, r, &core.Workspace{}, testApp(), tp, time.Hour)
	for _, name := range []string{clientauth.AccessCookieName(testAppID), clientauth.RefreshCookieName(testAppID)} {
		c := cookieByName(w.Result().Cookies(), name)
		if c == nil {
			t.Fatalf("%s missing", name)
		}
		if !c.Secure {
			t.Errorf("%s should have Secure=true outside dev", name)
		}
	}
}

func TestSetSessionCookies_NilTokenPairIsNoop(t *testing.T) {
	h := devModeHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/verify", nil)
	h.setSessionCookies(w, r, &core.Workspace{}, testApp(), nil, time.Hour)
	if cs := w.Result().Cookies(); len(cs) != 0 {
		t.Errorf("expected no cookies on nil TokenPair, got %d", len(cs))
	}
}

func TestClearSessionCookies(t *testing.T) {
	h := devModeHandler(t)
	w := httptest.NewRecorder()
	ws := &core.Workspace{CookieDomain: strp(".acme.com")}
	app := testApp()

	h.clearSessionCookies(w, ws, app)
	cs := w.Result().Cookies()
	at := cookieByName(cs, clientauth.AccessCookieName(testAppID))
	rt := cookieByName(cs, clientauth.RefreshCookieName(testAppID))
	if at == nil || rt == nil {
		t.Fatalf("expected both cookies emitted; at=%v rt=%v", at, rt)
	}
	for _, c := range []*http.Cookie{at, rt} {
		if c.Value != "" {
			t.Errorf("%s should have empty value, got %q", c.Name, c.Value)
		}
		if c.MaxAge != -1 {
			t.Errorf("%s MaxAge = %d, want -1 (delete)", c.Name, c.MaxAge)
		}
		// Go's http.Result().Cookies() strips the leading dot per RFC 6265
		// when parsing Set-Cookie. The raw header still carries ".acme.com",
		// which is what browsers receive for the deletion-match to work.
		if c.Domain != "acme.com" {
			t.Errorf("%s Domain = %q, want %q", c.Name, c.Domain, "acme.com")
		}
	}
}
