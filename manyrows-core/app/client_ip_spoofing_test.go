package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/auth"
)

// TestBaseRouter_ClientIPNotSpoofableViaHeaders is the regression guard for
// the client-IP spoofing fix. chi's middleware.RealIP must NOT be installed
// in the base-router chain: it overwrites r.RemoteAddr from client-supplied
// headers (True-Client-IP / X-Real-IP / X-Forwarded-For) before any
// trusted-proxy check runs, which would let a direct caller forge the IP
// that auth.ClientIP returns — defeating the per-app IP allowlist, per-IP
// rate limiting, and audit-log IP attribution.
//
// Both cases drive a request through the real createBaseRouter middleware
// stack and read the IP exactly as the security controls do (auth.ClientIP),
// so this asserts the behaviour of the whole chain, not auth.ClientIP alone.
func TestBaseRouter_ClientIPNotSpoofableViaHeaders(t *testing.T) {
	// Pin the default trusted set so the test is independent of any ambient
	// MANYROWS_TRUSTED_PROXIES value or prior test state.
	if err := auth.SetTrustedProxiesFromEnv("private"); err != nil {
		t.Fatalf("SetTrustedProxiesFromEnv: %v", err)
	}

	r := createBaseRouter(func() string { return "" }, false)
	r.Get("/__clientip", func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write([]byte(auth.ClientIP(req)))
	})

	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			// The vulnerability: a direct, untrusted caller sets forwarding
			// headers. The real kernel peer must win; the headers are ignored.
			// (With middleware.RealIP present this returned "198.51.100.99".)
			name:       "untrusted direct peer cannot spoof via X-Real-IP/XFF",
			remoteAddr: "203.0.113.7:9999", // public peer, not in the private trust set
			headers: map[string]string{
				"X-Real-IP":       "198.51.100.99",
				"X-Forwarded-For": "198.51.100.99",
			},
			want: "203.0.113.7",
		},
		{
			// No functional regression: a genuine proxy on a private network
			// is trusted, so its appended X-Forwarded-For still resolves the
			// real client IP.
			name:       "trusted private proxy still resolves the real client",
			remoteAddr: "10.0.0.1:443", // platform router on a private network
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.42", // real client appended by the proxy
			},
			want: "198.51.100.42",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/__clientip", nil)
			req.RemoteAddr = tc.remoteAddr
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			if got := rec.Body.String(); got != tc.want {
				t.Errorf("auth.ClientIP through base router = %q, want %q (client-supplied headers must not override the real peer)", got, tc.want)
			}
		})
	}
}
