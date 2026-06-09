package api

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"manyrows-core/auth"
)

func TestRequestBaseURL(t *testing.T) {
	cases := []struct {
		name    string
		host    string
		xfHost  string
		xfProto string
		tls     bool
		want    string
	}{
		{name: "plain http", host: "example.com", want: "http://example.com"},
		{name: "tls direct", host: "example.com", tls: true, want: "https://example.com"},
		{name: "x-forwarded-proto wins over tls field", host: "example.com", xfProto: "https", want: "https://example.com"},
		{name: "x-forwarded-host wins over Host", host: "internal:8080", xfHost: "auth.acme.com", xfProto: "https", want: "https://auth.acme.com"},
		{name: "host with port", host: "example.com:8443", xfProto: "https", want: "https://example.com:8443"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/admin/register", nil)
			r.Host = c.host
			if c.xfHost != "" {
				r.Header.Set("X-Forwarded-Host", c.xfHost)
			}
			if c.xfProto != "" {
				r.Header.Set("X-Forwarded-Proto", c.xfProto)
			}
			if c.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if got := requestBaseURL(r); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestRequestBaseURL_EmptyHost(t *testing.T) {
	r := httptest.NewRequest("POST", "/admin/register", nil)
	r.Host = ""
	if got := requestBaseURL(r); got != "" {
		t.Errorf("expected empty when no host, got %q", got)
	}
}

// TestRequestBaseURL_TrustedProxyGating pins the security property: the
// X-Forwarded-Host / X-Forwarded-Proto headers are honored only from a peer in
// the trusted-proxy allow-list. From an untrusted (direct) peer they're ignored
// so an attacker can't pin BASE_URL to their host on a fresh install.
func TestRequestBaseURL_TrustedProxyGating(t *testing.T) {
	// The test binary's TestMain installs "*" (trust all); scope a stricter
	// "private" allow-list to this test and restore the default afterwards.
	if err := auth.SetTrustedProxiesFromEnv("private"); err != nil {
		t.Fatalf("set trusted proxies: %v", err)
	}
	t.Cleanup(func() { _ = auth.SetTrustedProxiesFromEnv("*") })

	t.Run("untrusted peer: forwarded host ignored, falls back to Host", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/admin/register", nil)
		r.Host = "real-install.example.com"
		r.RemoteAddr = "203.0.113.5:5000" // public => untrusted
		r.Header.Set("X-Forwarded-Host", "attacker.example.com")
		r.Header.Set("X-Forwarded-Proto", "https")
		if got := requestBaseURL(r); got != "http://real-install.example.com" {
			t.Errorf("untrusted peer must ignore forwarded headers; got %q", got)
		}
	})

	t.Run("trusted peer: forwarded host honored", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/admin/register", nil)
		r.Host = "internal:8080"
		r.RemoteAddr = "10.0.0.7:5000" // RFC1918 => trusted under "private"
		r.Header.Set("X-Forwarded-Host", "auth.acme.com")
		r.Header.Set("X-Forwarded-Proto", "https")
		if got := requestBaseURL(r); got != "https://auth.acme.com" {
			t.Errorf("trusted peer should honor forwarded headers; got %q", got)
		}
	})
}
