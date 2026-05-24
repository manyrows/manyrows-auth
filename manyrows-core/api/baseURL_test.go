package api

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
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
