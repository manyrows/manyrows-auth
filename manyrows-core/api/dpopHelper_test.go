package api

import (
	"net/http/httptest"
	"testing"

	"manyrows-core/auth"
	"manyrows-core/config"
)

// TestRequestURIForDPoP_TrustedProxyGating pins the security property: the
// X-Original-Host / X-Forwarded-Proto headers feed the DPoP htu only from a
// trusted-proxy peer. From an untrusted (direct) peer they're ignored — so when
// BASE_URL is unset an attacker can't dictate the htu the server compares the
// proof against, which would otherwise neutralize DPoP's URL binding.
func TestRequestURIForDPoP_TrustedProxyGating(t *testing.T) {
	// A unique env prefix guarantees GetBaseURL() == "" regardless of any
	// MANYROWS_BASE_URL the wider test process set, exercising the no-BASE_URL
	// (fresh-install) path where the gate matters most.
	h := &RequestHandler{config: config.NewConfig("DPOPHELPERTEST_")}

	if err := auth.SetTrustedProxiesFromEnv("private"); err != nil {
		t.Fatalf("set trusted proxies: %v", err)
	}
	t.Cleanup(func() { _ = auth.SetTrustedProxiesFromEnv("*") })

	t.Run("untrusted peer: X-Original-Host ignored", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/auth/refresh", nil)
		r.Host = "real-install.example.com"
		r.RemoteAddr = "203.0.113.5:5000" // public => untrusted
		r.Header.Set("X-Original-Host", "attacker.example.com")
		r.Header.Set("X-Forwarded-Proto", "https")
		if got := h.requestURIForDPoP(r); got != "http://real-install.example.com/auth/refresh" {
			t.Errorf("untrusted peer must ignore forwarded host/proto; got %q", got)
		}
	})

	t.Run("trusted peer: X-Original-Host honored", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/auth/refresh", nil)
		r.Host = "internal:8080"
		r.RemoteAddr = "10.0.0.7:5000" // RFC1918 => trusted under "private"
		r.Header.Set("X-Original-Host", "auth.acme.com")
		if got := h.requestURIForDPoP(r); got != "https://auth.acme.com/auth/refresh" {
			t.Errorf("trusted peer should honor X-Original-Host; got %q", got)
		}
	})
}
