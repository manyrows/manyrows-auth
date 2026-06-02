package auth_test

import (
	"manyrows-core/auth"
	"net/http/httptest"
	"testing"
)

func TestClientIP_UsesRightmostForwardedIP(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.10, 203.0.113.7")

	if got := auth.ClientIP(req); got != "203.0.113.7" {
		t.Fatalf("expected rightmost forwarded IP, got %q", got)
	}
}

func TestClientIP_FallsBackToXRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Real-IP", "198.51.100.42")

	if got := auth.ClientIP(req); got != "198.51.100.42" {
		t.Fatalf("expected X-Real-IP fallback, got %q", got)
	}
}

func TestClientIP_NormalizesRemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "[2001:db8::1]:443"

	if got := auth.ClientIP(req); got != "2001:db8::1" {
		t.Fatalf("expected normalized IPv6 remote addr, got %q", got)
	}
}

func TestClientIP_StripsZoneSuffix(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "[fe80::1%en0]:443"

	if got := auth.ClientIP(req); got != "fe80::1" {
		t.Fatalf("expected zone-free IPv6 remote addr, got %q", got)
	}
}

// Untrusted peers cannot spoof the client IP via headers. RemoteAddr
// on a public IP (which isn't in the default "private" allow-list)
// means an attacker hitting the listener directly can't pretend to be
// anyone else by setting X-Forwarded-For / X-Real-IP / CF-Connecting-IP.
func TestClientIP_IgnoresHeadersFromUntrustedPeer(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "198.51.100.50:1234" // public, NOT in default "private"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	req.Header.Set("X-Real-IP", "9.10.11.12")
	req.Header.Set("CF-Connecting-IP", "13.14.15.16")

	if got := auth.ClientIP(req); got != "198.51.100.50" {
		t.Fatalf("expected RemoteAddr when peer is untrusted, got %q", got)
	}
}

// When operator enumerates the public-edge proxy CIDRs, headers from
// that peer are believed — restores production behaviour behind
// Cloudflare / ALB / nginx-with-known-IPs.
func TestClientIP_HonoursHeadersFromExplicitlyTrustedPeer(t *testing.T) {
	if err := auth.SetTrustedProxiesFromEnv("198.51.100.0/24"); err != nil {
		t.Fatalf("SetTrustedProxiesFromEnv: %v", err)
	}
	t.Cleanup(func() { _ = auth.SetTrustedProxiesFromEnv("") }) // reset to default

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "198.51.100.50:1234" // now in the trusted set
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.99")

	if got := auth.ClientIP(req); got != "203.0.113.99" {
		t.Fatalf("expected rightmost XFF when peer is trusted, got %q", got)
	}
}
