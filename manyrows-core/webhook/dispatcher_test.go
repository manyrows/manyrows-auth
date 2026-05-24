package webhook

import (
	"net"
	"net/http"
	"testing"
)

// TestIsBlockedDialIP pins the SSRF connect-time guard: the dialer must refuse
// every non-public address (loopback, RFC1918, link-local incl. the cloud
// metadata endpoint, ULA, unspecified, and IPv4-mapped forms of the above)
// while still allowing genuinely public addresses.
func TestIsBlockedDialIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", // loopback
		"10.0.0.1", "172.16.0.1", "192.168.1.1", // RFC1918
		"169.254.169.254", // link-local — cloud metadata
		"fe80::1",         // link-local v6
		"fc00::1",         // unique-local v6
		"0.0.0.0", "::",   // unspecified
		"::ffff:10.0.0.1", // IPv4-mapped private
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test fixture IP %q", s)
		}
		if !isBlockedDialIP(ip) {
			t.Errorf("isBlockedDialIP(%s) = false, want true — webhooks must not reach this", s)
		}
	}

	allowed := []string{
		"8.8.8.8", "1.1.1.1", // public v4
		"2606:4700:4700::1111", // public v6
	}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test fixture IP %q", s)
		}
		if isBlockedDialIP(ip) {
			t.Errorf("isBlockedDialIP(%s) = true, want false — public address", s)
		}
	}
}

// TestNewWebhookClientRefusesRedirects ensures the delivery client never
// follows a redirect (a validated public URL could otherwise 302 onto an
// internal target). The policy applies regardless of dev/prod mode.
func TestNewWebhookClientRefusesRedirects(t *testing.T) {
	for _, devMode := range []bool{true, false} {
		c := newWebhookClient(devMode)
		if c.CheckRedirect == nil {
			t.Fatalf("devMode=%v: CheckRedirect not set", devMode)
		}
		if err := c.CheckRedirect(&http.Request{}, nil); err != http.ErrUseLastResponse {
			t.Errorf("devMode=%v: CheckRedirect = %v, want http.ErrUseLastResponse", devMode, err)
		}
	}
}
