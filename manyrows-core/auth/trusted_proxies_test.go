package auth_test

import (
	"testing"

	"manyrows-core/auth"
)

func TestParseTrustedProxies_DefaultIsPrivate(t *testing.T) {
	// Empty string means "default", which is "private" — RFC1918 +
	// loopback + ULA. Public addresses should NOT match.
	tp, err := auth.ParseTrustedProxies("")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	for _, addr := range []string{
		"10.0.0.5:1234",   // RFC1918
		"172.16.0.1:80",   // RFC1918
		"192.168.1.1:443", // RFC1918
		"127.0.0.1:8080",  // loopback v4
		"[::1]:443",       // loopback v6
		"[fd00::1]:443",   // ULA v6
	} {
		if !tp.IsTrusted(addr) {
			t.Errorf("expected %q to be trusted under default, was not", addr)
		}
	}
	for _, addr := range []string{
		"198.51.100.10:1234", // public v4
		"203.0.113.7:80",     // public v4
		"[2001:db8::1]:443",  // public v6
	} {
		if tp.IsTrusted(addr) {
			t.Errorf("expected %q to be untrusted under default, was trusted", addr)
		}
	}
}

func TestParseTrustedProxies_None(t *testing.T) {
	tp, err := auth.ParseTrustedProxies("none")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	for _, addr := range []string{
		"10.0.0.5:1234",
		"127.0.0.1:8080",
		"198.51.100.10:1234",
	} {
		if tp.IsTrusted(addr) {
			t.Errorf("none should trust nothing; %q was trusted", addr)
		}
	}
}

func TestParseTrustedProxies_Wildcard(t *testing.T) {
	tp, err := auth.ParseTrustedProxies("*")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	for _, addr := range []string{
		"10.0.0.5:1234",
		"198.51.100.10:1234",
		"[2001:db8::1]:443",
	} {
		if !tp.IsTrusted(addr) {
			t.Errorf("wildcard should trust everyone; %q was untrusted", addr)
		}
	}
}

func TestParseTrustedProxies_ExplicitCIDR(t *testing.T) {
	tp, err := auth.ParseTrustedProxies("173.245.48.0/20, 2400:cb00::/32")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	if !tp.IsTrusted("173.245.48.5:1234") {
		t.Error("173.245.48.5 should be trusted")
	}
	if !tp.IsTrusted("[2400:cb00::1]:443") {
		t.Error("2400:cb00::1 should be trusted")
	}
	if tp.IsTrusted("198.51.100.10:1234") {
		t.Error("198.51.100.10 should NOT be trusted")
	}
	// Private not included when caller specifies explicit CIDRs only.
	if tp.IsTrusted("10.0.0.5:1234") {
		t.Error("10.0.0.5 should NOT be trusted under explicit-CIDR config")
	}
}

func TestParseTrustedProxies_MixedTokens(t *testing.T) {
	tp, err := auth.ParseTrustedProxies("private, 173.245.48.0/20")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	if !tp.IsTrusted("10.0.0.5:1234") {
		t.Error("RFC1918 should be trusted under 'private + extra'")
	}
	if !tp.IsTrusted("173.245.48.5:1234") {
		t.Error("explicit CIDR should be trusted alongside 'private'")
	}
	if tp.IsTrusted("198.51.100.10:1234") {
		t.Error("non-listed public IP should NOT be trusted")
	}
}

func TestParseTrustedProxies_BareIP(t *testing.T) {
	tp, err := auth.ParseTrustedProxies("203.0.113.7, 2001:db8::1")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	if !tp.IsTrusted("203.0.113.7:1234") {
		t.Error("bare IP should be trusted")
	}
	if tp.IsTrusted("203.0.113.8:1234") {
		t.Error("adjacent IP should NOT be trusted (bare-IP is host-only)")
	}
	if !tp.IsTrusted("[2001:db8::1]:443") {
		t.Error("bare IPv6 should be trusted")
	}
}

func TestParseTrustedProxies_RejectsGarbage(t *testing.T) {
	for _, bad := range []string{
		"not-a-cidr",
		"999.999.999.999",
		"10.0.0.0/99",
	} {
		if _, err := auth.ParseTrustedProxies(bad); err == nil {
			t.Errorf("expected ParseTrustedProxies(%q) to error", bad)
		}
	}
}
