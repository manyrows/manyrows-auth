package auth

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
)

// MANYROWS_TRUSTED_PROXIES configures which peer addresses ClientIP
// will believe X-Forwarded-For / X-Real-IP / CF-Connecting-IP from.
// Without this constraint, an attacker hitting the listener directly
// could send any header values they like and trivially defeat the
// per-IP rate limit + audit IP attribution.
//
// Value forms (comma-separated):
//
//	private   — convenience: RFC1918 IPv4 + loopback + IPv6 ULA + ::1.
//	            This is the default if the env var is unset, since the
//	            common self-hosted shape is "platform router on a
//	            private network in front of the app." Operators on
//	            Cloudflare or any public-edge proxy MUST set the
//	            relevant CIDRs explicitly — CF's edge IPs are public
//	            and won't match this default.
//	none      — trust no peer; ClientIP returns RemoteAddr regardless
//	            of headers. Use when terminating TLS directly on a
//	            public IP with no upstream proxy.
//	*         — trust every peer; preserves the legacy behaviour for
//	            operators who can't enumerate proxy IPs but accept the
//	            spoofing risk. Discouraged.
//	<CIDR>    — explicit allow. IPv4 or IPv6, e.g.
//	            "10.0.0.0/8, 173.245.48.0/20, 2400:cb00::/32".
//	<IP>      — a single host; equivalent to /32 (or /128 for IPv6).
//
// Multiple forms can be mixed: "private, 173.245.48.0/20".

// TrustedProxies is an immutable parsed allow-list of peer addresses
// that ClientIP will believe forwarding headers from. Construct with
// ParseTrustedProxies and install with SetTrustedProxies.
type TrustedProxies struct {
	// trustAll wins over prefixes when "*" is present in the env value.
	trustAll bool
	// prefixes are the parsed CIDR / single-host entries.
	prefixes []netip.Prefix
}

// IsTrusted reports whether the peer at remoteAddr (a string in
// "ip:port" or bare-IP form, as found on http.Request.RemoteAddr) is
// in the allow-list. Unparseable addresses return false so callers
// fall through to the "ignore headers" path.
func (t *TrustedProxies) IsTrusted(remoteAddr string) bool {
	if t == nil {
		return false
	}
	if t.trustAll {
		return true
	}
	candidate := sanitizeIPCandidate(remoteAddr)
	if candidate == "" {
		return false
	}
	addr, err := netip.ParseAddr(candidate)
	if err != nil {
		return false
	}
	for _, p := range t.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ParseTrustedProxies turns the comma-separated env value into a
// TrustedProxies. Empty / "private" input yields the same default
// (RFC1918 + loopback + ULA). Errors only on unparseable entries —
// callers that want a strict boot can bubble the error; the
// SetTrustedProxiesFromEnv wrapper falls back to the safe default
// and logs.
func ParseTrustedProxies(env string) (*TrustedProxies, error) {
	out := &TrustedProxies{}
	env = strings.TrimSpace(env)
	if env == "" {
		// Default = private. Self-hosters behind a private-network
		// proxy work out of the box; public-edge deploys must
		// configure their proxy CIDRs.
		env = "private"
	}
	for _, raw := range strings.Split(env, ",") {
		tok := strings.TrimSpace(raw)
		if tok == "" {
			continue
		}
		switch strings.ToLower(tok) {
		case "*", "all":
			out.trustAll = true
			continue
		case "none":
			// Explicit "trust nothing." Don't add any prefixes; if
			// other tokens are present, those still apply.
			continue
		case "private":
			for _, p := range privateNetworkPrefixes() {
				out.prefixes = append(out.prefixes, p)
			}
			continue
		}
		// Try CIDR first, then bare-IP.
		if p, err := netip.ParsePrefix(tok); err == nil {
			out.prefixes = append(out.prefixes, p)
			continue
		}
		if a, err := netip.ParseAddr(tok); err == nil {
			bits := 32
			if a.Is6() {
				bits = 128
			}
			p, err := a.Prefix(bits)
			if err != nil {
				return nil, fmt.Errorf("trusted proxies: bad host %q: %w", tok, err)
			}
			out.prefixes = append(out.prefixes, p)
			continue
		}
		return nil, fmt.Errorf("trusted proxies: %q is not a CIDR or IP address", tok)
	}
	return out, nil
}

// privateNetworkPrefixes returns the RFC1918 + loopback + ULA set used
// by the "private" token. Excluded: link-local (RFC3927 / fe80::/10) —
// those don't appear as kernel-set RemoteAddr in any deploy we care
// about, and including them would expand the trust surface needlessly.
func privateNetworkPrefixes() []netip.Prefix {
	parse := func(cidr string) netip.Prefix {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			// Static input; if a typo slips through tests catch it.
			panic("trusted_proxies: bad static cidr: " + cidr)
		}
		return p
	}
	return []netip.Prefix{
		parse("10.0.0.0/8"),     // RFC1918
		parse("172.16.0.0/12"),  // RFC1918
		parse("192.168.0.0/16"), // RFC1918
		parse("127.0.0.0/8"),    // loopback
		parse("::1/128"),        // IPv6 loopback
		parse("fc00::/7"),       // IPv6 ULA (RFC4193)
	}
}

// activeTrustedProxies holds the install-wide allow-list. Atomic so
// SetTrustedProxies + reads from ClientIP don't need a mutex on the
// hot path.
var activeTrustedProxies atomic.Pointer[TrustedProxies]

// SetTrustedProxies installs the parsed allow-list as the process-wide
// default consulted by ClientIP. Safe to call concurrently with
// requests; the swap is atomic.
func SetTrustedProxies(t *TrustedProxies) {
	activeTrustedProxies.Store(t)
}

// SetTrustedProxiesFromEnv parses the env value and installs the
// result. On parse error, returns the error and leaves any previously
// installed allow-list intact. App startup calls this with the
// MANYROWS_TRUSTED_PROXIES value before the listener starts taking
// requests; tests can re-call to swap configurations between cases.
func SetTrustedProxiesFromEnv(env string) error {
	t, err := ParseTrustedProxies(env)
	if err != nil {
		return err
	}
	SetTrustedProxies(t)
	return nil
}

// PeerIsTrustedProxy reports whether the request's immediate peer
// (r.RemoteAddr) is in the configured trusted-proxy allow-list. Use it to
// gate trust of proxy-set request headers — X-Forwarded-Host, X-Original-Host,
// X-Forwarded-Proto — the same way ClientIP gates X-Forwarded-For: an
// untrusted direct peer can set these to anything, so they must be ignored
// unless the peer is a known proxy.
func PeerIsTrustedProxy(r *http.Request) bool {
	if r == nil {
		return false
	}
	return loadTrustedProxies().IsTrusted(r.RemoteAddr)
}

// loadTrustedProxies returns the active allow-list, or a default
// "private" set when nothing has been installed yet. The default
// lets tests that don't init the package still see sensible
// behaviour without panicking.
func loadTrustedProxies() *TrustedProxies {
	if v := activeTrustedProxies.Load(); v != nil {
		return v
	}
	def, _ := ParseTrustedProxies("private")
	return def
}
