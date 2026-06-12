package utils

import (
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
)

// anonymizeIPInLogs is set once at boot from config; default ON
// (privacy-by-default). Use atomic so the boot-time set is race-free
// against request handlers.
var anonymizeIPInLogs atomic.Bool

func init() { anonymizeIPInLogs.Store(true) }

// SetAnonymizeIPInLogs configures whether LogIP truncates. Call once at boot.
func SetAnonymizeIPInLogs(on bool) { anonymizeIPInLogs.Store(on) }

// MaskEmail returns a partially-masked email safe to log:
// alice@example.com -> a***e@example.com ; single-char local -> a***@domain ;
// anything not email-shaped -> "***".
func MaskEmail(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	parts := strings.SplitN(s, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "***"
	}
	local, domain := parts[0], parts[1]
	if len(local) == 1 {
		return local + "***@" + domain
	}
	return string(local[0]) + "***" + string(local[len(local)-1]) + "@" + domain
}

// AnonymizeIP truncates an IP to its network prefix (IPv4 -> /24, IPv6 -> /48).
// Unparseable input -> "" (never echo a malformed value).
func AnonymizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	bits := 24
	if addr.Is6() && !addr.Is4In6() {
		bits = 48
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.Masked().Addr().String()
}

// LogIP returns the IP truncated iff anonymization is enabled, else as-is.
func LogIP(ip string) string {
	if anonymizeIPInLogs.Load() {
		return AnonymizeIP(ip)
	}
	return ip
}

// QueryString masks email values inside a raw URL query so access logs don't
// record full addresses from lookup params. Values of params named "email"
// (case-insensitive) or any value containing "@" are masked. On parse failure
// it returns "[redacted]" rather than echoing the raw query.
func QueryString(raw string) string {
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return "[redacted]"
	}
	for k, vs := range vals {
		for i, v := range vs {
			if strings.Contains(strings.ToLower(k), "email") || strings.Contains(v, "@") {
				vs[i] = MaskEmail(v)
			}
		}
		vals[k] = vs
	}
	return vals.Encode()
}
