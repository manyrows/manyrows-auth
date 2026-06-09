package api

import (
	"net/http"
	"strings"

	"manyrows-core/auth"
)

// requestBaseURL derives "scheme://host" from an inbound request.
// Used by the first-admin handler to capture the BASE_URL from
// whichever URL the operator was using when they registered, so
// downstream email links / OAuth callbacks point at the right host
// without the operator having to set MANYROWS_BASE_URL by hand.
//
// Trust model: the forwarding headers (X-Forwarded-Host / X-Forwarded-Proto)
// are believed ONLY when the immediate peer is a configured trusted proxy
// (MANYROWS_TRUSTED_PROXIES), mirroring auth.ClientIP. Otherwise an attacker
// who can reach the listener directly — e.g. before the operator registers on
// a fresh install — could pin BASE_URL (and thus every email link, OAuth
// callback, and OIDC issuer URL) to their host with a spoofed header. From an
// untrusted peer we fall back to the kernel-visible Host; operators on a
// public edge should still set MANYROWS_BASE_URL explicitly.
func requestBaseURL(r *http.Request) string {
	host := strings.TrimSpace(r.Host)
	scheme := ""
	if auth.PeerIsTrustedProxy(r) {
		if h := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); h != "" {
			host = h
		}
		scheme = strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	}
	if host == "" {
		return ""
	}
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	return scheme + "://" + host
}
