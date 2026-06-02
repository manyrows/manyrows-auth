package api

import (
	"net/http"
	"strings"
)

// requestBaseURL derives "scheme://host" from an inbound request.
// Used by the first-admin handler to capture the BASE_URL from
// whichever URL the operator was using when they registered, so
// downstream email links / OAuth callbacks point at the right host
// without the operator having to set MANYROWS_BASE_URL by hand.
//
// Trust model: only call this from privileged paths (e.g. AdminRegister
// at first-boot) where the requester is the operator. Calling it on
// public paths would let an attacker pin BASE_URL to their host via a
// spoofed Host / X-Forwarded-Host header.
func requestBaseURL(r *http.Request) string {
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		return ""
	}
	scheme := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	return scheme + "://" + host
}
