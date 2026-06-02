package api

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"manyrows-core/auth"
)

func auditRequestIP(r *http.Request) (string, *netip.Addr) {
	ip := strings.TrimSpace(auth.ClientIP(r))
	if ip == "" {
		return "", nil
	}

	if addr, err := netip.ParseAddr(ip); err == nil {
		return addr.String(), &addr
	}
	if parsed := net.ParseIP(ip); parsed != nil {
		if addr, ok := netip.AddrFromSlice(parsed); ok {
			canonical := addr.String()
			return canonical, &addr
		}
	}
	return ip, nil
}
