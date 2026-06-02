package api

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"manyrows-core/auth/dpop"

	"github.com/rs/zerolog/log"
)

// extractDPoPJKT inspects the inbound request for a `DPoP` header. If absent,
// returns ("", nil) — meaning the caller did not opt into DPoP and the call
// site should proceed with Bearer-only behavior.
//
// If a header is present, the proof is verified (signature, htm, htu, iat,
// jti) and the JWK SHA-256 thumbprint is returned. A malformed or invalid
// proof writes an HTTP 400 response and returns an error so the caller can
// abort.
//
// This helper does NOT compare the jkt against any expected value — that's
// the auth service's job (it has the bound jkt on the refresh-token row).
// Use this for both first-issuance flows (login/register) and refresh.
func (handler *RequestHandler) extractDPoPJKT(w http.ResponseWriter, r *http.Request) (string, error) {
	header := strings.TrimSpace(r.Header.Get("DPoP"))
	if header == "" {
		return "", nil
	}
	if handler.dpopVerifier == nil {
		// Defensive: should never happen in production but keep DPoP optional.
		return "", nil
	}

	proof, err := handler.dpopVerifier.Verify(r.Context(), header, r.Method, handler.requestURIForDPoP(r))
	if err != nil {
		// Don't leak which specific check failed; clients only need to know
		// their proof was rejected.
		switch {
		case errors.Is(err, dpop.ErrReplayed):
			log.Warn().Str("path", r.URL.Path).Msg("DPoP proof replay rejected")
		case errors.Is(err, dpop.ErrIATOutOfWindow):
			// Likely client clock skew; not necessarily an attack.
		default:
			log.Debug().Err(err).Str("path", r.URL.Path).Msg("DPoP proof rejected")
		}
		WriteError(w, r, "error.invalidDPoPProof", http.StatusBadRequest)
		return "", err
	}
	return proof.JKT, nil
}

// requestURIForDPoP reconstructs the htu value the client should have signed,
// per RFC 9449 §4.3: scheme://host/path with no query or fragment.
//
// Resolution order:
//
//  1. X-Original-Host — set by our Cloudflare-for-SaaS host-rewrite Worker
//     when an install serves multiple customer hostnames (e.g.
//     auth.<customer>.com → app.<install>.com). The Worker rewrites Host
//     before forwarding to origin and stashes the original here so DPoP /
//     redirect URLs / cookie scoping can still see what the user-agent
//     actually called.
//
//  2. BASE_URL — the configured install URL. Pins the htu to a known
//     hostname rather than trusting inbound Host / X-Forwarded-Proto.
//
//  3. Inbound Host header (fallback for local dev / single-host deploys
//     without BASE_URL pinned).
//
// DPoP's URL binding only protects against an attacker REPLAYING a captured
// proof at a different URL. Forging a proof for an arbitrary host requires
// the private key — which an X-Original-Host spoofer doesn't have — so
// preferring that header doesn't weaken the binding; it just lets the
// reconstruction match whatever URL the user-agent legitimately called
// when the install is fronted by a host-rewriting proxy.
func (handler *RequestHandler) requestURIForDPoP(r *http.Request) string {
	if oh := strings.TrimSpace(r.Header.Get("X-Original-Host")); oh != "" {
		return "https://" + oh + r.URL.Path
	}

	if base := strings.TrimRight(handler.config.GetBaseURL(), "/"); base != "" {
		if u, err := url.Parse(base); err == nil && u.Scheme != "" && u.Host != "" {
			return u.Scheme + "://" + u.Host + r.URL.Path
		}
		// Misconfigured BASE_URL — log loudly and fall through to the
		// header-based path so we don't hard-fail every DPoP request.
		log.Warn().Str("baseURL", base).Msg("could not parse BASE_URL for DPoP htu — falling back to request headers")
	}

	scheme := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := r.Host
	return scheme + "://" + host + r.URL.Path
}
