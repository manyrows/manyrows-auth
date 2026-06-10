package api

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"manyrows-core/auth"
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

// oidcExtractDPoPJKT is the OIDC-token-endpoint counterpart of extractDPoPJKT.
// It verifies a DPoP proof (if the RP presented one) and returns its JWK
// thumbprint, or ("", nil) when there is no proof — the Bearer flow. Unlike
// extractDPoPJKT it does NOT write a response: the OIDC token endpoint formats
// its own OAuth-shaped errors (oidcTokenError), so callers inspect the returned
// error and respond with invalid_dpop_proof.
func (handler *RequestHandler) oidcExtractDPoPJKT(r *http.Request) (string, error) {
	header := strings.TrimSpace(r.Header.Get("DPoP"))
	if header == "" || handler.dpopVerifier == nil {
		return "", nil
	}
	proof, err := handler.dpopVerifier.Verify(r.Context(), header, r.Method, handler.requestURIForDPoP(r))
	if err != nil {
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
//     actually called. Honored ONLY from a trusted-proxy peer
//     (MANYROWS_TRUSTED_PROXIES — the rewrite Worker's egress IPs).
//
//  2. BASE_URL — the configured install URL. Pins the htu to a known
//     hostname rather than trusting inbound Host / X-Forwarded-Proto.
//
//  3. Inbound Host header (fallback for local dev / single-host deploys
//     without BASE_URL pinned).
//
// Why the trusted-proxy gate matters: when BASE_URL is unset (e.g. a fresh
// install before first-boot pinning), an attacker hitting the listener
// directly could set X-Original-Host to anything, and the server would then
// reconstruct htu to match — neutralizing DPoP's URL binding, since the
// comparison target becomes attacker-controlled rather than fixed. Gating the
// header on a trusted peer (where the value comes from our own Worker, not the
// client) closes that. X-Forwarded-Proto is gated the same way.
func (handler *RequestHandler) requestURIForDPoP(r *http.Request) string {
	peerTrusted := auth.PeerIsTrustedProxy(r)

	if peerTrusted {
		if oh := strings.TrimSpace(r.Header.Get("X-Original-Host")); oh != "" {
			return "https://" + oh + r.URL.Path
		}
	}

	if base := strings.TrimRight(handler.config.GetBaseURL(), "/"); base != "" {
		if u, err := url.Parse(base); err == nil && u.Scheme != "" && u.Host != "" {
			return u.Scheme + "://" + u.Host + r.URL.Path
		}
		// Misconfigured BASE_URL — log loudly and fall through to the
		// header-based path so we don't hard-fail every DPoP request.
		log.Warn().Str("baseURL", base).Msg("could not parse BASE_URL for DPoP htu — falling back to request headers")
	}

	scheme := ""
	if peerTrusted {
		scheme = strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	}
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
