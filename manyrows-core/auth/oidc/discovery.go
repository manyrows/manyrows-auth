package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// discoveryTTL caches a provider's well-known document. Endpoints change
// very rarely; an hour avoids a discovery round-trip on every sign-in.
const discoveryTTL = time.Hour

// Endpoints is the resolved set a provider's authorize/callback flow
// needs. For OIDC mode these come from the discovery document; for
// OAuth2 mode they're the explicit config values.
type Endpoints struct {
	Issuer    string
	Authorize string
	Token     string
	Userinfo  string
	JWKS      string
}

type discoveryDoc struct {
	Issuer       string `json:"issuer"`
	AuthorizeURL string `json:"authorization_endpoint"`
	TokenURL     string `json:"token_endpoint"`
	UserinfoURL  string `json:"userinfo_endpoint"`
	JWKSURL      string `json:"jwks_uri"`
}

type discoveryCacheEntry struct {
	ep        Endpoints
	fetchedAt time.Time
}

var discoveryCache = struct {
	sync.Mutex
	byIssuer map[string]discoveryCacheEntry
}{byIssuer: map[string]discoveryCacheEntry{}}

// Discover fetches and caches <issuer>/.well-known/openid-configuration.
// It verifies the document's own `issuer` matches the configured one —
// a mismatch means the well-known doc was served from the wrong place
// (or tampered), and tokens would later fail issuer validation anyway.
func Discover(ctx context.Context, issuer string) (Endpoints, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return Endpoints{}, fmt.Errorf("%w: empty issuer", ErrDiscovery)
	}
	if err := RequireSecureURL(issuer); err != nil {
		return Endpoints{}, fmt.Errorf("%w: %v", ErrDiscovery, err)
	}

	discoveryCache.Lock()
	if e, ok := discoveryCache.byIssuer[issuer]; ok && time.Since(e.fetchedAt) < discoveryTTL {
		discoveryCache.Unlock()
		return e.ep, nil
	}
	discoveryCache.Unlock()

	wellKnown := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return Endpoints{}, fmt.Errorf("%w: %v", ErrDiscovery, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return Endpoints{}, fmt.Errorf("%w: %v", ErrDiscovery, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Endpoints{}, fmt.Errorf("%w: status %d from %s", ErrDiscovery, resp.StatusCode, wellKnown)
	}

	var doc discoveryDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&doc); err != nil {
		return Endpoints{}, fmt.Errorf("%w: decode: %v", ErrDiscovery, err)
	}

	// The doc's issuer must equal the one we asked about (OIDC Discovery
	// §4.3). Otherwise a provider could advertise someone else's issuer.
	if strings.TrimRight(doc.Issuer, "/") != issuer {
		return Endpoints{}, fmt.Errorf("%w: doc issuer %q != configured %q", ErrDiscovery, doc.Issuer, issuer)
	}
	if doc.AuthorizeURL == "" || doc.TokenURL == "" || doc.JWKSURL == "" {
		return Endpoints{}, fmt.Errorf("%w: doc missing required endpoints", ErrDiscovery)
	}
	// Downgrade defense: a (malicious or misconfigured) issuer must not
	// be able to point us at cleartext endpoints — these get fetched
	// server-side or sent the user's browser.
	for _, u := range []string{doc.AuthorizeURL, doc.TokenURL, doc.JWKSURL, doc.UserinfoURL} {
		if u == "" {
			continue
		}
		if err := RequireSecureURL(u); err != nil {
			return Endpoints{}, fmt.Errorf("%w: %v", ErrDiscovery, err)
		}
	}

	ep := Endpoints{
		Issuer:    issuer,
		Authorize: doc.AuthorizeURL,
		Token:     doc.TokenURL,
		Userinfo:  doc.UserinfoURL,
		JWKS:      doc.JWKSURL,
	}
	discoveryCache.Lock()
	discoveryCache.byIssuer[issuer] = discoveryCacheEntry{ep: ep, fetchedAt: time.Now().UTC()}
	discoveryCache.Unlock()
	return ep, nil
}
