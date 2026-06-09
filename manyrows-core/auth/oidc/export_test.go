package oidc

// ResetCaches clears the process-local discovery and JWKS caches. It
// exists only for tests: the caches are keyed by URL and never expire
// within a test run, so a later test whose httptest server reuses an
// earlier test's ephemeral port would otherwise get the earlier test's
// stale signing key (and fail signature verification). Each test starts
// from a clean slate by calling this.
func ResetCaches() {
	discoveryCache.Lock()
	discoveryCache.byIssuer = map[string]discoveryCacheEntry{}
	discoveryCache.Unlock()

	jwksCache.Lock()
	jwksCache.byURL = map[string]*jwksCacheEntry{}
	jwksCache.Unlock()
}
