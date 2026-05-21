package api

import "testing"

// TestOriginFromBaseURL covers the helper that reduces an app's base
// URL (AuthDomain or install BASE_URL, possibly with a path) to the
// bare scheme://host[:port] origin used to match a browser's
// window.location.origin in the OAuth opener-origin allow check.
func TestOriginFromBaseURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// AuthDomain form — already an origin.
		{"https://auth.drumkingdom.com", "https://auth.drumkingdom.com"},
		// Trailing slash is not a path; origin is unchanged.
		{"https://manyrows.example.com/", "https://manyrows.example.com"},
		// Path component stripped down to the origin.
		{"https://example.com/sub/path", "https://example.com"},
		// Port preserved (local dev install).
		{"http://localhost:8080", "http://localhost:8080"},
		// Garbage / non-absolute → empty (caller treats as "no match").
		{"", ""},
		{"not-a-url", ""},
		{"/x/foo/apps/bar", ""}, // path-only, no scheme/host
	}
	for _, c := range cases {
		if got := originFromBaseURL(c.in); got != c.want {
			t.Errorf("originFromBaseURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
