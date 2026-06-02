package api

// White-box tests for the Apple callback's targetOrigin handling.
// In its own _test.go in package api so it can reach the unexported
// sanitizeTargetOrigin without exposing it.

import "testing"

func TestSanitizeTargetOrigin(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"https origin", "https://app.example.com", "https://app.example.com"},
		{"http origin", "http://localhost:3000", "http://localhost:3000"},
		{"strips trailing slash via parse", "https://example.com/", "https://example.com"},
		{"strips path", "https://example.com/some/path", "https://example.com"},
		{"strips query", "https://example.com?foo=bar", "https://example.com"},
		{"strips fragment", "https://example.com#frag", "https://example.com"},
		{"trims surrounding whitespace", "  https://example.com  ", "https://example.com"},
		{"rejects empty", "", ""},
		{"rejects ftp", "ftp://example.com", ""},
		{"rejects javascript", "javascript:alert(1)", ""},
		{"rejects bare host", "example.com", ""},
		{"rejects script-tag injection", "https://example.com\"</script><script>alert(1)</script>", ""},
		{"rejects null byte", "https://example.com\x00", ""},
		{"accepts ipv6", "https://[::1]:8080", "https://[::1]:8080"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sanitizeTargetOrigin(c.in)
			if got != c.want {
				t.Errorf("sanitizeTargetOrigin(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
