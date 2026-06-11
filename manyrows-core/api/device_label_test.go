package api

import "testing"

func TestDeviceLabelFromUA(t *testing.T) {
	cases := []struct{ ua, want string }{
		{"", "Unknown device"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Chrome on macOS"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", "Safari on iOS"},
		{"curl/8.4.0", "Unknown device"},
	}
	for _, c := range cases {
		if got := deviceLabelFromUA(c.ua); got != c.want {
			t.Errorf("deviceLabelFromUA(%q) = %q, want %q", c.ua, got, c.want)
		}
	}
}
