package client

import "testing"

// deviceFingerprint must be stable across whitespace differences (so the
// same browser isn't seen as two devices) and distinct for distinct agents.
func TestDeviceFingerprint(t *testing.T) {
	const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120"

	h := deviceFingerprint(ua)
	if len(h) != 64 {
		t.Errorf("fingerprint length = %d, want 64 (sha256 hex)", len(h))
	}
	if got := deviceFingerprint("  " + ua + "  "); got != h {
		t.Errorf("fingerprint not whitespace-stable: %q vs %q", got, h)
	}
	if deviceFingerprint(ua+" Safari/537") == h {
		t.Error("distinct user agents must produce distinct fingerprints")
	}
	// Empty and whitespace-only collapse to the same (the "unknown" device).
	if deviceFingerprint("") != deviceFingerprint("   ") {
		t.Error("empty and whitespace-only agents should fingerprint identically")
	}
}

// shouldAlertNewDevice fires only for a genuinely new device on an account
// that already has at least one known device, and never for an unidentifiable
// (empty) user agent.
func TestShouldAlertNewDevice(t *testing.T) {
	tests := []struct {
		name      string
		wasNew    bool
		priorN    int
		userAgent string
		want      bool
	}{
		{"new device, account has prior devices", true, 1, "Chrome", true},
		{"new device, but it's the account's first device", true, 0, "Chrome", false},
		{"returning known device", false, 3, "Chrome", false},
		{"new device but empty UA can't be identified", true, 2, "", false},
		{"new device but whitespace-only UA", true, 2, "   ", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldAlertNewDevice(tt.wasNew, tt.priorN, tt.userAgent)
			if got != tt.want {
				t.Errorf("shouldAlertNewDevice(%v, %d, %q) = %v, want %v",
					tt.wasNew, tt.priorN, tt.userAgent, got, tt.want)
			}
		})
	}
}
