package api

import (
	"encoding/hex"
	"testing"
)

// TestGenerateBackupCodes_Entropy verifies backup codes are 64-bit (16 hex
// chars) — the hardened length — that the requested count is honored, and that
// codes are unique hex strings.
func TestGenerateBackupCodes_Entropy(t *testing.T) {
	codes, err := generateBackupCodes(8)
	if err != nil {
		t.Fatalf("generateBackupCodes: %v", err)
	}
	if len(codes) != 8 {
		t.Fatalf("want 8 codes, got %d", len(codes))
	}
	seen := make(map[string]bool, len(codes))
	for _, c := range codes {
		if len(c) != 16 {
			t.Errorf("code %q: want 16 hex chars (64-bit), got %d", c, len(c))
		}
		if _, err := hex.DecodeString(c); err != nil {
			t.Errorf("code %q is not valid hex: %v", c, err)
		}
		if seen[c] {
			t.Errorf("duplicate backup code %q", c)
		}
		seen[c] = true
	}
}
