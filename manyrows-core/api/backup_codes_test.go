package api

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/gofrs/uuid/v5"
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

// TestHashBackupCode pins the one-way storage properties: backup codes are
// HMAC-SHA256 hashed (not reversibly encrypted), normalized, and bound to both
// the owner id and the OTP pepper — so a DB (and even DB+key) compromise yields
// nothing usable.
func TestHashBackupCode(t *testing.T) {
	owner := uuid.Must(uuid.NewV4())
	pepper := "test-pepper-value"
	code := "aabbccdd11223344"

	h := hashBackupCode(code, owner, pepper)

	if len(h) != 64 { // 32-byte HMAC-SHA256 → 64 hex chars
		t.Fatalf("hash length = %d, want 64", len(h))
	}
	if strings.Contains(strings.ToLower(h), strings.ToLower(code)) {
		t.Fatal("hash must not contain the plaintext code")
	}
	if hashBackupCode("  AABBCCDD11223344 ", owner, pepper) != h {
		t.Fatal("hash must normalize case and surrounding whitespace")
	}
	if hashBackupCode(code, uuid.Must(uuid.NewV4()), pepper) == h {
		t.Fatal("hash must be bound to the owner id")
	}
	if hashBackupCode(code, owner, "different-pepper") == h {
		t.Fatal("hash must depend on the pepper")
	}
}
