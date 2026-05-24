package encmigrate

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"io"
	"testing"

	"manyrows-core/config"
	"manyrows-core/crypto"
)

// Test keys. 32 ASCII characters each so they parse as raw AES-256 keys.
const (
	keyA = "raw:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	keyB = "raw:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

// newEnc returns a SecretEncryptor with active = activeKey and an
// optional previous-keys list (CSV). Pass "" for previous when not
// rotating.
func newEnc(t *testing.T, activeKey, prevKeys string) crypto.SecretEncryptor {
	t.Helper()
	t.Setenv("MANYROWS_ENCRYPTION_KEY", activeKey)
	t.Setenv("MANYROWS_ENCRYPTION_KEY_PREVIOUS", prevKeys)
	return crypto.NewMySecretEncryptor(config.NewConfig("MANYROWS_"))
}

// rawAESKey extracts the 32 plaintext bytes from a "raw:..." key
// string the way crypto.normalizeKey does internally. Used for hand-
// crafting v0x03 fixtures (the production code only encrypts v0x04).
func rawAESKey(t *testing.T, key string) []byte {
	t.Helper()
	const prefix = "raw:"
	if len(key) <= len(prefix) || key[:len(prefix)] != prefix {
		t.Fatalf("key %q is not raw:-prefixed", key)
	}
	return []byte(key[len(prefix):])
}

// makeLegacyV3 hand-builds a v0x03 ciphertext: [0x03][nonce:12][gcm-sealed].
// The codebase no longer writes v0x03 (the encrypt path always emits
// v0x04). To exercise the legacy-format-upgrade path the walker exists
// for, we forge one with the AES-GCM primitives directly.
func makeLegacyV3(t *testing.T, rawKey, plaintext, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(rawKey)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(crand.Reader, nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	out := []byte{0x03}
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plaintext, aad)
	return out
}

// =================================================================
// Skipped: row already canonical under the active key
// =================================================================

func TestMigrateRow_AlreadyCanonical_Skipped(t *testing.T) {
	enc := newEnc(t, keyA, "")
	aad := []byte("apps:apple_private_key_encrypted:row1")
	plaintext := []byte("apple-p8-key-bytes")

	canonical, err := enc.EncryptToBytesWithAAD(plaintext, aad)
	if err != nil {
		t.Fatalf("seed encrypt: %v", err)
	}

	newCt, action, err := migrateRow(enc, canonical, aad)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if action != actionSkipped {
		t.Errorf("action: got %d want actionSkipped", action)
	}
	if newCt != nil {
		t.Errorf("newCt: must be nil on Skipped, got %d bytes (caller would clobber the row)", len(newCt))
	}
}

// =================================================================
// Migrated: legacy v0x03 → v0x04 canonical, plaintext preserved
// =================================================================

func TestMigrateRow_LegacyV3_Migrated(t *testing.T) {
	enc := newEnc(t, keyA, "")
	aad := []byte("users:totp_secret_encrypted:abc")
	plaintext := []byte("JBSWY3DPEHPK3PXP")

	legacy := makeLegacyV3(t, rawAESKey(t, keyA), plaintext, aad)

	newCt, action, err := migrateRow(enc, legacy, aad)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if action != actionMigrated {
		t.Fatalf("action: got %d want actionMigrated", action)
	}
	if !enc.IsCanonical(newCt) {
		t.Errorf("output is not canonical under the active key — walker would loop on the next run")
	}
	if newCt[0] != 0x04 {
		t.Errorf("output version byte: got 0x%02x want 0x04", newCt[0])
	}

	// Round-trip: the rewritten ciphertext MUST decrypt back to the
	// original plaintext under the same AAD. This is the security
	// invariant the walker exists to maintain.
	got, err := enc.DecryptFromBytesWithAAD(newCt, aad)
	if err != nil {
		t.Fatalf("re-decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip plaintext drift: got %q want %q", got, plaintext)
	}
}

// =================================================================
// Migrated: v0x04 under previous key → v0x04 under active key
// =================================================================

func TestMigrateRow_PreviousKey_Migrated(t *testing.T) {
	// Step 1: encrypt under A.
	encA := newEnc(t, keyA, "")
	aad := []byte("apps:google_oauth_client_secret_encrypted:xyz")
	plaintext := []byte("google-secret-bytes")
	ctA, err := encA.EncryptToBytesWithAAD(plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt under A: %v", err)
	}

	// Step 2: rotate — active is now B, A is in PREVIOUS.
	encB := newEnc(t, keyB, keyA)

	// Sanity: a row encrypted under A is NOT canonical under B's
	// active-key view, but IS still decryptable.
	if encB.IsCanonical(ctA) {
		t.Fatal("ctA must NOT report canonical under the rotated encryptor (kid is A's)")
	}

	newCt, action, err := migrateRow(encB, ctA, aad)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if action != actionMigrated {
		t.Fatalf("action: got %d want actionMigrated", action)
	}
	if !encB.IsCanonical(newCt) {
		t.Errorf("rotated output is not canonical under active key B")
	}

	// Round-trip under B alone (drop A from PREVIOUS) to confirm the
	// rewrite truly used B's key, not A's.
	encBOnly := newEnc(t, keyB, "")
	got, err := encBOnly.DecryptFromBytesWithAAD(newCt, aad)
	if err != nil {
		t.Fatalf("re-decrypt under B alone: %v — rotated row still binds to A?", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("rotation plaintext drift: got %q want %q", got, plaintext)
	}
}

// =================================================================
// Idempotency: migrate once → second call is Skipped
// =================================================================

func TestMigrateRow_IdempotentAfterMigration(t *testing.T) {
	enc := newEnc(t, keyA, "")
	aad := []byte("apps:microsoft_client_secret_encrypted:idempotent")
	legacy := makeLegacyV3(t, rawAESKey(t, keyA), []byte("ms-secret"), aad)

	// First call: should migrate.
	newCt, action, err := migrateRow(enc, legacy, aad)
	if err != nil || action != actionMigrated {
		t.Fatalf("first migrateRow: action=%d err=%v", action, err)
	}

	// Second call against the rewritten ciphertext: should skip.
	newCt2, action2, err := migrateRow(enc, newCt, aad)
	if err != nil {
		t.Fatalf("second migrateRow: %v", err)
	}
	if action2 != actionSkipped {
		t.Errorf("second action: got %d want actionSkipped (walker would loop)", action2)
	}
	if newCt2 != nil {
		t.Errorf("second newCt: must be nil on Skipped, got %d bytes", len(newCt2))
	}
}

// =================================================================
// Error: corrupt / unrecognized ciphertext
// =================================================================

func TestMigrateRow_BadCiphertext_Error(t *testing.T) {
	enc := newEnc(t, keyA, "")
	aad := []byte("apps:any:ignored")

	cases := map[string][]byte{
		"empty":                 {},
		"unknown version":       {0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		"v04 too short":         {0x04, 0x00, 0x00},
		"v04 garbage after kid": append([]byte{0x04, 0x01, 0x02, 0x03, 0x04}, make([]byte, 32)...),
		"random bytes":          bytes.Repeat([]byte{0xAB}, 64),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			newCt, action, err := migrateRow(enc, data, aad)
			if action != actionError {
				t.Errorf("action: got %d want actionError", action)
			}
			if err == nil {
				t.Error("expected non-nil err on actionError")
			}
			if newCt != nil {
				t.Errorf("newCt MUST be nil on actionError, got %d bytes (caller would clobber the row with garbage)", len(newCt))
			}
		})
	}
}

// =================================================================
// Error: AAD mismatch (row swapped to wrong column / id)
// =================================================================

func TestMigrateRow_AADMismatch_Error(t *testing.T) {
	enc := newEnc(t, keyA, "")
	rightAAD := []byte("apps:apple_private_key_encrypted:row1")
	wrongAAD := []byte("apps:apple_private_key_encrypted:row2") // different id

	legacy := makeLegacyV3(t, rawAESKey(t, keyA), []byte("apple-bytes"), rightAAD)

	newCt, action, err := migrateRow(enc, legacy, wrongAAD)
	if action != actionError {
		t.Errorf("action: got %d want actionError (a row moved to a different id MUST NOT decrypt)", action)
	}
	if err == nil {
		t.Error("expected non-nil err on AAD mismatch")
	}
	if newCt != nil {
		t.Error("newCt MUST be nil on AAD mismatch — never re-write a row we couldn't authenticate")
	}
}

// =================================================================
// Error: row encrypted under a key that's no longer in scope
// =================================================================

func TestMigrateRow_UnknownKey_Error(t *testing.T) {
	// Encrypt under A.
	encA := newEnc(t, keyA, "")
	aad := []byte("workspace_smtp_config:password_encrypted:ws1")
	ctA, err := encA.EncryptToBytesWithAAD([]byte("smtp-pw"), aad)
	if err != nil {
		t.Fatalf("encrypt under A: %v", err)
	}

	// Now boot with B as active and NO previous keys. ctA's kid won't
	// resolve and decrypt MUST fail — this is the "operator forgot to
	// set MANYROWS_ENCRYPTION_KEY_PREVIOUS during rotation" case.
	encB := newEnc(t, keyB, "")
	newCt, action, err := migrateRow(encB, ctA, aad)
	if action != actionError {
		t.Errorf("action: got %d want actionError", action)
	}
	if err == nil {
		t.Error("expected non-nil err — row's key is unknown")
	}
	if newCt != nil {
		t.Error("newCt MUST be nil — never clobber a row whose plaintext we can't recover")
	}
}

// =================================================================
// Edge case: empty plaintext is preserved
// =================================================================

func TestMigrateRow_EmptyPlaintext(t *testing.T) {
	enc := newEnc(t, keyA, "")
	aad := []byte("users:totp_backup_codes_encrypted:empty")

	// Hand-build a v0x03 row with empty plaintext.
	legacy := makeLegacyV3(t, rawAESKey(t, keyA), []byte{}, aad)

	newCt, action, err := migrateRow(enc, legacy, aad)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if action != actionMigrated {
		t.Fatalf("action: got %d want actionMigrated", action)
	}
	got, err := enc.DecryptFromBytesWithAAD(newCt, aad)
	if err != nil {
		t.Fatalf("re-decrypt: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty plaintext got rewritten as %d bytes: %x", len(got), got)
	}
}

// =================================================================
// Edge case: large-ish plaintext (1 KiB) preserves byte-for-byte
// =================================================================

func TestMigrateRow_LargePlaintext_BytewisePreserved(t *testing.T) {
	enc := newEnc(t, keyA, "")
	aad := []byte("apps:github_client_secret_encrypted:large")

	// 1 KiB of pseudo-random bytes — well past any GCM block boundary
	// so a length-off-by-one bug in the padding/seal layer would
	// surface as a tail mismatch.
	plaintext := make([]byte, 1024)
	for i := range plaintext {
		plaintext[i] = byte(i*7 + 3)
	}
	legacy := makeLegacyV3(t, rawAESKey(t, keyA), plaintext, aad)

	newCt, action, err := migrateRow(enc, legacy, aad)
	if err != nil || action != actionMigrated {
		t.Fatalf("migrate: action=%d err=%v", action, err)
	}
	got, err := enc.DecryptFromBytesWithAAD(newCt, aad)
	if err != nil {
		t.Fatalf("re-decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext drift over 1 KiB payload (first mismatch at byte %d)",
			firstMismatch(got, plaintext))
	}
}

func firstMismatch(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return n
	}
	return -1
}
