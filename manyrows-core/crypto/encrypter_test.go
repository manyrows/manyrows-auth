package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"io"
	"os"
	"strings"
	"testing"

	config2 "manyrows-core/config"
)

func newEncryptorWithKey(t *testing.T, key string) SecretEncryptor {
	t.Helper()
	t.Setenv("MANYROWS_ENCRYPTION_KEY", key)
	return NewMySecretEncryptor(config2.NewConfig("MANYROWS_"))
}

// keyOf is a tiny adapter to call the unexported key loader from tests.
func keyOf(t *testing.T, key string) ([]byte, error) {
	t.Helper()
	t.Setenv("MANYROWS_ENCRYPTION_KEY", key)
	en := NewMySecretEncryptor(config2.NewConfig("MANYROWS_")).(*MySecretEncryptor)
	return en.getKeyBytes()
}

func TestGetKeyBytes_ExplicitBase64(t *testing.T) {
	// 32 chars of digits → base64-decode to 24 bytes (AES-192)
	got, err := keyOf(t, "base64:01234567890123456789012345678901")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 24 {
		t.Fatalf("expected 24-byte key, got %d", len(got))
	}
}

func TestGetKeyBytes_ExplicitRaw(t *testing.T) {
	// 32-char ASCII → raw 32 bytes (AES-256)
	got, err := keyOf(t, "raw:01234567890123456789012345678901")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(got))
	}
}

func TestGetKeyBytes_ExplicitBase64_InvalidEncoding(t *testing.T) {
	_, err := keyOf(t, "base64:not!valid!base64")
	if err == nil {
		t.Fatal("expected error for invalid base64, got nil")
	}
}

func TestGetKeyBytes_ExplicitBase64_WrongLength(t *testing.T) {
	// "aGVsbG8=" decodes to 5 bytes ("hello") — not a valid AES key length.
	_, err := keyOf(t, "base64:aGVsbG8=")
	if err == nil {
		t.Fatal("expected error for invalid AES key length, got nil")
	}
}

func TestGetKeyBytes_ExplicitRaw_WrongLength(t *testing.T) {
	_, err := keyOf(t, "raw:tooshort")
	if err == nil {
		t.Fatal("expected error for short raw key, got nil")
	}
}

func TestGetKeyBytes_BareString_AmbiguousRejected(t *testing.T) {
	// A 32-char string that's ALSO valid base64 was historically
	// accepted (defaulting to base64). The audit closed that
	// silent-corruption footgun: now the operator must use an
	// explicit 'base64:' or 'raw:' prefix to lock in the intent.
	_, err := keyOf(t, "01234567890123456789012345678901")
	if err == nil {
		t.Fatal("expected error for ambiguous bare-string key, got nil")
	}
	if !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("error should call out the ambiguity, got: %v", err)
	}
}

func TestGetKeyBytes_BareString_RawOnlyValid(t *testing.T) {
	// A raw 16-byte string whose base64 decode is invalid. Should pick raw.
	got, err := keyOf(t, "ABCDEFGHIJKLMNOP") // 16 ASCII chars; base64 decodes to 12 bytes (not valid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 16 {
		t.Fatalf("expected raw 16-byte key, got %d", len(got))
	}
}

func TestGetKeyBytes_BareString_TooShort(t *testing.T) {
	_, err := keyOf(t, "tinykey")
	if err == nil {
		t.Fatal("expected error for too-short bare key, got nil")
	}
}

func TestGetKeyBytes_Empty(t *testing.T) {
	_, err := keyOf(t, "")
	if err == nil {
		t.Fatal("expected error for empty key, got nil")
	}
}

// Operators upgrading past the ambiguous-bare-string rejection should
// be able to make either intent explicit and get the bytes they
// expected. This confirms both prefixed forms yield distinct, valid
// keys from the same underlying string — proving migration is a
// config-side change, not a key-material rotation.
func TestGetKeyBytes_ExplicitPrefixesDifferentiate(t *testing.T) {
	rawKey, err := keyOf(t, "raw:01234567890123456789012345678901")
	if err != nil {
		t.Fatalf("raw: %v", err)
	}
	if len(rawKey) != 32 {
		t.Fatalf("expected raw key to be 32 bytes (AES-256), got %d", len(rawKey))
	}
	b64Key, err := keyOf(t, "base64:01234567890123456789012345678901")
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	if len(b64Key) != 24 {
		t.Fatalf("expected base64 decode to be 24 bytes (AES-192), got %d", len(b64Key))
	}
	if bytes.Equal(rawKey, b64Key[:24]) && len(rawKey) == len(b64Key) {
		t.Fatal("raw and base64 keys should NOT match — that's the whole reason the bare-string form was ambiguous")
	}
	// Restore env to known state. The defer below would also clear it,
	// but be explicit since other tests in this package may rely on
	// consistent values.
	_ = os.Unsetenv("MANYROWS_ENCRYPTION_KEY")
}

// ------------------------------------------------------------------
// AAD-bound encryption (v0x03) — C2/H6 foundation.
// ------------------------------------------------------------------

const testKey = "raw:01234567890123456789012345678901" // 32-byte AES-256

func TestEncryptWithAAD_RoundTrip(t *testing.T) {
	en := newEncryptorWithKey(t, testKey)
	plaintext := []byte("highly sensitive payload")
	aad := []byte("apps:google_oauth_client_secret_encrypted:019d4370-62af-79ea-bf0d-70c1d5429209")

	ct, err := en.EncryptToBytesWithAAD(plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(ct) == 0 || ct[0] != 0x04 {
		t.Fatalf("expected v0x04 ciphertext, got first byte %#x", ct[0])
	}

	pt, err := en.DecryptFromBytesWithAAD(ct, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", pt, plaintext)
	}
}

func TestEncryptWithAAD_WrongAADFails(t *testing.T) {
	en := newEncryptorWithKey(t, testKey)
	ct, err := en.EncryptToBytesWithAAD([]byte("payload"), []byte("table:column:id-A"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Decrypt with a different AAD must fail. This is the H6 anti-shuffle
	// guarantee: a DB-write attacker can't move ciphertext from row A
	// onto row B undetected.
	if _, err := en.DecryptFromBytesWithAAD(ct, []byte("table:column:id-B")); err == nil {
		t.Fatal("decrypt with wrong AAD should fail, got nil error")
	}
}

func TestEncryptWithAAD_EmptyAAD(t *testing.T) {
	// Empty AAD still produces a valid v0x03 ciphertext but provides
	// no row-binding. Caller is responsible for choosing not to use
	// this except when there's a deliberate reason.
	en := newEncryptorWithKey(t, testKey)
	ct, err := en.EncryptToBytesWithAAD([]byte("payload"), nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	pt, err := en.DecryptFromBytesWithAAD(ct, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != "payload" {
		t.Fatalf("got %q", pt)
	}
}

func TestDecryptFromBytesWithAAD_RejectsUnsupportedVersions(t *testing.T) {
	// Accepted versions are v0x03 (legacy AAD-bound GCM, pre-rotation
	// rollout) and v0x04 (kid-tagged AAD-bound GCM). Anything else —
	// pre-cutover v0x02 GCM, legacy CFB, or attacker-forged version
	// bytes — must hard-fail at the version check before any key
	// material is touched.
	en := newEncryptorWithKey(t, testKey)
	cases := [][]byte{
		// v0x02 nonce-prefix without AAD binding (pre-cutover format)
		append([]byte{0x02}, make([]byte, 28)...),
		// Legacy CFB shape (no version byte)
		append([]byte{0x00}, make([]byte, 31)...),
		// Some other random version byte
		append([]byte{0xff}, make([]byte, 28)...),
	}
	for i, ct := range cases {
		if _, err := en.DecryptFromBytesWithAAD(ct, []byte("any-aad")); err == nil {
			t.Fatalf("case %d: expected unsupported-version ciphertext to be rejected, got nil error", i)
		}
	}
}

func TestEncryptWithAAD_DistinctCiphertextsForSamePlaintext(t *testing.T) {
	// Same plaintext, same AAD, encrypted twice → different ciphertexts
	// because GCM uses a fresh random nonce. This is the standard GCM
	// guarantee and confirms we're not reusing nonces.
	en := newEncryptorWithKey(t, testKey)
	pt := []byte("same payload")
	aad := []byte("table:col:id")
	a, _ := en.EncryptToBytesWithAAD(pt, aad)
	b, _ := en.EncryptToBytesWithAAD(pt, aad)
	if string(a) == string(b) {
		t.Fatal("two encryptions of same plaintext+AAD produced identical ciphertext (nonce reuse?)")
	}
}

// ------------------------------------------------------------------
// Key rotation (v0x04 kid lookup, MANYROWS_ENCRYPTION_KEY_PREVIOUS).
// ------------------------------------------------------------------

func TestEncryptWithAAD_EmitsV04WithKid(t *testing.T) {
	// Sanity: writes are v0x04 and the next 4 bytes are the kid
	// derived from the active key. Nonce starts at byte 5.
	en := newEncryptorWithKey(t, testKey)
	ct, err := en.EncryptToBytesWithAAD([]byte("payload"), []byte("aad"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if ct[0] != 0x04 {
		t.Fatalf("expected version 0x04, got %#x", ct[0])
	}
	if len(ct) < 1+4+12+16 {
		t.Fatalf("ciphertext too short for [version][kid:4][nonce:12][tag:16+]: %d bytes", len(ct))
	}
}

func TestDecryptFromBytesWithAAD_V03LegacyReadCompat(t *testing.T) {
	// v0x03 rows pre-date the rotation rollout. They have no kid and
	// must be decryptable under the active key — that's what makes
	// the format-upgrade migration invisible to runtime callers.
	en := newEncryptorWithKey(t, testKey).(*MySecretEncryptor)
	key, err := en.getKeyBytes()
	if err != nil {
		t.Fatalf("getKeyBytes: %v", err)
	}

	// Hand-craft a v0x03 ciphertext: [0x03][nonce:12][sealed].
	v03 := append([]byte{0x03}, mustSealGCMv03(t, key, []byte("ancient secret"), []byte("aad"))...)

	pt, err := en.DecryptFromBytesWithAAD(v03, []byte("aad"))
	if err != nil {
		t.Fatalf("v0x03 read-compat decrypt failed: %v", err)
	}
	if string(pt) != "ancient secret" {
		t.Fatalf("got %q", pt)
	}
}

func TestDecryptFromBytesWithAAD_RotationFlow(t *testing.T) {
	// The end-to-end rotation contract:
	//   1. Encrypt under key A.
	//   2. Swap the active key to B, configure A as PREVIOUS.
	//   3. Old A-rows still decrypt (kid lookup finds A in PREVIOUS).
	//   4. New writes use B's kid.
	//   5. Once the walker has rewritten everyone, PREVIOUS can be
	//      unset and old A-rows would no longer decrypt — but until
	//      the migration runs, both keys are honoured.
	const keyA = "raw:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 32 ASCII chars
	const keyB = "raw:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

	// Step 1: encrypt under A.
	enA := newEncryptorWithKey(t, keyA)
	ctA, err := enA.EncryptToBytesWithAAD([]byte("rotation payload"), []byte("aad"))
	if err != nil {
		t.Fatalf("encrypt under A: %v", err)
	}

	// Step 2: rotate to B with A configured as previous.
	t.Setenv("MANYROWS_ENCRYPTION_KEY", keyB)
	t.Setenv("MANYROWS_ENCRYPTION_KEY_PREVIOUS", keyA)
	enB := NewMySecretEncryptor(en2config(t)).(*MySecretEncryptor)

	// Step 3: row encrypted under A still decrypts.
	pt, err := enB.DecryptFromBytesWithAAD(ctA, []byte("aad"))
	if err != nil {
		t.Fatalf("rotation read-compat decrypt failed: %v", err)
	}
	if string(pt) != "rotation payload" {
		t.Fatalf("got %q", pt)
	}

	// Step 4: a fresh encrypt now uses B's kid, distinct from A's.
	ctB, err := enB.EncryptToBytesWithAAD([]byte("post-rotation"), []byte("aad"))
	if err != nil {
		t.Fatalf("encrypt under B: %v", err)
	}
	if string(ctA[1:5]) == string(ctB[1:5]) {
		t.Fatal("rotation produced identical kid for distinct keys (kid derivation broken?)")
	}

	// Step 5: drop PREVIOUS — A-rows are now unreachable.
	t.Setenv("MANYROWS_ENCRYPTION_KEY_PREVIOUS", "")
	enBOnly := NewMySecretEncryptor(en2config(t))
	if _, err := enBOnly.DecryptFromBytesWithAAD(ctA, []byte("aad")); err == nil {
		t.Fatal("expected decrypt of A-row to fail once PREVIOUS is unset")
	}
	// But B-rows still work fine.
	if _, err := enBOnly.DecryptFromBytesWithAAD(ctB, []byte("aad")); err != nil {
		t.Fatalf("B-row should still decrypt: %v", err)
	}
}

func TestIsCanonical(t *testing.T) {
	en := newEncryptorWithKey(t, testKey)

	// Canonical: v0x04 with active kid.
	ct, _ := en.EncryptToBytesWithAAD([]byte("p"), []byte("aad"))
	if !en.IsCanonical(ct) {
		t.Fatal("freshly-encrypted ciphertext should be canonical")
	}

	// Not canonical: v0x03 (legacy, no kid).
	if en.IsCanonical(append([]byte{0x03}, make([]byte, 28)...)) {
		t.Fatal("v0x03 should not be canonical (must be re-encrypted)")
	}

	// Not canonical: v0x04 with a wrong kid.
	wrongKid := append([]byte{0x04}, []byte{0xde, 0xad, 0xbe, 0xef}...)
	wrongKid = append(wrongKid, make([]byte, 28)...)
	if en.IsCanonical(wrongKid) {
		t.Fatal("v0x04 with wrong kid should not be canonical")
	}

	// Not canonical: empty / too short.
	if en.IsCanonical(nil) || en.IsCanonical([]byte{0x04}) {
		t.Fatal("short ciphertext should not be canonical")
	}
}

// en2config builds a fresh Config the way callers in production do.
// Used by the rotation tests where we re-create the encryptor after
// changing env vars (the encryptor reads env on each call, so this
// is mainly to be explicit about the lifecycle).
func en2config(t *testing.T) *config2.Config {
	t.Helper()
	return config2.NewConfig("MANYROWS_")
}

// mustSealGCMv03 produces the body of a v0x03 ciphertext under the
// given key (i.e. [nonce][sealed-with-AAD], without the leading
// version byte). Used to fabricate legacy rows in tests.
func mustSealGCMv03(t *testing.T, key, plaintext, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(crand.Reader, nonce); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, aad)
}

func TestEncryptWithAAD_AADBindsAcrossRows(t *testing.T) {
	// The core H6 property: ciphertext A encrypted under AAD-A must not
	// decrypt successfully when presented with AAD-B, even though the
	// key is the same. This is what blocks ciphertext-shuffling
	// between rows.
	en := newEncryptorWithKey(t, testKey)
	rowA := []byte("apps:secret:00000000-0000-0000-0000-000000000001")
	rowB := []byte("apps:secret:00000000-0000-0000-0000-000000000002")

	ctA, _ := en.EncryptToBytesWithAAD([]byte("alice's secret"), rowA)
	ctB, _ := en.EncryptToBytesWithAAD([]byte("bob's secret"), rowB)

	// Each row decrypts cleanly with its own AAD.
	if pt, err := en.DecryptFromBytesWithAAD(ctA, rowA); err != nil || string(pt) != "alice's secret" {
		t.Fatalf("rowA→rowA failed: %v %q", err, pt)
	}
	if pt, err := en.DecryptFromBytesWithAAD(ctB, rowB); err != nil || string(pt) != "bob's secret" {
		t.Fatalf("rowB→rowB failed: %v %q", err, pt)
	}
	// Swapping the ciphertexts onto each other's row must fail.
	if _, err := en.DecryptFromBytesWithAAD(ctA, rowB); err == nil {
		t.Fatal("rowA ciphertext on rowB should fail")
	}
	if _, err := en.DecryptFromBytesWithAAD(ctB, rowA); err == nil {
		t.Fatal("rowB ciphertext on rowA should fail")
	}
}
