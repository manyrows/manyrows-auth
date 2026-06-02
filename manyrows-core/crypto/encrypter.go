package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	config2 "manyrows-core/config"

	"github.com/rs/zerolog/log"
)

// SecretEncryptor encrypts/decrypts secrets for at-rest storage.
//
// On-the-wire format: AEAD-GCM with AAD context binding and a 4-byte
// key identifier (kid), version byte 0x04. The kid is auto-derived as
// the first 4 bytes of SHA-256(key) so the operator never sees or
// types it; it's just enough to distinguish rows encrypted under
// different keys during a key-rotation window.
//
// AAD ("additional authenticated data" in GCM terms) binds the
// ciphertext to a stable string that identifies WHERE the row lives —
// recommended format `<table>:<column>:<id>` (use the AAD helper).
// The same plaintext encrypted under the same key for two different
// rows produces different ciphertext, AND a DB-write attacker cannot
// move a ciphertext from row A onto row B undetected — the AAD won't
// match at decrypt time and GCM will fail.
//
// Read-compat: v0x03 ciphertexts (AAD-bound GCM without a kid) are
// accepted and assumed to be encrypted under the active key. They
// only exist on deployments that pre-date the rotation-tooling
// rollout. Running `web migrate-encryption` rewrites them to v0x04.
type SecretEncryptor interface {
	// EncryptToBytesWithAAD writes a v0x04 (AEAD-GCM with AAD + kid)
	// ciphertext under the currently-active key. aad should be a
	// stable identifier such as "table:column:id" — the same string
	// MUST be supplied at decrypt time.
	EncryptToBytesWithAAD(plaintext, aad []byte) ([]byte, error)

	// DecryptFromBytesWithAAD verifies a v0x03 or v0x04 ciphertext
	// against the supplied aad. v0x04 looks the key up by kid (must
	// match the active key OR one configured in
	// MANYROWS_ENCRYPTION_KEY_PREVIOUS); v0x03 is decrypted with the
	// active key. Anything else is rejected.
	DecryptFromBytesWithAAD(ciphertext, aad []byte) ([]byte, error)

	// IsCanonical returns true when the ciphertext is already in the
	// active on-the-wire format under the active key. The migration
	// walker uses this to decide skip-vs-rewrite during a rotation.
	IsCanonical(ciphertext []byte) bool
}

type MySecretEncryptor struct {
	config *config2.Config

	// Cache parsed keys so the bare-key ambiguity warning fires once
	// per process (at first use) instead of on every encrypt/decrypt.
	// Env changes require a restart in practice.
	activeOnce sync.Once
	activeKey  []byte
	activeErr  error

	prevOnce sync.Once
	prevKeys [][]byte
	prevErr  error
}

func NewMySecretEncryptor(cfg *config2.Config) SecretEncryptor {
	return &MySecretEncryptor{config: cfg}
}

func (en *MySecretEncryptor) EncryptToBytesWithAAD(plaintext, aad []byte) ([]byte, error) {
	key, err := en.getKeyBytes()
	if err != nil {
		return nil, err
	}
	return encryptGCMWithAADKid(key, plaintext, aad)
}

func (en *MySecretEncryptor) DecryptFromBytesWithAAD(ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("ciphertext is empty")
	}
	switch ciphertext[0] {
	case versionGCMWithAAD:
		// Pre-rotation format. No kid in the row, so it must have been
		// written under whatever the only-ever key was — which is the
		// currently-active key for any deploy that hasn't rotated yet.
		// Operators in a rotation window must run encmigrate first to
		// bring every row up to v0x04 before swapping the active key.
		key, err := en.getKeyBytes()
		if err != nil {
			return nil, err
		}
		return decryptGCMWithAAD(key, ciphertext[1:], aad)
	case versionGCMWithAADKid:
		if len(ciphertext) < 1+kidLen {
			return nil, errors.New("v0x04 ciphertext too short for kid")
		}
		var kid [kidLen]byte
		copy(kid[:], ciphertext[1:1+kidLen])
		key, err := en.getKeyByKid(kid)
		if err != nil {
			return nil, err
		}
		return decryptGCMWithAAD(key, ciphertext[1+kidLen:], aad)
	default:
		return nil, errors.New("unsupported ciphertext version (expected v0x03 or v0x04)")
	}
}

// IsCanonical reports whether the ciphertext is already in the active
// format under the active key. Used by the migration walker.
func (en *MySecretEncryptor) IsCanonical(ciphertext []byte) bool {
	if len(ciphertext) < 1+kidLen {
		return false
	}
	if ciphertext[0] != versionGCMWithAADKid {
		return false
	}
	active, err := en.getKeyBytes()
	if err != nil {
		return false
	}
	activeKid := keyKid(active)
	return string(ciphertext[1:1+kidLen]) == string(activeKid[:])
}

// getKeyBytes returns the currently-active encryption key bytes.
func (en *MySecretEncryptor) getKeyBytes() ([]byte, error) {
	en.activeOnce.Do(func() {
		s, err := en.config.GetEncryptionKey()
		if err != nil {
			en.activeErr = err
			return
		}
		en.activeKey, en.activeErr = normalizeKey(s, "encryption key")
	})
	return en.activeKey, en.activeErr
}

// getKeyByKid resolves a kid to the matching key — first the active
// key, then anything in MANYROWS_ENCRYPTION_KEY_PREVIOUS. Returns a
// loud error if no key matches; that's the operator's signal to set
// the previous-keys env var or accept the row is unrecoverable.
func (en *MySecretEncryptor) getKeyByKid(target [kidLen]byte) ([]byte, error) {
	active, err := en.getKeyBytes()
	if err != nil {
		return nil, err
	}
	if keyKid(active) == target {
		return active, nil
	}
	prev, err := en.previousKeys()
	if err != nil {
		return nil, err
	}
	for _, k := range prev {
		if keyKid(k) == target {
			return k, nil
		}
	}
	return nil, fmt.Errorf("no encryption key matches kid %x — set MANYROWS_ENCRYPTION_KEY_PREVIOUS to include the prior key, or this row is unrecoverable", target[:])
}

// previousKeys parses MANYROWS_ENCRYPTION_KEY_PREVIOUS into key bytes.
// Each entry uses the same prefix scheme as the active key. Empty /
// missing returns nil — that's the steady state outside rotations.
func (en *MySecretEncryptor) previousKeys() ([][]byte, error) {
	en.prevOnce.Do(func() {
		en.prevKeys, en.prevErr = en.parsePreviousKeys()
	})
	return en.prevKeys, en.prevErr
}

func (en *MySecretEncryptor) parsePreviousKeys() ([][]byte, error) {
	raw := strings.TrimSpace(en.config.GetPreviousEncryptionKeys())
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([][]byte, 0, len(parts))
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		k, err := normalizeKey(p, fmt.Sprintf("previous encryption key #%d", i+1))
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// normalizeKey parses one of:
//
//   - "base64:<encoded>"  — strict base64 decode; must produce 16/24/32 bytes.
//   - "raw:<bytes>"       — strict raw bytes; must be 16/24/32 chars long.
//   - "<bare-string>"     — legacy backward-compatible path. Tries base64
//     first (the historical default), falls back to raw if base64 doesn't
//     decode to a valid AES key length. Hard-fails (with a clear migration
//     hint) when the input is ambiguous — a 32-byte raw ASCII key whose
//     bytes happen to also decode as valid base64 would silently produce
//     a different (shorter) key under the old "default to base64"
//     behaviour, and the operator wouldn't notice until decrypts started
//     failing months later.
//
// Operators SHOULD use an explicit prefix in production. The bare-string
// path stays for backward compat with existing deployments that have an
// unambiguous value. label is used in error messages so the operator
// can tell which key (active or which previous) was malformed.
func normalizeKey(s, label string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("%s is empty", label)
	}

	if rest, ok := strings.CutPrefix(s, "base64:"); ok {
		decoded, err := base64.StdEncoding.DecodeString(rest)
		if err != nil {
			return nil, fmt.Errorf("%s has 'base64:' prefix but the value is not valid base64", label)
		}
		if !isValidAESKeyLen(len(decoded)) {
			return nil, fmt.Errorf("%s (base64) decodes to an invalid AES key length: must be 16, 24, or 32 bytes", label)
		}
		return decoded, nil
	}
	if rest, ok := strings.CutPrefix(s, "raw:"); ok {
		raw := []byte(rest)
		if !isValidAESKeyLen(len(raw)) {
			return nil, fmt.Errorf("%s (raw) has invalid length: must be 16, 24, or 32 bytes", label)
		}
		return raw, nil
	}

	rawValid := isValidAESKeyLen(len(s))
	var b64 []byte
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil && isValidAESKeyLen(len(decoded)) {
		b64 = decoded
	}

	// Ambiguous: both interpretations yield a valid AES key, so we
	// can't safely guess what the operator meant. Refuse to boot
	// rather than picking one and silently corrupting all subsequent
	// writes the moment they decide later that it was the other one.
	if rawValid && b64 != nil {
		return nil, fmt.Errorf(
			"%s is ambiguous (valid as both raw bytes and base64-encoded). "+
				"Set the value with an explicit 'base64:' or 'raw:' prefix to lock in the intent. "+
				"For existing deployments that have been decrypting fine, the prior default was 'base64:'.",
			label,
		)
	}
	if b64 != nil {
		log.Warn().Str("which", label).Msg(
			"encryption key is using the bare-string format; switch to 'base64:<value>' to silence this warning and future-proof the config.",
		)
		return b64, nil
	}
	if rawValid {
		log.Warn().Str("which", label).Msg(
			"encryption key is using the bare-string format; switch to 'raw:<value>' to silence this warning and future-proof the config.",
		)
		return []byte(s), nil
	}
	return nil, fmt.Errorf("%s has invalid length: must be 16, 24, or 32 bytes (or base64 of those); use 'base64:' or 'raw:' prefix to be explicit", label)
}

func isValidAESKeyLen(n int) bool {
	return n == 16 || n == 24 || n == 32
}

// keyKid returns a 4-byte stable identifier for a key. Auto-derived
// from the key bytes so the operator never sees or types it. 4 bytes
// is plenty: with realistic rotation history (low single-digit keys
// concurrently configured) the birthday-collision space is ~2^16 keys
// before any meaningful collision risk.
func keyKid(key []byte) [kidLen]byte {
	sum := sha256.Sum256(key)
	var kid [kidLen]byte
	copy(kid[:], sum[:kidLen])
	return kid
}

const kidLen = 4

// versionGCMWithAAD is the legacy on-the-wire format from before key
// rotation tooling. Read-compat only — encrypts always write v0x04.
const versionGCMWithAAD byte = 0x03

// versionGCMWithAADKid is the active on-the-wire format. AEAD-GCM
// bound to a per-row AAD ("table:column:id") with a 4-byte key
// identifier so rotation windows can hold rows under the previous
// AND the new key concurrently.
const versionGCMWithAADKid byte = 0x04

// encryptGCMWithAADKid writes a v0x04 ciphertext:
// [0x04][kid:4][nonce:12][sealed-with-AAD]. The AAD is NOT stored in
// the ciphertext — the caller must supply the same bytes at decrypt
// time. The kid is NOT in the AAD: GCM's auth tag already binds the
// ciphertext to the key, so flipping the kid byte breaks decryption
// without help.
func encryptGCMWithAADKid(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(crand.Reader, nonce); err != nil {
		return nil, err
	}
	kid := keyKid(key)

	out := make([]byte, 0, 1+kidLen+len(nonce)+len(plaintext)+gcm.Overhead())
	out = append(out, versionGCMWithAADKid)
	out = append(out, kid[:]...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plaintext, aad)
	return out, nil
}

// decryptGCMWithAAD reverses the GCM-with-AAD layer. Caller has
// already stripped any version/kid prefix bytes. AAD mismatch surfaces
// as a generic "cipher: message authentication failed" — same shape
// as a tampered ciphertext. We don't try to distinguish the two
// failure modes for the caller; both mean "do not trust this row".
func decryptGCMWithAAD(key, data, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize+gcm.Overhead() {
		return nil, errors.New("GCM-with-AAD ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, aad)
}
