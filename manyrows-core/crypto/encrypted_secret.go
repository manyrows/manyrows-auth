package crypto

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
)

// system_secrets is a kv table that holds bootstrap material: the
// install's encryption_key (chicken-egg — must stay plaintext), the
// JWT signing keypair, the session HMAC + AEAD keys, the OTP pepper,
// the SMTP password mirror, and a few non-sensitive operator-editable
// rows (BASE_URL override, brand name). Anything sensitive in that
// list survives a pg_dump unless encrypted at rest — see the audit
// note in SECURITY for the threat model.
//
// EncodeSystemSecretValue / DecodeSystemSecretValue handle the
// on-disk format: sensitive rows are base64-encoded ciphertext under
// the install's encryption_key with the row name baked into the AAD
// so DB-write attackers can't shuffle blobs between rows.
//
// Legacy plaintext rows (pre-encryption migration) decode as-is so
// the bootstrap path stays backward-compatible; the wrapper store
// re-encrypts them on first read.

const (
	systemSecretsAADTable = "system_secrets"
	systemSecretsAADCol   = "value"

	// encryptedPrefix marks a value as encrypted on-disk.
	// Pre-migration rows do not have this prefix and are read as
	// plaintext; the encrypting wrapper rewrites them on first read.
	encryptedPrefix = "enc1:"
)

// AADNamed builds an AAD string for a row identified by a string key
// (e.g. system_secrets.name). Mirrors AAD() for uuid-keyed rows so
// every encrypted column in the schema follows the same
// table:column:id binding format.
func AADNamed(table, column, name string) []byte {
	return []byte(table + ":" + column + ":" + name)
}

// EncodeSystemSecretValue produces the on-disk representation of an
// encrypted system_secrets row: "enc1:<base64-ciphertext>". The AAD
// binds the ciphertext to the row name so swapping blobs between
// rows breaks authentication.
func EncodeSystemSecretValue(enc SecretEncryptor, name, plaintext string) (string, error) {
	if enc == nil {
		return "", errors.New("crypto: nil encryptor for system_secrets encode")
	}
	if strings.TrimSpace(name) == "" {
		return "", errors.New("crypto: empty name for system_secrets encode")
	}
	ct, err := enc.EncryptToBytesWithAAD([]byte(plaintext), AADNamed(systemSecretsAADTable, systemSecretsAADCol, name))
	if err != nil {
		return "", fmt.Errorf("encrypt system_secret %q: %w", name, err)
	}
	return encryptedPrefix + base64.StdEncoding.EncodeToString(ct), nil
}

// DecodeSystemSecretValue returns the plaintext for a stored value.
//
// Behaviour:
//   - empty input            → ("", false, nil), i.e. "no row"
//   - "enc1:..." prefix      → base64-decode, decrypt, return (pt, true, nil)
//   - anything else          → legacy plaintext row; return (stored, false, nil)
//     so the caller can opportunistically re-store it encrypted.
//
// A decrypt failure on a properly-prefixed row IS surfaced as an error
// — that's the operator booting with the wrong encryption_key, which
// must be a hard failure rather than a silent "treat as plaintext".
func DecodeSystemSecretValue(enc SecretEncryptor, name, stored string) (plaintext string, wasEncrypted bool, err error) {
	if stored == "" {
		return "", false, nil
	}
	if !strings.HasPrefix(stored, encryptedPrefix) {
		return stored, false, nil
	}
	if enc == nil {
		return "", false, errors.New("crypto: nil encryptor for encrypted system_secret")
	}
	ct, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, encryptedPrefix))
	if err != nil {
		return "", false, fmt.Errorf("decode system_secret %q: %w", name, err)
	}
	pt, err := enc.DecryptFromBytesWithAAD(ct, AADNamed(systemSecretsAADTable, systemSecretsAADCol, name))
	if err != nil {
		return "", false, fmt.Errorf("decrypt system_secret %q: %w", name, err)
	}
	return string(pt), true, nil
}

// systemSecretsBackingStore is the surface EncryptingSystemSecretsStore
// needs from its underlying store. Matches *core/repo.Repo's system
// secrets methods.
type systemSecretsBackingStore interface {
	GetSystemSecret(ctx context.Context, name string) (string, error)
	PutSystemSecret(ctx context.Context, name, value string) (string, error)
	UpsertSystemSecret(ctx context.Context, name, value string) error
	DeleteSystemSecret(ctx context.Context, name string) error
}

// EncryptingSystemSecretsStore wraps a system_secrets backing store and
// transparently encrypts every secret it touches except encryption_key
// — that one is the install's master KEK, so it must stay plaintext or
// nothing else could be decrypted on boot (chicken and egg).
//
// On read, the wrapper handles three shapes (see DecodeSystemSecretValue):
// fresh encrypted rows, empty (no row), and legacy plaintext rows. A
// legacy plaintext read is lazily re-stored encrypted via Upsert so the
// next read sees the modern form — best effort; the underlying error
// is logged but the read still succeeds with the plaintext value.
//
// On write, the wrapper always emits the encrypted form. Concurrent
// first-write-wins races (PutSystemSecret) decrypt the winner's blob
// so the caller's returned plaintext is consistent regardless of who
// won.
type EncryptingSystemSecretsStore struct {
	inner systemSecretsBackingStore
	enc   SecretEncryptor
}

// NewEncryptingSystemSecretsStore wraps store with transparent
// encryption for every name except encryption_key.
func NewEncryptingSystemSecretsStore(store systemSecretsBackingStore, enc SecretEncryptor) *EncryptingSystemSecretsStore {
	return &EncryptingSystemSecretsStore{inner: store, enc: enc}
}

// shouldEncrypt reports whether the given secret name's value should be
// encrypted at rest. encryption_key is excluded because the encryptor
// itself is built from it — encrypting it would break boot.
func (s *EncryptingSystemSecretsStore) shouldEncrypt(name string) bool {
	return name != "encryption_key"
}

// GetSystemSecret reads + decrypts the row. Legacy plaintext rows are
// re-stored encrypted in-place (best effort) so future reads short-
// circuit the migration path.
func (s *EncryptingSystemSecretsStore) GetSystemSecret(ctx context.Context, name string) (string, error) {
	raw, err := s.inner.GetSystemSecret(ctx, name)
	if err != nil || raw == "" {
		return raw, err
	}
	if !s.shouldEncrypt(name) {
		return raw, nil
	}
	pt, wasEncrypted, err := DecodeSystemSecretValue(s.enc, name, raw)
	if err != nil {
		return "", err
	}
	if !wasEncrypted {
		// Legacy plaintext row — re-store encrypted now. Best-effort:
		// log + continue if the rewrite fails. The plaintext we just
		// decoded is still correct to return either way.
		encoded, encErr := EncodeSystemSecretValue(s.enc, name, pt)
		if encErr != nil {
			log.Err(encErr).Str("secret", name).Msg("system_secrets: failed to encode legacy plaintext row for migration")
		} else if upErr := s.inner.UpsertSystemSecret(ctx, name, encoded); upErr != nil {
			log.Err(upErr).Str("secret", name).Msg("system_secrets: failed to rewrite legacy plaintext row as encrypted")
		} else {
			log.Info().Str("secret", name).Msg("system_secrets: migrated legacy plaintext row to encrypted form")
		}
	}
	return pt, nil
}

// PutSystemSecret encrypts then writes via the underlying store's
// first-write-wins primitive. If a concurrent writer won the race the
// returned plaintext reflects their value (decoded from their blob).
func (s *EncryptingSystemSecretsStore) PutSystemSecret(ctx context.Context, name, value string) (string, error) {
	if !s.shouldEncrypt(name) {
		return s.inner.PutSystemSecret(ctx, name, value)
	}
	encoded, err := EncodeSystemSecretValue(s.enc, name, value)
	if err != nil {
		return "", err
	}
	stored, err := s.inner.PutSystemSecret(ctx, name, encoded)
	if err != nil {
		return "", err
	}
	// Race lost: another caller's blob is already in place. Decode it
	// so the caller sees the actual stored plaintext, not their own
	// candidate. (The inner store returns the existing row's value
	// verbatim when ON CONFLICT DO NOTHING fires.)
	if stored == encoded {
		return value, nil
	}
	pt, _, decErr := DecodeSystemSecretValue(s.enc, name, stored)
	if decErr != nil {
		return "", decErr
	}
	return pt, nil
}

// UpsertSystemSecret encrypts then writes unconditionally.
func (s *EncryptingSystemSecretsStore) UpsertSystemSecret(ctx context.Context, name, value string) error {
	if !s.shouldEncrypt(name) {
		return s.inner.UpsertSystemSecret(ctx, name, value)
	}
	encoded, err := EncodeSystemSecretValue(s.enc, name, value)
	if err != nil {
		return err
	}
	return s.inner.UpsertSystemSecret(ctx, name, encoded)
}

// DeleteSystemSecret passes through. The crypto layer doesn't change
// the semantics of removing a row.
func (s *EncryptingSystemSecretsStore) DeleteSystemSecret(ctx context.Context, name string) error {
	return s.inner.DeleteSystemSecret(ctx, name)
}
