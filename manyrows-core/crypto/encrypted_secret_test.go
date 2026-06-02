package crypto

// Tests for the system_secrets encryption helpers + the encrypting
// store wrapper. Cover: round-trip, legacy plaintext compat, lazy
// migration on first read, AAD binding (different row name → can't
// swap blobs), encryption_key passthrough.
//
// Uses an in-memory fake of the four system_secrets methods so
// these run without a database.

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// fakeStore is a minimal in-memory system_secrets backing store
// satisfying the systemSecretsBackingStore interface. Behaviour
// matches the real repo's contracts: Put = first-write-wins,
// Upsert = unconditional write, Delete = best-effort remove.
type fakeStore struct {
	mu      sync.Mutex
	values  map[string]string
	upserts int
	puts    int
}

func newFakeStore() *fakeStore {
	return &fakeStore{values: map[string]string{}}
}

func (f *fakeStore) GetSystemSecret(_ context.Context, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.values[name], nil
}

func (f *fakeStore) PutSystemSecret(_ context.Context, name, value string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts++
	if existing, ok := f.values[name]; ok {
		return existing, nil
	}
	f.values[name] = value
	return value, nil
}

func (f *fakeStore) UpsertSystemSecret(_ context.Context, name, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upserts++
	f.values[name] = value
	return nil
}

func (f *fakeStore) DeleteSystemSecret(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.values, name)
	return nil
}

func TestSystemSecretValue_RoundTrip(t *testing.T) {
	enc := newEncryptorWithKey(t, testKey)

	encoded, err := EncodeSystemSecretValue(enc, "jwt_signing_key_pem", "the secret payload")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.HasPrefix(encoded, "enc1:") {
		t.Fatalf("encoded value should have enc1: prefix, got %q", encoded)
	}

	pt, wasEncrypted, err := DecodeSystemSecretValue(enc, "jwt_signing_key_pem", encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !wasEncrypted {
		t.Error("expected wasEncrypted=true on a fresh round-trip")
	}
	if pt != "the secret payload" {
		t.Errorf("round-trip mismatch: got %q", pt)
	}
}

func TestSystemSecretValue_LegacyPlaintextAcceptedAsIs(t *testing.T) {
	enc := newEncryptorWithKey(t, testKey)

	// Legacy rows from pre-encryption deploys don't carry the prefix.
	// Decode returns them as plaintext with wasEncrypted=false so the
	// caller can opportunistically rewrite them.
	pt, wasEncrypted, err := DecodeSystemSecretValue(enc, "session_auth_key", "deadbeefcafedeadbeefcafedeadbeefcafe")
	if err != nil {
		t.Fatalf("decode of legacy plaintext: %v", err)
	}
	if wasEncrypted {
		t.Error("wasEncrypted should be false for a value without the prefix")
	}
	if pt != "deadbeefcafedeadbeefcafedeadbeefcafe" {
		t.Errorf("legacy plaintext should pass through unchanged, got %q", pt)
	}
}

func TestSystemSecretValue_DecryptFailureSurfaces(t *testing.T) {
	enc := newEncryptorWithKey(t, testKey)

	// A value that LOOKS encrypted (has the prefix) but isn't valid
	// must surface as an error — that's the operator booting with
	// the wrong encryption_key, which has to be a hard failure
	// rather than a silent "treat as plaintext."
	_, _, err := DecodeSystemSecretValue(enc, "jwt_signing_key_pem", "enc1:!!!garbage-base64")
	if err == nil {
		t.Error("expected error on enc1:-prefixed garbage; got nil")
	}
}

func TestSystemSecretValue_AADBindsRowName(t *testing.T) {
	enc := newEncryptorWithKey(t, testKey)

	encoded, err := EncodeSystemSecretValue(enc, "jwt_signing_key_pem", "row-A-secret")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Decoding the same blob under a different row name MUST fail —
	// AAD binding stops a DB-write attacker from shuffling encrypted
	// blobs between rows.
	_, _, err = DecodeSystemSecretValue(enc, "session_auth_key", encoded)
	if err == nil {
		t.Error("expected AAD-mismatch error when decoding under wrong row name; got nil")
	}
}

func TestEncryptingStore_WriteEncrypts(t *testing.T) {
	ctx := context.Background()
	enc := newEncryptorWithKey(t, testKey)
	inner := newFakeStore()
	store := NewEncryptingSystemSecretsStore(inner, enc)

	if _, err := store.PutSystemSecret(ctx, "smtp_password", "swordfish"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	raw := inner.values["smtp_password"]
	if !strings.HasPrefix(raw, "enc1:") {
		t.Fatalf("raw stored value should be enc1: prefixed, got %q", raw)
	}
	if strings.Contains(raw, "swordfish") {
		t.Error("plaintext leaked into raw stored value")
	}

	// Read-back through the wrapper returns plaintext.
	pt, err := store.GetSystemSecret(ctx, "smtp_password")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if pt != "swordfish" {
		t.Errorf("Get returned %q, want swordfish", pt)
	}
}

func TestEncryptingStore_LegacyPlaintextRowMigratesOnRead(t *testing.T) {
	ctx := context.Background()
	enc := newEncryptorWithKey(t, testKey)
	inner := newFakeStore()
	// Simulate a pre-migration deploy: a plaintext row was written
	// before the encrypting wrapper existed.
	inner.values["session_auth_key"] = "legacy-plaintext-value"

	store := NewEncryptingSystemSecretsStore(inner, enc)

	// First read returns the plaintext + triggers the lazy rewrite.
	pt, err := store.GetSystemSecret(ctx, "session_auth_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if pt != "legacy-plaintext-value" {
		t.Errorf("Get returned %q, want legacy-plaintext-value", pt)
	}

	// Inner store should now hold the encrypted form.
	raw := inner.values["session_auth_key"]
	if !strings.HasPrefix(raw, "enc1:") {
		t.Errorf("legacy row should have been rewritten as enc1:, got %q", raw)
	}
	if inner.upserts == 0 {
		t.Error("expected the lazy migration to Upsert the new encrypted form")
	}

	// Second read works against the rewritten row.
	pt2, err := store.GetSystemSecret(ctx, "session_auth_key")
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if pt2 != "legacy-plaintext-value" {
		t.Errorf("second Get returned %q, want legacy-plaintext-value", pt2)
	}
}

func TestEncryptingStore_EncryptionKeyPassthrough(t *testing.T) {
	ctx := context.Background()
	enc := newEncryptorWithKey(t, testKey)
	inner := newFakeStore()
	store := NewEncryptingSystemSecretsStore(inner, enc)

	const masterKey = "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if _, err := store.PutSystemSecret(ctx, "encryption_key", masterKey); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// encryption_key bootstraps the encryptor itself, so encrypting
	// it would prevent boot. The wrapper must pass it through
	// verbatim.
	if got := inner.values["encryption_key"]; got != masterKey {
		t.Errorf("encryption_key should be stored verbatim; got %q", got)
	}
	if pt, err := store.GetSystemSecret(ctx, "encryption_key"); err != nil || pt != masterKey {
		t.Errorf("encryption_key round-trip: pt=%q err=%v", pt, err)
	}
}

func TestEncryptingStore_PutLostRaceDecodesWinner(t *testing.T) {
	ctx := context.Background()
	enc := newEncryptorWithKey(t, testKey)
	inner := newFakeStore()
	// Pre-seed with an encrypted "winner" value so PutSystemSecret's
	// first-write-wins kicks in.
	winnerEncoded, err := EncodeSystemSecretValue(enc, "otp_pepper", "first-writer-pepper")
	if err != nil {
		t.Fatalf("setup encode: %v", err)
	}
	inner.values["otp_pepper"] = winnerEncoded

	store := NewEncryptingSystemSecretsStore(inner, enc)

	// Now race in with a different candidate. The wrapper should
	// return the WINNER's plaintext (decoded from the existing
	// blob), not the caller's candidate.
	got, err := store.PutSystemSecret(ctx, "otp_pepper", "loser-pepper")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got != "first-writer-pepper" {
		t.Errorf("lost-race Put returned %q, want first-writer-pepper", got)
	}
}
