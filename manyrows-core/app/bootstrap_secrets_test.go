package app

// Unit tests for bootstrapSecrets — no DB. The function takes the
// secretsStore interface, which we satisfy with an in-memory map so
// we can drive the env-precedence + generation + persistence cases
// directly.

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
)

type fakeStore struct {
	mu      sync.Mutex
	values  map[string]string
	getN    int
	putN    int
	failGet bool
}

func newFakeStore() *fakeStore { return &fakeStore{values: map[string]string{}} }

func (f *fakeStore) GetSystemSecret(_ context.Context, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getN++
	if f.failGet {
		return "", errors.New("simulated read error")
	}
	return f.values[name], nil
}

func (f *fakeStore) PutSystemSecret(_ context.Context, name, value string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.putN++
	if existing, ok := f.values[name]; ok {
		// Mirrors the real repo's ON CONFLICT DO NOTHING semantic.
		return existing, nil
	}
	f.values[name] = value
	return value, nil
}

func (f *fakeStore) UpsertSystemSecret(_ context.Context, name, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.putN++
	f.values[name] = value
	return nil
}

func (f *fakeStore) DeleteSystemSecret(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.values, name)
	return nil
}

const testPrefix = "BOOTSTRAP_TEST_"

// resetEnv unsets every env var bootstrapSecrets can write. t.Setenv
// would be cleaner per-var but bootstrap touches a fixed set, so a
// loop is fine and keeps the per-test setup tight.
func resetEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		testPrefix + "SESSION_AUTH_KEY",
		testPrefix + "SESSION_SECRET_KEY",
		testPrefix + "ENCRYPTION_KEY",
		testPrefix + "PREVIOUS_ENCRYPTION_KEYS",
		testPrefix + "OTP_PEPPER",
	} {
		t.Setenv(name, "")
	}
}

func TestBootstrapSecrets_GeneratesAllOnFirstBoot(t *testing.T) {
	resetEnv(t)
	store := newFakeStore()
	if err := bootstrapSecrets(context.Background(), store, testPrefix); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	wantSecrets := []string{"session_auth_key", "session_secret_key", "encryption_key", "otp_pepper"}
	for _, name := range wantSecrets {
		if v, ok := store.values[name]; !ok || v == "" {
			t.Errorf("%s not persisted (got %q)", name, v)
		}
	}
	// Encryption key has the format the encrypter parses.
	if !strings.HasPrefix(store.values["encryption_key"], "base64:") {
		t.Errorf("encryption_key must use base64: prefix, got %q", store.values["encryption_key"])
	}
	// Hex-encoded keys are the right length for the [:N] slicing in config.
	if len(store.values["session_auth_key"]) < 64 {
		t.Errorf("session_auth_key too short: %d", len(store.values["session_auth_key"]))
	}
	if len(store.values["session_secret_key"]) < 32 {
		t.Errorf("session_secret_key too short: %d", len(store.values["session_secret_key"]))
	}
}

func TestBootstrapSecrets_EnvWinsOverDB(t *testing.T) {
	resetEnv(t)
	t.Setenv(testPrefix+"SESSION_SECRET_KEY", "operator-supplied-session-secret-with-enough-padding")

	store := newFakeStore()
	store.values["session_secret_key"] = "stale-db-value-from-an-old-deploy"

	if err := bootstrapSecrets(context.Background(), store, testPrefix); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	// Operator-supplied env wins; the DB row must NOT be overwritten.
	if got := store.values["session_secret_key"]; got != "stale-db-value-from-an-old-deploy" {
		t.Errorf("DB row got overwritten: %q", got)
	}
	// And we did NOT touch their env value.
	if got := getEnv(t, testPrefix+"SESSION_SECRET_KEY"); got != "operator-supplied-session-secret-with-enough-padding" {
		t.Errorf("env var clobbered: %q", got)
	}
}

func TestBootstrapSecrets_ReusesPersistedValues(t *testing.T) {
	resetEnv(t)
	store := newFakeStore()

	// First boot generates everything.
	if err := bootstrapSecrets(context.Background(), store, testPrefix); err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	first := map[string]string{}
	for k, v := range store.values {
		first[k] = v
	}
	puts1 := store.putN

	// Reset env (simulating a process restart) and run again. Same
	// values should be reused — no new generation, no new writes.
	resetEnv(t)
	if err := bootstrapSecrets(context.Background(), store, testPrefix); err != nil {
		t.Fatalf("second bootstrap: %v", err)
	}
	if store.putN != puts1 {
		t.Errorf("expected no new writes on second boot, got %d new", store.putN-puts1)
	}
	for k, v := range first {
		if store.values[k] != v {
			t.Errorf("%s changed across boot: %q → %q", k, v, store.values[k])
		}
	}
}

func TestBootstrapSecrets_PropagatesToEnv(t *testing.T) {
	resetEnv(t)
	store := newFakeStore()

	if err := bootstrapSecrets(context.Background(), store, testPrefix); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if got := getEnv(t, testPrefix+"SESSION_AUTH_KEY"); got == "" {
		t.Error("SESSION_AUTH_KEY not exported to env after generate")
	}
	if got := getEnv(t, testPrefix+"ENCRYPTION_KEY"); !strings.HasPrefix(got, "base64:") {
		t.Errorf("ENCRYPTION_KEY not exported with base64: prefix; got %q", got)
	}
	if got := getEnv(t, testPrefix+"OTP_PEPPER"); got == "" {
		t.Error(testPrefix + "OTP_PEPPER not exported to env")
	}
}

// ENCRYPTION_KEY is special — every encrypted column is bound to it,
// so booting under a key that differs from what's stored would silently
// corrupt new writes. The guard refuses to boot unless the operator
// has signalled an intentional rotation.

func TestBootstrapSecrets_EncryptionKeyEnvMatchesStored_OK(t *testing.T) {
	resetEnv(t)
	store := newFakeStore()
	const key = "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	store.values["encryption_key"] = key
	t.Setenv(testPrefix+"ENCRYPTION_KEY", key)

	if err := bootstrapSecrets(context.Background(), store, testPrefix); err != nil {
		t.Fatalf("bootstrap should accept matching env+stored: %v", err)
	}
}

func TestBootstrapSecrets_EncryptionKeyMismatchWithoutPrevious_Refuses(t *testing.T) {
	resetEnv(t)
	store := newFakeStore()
	store.values["encryption_key"] = "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	t.Setenv(testPrefix+"ENCRYPTION_KEY", "base64:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=")

	err := bootstrapSecrets(context.Background(), store, testPrefix)
	if err == nil {
		t.Fatal("expected refusal when env differs from stored without rotation signal")
	}
	if !strings.Contains(err.Error(), "PREVIOUS_ENCRYPTION_KEYS") {
		t.Errorf("error should point operators at PREVIOUS_ENCRYPTION_KEYS; got %q", err.Error())
	}
}

func TestBootstrapSecrets_EncryptionKeyMismatchWithPrevious_AllowsRotation(t *testing.T) {
	resetEnv(t)
	store := newFakeStore()
	const oldKey = "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const newKey = "base64:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
	store.values["encryption_key"] = oldKey
	t.Setenv(testPrefix+"ENCRYPTION_KEY", newKey)
	t.Setenv(testPrefix+"PREVIOUS_ENCRYPTION_KEYS", oldKey)

	if err := bootstrapSecrets(context.Background(), store, testPrefix); err != nil {
		t.Fatalf("bootstrap should accept rotation when PREVIOUS_ENCRYPTION_KEYS is set: %v", err)
	}
	// Stored value isn't overwritten by env-wins; the rotation is
	// expected to be finished by `./web migrate-encryption` separately.
	if got := store.values["encryption_key"]; got != oldKey {
		t.Errorf("stored key should be untouched during rotation boot; got %q", got)
	}
}

func TestBootstrapSecrets_ReadErrorBubbles(t *testing.T) {
	resetEnv(t)
	store := newFakeStore()
	store.failGet = true
	if err := bootstrapSecrets(context.Background(), store, testPrefix); err == nil {
		t.Error("expected error to bubble from store.GetSystemSecret")
	}
}

func getEnv(t *testing.T, name string) string {
	t.Helper()
	return os.Getenv(name)
}
