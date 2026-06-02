package jwks

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"
)

// samePrivateKey compares two ECDSA private keys by their PKCS8 encoding.
// Avoids touching the deprecated big.Int D field.
func samePrivateKey(t *testing.T, a, b *ecdsa.PrivateKey) bool {
	t.Helper()
	ab, err := x509.MarshalPKCS8PrivateKey(a)
	if err != nil {
		t.Fatalf("marshal a: %v", err)
	}
	bb, err := x509.MarshalPKCS8PrivateKey(b)
	if err != nil {
		t.Fatalf("marshal b: %v", err)
	}
	return bytes.Equal(ab, bb)
}

// fakeStore implements SecretsStore. PutSystemSecret is first-write-wins
// to mirror the production INSERT ON CONFLICT DO NOTHING semantic.
type fakeStore struct {
	mu   sync.Mutex
	rows map[string]string
}

func newFakeStore() *fakeStore { return &fakeStore{rows: map[string]string{}} }

func (f *fakeStore) GetSystemSecret(_ context.Context, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rows[name], nil
}

func (f *fakeStore) PutSystemSecret(_ context.Context, name, value string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if existing, ok := f.rows[name]; ok && existing != "" {
		return existing, nil
	}
	f.rows[name] = value
	return value, nil
}

// UpsertSystemSecret + DeleteSystemSecret round out MutableSecretsStore
// so the rotation tests can exercise the full surface without a real
// Postgres.
func (f *fakeStore) UpsertSystemSecret(_ context.Context, name, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows[name] = value
	return nil
}

func (f *fakeStore) DeleteSystemSecret(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rows, name)
	return nil
}

func TestLoadOrGenerate_FirstCallGenerates(t *testing.T) {
	store := newFakeStore()
	k, err := LoadOrGenerate(context.Background(), store)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	if k == nil || k.Private == nil {
		t.Fatal("nil key returned")
	}
	if k.KID == "" {
		t.Error("kid not set")
	}
	if k.Private.Curve != elliptic.P256() {
		t.Error("not P-256")
	}
	if got := store.rows[rowKey]; got == "" {
		t.Error("key was not persisted")
	}
}

func TestLoadOrGenerate_SecondCallReturnsSame(t *testing.T) {
	store := newFakeStore()
	k1, err := LoadOrGenerate(context.Background(), store)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	k2, err := LoadOrGenerate(context.Background(), store)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if k1.KID != k2.KID {
		t.Errorf("kid changed across calls: %s vs %s — keypair was regenerated", k1.KID, k2.KID)
	}
	if !samePrivateKey(t, k1.Private, k2.Private) {
		t.Error("private key changed across calls")
	}
}

func TestLoadOrGenerate_ConcurrentRaceConverges(t *testing.T) {
	// First-write-wins: two concurrent boots must converge to the same
	// keypair. Otherwise tokens signed by the loser would never verify.
	store := newFakeStore()
	const N = 8
	keys := make([]*Key, N)
	errs := make([]error, N)
	var wg sync.WaitGroup
	for i := range N {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			keys[i], errs[i] = LoadOrGenerate(context.Background(), store)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	for i := 1; i < N; i++ {
		if keys[i].KID != keys[0].KID {
			t.Fatalf("goroutine %d returned kid %s, expected %s", i, keys[i].KID, keys[0].KID)
		}
	}
}

func TestLoadOrGenerate_NilStore(t *testing.T) {
	_, err := LoadOrGenerate(context.Background(), nil)
	if err == nil {
		t.Fatal("nil store: want error")
	}
}

func TestLoadOrGenerate_BadStoredPEM(t *testing.T) {
	store := newFakeStore()
	store.rows[rowKey] = "not a pem"
	_, err := LoadOrGenerate(context.Background(), store)
	if err == nil || !strings.Contains(err.Error(), "stored key parse") {
		t.Fatalf("want parse error, got %v", err)
	}
}

func TestParsePEM_RejectsRSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	if _, err := parsePEM(pemStr); err == nil {
		t.Fatal("want error rejecting RSA key, got nil")
	}
}

func TestParsePEM_RejectsP384(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("p384 gen: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(p384)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	_, err = parsePEM(pemStr)
	if err == nil || !strings.Contains(err.Error(), "P-256") {
		t.Fatalf("want P-256 error, got %v", err)
	}
}

func TestParsePEM_NotPEM(t *testing.T) {
	if _, err := parsePEM("garbage"); err == nil {
		t.Fatal("want error")
	}
}

func TestThumbprint_Deterministic(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := thumbprint(&priv.PublicKey)
	b := thumbprint(&priv.PublicKey)
	if a != b {
		t.Errorf("thumbprint not deterministic: %q vs %q", a, b)
	}
	if a == "" {
		t.Error("empty thumbprint")
	}
	// thumbprint must be base64url of a sha256 (32 bytes → 43 chars unpadded).
	raw, err := base64.RawURLEncoding.DecodeString(a)
	if err != nil {
		t.Fatalf("thumbprint not base64url: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("thumbprint length: got %d want 32", len(raw))
	}
}

func TestThumbprint_DifferentKeysDifferentThumbprints(t *testing.T) {
	a, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if thumbprint(&a.PublicKey) == thumbprint(&b.PublicKey) {
		t.Error("two distinct keys produced the same thumbprint")
	}
}

func TestKey_Document(t *testing.T) {
	store := newFakeStore()
	k, err := LoadOrGenerate(context.Background(), store)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	doc, err := k.Document()
	if err != nil {
		t.Fatalf("Document: %v", err)
	}
	var parsed JWKSDocument
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("Document is not valid JSON: %v\n%s", err, doc)
	}
	if len(parsed.Keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(parsed.Keys))
	}
	jwk := parsed.Keys[0]
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.Use != "sig" || jwk.Alg != "ES256" {
		t.Errorf("wrong header values: %+v", jwk)
	}
	if jwk.Kid != k.KID {
		t.Errorf("kid mismatch: doc=%s key=%s", jwk.Kid, k.KID)
	}
	// X and Y must decode as 32-byte big-endian coordinates.
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || len(x) != 32 {
		t.Errorf("x bad: err=%v len=%d", err, len(x))
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil || len(y) != 32 {
		t.Errorf("y bad: err=%v len=%d", err, len(y))
	}
}

func TestKey_DocumentNil(t *testing.T) {
	var k *Key
	if _, err := k.Document(); err == nil {
		t.Fatal("nil receiver: want error")
	}
	empty := &Key{}
	if _, err := empty.Document(); err == nil {
		t.Fatal("nil Private: want error")
	}
}

func TestKey_PublicKeyByKID(t *testing.T) {
	store := newFakeStore()
	k, err := LoadOrGenerate(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if got := k.PublicKeyByKID(k.KID); got == nil {
		t.Error("matching kid: want pubkey, got nil")
	}
	if got := k.PublicKeyByKID(""); got == nil {
		t.Error("empty kid: callers passing no kid should still get the key")
	}
	if got := k.PublicKeyByKID("nonsense"); got != nil {
		t.Error("unknown kid: want nil so caller refetches JWKS")
	}

	var nilKey *Key
	if got := nilKey.PublicKeyByKID("x"); got != nil {
		t.Error("nil receiver: want nil")
	}
}

func TestKey_String(t *testing.T) {
	var nilKey *Key
	if nilKey.String() != "<nil>" {
		t.Errorf("nil receiver: %q", nilKey.String())
	}
	store := newFakeStore()
	k, _ := LoadOrGenerate(context.Background(), store)
	s := k.String()
	if !strings.Contains(s, k.KID) {
		t.Errorf("String missing kid: %q", s)
	}
	// Curve label only — must not include any encoding of the secret.
	if strings.Contains(s, "PRIVATE KEY") || strings.Contains(strings.ToLower(s), "scalar") {
		t.Errorf("String leaks private material: %q", s)
	}
}

// errStore returns an error from PutSystemSecret to exercise the persist
// failure path in LoadOrGenerate.
type errStore struct{}

func (errStore) GetSystemSecret(_ context.Context, _ string) (string, error) {
	return "", nil
}
func (errStore) PutSystemSecret(_ context.Context, _, _ string) (string, error) {
	return "", errors.New("disk on fire")
}

func TestLoadOrGenerate_PersistError(t *testing.T) {
	_, err := LoadOrGenerate(context.Background(), errStore{})
	if err == nil || !strings.Contains(err.Error(), "persist") {
		t.Fatalf("want persist error, got %v", err)
	}
}

// =====================================================================
// KeySet rotation tests
// =====================================================================

func TestLoadOrGenerateSet_NoPrevious(t *testing.T) {
	store := newFakeStore()
	set, err := LoadOrGenerateSet(context.Background(), store)
	if err != nil {
		t.Fatalf("LoadOrGenerateSet: %v", err)
	}
	if set.Current == nil {
		t.Fatal("Current is nil on fresh boot")
	}
	if set.Previous != nil {
		t.Errorf("Previous should be nil on fresh boot, got %+v", set.Previous)
	}
}

func TestLoadOrGenerateSet_LoadsPrevious(t *testing.T) {
	store := newFakeStore()
	// Seed a previous key by simulating a prior rotation: write both
	// rows directly.
	first, err := LoadOrGenerate(context.Background(), store)
	if err != nil {
		t.Fatalf("seed current: %v", err)
	}
	// Rotate so previous is set.
	set, err := LoadOrGenerateSet(context.Background(), store)
	if err != nil {
		t.Fatalf("load set: %v", err)
	}
	rotated, err := set.Rotate(context.Background(), store)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated.Previous == nil || rotated.Previous.KID != first.KID {
		t.Errorf("after rotate, previous should be the original key (%s); got %+v", first.KID, rotated.Previous)
	}
	// Reload from store — both rows should round-trip.
	reloaded, err := LoadOrGenerateSet(context.Background(), store)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Current.KID != rotated.Current.KID {
		t.Errorf("reloaded current kid mismatch: %s vs %s", reloaded.Current.KID, rotated.Current.KID)
	}
	if reloaded.Previous == nil || reloaded.Previous.KID != first.KID {
		t.Errorf("reloaded previous kid mismatch: %v vs %s", reloaded.Previous, first.KID)
	}
}

func TestKeySet_RotateProducesFreshKID(t *testing.T) {
	store := newFakeStore()
	set, err := LoadOrGenerateSet(context.Background(), store)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	origKID := set.Current.KID
	rotated, err := set.Rotate(context.Background(), store)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated.Current.KID == origKID {
		t.Error("rotate produced same kid — keypair was not regenerated")
	}
	if rotated.Previous.KID != origKID {
		t.Errorf("previous kid mismatch: %s vs %s", rotated.Previous.KID, origKID)
	}
}

func TestKeySet_DocumentPublishesBothKeys(t *testing.T) {
	store := newFakeStore()
	set, _ := LoadOrGenerateSet(context.Background(), store)
	doc1, _ := set.Document()
	var d1 JWKSDocument
	if err := json.Unmarshal(doc1, &d1); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(d1.Keys) != 1 {
		t.Errorf("steady state: want 1 key, got %d", len(d1.Keys))
	}

	rotated, _ := set.Rotate(context.Background(), store)
	doc2, _ := rotated.Document()
	var d2 JWKSDocument
	if err := json.Unmarshal(doc2, &d2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(d2.Keys) != 2 {
		t.Fatalf("post-rotate: want 2 keys, got %d", len(d2.Keys))
	}
	if d2.Keys[0].Kid != rotated.Current.KID {
		t.Errorf("first key should be current: %s vs %s", d2.Keys[0].Kid, rotated.Current.KID)
	}
	if d2.Keys[1].Kid != rotated.Previous.KID {
		t.Errorf("second key should be previous: %s vs %s", d2.Keys[1].Kid, rotated.Previous.KID)
	}
}

func TestKeySet_PublicKeyByKIDChecksBothSlots(t *testing.T) {
	store := newFakeStore()
	set, _ := LoadOrGenerateSet(context.Background(), store)
	origKID := set.Current.KID

	rotated, err := set.Rotate(context.Background(), store)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// Current kid hits Current.
	if pub := rotated.PublicKeyByKID(rotated.Current.KID); pub == nil {
		t.Error("current kid should resolve to current public key")
	}
	// Previous kid hits Previous — the in-flight-token case.
	if pub := rotated.PublicKeyByKID(origKID); pub == nil {
		t.Error("previous kid should resolve via Previous slot")
	}
	// Unknown kid resolves to nil.
	if pub := rotated.PublicKeyByKID("not-a-real-kid"); pub != nil {
		t.Error("unknown kid should return nil")
	}
	// Empty kid resolves to current (back-compat with pre-kid tokens).
	if pub := rotated.PublicKeyByKID(""); pub == nil {
		t.Error("empty kid should resolve to current public key")
	}
}

func TestKeySet_RetirePreviousDropsRowAndField(t *testing.T) {
	store := newFakeStore()
	set, _ := LoadOrGenerateSet(context.Background(), store)
	rotated, _ := set.Rotate(context.Background(), store)
	if rotated.Previous == nil {
		t.Fatal("setup: Previous should be set after rotate")
	}
	if got := store.rows[rowKeyPrevious]; got == "" {
		t.Fatal("setup: previous row should be present")
	}
	retired, err := rotated.RetirePrevious(context.Background(), store)
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	if retired.Previous != nil {
		t.Error("retire should null out the Previous field")
	}
	if _, ok := store.rows[rowKeyPrevious]; ok {
		t.Error("retire should delete the previous row from the store")
	}
}

func TestKeySet_RetirePreviousNoOpWhenAlreadyRetired(t *testing.T) {
	store := newFakeStore()
	set, _ := LoadOrGenerateSet(context.Background(), store)
	retired, err := set.RetirePrevious(context.Background(), store)
	if err != nil {
		t.Fatalf("retire on no-previous keyset: %v", err)
	}
	if retired.Previous != nil {
		t.Error("retire on no-previous keyset should remain Previous == nil")
	}
	if retired.Current.KID != set.Current.KID {
		t.Error("retire should not touch the current key")
	}
}

func TestKeySet_RotateTwiceLosesOldestKey(t *testing.T) {
	// Rotation policy: only the most recent prior key is kept. A
	// rotate-before-retire sequence overwrites the previous slot,
	// dropping the oldest key — which is the desired retirement
	// semantic (operators who roll fast accept that older tokens
	// fail to verify).
	store := newFakeStore()
	set, _ := LoadOrGenerateSet(context.Background(), store)
	originalKID := set.Current.KID

	first, _ := set.Rotate(context.Background(), store)
	if first.Previous.KID != originalKID {
		t.Fatalf("after rotate 1, previous should be the original key (%s); got %s",
			originalKID, first.Previous.KID)
	}

	second, _ := first.Rotate(context.Background(), store)
	if second.Previous.KID != first.Current.KID {
		t.Errorf("after rotate 2, previous should be rotate-1's current (%s); got %s",
			first.Current.KID, second.Previous.KID)
	}
	if second.Previous.KID == originalKID {
		t.Error("after rotate 2, previous should NOT still be the very-first key")
	}
}

func TestKeySet_DocumentEmptyKeysetErrors(t *testing.T) {
	var empty *KeySet
	if _, err := empty.Document(); err == nil {
		t.Error("Document on nil KeySet should error")
	}
	if _, err := (&KeySet{}).Document(); err == nil {
		t.Error("Document on empty KeySet (no Current) should error")
	}
}

func TestLoadOrGenerateSet_MalformedPreviousIsLoggedNotFatal(t *testing.T) {
	store := newFakeStore()
	// Seed current via normal path, then write a garbage previous.
	if _, err := LoadOrGenerate(context.Background(), store); err != nil {
		t.Fatalf("seed: %v", err)
	}
	store.rows[rowKeyPrevious] = "not-a-pem"

	set, err := LoadOrGenerateSet(context.Background(), store)
	// We return the working keyset PLUS a non-nil error so the caller
	// can decide whether to fail the boot. Current must still be loaded.
	if set == nil || set.Current == nil {
		t.Fatal("malformed previous should not block Current from loading")
	}
	if err == nil {
		t.Error("expected a non-fatal error describing the malformed previous")
	}
	if set.Previous != nil {
		t.Error("malformed previous should be dropped, not loaded")
	}
}
