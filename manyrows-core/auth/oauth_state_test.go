package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
)

// fakeOAuthStateStore is an in-memory implementation of OAuthStateStore.
// Mirrors repo.ErrOAuthStateNotFoundOrConsumed by string text — the
// auth package matches the sentinel by Error() to avoid importing repo.
type fakeOAuthStateStore struct {
	rows     map[uuid.UUID]oauthStateRow
	insertOK bool
}

type oauthStateRow struct {
	appID        uuid.UUID
	provider     string
	openerOrigin string
	preloginSes  *uuid.UUID
	expiresAt    time.Time
	consumed     bool
}

var errFakeNotFoundOrConsumed = errors.New("oauth state not found or already consumed")

func newFakeStore() *fakeOAuthStateStore {
	return &fakeOAuthStateStore{rows: map[uuid.UUID]oauthStateRow{}, insertOK: true}
}

func (f *fakeOAuthStateStore) InsertOAuthState(_ context.Context, jti, appID uuid.UUID, provider, openerOrigin string, preloginSessionID *uuid.UUID, expiresAt time.Time) error {
	if !f.insertOK {
		return errors.New("insert failed")
	}
	f.rows[jti] = oauthStateRow{
		appID:        appID,
		provider:     provider,
		openerOrigin: openerOrigin,
		preloginSes:  preloginSessionID,
		expiresAt:    expiresAt,
	}
	return nil
}

func (f *fakeOAuthStateStore) ConsumeOAuthState(_ context.Context, jti uuid.UUID) (uuid.UUID, string, string, *uuid.UUID, error) {
	row, ok := f.rows[jti]
	if !ok || row.consumed {
		return uuid.Nil, "", "", nil, errFakeNotFoundOrConsumed
	}
	if time.Now().UTC().After(row.expiresAt) {
		return uuid.Nil, "", "", nil, errFakeNotFoundOrConsumed
	}
	row.consumed = true
	f.rows[jti] = row
	return row.appID, row.provider, row.openerOrigin, row.preloginSes, nil
}

func (f *fakeOAuthStateStore) PeekOAuthStateOpenerOrigin(_ context.Context, jti uuid.UUID) (string, error) {
	row, ok := f.rows[jti]
	if !ok || row.consumed {
		return "", errFakeNotFoundOrConsumed
	}
	return row.openerOrigin, nil
}

func newKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func TestOAuthState_RoundTrip(t *testing.T) {
	store := newFakeStore()
	key := newKey()
	appID := uuid.Must(uuid.NewV4())
	ctx := context.Background()

	tok, err := SignOAuthState(ctx, store, key, appID, "google", "https://app.example.com", nil, time.Minute)
	if err != nil {
		t.Fatalf("SignOAuthState: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}

	gotApp, gotOrigin, _, err := VerifyOAuthState(ctx, store, key, tok, "google")
	if err != nil {
		t.Fatalf("VerifyOAuthState: %v", err)
	}
	if gotApp != appID {
		t.Errorf("appID: got %s want %s", gotApp, appID)
	}
	if gotOrigin != "https://app.example.com" {
		t.Errorf("origin: got %q", gotOrigin)
	}
}

func TestOAuthState_Replay(t *testing.T) {
	store := newFakeStore()
	key := newKey()
	appID := uuid.Must(uuid.NewV4())
	ctx := context.Background()

	tok, err := SignOAuthState(ctx, store, key, appID, "github", "", nil, time.Minute)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, _, _, err := VerifyOAuthState(ctx, store, key, tok, "github"); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	_, _, _, err = VerifyOAuthState(ctx, store, key, tok, "github")
	if !errors.Is(err, ErrOAuthStateReused) {
		t.Fatalf("replay: want ErrOAuthStateReused, got %v", err)
	}
}

func TestOAuthState_TamperedHMAC(t *testing.T) {
	store := newFakeStore()
	key := newKey()
	appID := uuid.Must(uuid.NewV4())
	ctx := context.Background()

	tok, err := SignOAuthState(ctx, store, key, appID, "apple", "", nil, time.Minute)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Decode, flip last byte of HMAC, re-encode.
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	bad := base64.RawURLEncoding.EncodeToString(raw)

	_, _, _, err = VerifyOAuthState(ctx, store, key, bad, "apple")
	if !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("tampered: want ErrOAuthStateInvalid, got %v", err)
	}
}

func TestOAuthState_TamperedAppID(t *testing.T) {
	store := newFakeStore()
	key := newKey()
	appID := uuid.Must(uuid.NewV4())
	ctx := context.Background()

	tok, err := SignOAuthState(ctx, store, key, appID, "microsoft", "", nil, time.Minute)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(tok)
	raw[0] ^= 0x01 // flip a bit in app_id portion of payload
	bad := base64.RawURLEncoding.EncodeToString(raw)

	// HMAC will fail first, so this still maps to ErrOAuthStateInvalid.
	_, _, _, err = VerifyOAuthState(ctx, store, key, bad, "microsoft")
	if !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("appID-tampered: want ErrOAuthStateInvalid, got %v", err)
	}
}

func TestOAuthState_Expired(t *testing.T) {
	store := newFakeStore()
	key := newKey()
	appID := uuid.Must(uuid.NewV4())
	ctx := context.Background()

	// Negative TTL → token expires before VerifyOAuthState looks at it.
	tok, err := SignOAuthState(ctx, store, key, appID, "google", "", nil, -time.Second)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	_, _, _, err = VerifyOAuthState(ctx, store, key, tok, "google")
	if !errors.Is(err, ErrOAuthStateExpired) {
		t.Fatalf("expired: want ErrOAuthStateExpired, got %v", err)
	}
}

func TestOAuthState_ProviderMismatch(t *testing.T) {
	store := newFakeStore()
	key := newKey()
	appID := uuid.Must(uuid.NewV4())
	ctx := context.Background()

	tok, err := SignOAuthState(ctx, store, key, appID, "google", "", nil, time.Minute)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Same token, wrong expectedProvider — defends against an attacker
	// swapping a Google state into the GitHub callback.
	_, _, _, err = VerifyOAuthState(ctx, store, key, tok, "github")
	if !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("provider-mismatch: want ErrOAuthStateInvalid, got %v", err)
	}
}

func TestOAuthState_WrongKey(t *testing.T) {
	store := newFakeStore()
	key := newKey()
	other := make([]byte, 32) // all zeros — different key
	appID := uuid.Must(uuid.NewV4())
	ctx := context.Background()

	tok, err := SignOAuthState(ctx, store, other, appID, "google", "", nil, time.Minute)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	_, _, _, err = VerifyOAuthState(ctx, store, key, tok, "google")
	if !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("wrong key: want ErrOAuthStateInvalid, got %v", err)
	}
}

func TestOAuthState_MalformedInput(t *testing.T) {
	store := newFakeStore()
	key := newKey()
	ctx := context.Background()

	cases := map[string]string{
		"empty":      "",
		"not base64": "!!! not valid base64 !!!",
		"too short":  base64.RawURLEncoding.EncodeToString([]byte("short")),
		"too long":   base64.RawURLEncoding.EncodeToString(make([]byte, 200)),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := VerifyOAuthState(ctx, store, key, tok, "google")
			if !errors.Is(err, ErrOAuthStateInvalid) {
				t.Fatalf("want ErrOAuthStateInvalid, got %v", err)
			}
		})
	}
}

func TestOAuthState_InsertFails(t *testing.T) {
	store := newFakeStore()
	store.insertOK = false
	_, err := SignOAuthState(context.Background(), store, newKey(), uuid.Must(uuid.NewV4()), "google", "", nil, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "insert failed") {
		t.Fatalf("want insert error, got %v", err)
	}
}

func TestPeekOAuthStateOpenerOrigin(t *testing.T) {
	store := newFakeStore()
	key := newKey()
	appID := uuid.Must(uuid.NewV4())
	ctx := context.Background()

	tok, err := SignOAuthState(ctx, store, key, appID, "apple", "https://opener.example", nil, time.Minute)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := PeekOAuthStateOpenerOrigin(ctx, store, key, tok); got != "https://opener.example" {
		t.Errorf("peek opener: got %q want %q", got, "https://opener.example")
	}
	// Peek does NOT consume — verify the row is still claimable.
	if _, _, _, err := VerifyOAuthState(ctx, store, key, tok, "apple"); err != nil {
		t.Fatalf("verify after peek: %v", err)
	}
	// After consume, peek returns "".
	if got := PeekOAuthStateOpenerOrigin(ctx, store, key, tok); got != "" {
		t.Errorf("peek-after-consume: got %q want empty", got)
	}
}

func TestPeekOAuthStateOpenerOrigin_BadInput(t *testing.T) {
	store := newFakeStore()
	key := newKey()
	ctx := context.Background()
	for _, tok := range []string{"", "!!!", base64.RawURLEncoding.EncodeToString(make([]byte, 10))} {
		if got := PeekOAuthStateOpenerOrigin(ctx, store, key, tok); got != "" {
			t.Errorf("malformed token %q: got %q want empty", tok, got)
		}
	}
	// Tampered HMAC also returns "".
	good, _ := SignOAuthState(ctx, store, key, uuid.Must(uuid.NewV4()), "google", "x", nil, time.Minute)
	raw, _ := base64.RawURLEncoding.DecodeString(good)
	raw[len(raw)-1] ^= 0x01
	if got := PeekOAuthStateOpenerOrigin(ctx, store, key, base64.RawURLEncoding.EncodeToString(raw)); got != "" {
		t.Errorf("tampered: got %q want empty", got)
	}
}
