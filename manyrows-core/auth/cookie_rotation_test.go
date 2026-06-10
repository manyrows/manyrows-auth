package auth

import (
	"testing"

	"manyrows-core/config"

	"github.com/gorilla/securecookie"
)

const (
	rotOldAuthKey = "old-auth-key-old-auth-key-old-auth-key-old-auth-key-old-auth-key" // 64 chars
	rotNewAuthKey = "new-auth-key-new-auth-key-new-auth-key-new-auth-key-new-auth-key" // 64 chars
	rotOldEncKey  = "old-enc-key-old-enc-key-old-enc-"                                 // 32 chars
	rotNewEncKey  = "new-enc-key-new-enc-key-new-enc-"                                 // 32 chars
)

// A cookie minted under the OLD pair must decode through a store built
// with the new pair + _PREVIOUS fallback.
func TestCookieStore_PreviousPairDecodesOldCookies(t *testing.T) {
	t.Setenv("MANYROWS_SESSION_AUTH_KEY", rotNewAuthKey)
	t.Setenv("MANYROWS_SESSION_SECRET_KEY", rotNewEncKey)
	t.Setenv("MANYROWS_SESSION_AUTH_KEY_PREVIOUS", rotOldAuthKey)
	t.Setenv("MANYROWS_SESSION_SECRET_KEY_PREVIOUS", rotOldEncKey)

	store, err := newCookieStore(config.NewConfig("MANYROWS_"))
	if err != nil {
		t.Fatal(err)
	}

	oldCodec := securecookie.New([]byte(rotOldAuthKey), []byte(rotOldEncKey))
	encoded, err := oldCodec.Encode("mr_admin", map[any]any{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}

	dst := map[any]any{}
	if err := securecookie.DecodeMulti("mr_admin", encoded, &dst, store.Codecs...); err != nil {
		t.Fatalf("old cookie should decode through rotated store: %v", err)
	}
	if dst["k"] != "v" {
		t.Fatalf("got %v", dst)
	}
}

// Without _PREVIOUS the old cookie must NOT decode — pins that the test
// above passes because of the fallback, not by accident.
func TestCookieStore_NoPreviousRejectsOldCookies(t *testing.T) {
	t.Setenv("MANYROWS_SESSION_AUTH_KEY", rotNewAuthKey)
	t.Setenv("MANYROWS_SESSION_SECRET_KEY", rotNewEncKey)
	t.Setenv("MANYROWS_SESSION_AUTH_KEY_PREVIOUS", "")
	t.Setenv("MANYROWS_SESSION_SECRET_KEY_PREVIOUS", "")

	store, err := newCookieStore(config.NewConfig("MANYROWS_"))
	if err != nil {
		t.Fatal(err)
	}
	oldCodec := securecookie.New([]byte(rotOldAuthKey), []byte(rotOldEncKey))
	encoded, err := oldCodec.Encode("mr_admin", map[any]any{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	dst := map[any]any{}
	if err := securecookie.DecodeMulti("mr_admin", encoded, &dst, store.Codecs...); err == nil {
		t.Fatal("old cookie decoded without _PREVIOUS — fallback test would be vacuous")
	}
}

// Fresh cookies are written with the CURRENT pair even when previous
// pairs are configured.
func TestCookieStore_EncodesWithCurrentPair(t *testing.T) {
	t.Setenv("MANYROWS_SESSION_AUTH_KEY", rotNewAuthKey)
	t.Setenv("MANYROWS_SESSION_SECRET_KEY", rotNewEncKey)
	t.Setenv("MANYROWS_SESSION_AUTH_KEY_PREVIOUS", rotOldAuthKey)
	t.Setenv("MANYROWS_SESSION_SECRET_KEY_PREVIOUS", rotOldEncKey)

	rotated, err := newCookieStore(config.NewConfig("MANYROWS_"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := securecookie.EncodeMulti("mr_admin", map[any]any{"k": "v"}, rotated.Codecs...)
	if err != nil {
		t.Fatal(err)
	}
	currentOnly := securecookie.New([]byte(rotNewAuthKey), []byte(rotNewEncKey))
	dst := map[any]any{}
	if err := currentOnly.Decode("mr_admin", encoded, &dst); err != nil {
		t.Fatalf("fresh cookie should be current-pair encoded: %v", err)
	}
}
