package passwordhash

import (
	"strings"
	"testing"
)

func TestHash_RoundTrip(t *testing.T) {
	h, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=1$") {
		t.Errorf("hash should be argon2id PHC string, got %q", h)
	}
	ok, err := Verify(h, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("Verify rejected its own hash")
	}
}

func TestHash_DifferentSaltEachCall(t *testing.T) {
	h1, _ := Hash("same-password")
	h2, _ := Hash("same-password")
	if h1 == h2 {
		t.Error("Hash should produce different output (random salt) for the same password")
	}
}

func TestVerify_WrongPassword(t *testing.T) {
	h, _ := Hash("right-password")
	ok, err := Verify(h, "wrong-password")
	if err != nil {
		t.Fatalf("Verify wrong-password should not error, got: %v", err)
	}
	if ok {
		t.Error("Verify accepted the wrong password")
	}
}

func TestVerify_UnknownPrefixIsError(t *testing.T) {
	_, err := Verify("not-a-real-hash", "anything")
	if err == nil {
		t.Error("expected error for unrecognised hash format")
	}
}

func TestVerify_MalformedArgonIsError(t *testing.T) {
	_, err := Verify("$argon2id$nope", "anything")
	if err == nil {
		t.Error("expected error for malformed argon2id PHC string")
	}
}

func TestHash_EmptyPasswordRejected(t *testing.T) {
	if _, err := Hash(""); err == nil {
		t.Error("Hash should reject empty password")
	}
}

func TestDummyVerify_DoesNotPanic(t *testing.T) {
	DummyVerify("anything")
	DummyVerify("")
}
