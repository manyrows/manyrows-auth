package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
)

func TestVerifyTOTPChallengeAny_TriesAllKeys(t *testing.T) {
	oldKey := DeriveTokenSigningKey([]byte("old-master-old-master-old-master"))
	newKey := DeriveTokenSigningKey([]byte("new-master-new-master-new-master"))
	id := uuid.Must(uuid.NewV4())
	token := SignTOTPChallenge(oldKey, id, time.Minute)

	got, _, err := VerifyTOTPChallengeAny([][]byte{newKey, oldKey}, token)
	if err != nil || got != id {
		t.Fatalf("old-key token should verify via list: %v %v", got, err)
	}

	if _, _, err := VerifyTOTPChallengeAny([][]byte{newKey}, token); err == nil {
		t.Fatal("old-key token must NOT verify with new key only")
	}
}

func TestVerifyTOTPSetupChallengeAny(t *testing.T) {
	oldKey := DeriveTokenSigningKey([]byte("old-master-old-master-old-master"))
	newKey := DeriveTokenSigningKey([]byte("new-master-new-master-new-master"))
	u := uuid.Must(uuid.NewV4())
	a := uuid.Must(uuid.NewV4())
	token := SignTOTPSetupChallenge(oldKey, u, a, time.Minute, true)

	gu, ga, remember, err := VerifyTOTPSetupChallengeAny([][]byte{newKey, oldKey}, token)
	if err != nil || gu != u || ga != a || !remember {
		t.Fatalf("setup token should verify via list: %v %v %v %v", gu, ga, remember, err)
	}
}

// TestVerifyTOTPChallengeAny_ExpiredReturnsSentinel verifies that a token
// signed with the old key but already expired yields ErrTOTPChallengeExpired
// (not ErrTOTPChallengeInvalid) even when the new key is tried first. The
// early-stop on definitive errors must surface the correct sentinel.
func TestVerifyTOTPChallengeAny_ExpiredReturnsSentinel(t *testing.T) {
	oldKey := DeriveTokenSigningKey([]byte("old-master-old-master-old-master"))
	newKey := DeriveTokenSigningKey([]byte("new-master-new-master-new-master"))
	id := uuid.Must(uuid.NewV4())

	// Negative TTL produces a token whose expiresAt is already in the past.
	expiredToken := SignTOTPChallenge(oldKey, id, -1*time.Minute)

	_, _, err := VerifyTOTPChallengeAny([][]byte{newKey, oldKey}, expiredToken)
	if !errors.Is(err, ErrTOTPChallengeExpired) {
		t.Fatalf("expected ErrTOTPChallengeExpired, got: %v", err)
	}
}
