package auth

import (
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
