package auth_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"manyrows-core/auth"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
)

func TestSignAndVerifyTOTPChallenge_Success(t *testing.T) {
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")
	accountID := uuid.Must(uuid.NewV4())

	token := auth.SignTOTPChallenge(key, accountID, 10*time.Minute)
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	recovered, rememberMe, err := auth.VerifyTOTPChallenge(key, token)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if recovered != accountID {
		t.Errorf("expected %v, got %v", accountID, recovered)
	}
	if rememberMe {
		t.Error("expected rememberMe=false from default-sign helper, got true")
	}
}

func TestVerifyTOTPChallenge_Expired(t *testing.T) {
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")
	accountID := uuid.Must(uuid.NewV4())

	token := auth.SignTOTPChallenge(key, accountID, -1*time.Second)

	_, _, err := auth.VerifyTOTPChallenge(key, token)
	if !errors.Is(err, auth.ErrTOTPChallengeExpired) {
		t.Errorf("expected ErrTOTPChallengeExpired, got %v", err)
	}
}

func TestVerifyTOTPChallenge_InvalidToken(t *testing.T) {
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")

	_, _, err := auth.VerifyTOTPChallenge(key, "not-valid-base64-token")
	if !errors.Is(err, auth.ErrTOTPChallengeInvalid) {
		t.Errorf("expected ErrTOTPChallengeInvalid, got %v", err)
	}
}

func TestVerifyTOTPChallenge_EmptyToken(t *testing.T) {
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")

	_, _, err := auth.VerifyTOTPChallenge(key, "")
	if !errors.Is(err, auth.ErrTOTPChallengeInvalid) {
		t.Errorf("expected ErrTOTPChallengeInvalid, got %v", err)
	}
}

func TestVerifyTOTPChallenge_WrongKey(t *testing.T) {
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")
	wrongKey := []byte("abcdefghijklmnopqrstuvwxyz012345abcdefghijklmnopqrstuvwxyz012345")
	accountID := uuid.Must(uuid.NewV4())

	token := auth.SignTOTPChallenge(key, accountID, 10*time.Minute)

	_, _, err := auth.VerifyTOTPChallenge(wrongKey, token)
	if !errors.Is(err, auth.ErrTOTPChallengeInvalid) {
		t.Errorf("expected ErrTOTPChallengeInvalid, got %v", err)
	}
}

func TestVerifyTOTPChallenge_TamperedToken(t *testing.T) {
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")
	accountID := uuid.Must(uuid.NewV4())

	token := auth.SignTOTPChallenge(key, accountID, 10*time.Minute)

	// Tamper with the token by changing a character
	runes := []byte(token)
	if runes[0] == 'A' {
		runes[0] = 'B'
	} else {
		runes[0] = 'A'
	}
	tampered := string(runes)

	_, _, err := auth.VerifyTOTPChallenge(key, tampered)
	if err == nil {
		t.Error("expected error for tampered token, got nil")
	}
}

func TestSignTOTPChallengeWithFlags_RememberMeRoundTrip(t *testing.T) {
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")
	accountID := uuid.Must(uuid.NewV4())

	for _, rememberMe := range []bool{true, false} {
		token := auth.SignTOTPChallengeWithFlags(key, accountID, 10*time.Minute, rememberMe)
		recovered, recoveredFlag, err := auth.VerifyTOTPChallenge(key, token)
		if err != nil {
			t.Fatalf("rememberMe=%v: expected no error, got %v", rememberMe, err)
		}
		if recovered != accountID {
			t.Errorf("rememberMe=%v: account = %v, want %v", rememberMe, recovered, accountID)
		}
		if recoveredFlag != rememberMe {
			t.Errorf("rememberMe=%v: flag round-trip = %v, want %v", rememberMe, recoveredFlag, rememberMe)
		}
	}
}

func TestVerifyTOTPChallenge_FlippedRememberMeFlagInvalidatesHmac(t *testing.T) {
	// The whole point of v2: a holder of the (challenge + TOTP code) cannot
	// flip rememberMe — flipping invalidates the HMAC.
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")
	accountID := uuid.Must(uuid.NewV4())

	token := auth.SignTOTPChallengeWithFlags(key, accountID, 10*time.Minute, false)

	// Decode, flip the flag byte (index 24 of payload), re-encode without
	// recomputing the HMAC. Verify must reject.
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(data) != 57 {
		t.Fatalf("expected 57-byte v2 token, got %d", len(data))
	}
	data[24] ^= 0x01 // flip rememberMe bit
	tampered := base64.RawURLEncoding.EncodeToString(data)

	_, _, err = auth.VerifyTOTPChallenge(key, tampered)
	if !errors.Is(err, auth.ErrTOTPChallengeInvalid) {
		t.Errorf("expected ErrTOTPChallengeInvalid for flag-flipped token, got %v", err)
	}
}

func TestVerifyTOTPChallenge_V1TokensStillVerify(t *testing.T) {
	// Backward-compat: v1 tokens (no flag byte) issued before this deploy
	// must still verify so the ~10-minute window of in-flight challenges
	// doesn't break. Construct a v1 token by hand since the public helpers
	// now emit v2.
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")
	accountID := uuid.Must(uuid.NewV4())
	expiresAt := time.Now().UTC().Add(10 * time.Minute).Unix()

	payload := make([]byte, 24)
	copy(payload[0:16], accountID.Bytes())
	binary.BigEndian.PutUint64(payload[16:24], uint64(expiresAt))

	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	v1Token := base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))

	recovered, rememberMe, err := auth.VerifyTOTPChallenge(key, v1Token)
	if err != nil {
		t.Fatalf("expected v1 to verify, got %v", err)
	}
	if recovered != accountID {
		t.Errorf("account mismatch: %v vs %v", recovered, accountID)
	}
	if rememberMe {
		t.Error("v1 tokens carry no flag; rememberMe should default false")
	}
}

func TestSignTOTPChallenge_DifferentAccountsProduceDifferentTokens(t *testing.T) {
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")
	id1 := uuid.Must(uuid.NewV4())
	id2 := uuid.Must(uuid.NewV4())

	token1 := auth.SignTOTPChallenge(key, id1, 10*time.Minute)
	token2 := auth.SignTOTPChallenge(key, id2, 10*time.Minute)

	if token1 == token2 {
		t.Error("expected different tokens for different account IDs")
	}
}

// =====================================================================
// TOTP setup-challenge token (separate HMAC domain — verify-tokens
// must NEVER be accepted at setup endpoints, and vice-versa).
// =====================================================================

func TestSignAndVerifyTOTPSetupChallenge_Success(t *testing.T) {
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")
	userID := uuid.Must(uuid.NewV4())
	appID := uuid.Must(uuid.NewV4())

	for _, rememberMe := range []bool{true, false} {
		token := auth.SignTOTPSetupChallenge(key, userID, appID, 10*time.Minute, rememberMe)
		if token == "" {
			t.Fatalf("rememberMe=%v: expected non-empty token", rememberMe)
		}
		gotUser, gotApp, gotRM, err := auth.VerifyTOTPSetupChallenge(key, token)
		if err != nil {
			t.Fatalf("rememberMe=%v: verify err = %v", rememberMe, err)
		}
		if gotUser != userID {
			t.Errorf("user round-trip: got %v, want %v", gotUser, userID)
		}
		if gotApp != appID {
			t.Errorf("app round-trip: got %v, want %v", gotApp, appID)
		}
		if gotRM != rememberMe {
			t.Errorf("rememberMe round-trip: got %v, want %v", gotRM, rememberMe)
		}
	}
}

func TestVerifyTOTPSetupChallenge_Expired(t *testing.T) {
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")
	userID := uuid.Must(uuid.NewV4())
	appID := uuid.Must(uuid.NewV4())

	token := auth.SignTOTPSetupChallenge(key, userID, appID, -1*time.Second, false)

	_, _, _, err := auth.VerifyTOTPSetupChallenge(key, token)
	if !errors.Is(err, auth.ErrTOTPSetupChallengeExpired) {
		t.Errorf("expected ErrTOTPSetupChallengeExpired, got %v", err)
	}
}

func TestVerifyTOTPSetupChallenge_InvalidEncoding(t *testing.T) {
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")

	_, _, _, err := auth.VerifyTOTPSetupChallenge(key, "not-valid-base64-!@#")
	if !errors.Is(err, auth.ErrTOTPSetupChallengeInvalid) {
		t.Errorf("expected ErrTOTPSetupChallengeInvalid, got %v", err)
	}
}

func TestVerifyTOTPSetupChallenge_WrongLength(t *testing.T) {
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")

	// Valid base64url but wrong byte length.
	short := base64.RawURLEncoding.EncodeToString([]byte("too short"))
	_, _, _, err := auth.VerifyTOTPSetupChallenge(key, short)
	if !errors.Is(err, auth.ErrTOTPSetupChallengeInvalid) {
		t.Errorf("expected ErrTOTPSetupChallengeInvalid for wrong-length token, got %v", err)
	}
}

func TestVerifyTOTPSetupChallenge_WrongKey(t *testing.T) {
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")
	wrongKey := []byte("abcdefghijklmnopqrstuvwxyz012345abcdefghijklmnopqrstuvwxyz012345")
	userID := uuid.Must(uuid.NewV4())
	appID := uuid.Must(uuid.NewV4())

	token := auth.SignTOTPSetupChallenge(key, userID, appID, 10*time.Minute, false)

	_, _, _, err := auth.VerifyTOTPSetupChallenge(wrongKey, token)
	if !errors.Is(err, auth.ErrTOTPSetupChallengeInvalid) {
		t.Errorf("expected ErrTOTPSetupChallengeInvalid for wrong key, got %v", err)
	}
}

func TestVerifyTOTPSetupChallenge_TamperedToken(t *testing.T) {
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")
	userID := uuid.Must(uuid.NewV4())
	appID := uuid.Must(uuid.NewV4())

	token := auth.SignTOTPSetupChallenge(key, userID, appID, 10*time.Minute, false)

	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Flip a byte in the userID portion of the payload.
	data[5] ^= 0x01
	tampered := base64.RawURLEncoding.EncodeToString(data)

	_, _, _, err = auth.VerifyTOTPSetupChallenge(key, tampered)
	if !errors.Is(err, auth.ErrTOTPSetupChallengeInvalid) {
		t.Errorf("expected ErrTOTPSetupChallengeInvalid for tampered token, got %v", err)
	}
}

func TestVerifyTOTPSetupChallenge_RejectsVerifyTokens(t *testing.T) {
	// CRITICAL: a TOTP-verify challenge token (held by a user mid-2FA)
	// MUST NOT be redeemable at the setup endpoint. The two surfaces
	// have different security properties — the verify token says "this
	// user is mid-login and has a TOTP code to enter", which would let
	// it bypass setup entirely if accepted as a setup credential.
	//
	// Different HMAC domains is what makes this safe.
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")
	userID := uuid.Must(uuid.NewV4())

	verifyToken := auth.SignTOTPChallengeWithFlags(key, userID, 10*time.Minute, false)

	_, _, _, err := auth.VerifyTOTPSetupChallenge(key, verifyToken)
	if err == nil {
		t.Error("verify-token must NOT verify as a setup-challenge")
	}
}

func TestVerifyTOTPChallenge_RejectsSetupTokens(t *testing.T) {
	// Inverse direction: a setup-challenge token MUST NOT verify as a
	// TOTP-verify challenge. Keeps the two domains strictly disjoint.
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")
	userID := uuid.Must(uuid.NewV4())
	appID := uuid.Must(uuid.NewV4())

	setupToken := auth.SignTOTPSetupChallenge(key, userID, appID, 10*time.Minute, false)

	_, _, err := auth.VerifyTOTPChallenge(key, setupToken)
	if err == nil {
		t.Error("setup-token must NOT verify as a verify-challenge")
	}
}

func TestSignTOTPSetupChallenge_DifferentAppsProduceDifferentTokens(t *testing.T) {
	// Same user + same TTL + different app → different tokens. Drives
	// the "token bound to app" property the setup endpoints rely on.
	key := []byte("0123456789012345678901234567890123456789012345678901234567890123")
	userID := uuid.Must(uuid.NewV4())
	app1 := uuid.Must(uuid.NewV4())
	app2 := uuid.Must(uuid.NewV4())

	token1 := auth.SignTOTPSetupChallenge(key, userID, app1, 10*time.Minute, false)
	token2 := auth.SignTOTPSetupChallenge(key, userID, app2, 10*time.Minute, false)

	if token1 == token2 {
		t.Error("expected different tokens for different app IDs")
	}

	// And the bound appID must round-trip correctly so handlers can
	// cross-check it against the URL-resolved app.
	_, gotApp1, _, err := auth.VerifyTOTPSetupChallenge(key, token1)
	if err != nil || gotApp1 != app1 {
		t.Errorf("token1 should bind app1: got app=%v err=%v", gotApp1, err)
	}
	_, gotApp2, _, err := auth.VerifyTOTPSetupChallenge(key, token2)
	if err != nil || gotApp2 != app2 {
		t.Errorf("token2 should bind app2: got app=%v err=%v", gotApp2, err)
	}
}
