package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"

	"github.com/gofrs/uuid/v5"
)

var (
	ErrTOTPChallengeExpired      = errors.New("totp challenge expired")
	ErrTOTPChallengeInvalid      = errors.New("totp challenge invalid")
	ErrTOTPSetupChallengeExpired = errors.New("totp setup challenge expired")
	ErrTOTPSetupChallengeInvalid = errors.New("totp setup challenge invalid")
)

// totpSetupDomain is prepended to the payload before HMAC for setup
// tokens so a verify-token (used for "enter your existing TOTP code")
// can never be replayed against a setup endpoint, and vice-versa.
// Different domain → different HMAC → wrong-purpose tokens fail.
const totpSetupDomain = "manyrows:totp_setup_challenge:v1"

// Token layout (v1, no flags): base64url(accountID[16] | expiresAt[8] | hmac[32])  = 56 bytes
// Token layout (v2, with flags): base64url(accountID[16] | expiresAt[8] | flags[1] | hmac[32]) = 57 bytes
//
// flags bit 0 = rememberMe. Bumping the format means the signed token
// authoritatively carries the user's "Keep me signed in" choice across
// the 2FA round trip — the verify-step request body can no longer flip
// it, since flipping would invalidate the HMAC.
//
// Verify accepts both layouts so any in-flight v1 challenges issued just
// before deploy (~10-minute TTL window) still work; v1 implies
// rememberMe=false.
const (
	totpChallengeV1Len = 56
	totpChallengeV2Len = 57
)

// SignTOTPChallenge — backward-compatible shim defaulting rememberMe to
// false. Used by the admin-side TOTP flow which doesn't have a remember-me
// concept.
func SignTOTPChallenge(key []byte, accountID uuid.UUID, ttl time.Duration) string {
	return SignTOTPChallengeWithFlags(key, accountID, ttl, false)
}

// SignTOTPChallengeWithFlags creates a v2 challenge token that carries an
// HMAC-signed rememberMe flag alongside the account ID and expiry. Used by
// the app-user login paths so the TOTP verify step can recover the original
// "Keep me signed in" choice from the challenge itself, not the request body.
func SignTOTPChallengeWithFlags(key []byte, accountID uuid.UUID, ttl time.Duration, rememberMe bool) string {
	expiresAt := time.Now().UTC().Add(ttl)

	payload := make([]byte, 25)
	copy(payload[0:16], accountID.Bytes())
	binary.BigEndian.PutUint64(payload[16:24], uint64(expiresAt.Unix()))
	if rememberMe {
		payload[24] = 1
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	sig := mac.Sum(nil)

	token := append(payload, sig...)
	return base64.RawURLEncoding.EncodeToString(token)
}

// =====================================================================
// TOTP setup-challenge token
//
// Issued whenever a sign-in flow lands on a user who must enroll TOTP
// before any session can be granted (Require2FA && !HasTOTP). Carries
// the user + app the original sign-in was scoped to, plus the original
// rememberMe choice, so the setup-complete endpoint can recreate the
// session WITHOUT trusting any of these from the request body.
//
// Layout: base64url(userID[16] | appID[16] | expiresAt[8] | flags[1] | hmac[32]) = 73 bytes
// flags bit 0 = rememberMe.
// HMAC includes the totpSetupDomain string so verify-tokens cannot be
// replayed against setup endpoints.
// =====================================================================

const totpSetupChallengeLen = 73

// SignTOTPSetupChallenge produces the credential the OTP / password /
// OAuth / magic-link flows hand back when the user must enroll TOTP
// before login can complete. The setup-init and setup-complete
// endpoints accept this token in lieu of a session.
func SignTOTPSetupChallenge(key []byte, userID, appID uuid.UUID, ttl time.Duration, rememberMe bool) string {
	expiresAt := time.Now().UTC().Add(ttl)

	payload := make([]byte, 41)
	copy(payload[0:16], userID.Bytes())
	copy(payload[16:32], appID.Bytes())
	binary.BigEndian.PutUint64(payload[32:40], uint64(expiresAt.Unix()))
	if rememberMe {
		payload[40] = 1
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(totpSetupDomain))
	mac.Write(payload)
	sig := mac.Sum(nil)

	token := append(payload, sig...)
	return base64.RawURLEncoding.EncodeToString(token)
}

// VerifyTOTPSetupChallenge validates the HMAC + expiry of a setup
// challenge token and returns the bound user + app + rememberMe flag.
// The caller MUST cross-check the returned appID against whichever
// app context the request lands in — a token issued for app A cannot
// be redeemed against app B.
func VerifyTOTPSetupChallenge(key []byte, token string) (userID uuid.UUID, appID uuid.UUID, rememberMe bool, err error) {
	data, decErr := base64.RawURLEncoding.DecodeString(token)
	if decErr != nil {
		return uuid.Nil, uuid.Nil, false, ErrTOTPSetupChallengeInvalid
	}
	if len(data) != totpSetupChallengeLen {
		return uuid.Nil, uuid.Nil, false, ErrTOTPSetupChallengeInvalid
	}

	payload := data[:41]
	sig := data[41:]

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(totpSetupDomain))
	mac.Write(payload)
	expected := mac.Sum(nil)

	if !hmac.Equal(sig, expected) {
		return uuid.Nil, uuid.Nil, false, ErrTOTPSetupChallengeInvalid
	}

	expiresUnix := binary.BigEndian.Uint64(payload[32:40])
	if time.Now().UTC().Unix() > int64(expiresUnix) {
		return uuid.Nil, uuid.Nil, false, ErrTOTPSetupChallengeExpired
	}

	uid, parseErr := uuid.FromBytes(payload[0:16])
	if parseErr != nil {
		return uuid.Nil, uuid.Nil, false, ErrTOTPSetupChallengeInvalid
	}
	aid, parseErr := uuid.FromBytes(payload[16:32])
	if parseErr != nil {
		return uuid.Nil, uuid.Nil, false, ErrTOTPSetupChallengeInvalid
	}
	rm := payload[40]&0x01 != 0
	return uid, aid, rm, nil
}

// VerifyTOTPChallenge verifies the HMAC signature and expiry of a challenge
// token. Returns the account ID and the rememberMe flag (false for v1
// tokens, decoded from the payload for v2).
func VerifyTOTPChallenge(key []byte, token string) (uuid.UUID, bool, error) {
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return uuid.Nil, false, ErrTOTPChallengeInvalid
	}

	var payloadLen int
	switch len(data) {
	case totpChallengeV1Len:
		payloadLen = 24
	case totpChallengeV2Len:
		payloadLen = 25
	default:
		return uuid.Nil, false, ErrTOTPChallengeInvalid
	}

	payload := data[:payloadLen]
	sig := data[payloadLen:]

	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	expected := mac.Sum(nil)

	if !hmac.Equal(sig, expected) {
		return uuid.Nil, false, ErrTOTPChallengeInvalid
	}

	expiresUnix := binary.BigEndian.Uint64(payload[16:24])
	if time.Now().UTC().Unix() > int64(expiresUnix) {
		return uuid.Nil, false, ErrTOTPChallengeExpired
	}

	accountID, err := uuid.FromBytes(payload[0:16])
	if err != nil {
		return uuid.Nil, false, ErrTOTPChallengeInvalid
	}

	rememberMe := false
	if payloadLen == 25 {
		rememberMe = payload[24]&0x01 != 0
	}

	return accountID, rememberMe, nil
}
