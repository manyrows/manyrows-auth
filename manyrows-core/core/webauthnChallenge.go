package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

type WebAuthnChallengePurpose string

const (
	WebAuthnChallengePurposeRegister WebAuthnChallengePurpose = "register"
	WebAuthnChallengePurposeLogin    WebAuthnChallengePurpose = "login"
)

// WebAuthnChallenge stores in-flight ceremony state between a /begin and
// /finish call. SessionData is the raw JSON of the go-webauthn library's
// webauthn.SessionData struct — we don't interpret it; the library does.
//
// UserID is nullable because passwordless login-begin (discoverable
// credentials) doesn't know which user is signing in until the authenticator
// responds.
type WebAuthnChallenge struct {
	ID          uuid.UUID
	AppID       uuid.UUID
	UserID      *uuid.UUID
	Purpose     WebAuthnChallengePurpose
	Challenge   []byte
	SessionData []byte
	ExpiresAt   time.Time
	CreatedAt   time.Time
}
