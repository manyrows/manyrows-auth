package client

import (
	"errors"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
)

// =====================
// OIDC id_token issuance
// =====================
//
// Lives alongside IssueAccessToken so id_tokens reuse the same ES256
// signing keys + rotation machinery. Consumers verify against the
// unchanged /.well-known/jwks.json (the discovery doc just points at
// it), so adding id_token issuance does not change anything about
// how access tokens are signed or how customers verify them.

// IDTokenTTL is the lifetime of an issued id_token. Matches the
// default access-token TTL — id_tokens are designed to be consumed
// immediately after the auth code exchange, not long-lived.
const IDTokenTTL = 15 * time.Minute

// mrIDTokenClaims is the JSON shape of an OIDC id_token issued by
// ManyRows. The OIDC-specific extras (auth_time, nonce, scope-gated
// profile claims) sit alongside the standard RegisteredClaims for
// iss/sub/aud/exp/iat.
type mrIDTokenClaims struct {
	AuthTime int64  `json:"auth_time,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
	// Email + email_verified travel together: when Email is present we
	// emit email_verified explicitly (boolean, not omitted) so consumers
	// don't have to infer "unknown" vs. "false". *bool gives us the
	// nil-means-omit distinction.
	Email             string `json:"email,omitempty"`
	EmailVerified     *bool  `json:"email_verified,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Picture           string `json:"picture,omitempty"`
	jwt.RegisteredClaims
}

// IDTokenClaimSet is the input to IssueIDToken. The caller (the
// /oidc/token handler) is responsible for filtering scope-gated
// claims (email/profile/etc.) according to the scope on the consumed
// authorization code — this struct just transports the already-
// resolved values.
//
// HasEmail signals whether the caller is granting email-scope claims,
// independent of EmailVerified's value — without this, a user with
// unverified email + email-scope granted would render as "no email
// scope" because both fields are zero. Caller sets HasEmail=true
// whenever Email is meant to be emitted.
type IDTokenClaimSet struct {
	// Issuer matches the discovery doc's "issuer" value for this app
	// (per-app AuthDomain when set; install BASE_URL otherwise).
	Issuer string
	// Audience is the client_id — i.e. the app UUID as a string.
	Audience string
	// Subject is the end-user identifier (user_id) — stable per
	// user pool so a customer's downstream RP sees the same sub
	// across logins.
	Subject uuid.UUID
	// AuthTime is when the user originally authenticated (typically
	// session.CreatedAt). Optional per OIDC §2 — included always
	// for diagnostic value, set zero to omit.
	AuthTime time.Time
	// Nonce is the value the RP sent at /authorize, echoed verbatim.
	// Empty when the RP didn't supply one (legal but unusual — id_token
	// nonce binding is the standard CSRF defence for the implicit
	// flow and a best-practice for code flow too).
	Nonce string

	// Scope-gated profile claims. Caller has already filtered these
	// against the granted scope; empty values are simply omitted.
	// HasEmail and Email travel together — HasEmail emits email_verified
	// alongside, even when EmailVerified is false (spec: §5.1).
	HasEmail          bool
	Email             string
	EmailVerified     bool
	Name              string
	PreferredUsername string
	Picture           string
}

// IssueIDToken signs an OIDC id_token from the supplied claim set.
// Same key + algorithm + kid header pipeline as IssueAccessToken;
// verifiers point at the same JWKS document.
func (a *AuthService) IssueIDToken(claims IDTokenClaimSet) (string, time.Time, error) {
	iss := strings.TrimRight(strings.TrimSpace(claims.Issuer), "/")
	if iss == "" {
		return "", time.Time{}, errors.New("cannot issue id_token: empty issuer")
	}
	if strings.TrimSpace(claims.Audience) == "" {
		return "", time.Time{}, errors.New("cannot issue id_token: empty audience")
	}
	if claims.Subject == uuid.Nil {
		return "", time.Time{}, errors.New("cannot issue id_token: empty subject")
	}

	now := time.Now().UTC()
	expiresAt := now.Add(IDTokenTTL)

	var authTime int64
	if !claims.AuthTime.IsZero() {
		authTime = claims.AuthTime.Unix()
	}

	idt := mrIDTokenClaims{
		AuthTime:          authTime,
		Nonce:             claims.Nonce,
		Name:              claims.Name,
		PreferredUsername: claims.PreferredUsername,
		Picture:           claims.Picture,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   claims.Subject.String(),
			Audience:  jwt.ClaimStrings{claims.Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	if claims.HasEmail {
		idt.Email = claims.Email
		v := claims.EmailVerified
		idt.EmailVerified = &v
	}

	current := a.jwtKeys.Load().Current
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, idt)
	tok.Header["kid"] = current.KID
	signed, err := tok.SignedString(current.Private)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}
