package api

import (
	"context"
	"time"

	"manyrows-core/core"
	"manyrows-core/crypto/passwordhash"
)

// PasswordAuthOutcome enumerates the possible results of validating an
// email + password against an app. The caller is responsible for
// deciding how each outcome is reported (HTTP status, audit log,
// rate-limit attempt burn, lockout escalation) — this function only
// runs the security-critical lookup + compare.
type PasswordAuthOutcome int

const (
	PWAuthInvalid          PasswordAuthOutcome = iota // zero value never returned
	PWAuthOK                                          // credentials valid, user usable
	PWAuthNoUser                                      // user not found OR has no password (collapsed to one outcome to avoid leaking enumeration)
	PWAuthLocked                                      // user account is in a lockout window
	PWAuthNotVerified                                 // user has not verified their email
	PWAuthWrongPassword                               // user exists, has password, but it didn't match
)

// PasswordAuthResult is what the caller gets back from
// validateAppPasswordCredentials. User is non-nil only on Outcome ==
// PWAuthOK or PWAuthLocked / PWAuthNotVerified / PWAuthWrongPassword
// (any case where we successfully looked up a user); on PWAuthNoUser
// it's nil because either the user doesn't exist or has no password.
type PasswordAuthResult struct {
	Outcome PasswordAuthOutcome
	User    *core.User
}

// validateAppPasswordCredentials runs the security-critical part of
// password login: user lookup, constant-time hash compare, lockout
// check, email-verification check. It does NOT touch rate limits,
// audit logs, attempt counters, or sessions — those are the caller's
// responsibility because they depend on which surface is calling.
//
// The function performs a verify on every call, even on the
// no-user branch (against a dummy), so the timing is constant
// across all outcomes. Without that the response time leaks whether
// a given email exists.
//
// Returns an error only on genuine I/O / encoding failures. All
// authentication-result conditions are surfaced via Outcome.
func validateAppPasswordCredentials(
	ctx context.Context,
	repo passwordAuthRepo,
	app *core.App,
	email, password string,
) (PasswordAuthResult, error) {
	user, passwordHash, err := repo.GetUserWithPasswordByEmailAndApp(ctx, email, app)
	if err != nil {
		return PasswordAuthResult{}, err
	}

	// No-user / no-password branch: still burn one verify's worth of
	// CPU so the response time matches the real-user branch.
	// Returning early without the work would leak account existence
	// via timing.
	if user == nil || passwordHash == "" {
		passwordhash.DummyVerify(password)
		return PasswordAuthResult{Outcome: PWAuthNoUser}, nil
	}

	// Lockout: report and stop. Email-verified and password checks
	// are intentionally NOT run during a lockout — the response is
	// the same whether the password would have been right or wrong.
	if user.LockedUntil != nil && time.Until(*user.LockedUntil) > 0 {
		return PasswordAuthResult{Outcome: PWAuthLocked, User: user}, nil
	}

	// Email verification: required for password login. Run the
	// verify anyway so timing for "unverified email" matches the
	// other outcomes; otherwise the unverified branch would be a
	// fast-fail and the response time would distinguish it.
	if !user.IsEmailVerified() {
		_, _ = passwordhash.Verify(passwordHash, password)
		return PasswordAuthResult{Outcome: PWAuthNotVerified, User: user}, nil
	}

	ok, vErr := passwordhash.Verify(passwordHash, password)
	if vErr != nil || !ok {
		return PasswordAuthResult{Outcome: PWAuthWrongPassword, User: user}, nil
	}
	return PasswordAuthResult{Outcome: PWAuthOK, User: user}, nil
}

// passwordAuthRepo is the narrow repo interface this helper needs.
// Defined here (not as the full *repo.Repo) to make testing easier
// and to make the dependency surface explicit.
type passwordAuthRepo interface {
	GetUserWithPasswordByEmailAndApp(ctx context.Context, email string, app *core.App) (*core.User, string, error)
}
