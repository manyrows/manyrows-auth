package api

import (
	"manyrows-core/core"

	"github.com/trustelem/zxcvbn"
)

// passwordPolicyResult is the outcome of a per-app password-strength
// check. Issue is empty when the password is acceptable.
type passwordPolicyResult struct {
	OK          bool
	Issue       string // "too_short" | "too_weak"
	MinLength   int    // echoes app.PasswordMinLength for error formatting
	MinScore    int    // echoes app.PasswordMinZxcvbnScore
	ActualScore int    // zxcvbn 0..4
}

// checkPasswordPolicy runs the per-app password strength rules on a
// candidate password. The rules are:
//
//  1. Length >= app.PasswordMinLength.
//  2. zxcvbn score >= app.PasswordMinZxcvbnScore.
//
// userInputs are extra strings (typically email + name) that zxcvbn
// uses as "personal" dictionary entries — passing these makes
// "asdf@example.com" score lower when the password is "example123".
//
// Caller is responsible for:
//   - mapping Issue to the right error key + status,
//   - deciding what to do when policy is "weaker than the previous
//     defaults" (we never auto-strengthen existing rows; admins can
//     still loosen as long as the policy check passes for new passwords).
func checkPasswordPolicy(app *core.App, pw string, userInputs ...string) passwordPolicyResult {
	out := passwordPolicyResult{
		MinLength: app.PasswordMinLength,
		MinScore:  app.PasswordMinZxcvbnScore,
	}
	if app.PasswordMinLength > 0 && len(pw) < app.PasswordMinLength {
		out.Issue = "too_short"
		return out
	}
	// zxcvbn is the load-bearing check. It catches dictionary words,
	// keyboard runs ("qwerty"), trivial substitutions ("p@ssw0rd")
	// and personal-info reuse — i.e. the categories the length-only
	// rule misses.
	res := zxcvbn.PasswordStrength(pw, userInputs)
	out.ActualScore = res.Score
	if res.Score < app.PasswordMinZxcvbnScore {
		out.Issue = "too_weak"
		return out
	}
	out.OK = true
	return out
}
