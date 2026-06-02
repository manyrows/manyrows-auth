package auth

import (
	"crypto/subtle"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// totpStepPeriod is the standard TOTP step length (30s) used by RFC 6238
// and what pquerna/otp's totp.Validate defaults to.
const totpStepPeriod = 30

// totpSkewSteps is the ±N step window we accept around the current
// timestamp to tolerate small client clock skew. Matches pquerna/otp's
// default of 1 (so a code is accepted if it matches the current step,
// the previous step, or the next step).
const totpSkewSteps = 1

// VerifyTOTPCode validates a 6-digit TOTP code against a base32 secret and
// returns the step number that matched on success.
//
// The caller MUST persist the returned step (via the repo's atomic
// "advance only if step > last_step" UPDATE) and reject codes whose step
// is not strictly greater than the previously-stored value. Without that
// step record, the same 30-second code is replayable inside its window —
// pquerna/otp's totp.Validate doesn't track which step it accepted.
//
// The library's totp.Validate is otherwise drop-in equivalent to the
// loop here (period=30, skew=±1, 6 digits, SHA-1); we re-implement the
// check so we can return the matched step.
func VerifyTOTPCode(code, secret string) (step int64, ok bool) {
	now := time.Now().Unix()
	currentStep := now / totpStepPeriod

	opts := totp.ValidateOpts{
		Period:    totpStepPeriod,
		Skew:      0, // we iterate the skew window ourselves
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}

	for delta := int64(-totpSkewSteps); delta <= totpSkewSteps; delta++ {
		s := currentStep + delta
		candidate, err := totp.GenerateCodeCustom(
			secret,
			time.Unix(s*totpStepPeriod, 0),
			opts,
		)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(code), []byte(candidate)) == 1 {
			return s, true
		}
	}
	return 0, false
}
