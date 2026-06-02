package auth

import (
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const testSecret = "JBSWY3DPEHPK3PXP" // RFC 6238 reference-style base32 secret

// generateAt returns the 6-digit TOTP code that the standard pquerna
// settings (period=30, SHA-1, 6 digits) produce at the given time.
func generateAt(t *testing.T, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(testSecret, at, totp.ValidateOpts{
		Period:    totpStepPeriod,
		Skew:      0,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	return code
}

func TestVerifyTOTPCode_CurrentStep(t *testing.T) {
	now := time.Now()
	currentStep := now.Unix() / totpStepPeriod
	code := generateAt(t, now)

	step, ok := VerifyTOTPCode(code, testSecret)
	if !ok {
		t.Fatal("current step: expected ok=true")
	}
	if step != currentStep {
		t.Errorf("step: got %d want %d", step, currentStep)
	}
}

func TestVerifyTOTPCode_PrevStepWithinSkew(t *testing.T) {
	prev := time.Now().Add(-time.Duration(totpStepPeriod) * time.Second)
	prevStep := prev.Unix() / totpStepPeriod
	code := generateAt(t, prev)

	step, ok := VerifyTOTPCode(code, testSecret)
	if !ok {
		t.Fatal("previous step: expected ok=true (skew=±1)")
	}
	if step != prevStep {
		t.Errorf("step: got %d want %d", step, prevStep)
	}
}

func TestVerifyTOTPCode_NextStepWithinSkew(t *testing.T) {
	next := time.Now().Add(time.Duration(totpStepPeriod) * time.Second)
	nextStep := next.Unix() / totpStepPeriod
	code := generateAt(t, next)

	step, ok := VerifyTOTPCode(code, testSecret)
	if !ok {
		t.Fatal("next step: expected ok=true (skew=±1)")
	}
	if step != nextStep {
		t.Errorf("step: got %d want %d", step, nextStep)
	}
}

func TestVerifyTOTPCode_OutsideSkew(t *testing.T) {
	// Two periods in the past — outside the ±1 window.
	old := time.Now().Add(-2 * time.Duration(totpStepPeriod) * time.Second)
	code := generateAt(t, old)

	if step, ok := VerifyTOTPCode(code, testSecret); ok {
		t.Errorf("outside skew: expected ok=false, got step=%d", step)
	}
}

func TestVerifyTOTPCode_WrongCode(t *testing.T) {
	if step, ok := VerifyTOTPCode("000000", testSecret); ok {
		// Will only flake if "000000" happens to be the current code — astronomically rare.
		t.Errorf("wrong code: expected ok=false, got step=%d", step)
	}
}

func TestVerifyTOTPCode_EmptyCode(t *testing.T) {
	if _, ok := VerifyTOTPCode("", testSecret); ok {
		t.Error("empty code: expected ok=false")
	}
}

func TestVerifyTOTPCode_EmptySecret(t *testing.T) {
	// pquerna/otp returns an error on an empty secret; the loop should
	// swallow it and return ok=false rather than panicking.
	if _, ok := VerifyTOTPCode("123456", ""); ok {
		t.Error("empty secret: expected ok=false")
	}
}

func TestVerifyTOTPCode_LengthMismatch(t *testing.T) {
	// constant-time compare must not panic on a length mismatch.
	if _, ok := VerifyTOTPCode("12", testSecret); ok {
		t.Error("short code: expected ok=false")
	}
	if _, ok := VerifyTOTPCode("1234567890", testSecret); ok {
		t.Error("long code: expected ok=false")
	}
}

func TestVerifyTOTPCode_StepStrictlyIncreases(t *testing.T) {
	// Replay-protection contract: a code accepted at step N must
	// never report a step <= N for the same secret. Verify across
	// the skew window to confirm the returned step is the matched
	// step, not always the current step.
	now := time.Now()
	currentStep := now.Unix() / totpStepPeriod

	prevCode := generateAt(t, now.Add(-time.Duration(totpStepPeriod)*time.Second))
	prevStep, ok := VerifyTOTPCode(prevCode, testSecret)
	if !ok {
		t.Fatal("prev: expected ok=true")
	}
	if prevStep != currentStep-1 {
		t.Errorf("prev step: got %d want %d", prevStep, currentStep-1)
	}

	nextCode := generateAt(t, now.Add(time.Duration(totpStepPeriod)*time.Second))
	nextStep, ok := VerifyTOTPCode(nextCode, testSecret)
	if !ok {
		t.Fatal("next: expected ok=true")
	}
	if nextStep != currentStep+1 {
		t.Errorf("next step: got %d want %d", nextStep, currentStep+1)
	}
	if !(prevStep < nextStep) {
		t.Errorf("step ordering: prev=%d next=%d", prevStep, nextStep)
	}
}
