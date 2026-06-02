package core

import (
	"context"
	"errors"
	"testing"
)

func TestIsTurnstileTestSecret(t *testing.T) {
	cases := []struct {
		secret string
		want   bool
	}{
		{"1x0000000000000000000000000000000AA", true},
		{"3x0000000000000000000000000000000AA", true},
		{"2x0000000000000000000000000000000AA", false}, // always-fail key — not bypassed
		{"0x4AAAAAAAAYourRealSecret", false},
		{"", false},
		{"not-a-key", false},
	}
	for _, c := range cases {
		if got := IsTurnstileTestSecret(c.secret); got != c.want {
			t.Errorf("IsTurnstileTestSecret(%q) = %v, want %v", c.secret, got, c.want)
		}
	}
}

func TestVerifyTurnstileToken_LocalBypassForTestSecret(t *testing.T) {
	// Test secrets short-circuit before any HTTP call. A blank token should
	// also pass — tests don't always carry a token.
	ctx := context.Background()
	res, err := VerifyTurnstileToken(ctx, "1x0000000000000000000000000000000AA", "any-token", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Error("expected Success=true with test secret")
	}

	res2, err := VerifyTurnstileToken(ctx, "1x0000000000000000000000000000000AA", "", "")
	if err != nil {
		t.Fatalf("empty token + test secret should bypass, got error: %v", err)
	}
	if !res2.Success {
		t.Error("expected Success=true with test secret + empty token")
	}
}

func TestVerifyTurnstileToken_EmptySecretReturnsMissingInput(t *testing.T) {
	_, err := VerifyTurnstileToken(context.Background(), "", "tok", "")
	if !errors.Is(err, ErrTurnstileMissingInput) {
		t.Errorf("expected ErrTurnstileMissingInput, got %v", err)
	}
}

func TestVerifyTurnstileToken_RealSecretEmptyTokenReturnsMissingInput(t *testing.T) {
	// A non-test secret with an empty token still short-circuits — we must
	// not hit Cloudflare with a known-bad request.
	_, err := VerifyTurnstileToken(context.Background(), "0x4AAAAAAAAYourRealSecret", "", "")
	if !errors.Is(err, ErrTurnstileMissingInput) {
		t.Errorf("expected ErrTurnstileMissingInput for empty token, got %v", err)
	}
}
