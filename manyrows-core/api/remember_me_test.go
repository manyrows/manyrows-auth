package api

// Internal-package test so we can exercise the unexported effectiveSessionTTL
// helper directly. Pure-function math; no DB needed.

import (
	"testing"
	"time"

	"manyrows-core/auth/client"
	"manyrows-core/core"
)

func TestEffectiveSessionTTL(t *testing.T) {
	const oneHour = 1 * time.Hour
	const twoMonths = 60 * 24 * time.Hour

	cases := []struct {
		name       string
		appTTLMin  *int
		rememberMe bool
		want       time.Duration
	}{
		{
			name:       "no remember-me, no app config → fall through to 0 (caller picks default)",
			appTTLMin:  nil,
			rememberMe: false,
			want:       0,
		},
		{
			name:       "no remember-me, app TTL set → app TTL wins",
			appTTLMin:  intp(60), // 1 hour
			rememberMe: false,
			want:       oneHour,
		},
		{
			name:       "remember-me, no app config → bumped to 30 days",
			appTTLMin:  nil,
			rememberMe: true,
			want:       client.RememberMeTTL,
		},
		{
			name:       "remember-me, short app TTL → bumped to 30 days",
			appTTLMin:  intp(60), // 1 hour
			rememberMe: true,
			want:       client.RememberMeTTL,
		},
		{
			name:       "remember-me, app TTL longer than 30 days → app TTL wins (don't shrink)",
			appTTLMin:  intp(60 * 24 * 60), // 60 days
			rememberMe: true,
			want:       twoMonths,
		},
		{
			name:       "remember-me, app TTL exactly 30 days → 30 days",
			appTTLMin:  intp(60 * 24 * 30),
			rememberMe: true,
			want:       client.RememberMeTTL,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			app := &core.App{SessionTTLMinutes: c.appTTLMin}
			got := effectiveSessionTTL(app, c.rememberMe)
			if got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func intp(v int) *int {
	return &v
}

// (No external test scaffolding here — round-trip tests for
// CreateSessionWithOptions live in remember_me_integration_test.go in the
// api_test package alongside the other auth-flow tests.)
