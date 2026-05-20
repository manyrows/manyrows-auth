// Package janitor runs a single background goroutine that periodically
// sweeps transient and event-log tables. It exists because without one,
// dpop_replay / attempts / auth_logs / refresh tokens / OTP rows all grow
// unbounded for the lifetime of a self-hosted install.
//
// Design notes:
//
//   - One goroutine, one configurable interval. Each tick runs every sweep
//     serially — predictable DB load, easy to read in the logs.
//   - Each sweep is best-effort: one table's failure logs and moves on,
//     it doesn't abort the rest of the tick.
//   - Defaults are conservative on retention (90d for auth_logs, 7d for
//     attempts) so an upgrade doesn't surprise anyone with sudden wipes.
//     Operators tune via env vars.
package janitor

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

	"manyrows-core/core/repo"
)

// Config holds the janitor's tunables. Zero values are treated as
// "use the sensible default" — see the Default* constants below.
type Config struct {
	// Interval between sweeps. Default: 1 hour.
	Interval time.Duration

	// Retention window for the attempts (rate-limit) table. Rows older
	// than this are deleted. Default: 7 days.
	AttemptsRetention time.Duration

	// Retention window for the auth_logs (audit) table. Default: 90 days.
	AuthLogRetention time.Duration

	// OAuth state rows past `expires_at` plus this grace are deleted.
	// Default: 1 hour.
	OAuthStateGrace time.Duration
}

const (
	DefaultInterval          = 1 * time.Hour
	DefaultAttemptsRetention = 7 * 24 * time.Hour
	DefaultAuthLogRetention  = 90 * 24 * time.Hour
	DefaultOAuthStateGrace   = 1 * time.Hour
)

// Janitor coordinates the periodic cleanup sweep.
type Janitor struct {
	repo *repo.Repo
	cfg  Config
}

// New builds a Janitor with cfg, substituting defaults for any zero
// values so callers can leave fields unset to get reasonable behaviour.
func New(r *repo.Repo, cfg Config) *Janitor {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.AttemptsRetention <= 0 {
		cfg.AttemptsRetention = DefaultAttemptsRetention
	}
	if cfg.AuthLogRetention <= 0 {
		cfg.AuthLogRetention = DefaultAuthLogRetention
	}
	if cfg.OAuthStateGrace <= 0 {
		cfg.OAuthStateGrace = DefaultOAuthStateGrace
	}
	return &Janitor{repo: r, cfg: cfg}
}

// Start launches the sweep loop in a goroutine. The loop exits when ctx
// is cancelled. A first sweep runs immediately so a freshly-booted
// process with a backlog of expired rows starts cleaning right away
// instead of waiting Interval before the first hit.
func (j *Janitor) Start(ctx context.Context) {
	go j.run(ctx)
}

func (j *Janitor) run(ctx context.Context) {
	log.Info().
		Dur("interval", j.cfg.Interval).
		Dur("attempts_retention", j.cfg.AttemptsRetention).
		Dur("auth_log_retention", j.cfg.AuthLogRetention).
		Msg("janitor: starting")

	j.sweep(ctx)

	ticker := time.NewTicker(j.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("janitor: stopping")
			return
		case <-ticker.C:
			j.sweep(ctx)
		}
	}
}

// sweep runs every cleanup once. Each step is independent so a failure
// in one table doesn't block the rest of the tick. Totals get rolled up
// into a single info line when something was actually deleted, so the
// log stays quiet on a healthy install.
//
// Multi-instance leader election: a Postgres session-level advisory
// lock guards the sweep so only one replica per tick does the work.
// Without this, N replicas would issue N parallel DELETE storms on the
// same rows — idempotent (correct) but wasted DB IO. If a replica
// crashes mid-sweep the connection drops and Postgres releases the
// lock automatically; the next ticker on any replica picks it up.
func (j *Janitor) sweep(ctx context.Context) {
	release, got, err := j.repo.TryClaimJanitorLock(ctx)
	if err != nil {
		log.Err(err).Msg("janitor: advisory-lock claim failed; skipping tick")
		return
	}
	if !got {
		log.Debug().Msg("janitor: another replica holds the sweep lock; skipping tick")
		return
	}
	defer release()

	now := time.Now().UTC()

	var total int64
	step := func(label string, fn func() (int64, error)) {
		n, err := fn()
		if err != nil {
			log.Err(err).Str("table", label).Msg("janitor: sweep failed")
			return
		}
		if n > 0 {
			log.Debug().Str("table", label).Int64("rows", n).Msg("janitor: swept")
			total += n
		}
	}

	// Event logs (configurable retention).
	step("attempts", func() (int64, error) {
		return j.repo.DeleteOldAttempts(ctx, j.cfg.AttemptsRetention)
	})
	step("auth_logs", func() (int64, error) {
		return j.repo.DeleteOldAuthLogs(ctx, j.cfg.AuthLogRetention)
	})

	// OAuth state — uses olderThan grace (matches the existing repo
	// method's signature).
	step("oauth_states", func() (int64, error) {
		return j.repo.DeleteExpiredOAuthStates(ctx, j.cfg.OAuthStateGrace)
	})

	// Everything else: delete past natural expiry.
	step("dpop_replay", func() (int64, error) {
		return j.repo.DeleteExpiredDPopReplay(ctx, now)
	})
	step("webauthn_challenges", func() (int64, error) {
		return j.repo.DeleteExpiredWebAuthnChallenges(ctx, now)
	})
	step("magic_links", func() (int64, error) {
		return j.repo.DeleteExpiredMagicLinks(ctx, now)
	})
	step("client_refresh_tokens", func() (int64, error) {
		return j.repo.DeleteExpiredClientRefreshTokens(ctx, now)
	})
	step("client_otp_codes", func() (int64, error) {
		return j.repo.DeleteExpiredClientOTPCodes(ctx, now)
	})
	step("account_email_otps", func() (int64, error) {
		return j.repo.DeleteExpiredAccountEmailOTPs(ctx, now)
	})
	step("account_password_reset_otps", func() (int64, error) {
		return j.repo.DeleteExpiredAccountPasswordResetOTPs(ctx, now)
	})
	step("account_email_change_otps", func() (int64, error) {
		return j.repo.DeleteExpiredAccountEmailChangeOTPs(ctx, now)
	})
	step("email_change_requests", func() (int64, error) {
		return j.repo.DeleteExpiredEmailChangeRequests(ctx, now)
	})
	step("sessions", func() (int64, error) {
		return j.repo.DeleteExpiredAdminSessions(ctx, now)
	})
	step("client_sessions", func() (int64, error) {
		return j.repo.DeleteAllExpiredClientSessions(ctx, now)
	})

	// OIDC provider tables. Sweep methods delete expired rows AND
	// used/consumed rows that have aged past their replay-detection
	// grace window (oidcCodeUsedGrace / oidcPendingConsumedGrace in
	// the repo).
	step("oidc_auth_codes", func() (int64, error) {
		return j.repo.SweepExpiredOIDCAuthCodes(ctx)
	})
	step("oidc_pending_authorize", func() (int64, error) {
		return j.repo.SweepExpiredOIDCPendingAuthorize(ctx)
	})

	if total > 0 {
		log.Info().Int64("rows_deleted", total).Msg("janitor: sweep complete")
	}
}
