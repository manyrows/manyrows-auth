package api

import (
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// checkAttemptRateLimit checks IP + (optionally) subject attempt counts
// in the attemptWindow against the per-IP and per-subject caps. When
// either cap is exceeded, OR an underlying repo query errors, the helper
// writes the HTTP response and returns false — the caller must return
// immediately without touching the response writer again.
//
// Pass an empty subject ("") to skip the per-subject check; some flows
// rate-limit by IP only (e.g. refresh-token rotation, which has no
// caller-supplied identifier at the moment of the check).
//
// purposeContext is the human-readable phrase suffixed onto the log
// message ("failed to count attempts by IP for <purposeContext>"). It
// is for operator-side telemetry only and is never written to the
// response.
//
// onCapExceeded, when non-nil, is invoked immediately before the
// rate-limit response on the cap-exceeded branch (NOT on the repo-error
// branch). Used by call sites that emit an AuthFailRateLimited audit log
// so operators can see attack patterns. Closure over locals captured by
// the caller (ws, app, email) is the standard idiom.
//
// NOTE on burn timing: this helper does NOT insert an attempt row. The
// burn (InsertAttempt) is intentionally left to callers because the
// correct timing is purpose-specific — some flows burn before the
// existence check (so probing for accounts is rate-limited) while
// others only burn after a successful side-effect (so a flood of bad
// inputs doesn't starve a real user's budget). Get this right per-call
// site; this helper only enforces the cap.
func (h *RequestHandler) checkAttemptRateLimit(
	w http.ResponseWriter,
	r *http.Request,
	purpose string,
	ip, subject string,
	purposeContext string,
	onCapExceeded func(),
) bool {
	since := time.Now().UTC().Add(-attemptWindow)
	retryAfter := int(attemptWindow.Seconds())

	ipCount, err := h.repo.CountAttemptsByIP(r.Context(), purpose, ip, since)
	if err != nil {
		log.Err(err).Msgf("failed to count attempts by IP for %s", purposeContext)
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return false
	}
	if ipCount >= maxAttemptsPerIP10Min {
		if onCapExceeded != nil {
			onCapExceeded()
		}
		WriteRateLimitError(w, r, retryAfter)
		return false
	}

	if subject == "" {
		return true
	}

	subjectCount, err := h.repo.CountAttemptsBySubject(r.Context(), purpose, subject, since)
	if err != nil {
		log.Err(err).Msgf("failed to count attempts by subject for %s", purposeContext)
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return false
	}
	if subjectCount >= maxAttemptsPerSubject10Min {
		if onCapExceeded != nil {
			onCapExceeded()
		}
		WriteRateLimitError(w, r, retryAfter)
		return false
	}
	return true
}

// checkEmailSendDailyQuota enforces a per-email daily cap on outbound
// email-sending flows (magic-link / OTP / email-change). The 10/10min
// burst cap in checkAttemptRateLimit bounds rate, but a patient
// attacker rotating IPs can still drip-flood a single inbox to ~1440
// emails a day. This daily cap kills the slow-flood while leaving
// generous headroom (30/day) for a confused legitimate user.
//
// Call AFTER checkAttemptRateLimit; only applied to send-flows where
// the cost surface is the recipient's inbox (and the operator's email
// transport bill), not to login/verify/etc. flows where a confused
// user could legitimately retry many times per day.
//
// Same response shape and onCapExceeded contract as the burst check:
// returns true to proceed, false (with response already written) to
// abort.
func (h *RequestHandler) checkEmailSendDailyQuota(
	w http.ResponseWriter,
	r *http.Request,
	purpose string,
	subject string,
	purposeContext string,
	onCapExceeded func(),
) bool {
	if subject == "" {
		return true
	}
	since := time.Now().UTC().Add(-emailSendDailyWindow)
	count, err := h.repo.CountAttemptsBySubject(r.Context(), purpose, subject, since)
	if err != nil {
		log.Err(err).Msgf("failed to count daily attempts for %s", purposeContext)
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return false
	}
	if count >= maxEmailSendsPerSubjectDay {
		if onCapExceeded != nil {
			onCapExceeded()
		}
		// Retry-After hints when the oldest in-window attempt ages
		// out. Without per-attempt timestamps in the count query we
		// can't compute the exact value here, so hand back the full
		// window — clients should not poll harder than that.
		WriteRateLimitError(w, r, int(emailSendDailyWindow.Seconds()))
		return false
	}
	return true
}
