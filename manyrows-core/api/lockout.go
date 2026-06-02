package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

const (
	lockoutCountWindow = 1 * time.Hour

	lockoutThreshold1 = 10
	lockoutThreshold2 = 20
	lockoutThreshold3 = 30

	lockoutDuration1 = 15 * time.Minute
	lockoutDuration2 = 1 * time.Hour
	lockoutDuration3 = 24 * time.Hour
)

// checkAccountLocked checks if the account is currently locked.
// Returns true and writes a 403 response with Retry-After if locked.
func (handler *RequestHandler) checkAccountLocked(w http.ResponseWriter, r *http.Request, lockedUntil *time.Time) bool {
	if lockedUntil == nil {
		return false
	}
	remaining := time.Until(*lockedUntil)
	if remaining <= 0 {
		return false
	}

	retryAfter := int(remaining.Seconds()) + 1
	w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
	WriteError(w, r, "error.accountLocked", http.StatusForbidden)
	return true
}

// lockoutDuration returns the lockout duration based on failure count, or 0 if no lockout.
func lockoutDuration(failureCount int) time.Duration {
	if failureCount >= lockoutThreshold3 {
		return lockoutDuration3
	}
	if failureCount >= lockoutThreshold2 {
		return lockoutDuration2
	}
	if failureCount >= lockoutThreshold1 {
		return lockoutDuration1
	}
	return 0
}

// maybeApplyAdminLockout counts recent failures and locks the admin account if thresholds are exceeded.
func (handler *RequestHandler) maybeApplyAdminLockout(ctx context.Context, accountID uuid.UUID, purpose, subject string) {
	now := time.Now().UTC()
	since := now.Add(-lockoutCountWindow)

	count, err := handler.repo.CountAttemptsBySubject(ctx, purpose, subject, since)
	if err != nil {
		log.Err(err).Msg("failed to count attempts for admin lockout")
		return
	}

	d := lockoutDuration(count)
	if d == 0 {
		return
	}

	lockedUntil := now.Add(d)
	if err := handler.repo.SetAccountLockedUntil(ctx, accountID, lockedUntil); err != nil {
		log.Err(err).Msg("failed to set admin account locked_until")
	}
}

// maybeApplyUserLockout counts recent failures and locks the user if thresholds are exceeded.
func (handler *RequestHandler) maybeApplyUserLockout(r *http.Request, userID uuid.UUID, purpose, subject string) {
	ctx := r.Context()
	now := time.Now().UTC()
	since := now.Add(-lockoutCountWindow)

	count, err := handler.repo.CountAttemptsBySubject(ctx, purpose, subject, since)
	if err != nil {
		log.Err(err).Msg("failed to count attempts for user lockout")
		return
	}

	d := lockoutDuration(count)
	if d == 0 {
		return
	}

	lockedUntil := now.Add(d)
	if err := handler.repo.SetUserLockedUntil(ctx, userID, lockedUntil); err != nil {
		log.Err(err).Msg("failed to set user locked_until")
		return
	}

	// Emit account.locked when the workspace is in context. Lockout from
	// background paths without a workspace silently skips the log.
	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		return
	}
	subjectUserID := userID
	in := AuthLogInput{
		WorkspaceID:    ws.ID,
		Event:          core.AuthEventAccountLocked,
		Outcome:        core.AuthOutcomeSuccess,
		SubjectUserID:  &subjectUserID,
		EmailAttempted: subject,
		ActorType:      core.AuthActorSystem,
	}
	if app, ok := core.AppFromContext(ctx); ok && app != nil {
		in.AppID = &app.ID
	}
	handler.writeAuthLogFromRequest(r, in)
}
