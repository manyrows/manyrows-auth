package api

import (
	"context"

	"manyrows-core/core"
)

// unlockUserAccount fully unlocks an end user: clears the lock flag AND
// purges the failed-login attempts that drive the lockout counter. Without
// the purge, the next failed login within the counting window re-locks
// immediately. attemptPurposeWorkspaceLoginPassword is the only end-user
// lockout purpose (see maybeApplyUserLockout).
func (handler *RequestHandler) unlockUserAccount(ctx context.Context, user *core.User) error {
	if err := handler.repo.ClearUserLockedUntil(ctx, user.ID); err != nil {
		return err
	}
	return handler.repo.DeleteAttemptsBySubject(ctx, normalizeEmail(user.Email),
		attemptPurposeWorkspaceLoginPassword)
}
