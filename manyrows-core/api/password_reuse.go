package api

import (
	"context"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/crypto/passwordhash"

	"github.com/gofrs/uuid/v5"
)

// passwordRecentlyUsed reports whether candidate matches any of the user's
// most recent password hashes. currentHash (the live users.password_hash,
// possibly "") is checked as a safety net for accounts whose history
// predates the password_history table. Only call when the app's
// reuse-prevention toggle is on.
func passwordRecentlyUsed(ctx context.Context, rpo *repo.Repo, userID uuid.UUID, candidate, currentHash string) (bool, error) {
	hashes, err := rpo.GetRecentPasswordHistory(ctx, userID, repo.PasswordHistoryKeep)
	if err != nil {
		return false, err
	}
	if currentHash != "" {
		hashes = append(hashes, currentHash)
	}
	for _, h := range hashes {
		ok, verr := passwordhash.Verify(h, candidate)
		if verr == nil && ok {
			return true, nil
		}
	}
	return false, nil
}

// recordPasswordHistory appends the freshly set hash to the user's rolling
// history. Best-effort: a failure must never block the user's password
// change (enforcement still has the live users.password_hash safety net).
func recordPasswordHistory(ctx context.Context, rpo *repo.Repo, userID uuid.UUID, newHash string) {
	_ = rpo.AppendPasswordHistory(ctx, userID, newHash)
}

// appBlocksPasswordReuse is a nil-safe accessor for the per-app toggle.
func appBlocksPasswordReuse(app *core.App) bool {
	return app != nil && app.PasswordReusePrevention
}
