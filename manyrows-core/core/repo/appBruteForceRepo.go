package repo

import (
	"context"
	"errors"
	"fmt"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// UpdateAppBruteForceProtectionConfig flips the per-app brute-force-protection
// toggle. Unlike QR sign-in there is no precondition to enabling — the
// protection is self-contained — so this is a plain single-statement update.
// The toggle gates enforcement only (lockout check + login rate limit +
// lockout application); failed-attempt rows are always recorded elsewhere.
func (r *Repo) UpdateAppBruteForceProtectionConfig(ctx context.Context, workspaceID, projectID, appID uuid.UUID, enabled bool) (core.App, error) {
	q := `
		update apps
		set brute_force_protection_enabled = $4,
		    updated_at = now()
		where id = $1 and workspace_id = $2 and project_id = $3
		returning ` + appColumnsReturning

	var out core.App
	err := scanAppFull(r.db.Pool().QueryRow(ctx, q, appID, workspaceID, projectID, enabled), &out)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.App{}, ErrNotFound
		}
		return core.App{}, fmt.Errorf("UpdateAppBruteForceProtectionConfig: %w", err)
	}
	return out, nil
}
