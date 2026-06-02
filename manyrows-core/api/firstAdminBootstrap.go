package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
)

// createDefaultWorkspaceForFirstAdmin spins up the single workspace
// every self-hosted install runs against. Called from AdminRegister
// when the registrant has just won the super-admin claim.
// Best-effort: returns nil on success, or an error the caller
// should log but probably not surface to the user — the admin still
// got registered, the workspace can be retried by a follow-up.
//
// Slug is "default" by default; if that's taken (e.g. left over from
// an earlier boot), falls back to "default-<8 hex>". Workspace name
// is "My Workspace" — meant to be edited via the workspace settings UI.
func (handler *RequestHandler) createDefaultWorkspaceForFirstAdmin(ctx context.Context, ownerID uuid.UUID) error {
	slug, err := pickAvailableDefaultSlug(ctx, handler.repo)
	if err != nil {
		return fmt.Errorf("pick slug: %w", err)
	}

	ws := core.Workspace{
		ID:        utils.NewUUID(),
		Name:      "My Workspace",
		Slug:      slug,
		Status:    core.WorkspaceStatusActive,
		CreatedBy: &ownerID,
		CreatedAt: time.Now().UTC(),
	}

	tx, err := handler.repo.DB().Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := handler.repo.InsertWorkspace(ctx, &ws, tx); err != nil {
		if errors.Is(err, ErrSlugConflict) {
			// Slot got taken between our slug check and insert. The
			// caller can retry — but in practice the suffixed slug
			// is essentially-unique so this is vanishingly unlikely.
			return fmt.Errorf("insert workspace (slug raced): %w", err)
		}
		return fmt.Errorf("insert workspace: %w", err)
	}

	const insertAdminQ = `
		INSERT INTO workspace_admins (workspace_id, account_id, role, added_by)
		VALUES ($1, $2, 'owner', $3)
		ON CONFLICT (workspace_id, account_id) DO NOTHING
	`
	if _, err := tx.Exec(ctx, insertAdminQ, ws.ID, ownerID, ownerID); err != nil {
		return fmt.Errorf("insert workspace_admins: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// pickAvailableDefaultSlug tries "default", then "default-<rand>" if
// taken. Won't loop forever — one retry is enough because the random
// suffix has 32 bits of entropy.
func pickAvailableDefaultSlug(ctx context.Context, repo interface {
	GetWorkspaceBySlug(ctx context.Context, slug string) (*core.Workspace, bool, error)
}) (string, error) {
	candidate := "default"
	existing, _, err := repo.GetWorkspaceBySlug(ctx, candidate)
	if err != nil {
		return "", err
	}
	if existing == nil {
		return candidate, nil
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	return "default-" + hex.EncodeToString(suffix), nil
}
