package repo

import (
	"context"
	"strings"
	"time"

	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
)

// ListUserTags returns the tags for a single user in an app, sorted alpha.
func (r *Repo) ListUserTags(ctx context.Context, appID, userID uuid.UUID) ([]string, error) {
	const q = `
SELECT tag FROM user_tags
WHERE app_id = $1 AND user_id = $2
ORDER BY tag ASC;
`
	rows, err := r.db.Pool().Query(ctx, q, appID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ReplaceUserTags overwrites the full tag set for a user. Tags are
// normalized (trimmed + lowercased) and deduplicated; entries longer than
// 40 chars or empty are dropped silently.
//
// Atomic via a transaction so callers see all-or-nothing.
func (r *Repo) ReplaceUserTags(ctx context.Context, appID, userID uuid.UUID, tags []string) ([]string, error) {
	clean := normalizeTags(tags)

	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`DELETE FROM user_tags WHERE app_id = $1 AND user_id = $2`,
		appID, userID); err != nil {
		return nil, err
	}

	for _, t := range clean {
		id := utils.NewUUID()
		if _, err := tx.Exec(ctx, `
INSERT INTO user_tags (id, app_id, user_id, tag, created_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (app_id, user_id, tag) DO NOTHING;
`, id, appID, userID, t, time.Now().UTC()); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return clean, nil
}

// ListAppDistinctTags returns every distinct tag in use across the app —
// powers the autocomplete on the edit dialog so admins reuse existing tag
// names rather than creating typo-variants.
func (r *Repo) ListAppDistinctTags(ctx context.Context, appID uuid.UUID) ([]string, error) {
	const q = `
SELECT DISTINCT tag FROM user_tags
WHERE app_id = $1
ORDER BY tag ASC;
`
	rows, err := r.db.Pool().Query(ctx, q, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetUserTagsForUsers returns a map[userID][]tag for a batch of users in
// the same app. Used to populate tag chips on the user-list rows in one
// query rather than N+1.
func (r *Repo) GetUserTagsForUsers(ctx context.Context, appID uuid.UUID, userIDs []uuid.UUID) (map[uuid.UUID][]string, error) {
	out := map[uuid.UUID][]string{}
	if appID == uuid.Nil || len(userIDs) == 0 {
		return out, nil
	}
	const q = `
SELECT user_id, tag FROM user_tags
WHERE app_id = $1 AND user_id = ANY($2::uuid[])
ORDER BY user_id, tag ASC;
`
	rows, err := r.db.Pool().Query(ctx, q, appID, userIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var uid uuid.UUID
		var tag string
		if err := rows.Scan(&uid, &tag); err != nil {
			return nil, err
		}
		out[uid] = append(out[uid], tag)
	}
	return out, rows.Err()
}

// normalizeTags trims, lowercases, dedupes, and length-caps the input. Tags
// over 40 chars or empty after trim are dropped silently — admins can fix
// the input rather than getting a hard error mid-list.
func normalizeTags(in []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, raw := range in {
		t := strings.ToLower(strings.TrimSpace(raw))
		if t == "" || len(t) > 40 {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}
