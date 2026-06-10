package repo

import (
	"context"

	"github.com/gofrs/uuid/v5"
)

// PasswordHistoryKeep is the rolling window of password hashes kept per
// user. The reuse-prevention check compares against this window; recording
// happens on every successful password set regardless of the app toggle.
const PasswordHistoryKeep = 5

// AppendPasswordHistory records a newly set password hash and prunes the
// user's history beyond the newest PasswordHistoryKeep entries. Two
// statements rather than one INSERT...CTE: a data-modifying CTE's insert
// isn't visible to the delete in the same statement, so a single-statement
// version would prune against the pre-insert snapshot and keep 6 rows.
// A prune failure leaves the freshly inserted row in place (callers treat
// recording as best-effort); concurrent appends can transiently exceed the
// window and self-heal on the next append.
func (r *Repo) AppendPasswordHistory(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	if _, err := r.db.Pool().Exec(ctx,
		`insert into password_history (user_id, password_hash) values ($1, $2)`,
		userID, passwordHash); err != nil {
		return err
	}
	_, err := r.db.Pool().Exec(ctx, `
delete from password_history
where user_id = $1
  and id not in (
      select id from password_history
      where user_id = $1
      order by created_at desc, id desc
      limit $2
  );`, userID, PasswordHistoryKeep)
	return err
}

// GetRecentPasswordHistory returns the user's most recent password hashes,
// newest first, up to limit.
func (r *Repo) GetRecentPasswordHistory(ctx context.Context, userID uuid.UUID, limit int) ([]string, error) {
	rows, err := r.db.Pool().Query(ctx, `
select password_hash from password_history
where user_id = $1
order by created_at desc, id desc
limit $2;`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
