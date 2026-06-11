package repo

import (
	"context"
	"fmt"
	"manyrows-core/utils"
	"time"
)

func (r *Repo) InsertAttempt(ctx context.Context, purpose string, subject string, ip string) error {
	id := utils.NewUUID()
	const q = `
		insert into attempts (id, purpose, subject, ip)
		values ($1, $2, $3, $4)
	`
	_, err := r.db.Pool().Exec(ctx, q, id, purpose, subject, ip)
	return err
}

func (r *Repo) CountAttemptsBySubject(ctx context.Context, purpose string, subject string, since time.Time) (int, error) {
	const q = `
		select count(*)
		from attempts
		where purpose = $1
		  and subject = $2
		  and created_at >= $3
	`
	var count int
	if err := r.db.Pool().QueryRow(ctx, q, purpose, subject, since).Scan(&count); err != nil {
		return 0, fmt.Errorf("count attempts by subject: %w", err)
	}
	return count, nil
}

// DeleteAttemptsBySubject removes attempt rows for a subject across the
// given purposes. Used by the admin/server unlock to clear the lockout
// counter so an unlocked user is not immediately re-locked by the stale
// failure count.
func (r *Repo) DeleteAttemptsBySubject(ctx context.Context, subject string, purposes ...string) error {
	if subject == "" || len(purposes) == 0 {
		return nil
	}
	const q = `delete from attempts where subject = $1 and purpose = any($2)`
	_, err := r.db.Pool().Exec(ctx, q, subject, purposes)
	return err
}

func (r *Repo) CountAttemptsByIP(ctx context.Context, purpose string, ip string, since time.Time) (int, error) {
	const q = `
		select count(*)
		from attempts
		where purpose = $1
		  and ip = $2
		  and created_at >= $3
	`
	var count int
	if err := r.db.Pool().QueryRow(ctx, q, purpose, ip, since).Scan(&count); err != nil {
		return 0, fmt.Errorf("count attempts by ip: %w", err)
	}
	return count, nil
}
