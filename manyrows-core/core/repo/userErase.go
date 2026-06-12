package repo

import (
	"context"
	"errors"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// scrubResidualPII removes a user's residual personal data not covered by the
// users-row cascade. Caller supplies a live tx. auth_logs anonymization runs
// before the users row is deleted (the FK is ON DELETE SET NULL, which would
// otherwise null subject_user_id and lose the link).
func scrubResidualPII(ctx context.Context, tx pgx.Tx, userID uuid.UUID, email string, wsID uuid.UUID) error {
	// Collect prior email addresses from this user's email-change history.
	// Failed-login rows carry email_attempted but no subject_user_id, so a row
	// logged under a FORMER address would otherwise survive erasure. Read the
	// metadata before the UPDATE below nulls it. The rows cursor MUST be fully
	// drained + closed before the next Exec on this tx.
	emails := []string{strings.ToLower(strings.TrimSpace(email))}
	rows, err := tx.Query(ctx, `
SELECT DISTINCT lower(e) AS e FROM (
    SELECT metadata->>'old_email' AS e FROM auth_logs
      WHERE subject_user_id = $1 AND metadata->>'old_email' IS NOT NULL
    UNION
    SELECT metadata->>'new_email' AS e FROM auth_logs
      WHERE subject_user_id = $1 AND metadata->>'new_email' IS NOT NULL
) s WHERE e IS NOT NULL AND e <> '';`, userID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			rows.Close()
			return err
		}
		emails = append(emails, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// 1. Anonymize auth_logs: null direct identifiers, keep the event skeleton.
	if _, err := tx.Exec(ctx, `
UPDATE auth_logs
   SET email_attempted = NULL, ip = NULL, user_agent = NULL, actor_label = NULL, metadata = NULL
 WHERE workspace_id = $1
   AND ( subject_user_id = $2
         OR lower(email_attempted) = ANY($3)
         OR lower(actor_label) = ANY($3) );`,
		wsID, userID, emails); err != nil {
		return err
	}

	// 2. Scrub webhook delivery payloads that carry this user's email. Keyed on
	// the payload userId; payloads without one (e.g. org-invite events) are not
	// this user's to scrub here and are intentionally out of scope.
	if _, err := tx.Exec(ctx, `
UPDATE webhook_deliveries
   SET payload = payload - 'email' - 'oldEmail' - 'newEmail'
 WHERE payload->>'userId' = $1;`,
		userID.String()); err != nil {
		return err
	}

	// NOTE: rate-limit `attempts` rows are intentionally NOT deleted here.
	// attempts.subject is a bare email with no tenant column, so a global
	// DELETE would reset rate-limit/lockout state for the same email in OTHER
	// tenants. Those rows (email + ip) age out under the janitor's 7-day TTL,
	// a bounded storage-limitation control.
	return nil
}

// EraseUser performs a GDPR-complete erasure of a user in one transaction:
// anonymize residual auth_logs, scrub webhook payloads, then DELETE the users
// row (existing FK cascade clears sessions, tokens, MFA, passkeys, identities,
// org memberships, password history, field values).
func (r *Repo) EraseUser(ctx context.Context, userID uuid.UUID, email string, wsID uuid.UUID) error {
	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := scrubResidualPII(ctx, tx, userID, email, wsID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1;`, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// EraseUserIfOrphanInPool is the admin/orphan-prune counterpart: it deletes
// the user (and scrubs residual PII) only if they belong to poolID and have no
// app memberships. The users row is locked FOR UPDATE so a concurrent
// membership insert (which takes FOR KEY SHARE on the row) serializes against
// this check. Reports whether a row was erased.
func (r *Repo) EraseUserIfOrphanInPool(ctx context.Context, userID, poolID uuid.UUID, email string, wsID uuid.UUID) (bool, error) {
	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var locked uuid.UUID
	if err := tx.QueryRow(ctx,
		`SELECT id FROM users WHERE id = $1 AND user_pool_id = $2 FOR UPDATE`, userID, poolID,
	).Scan(&locked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil // not in this pool — nothing to do
		}
		return false, err
	}

	var hasMembership bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM app_users WHERE user_id = $1)`, userID,
	).Scan(&hasMembership); err != nil {
		return false, err
	}
	if hasMembership {
		return false, nil // still belongs to another app sharing the pool — keep identity
	}

	if err := scrubResidualPII(ctx, tx, userID, email, wsID); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1;`, userID); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}
