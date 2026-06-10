package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// ---- scanner helper ----

type webhookScanner interface {
	Scan(dest ...any) error
}

func scanWebhook(s webhookScanner, w *core.Webhook) error {
	return s.Scan(
		&w.ID,
		&w.ProjectID,
		&w.AppID,
		&w.URL,
		&w.Secret,
		&w.SecretEncrypted,
		&w.Events,
		&w.Status,
		&w.Description,
		&w.CreatedAt,
		&w.UpdatedAt,
		&w.CreatedBy,
	)
}

type webhookDeliveryScanner interface {
	Scan(dest ...any) error
}

func scanWebhookDelivery(s webhookDeliveryScanner, d *core.WebhookDelivery) error {
	return s.Scan(
		&d.ID,
		&d.WebhookID,
		&d.Event,
		&d.Payload,
		&d.Status,
		&d.StatusCode,
		&d.ResponseBody,
		&d.Attempts,
		&d.NextRetryAt,
		&d.CreatedAt,
		&d.CompletedAt,
	)
}

// ---- Webhook CRUD ----

func (r *Repo) GetWebhooksByAppID(ctx context.Context, appID uuid.UUID) ([]core.Webhook, error) {
	const q = `
		SELECT id, project_id, app_id, url, secret, secret_encrypted, events, status, description, created_at, updated_at, created_by
		FROM webhooks
		WHERE app_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.Pool().Query(ctx, q, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]core.Webhook, 0)
	for rows.Next() {
		var w core.Webhook
		if err := scanWebhook(rows, &w); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (r *Repo) GetWebhookByID(ctx context.Context, webhookID, appID uuid.UUID) (core.Webhook, bool, error) {
	const q = `
		SELECT id, project_id, app_id, url, secret, secret_encrypted, events, status, description, created_at, updated_at, created_by
		FROM webhooks
		WHERE id = $1 AND app_id = $2
	`

	row := r.db.Pool().QueryRow(ctx, q, webhookID, appID)
	var w core.Webhook
	if err := scanWebhook(row, &w); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return w, false, nil
		}
		return w, false, fmt.Errorf("get webhook by id: %w", err)
	}
	return w, true, nil
}

func (r *Repo) GetWebhookByIDOnly(ctx context.Context, webhookID uuid.UUID) (core.Webhook, bool, error) {
	const q = `
		SELECT id, project_id, app_id, url, secret, secret_encrypted, events, status, description, created_at, updated_at, created_by
		FROM webhooks
		WHERE id = $1
	`

	row := r.db.Pool().QueryRow(ctx, q, webhookID)
	var w core.Webhook
	if err := scanWebhook(row, &w); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return w, false, nil
		}
		return w, false, fmt.Errorf("get webhook by id only: %w", err)
	}
	return w, true, nil
}

func (r *Repo) CountWebhooksByAppID(ctx context.Context, appID uuid.UUID) (int, error) {
	const q = `
		SELECT count(*)
		FROM webhooks
		WHERE app_id = $1
	`

	var count int
	if err := r.db.Pool().QueryRow(ctx, q, appID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count webhooks: %w", err)
	}
	return count, nil
}

func (r *Repo) InsertWebhook(ctx context.Context, w core.Webhook) error {
	const q = `
		INSERT INTO webhooks (
			id, project_id, app_id, url, secret, secret_encrypted, events, status, description, created_at, updated_at, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)
	`

	_, err := r.db.Pool().Exec(ctx, q,
		w.ID,
		w.ProjectID,
		w.AppID,
		w.URL,
		w.Secret,
		w.SecretEncrypted,
		w.Events,
		w.Status,
		w.Description,
		w.CreatedAt,
		w.UpdatedAt,
		w.CreatedBy,
	)
	return err
}

// InsertWebhookWithLimit atomically inserts a webhook only if the app has fewer than maxLimit webhooks.
func (r *Repo) InsertWebhookWithLimit(ctx context.Context, w core.Webhook, maxLimit int) (bool, error) {
	const q = `
		INSERT INTO webhooks (
			id, project_id, app_id, url, secret, secret_encrypted, events, status, description, created_at, updated_at, created_by
		)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		WHERE (SELECT count(*) FROM webhooks WHERE app_id = $3) < $13
	`

	tag, err := r.db.Pool().Exec(ctx, q,
		w.ID,
		w.ProjectID,
		w.AppID,
		w.URL,
		w.Secret,
		w.SecretEncrypted,
		w.Events,
		w.Status,
		w.Description,
		w.CreatedAt,
		w.UpdatedAt,
		w.CreatedBy,
		maxLimit,
	)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (r *Repo) UpdateWebhook(ctx context.Context, w core.Webhook) error {
	const q = `
		UPDATE webhooks
		SET url = $1, events = $2, status = $3, description = $4, updated_at = $5
		WHERE id = $6 AND app_id = $7
	`

	_, err := r.db.Pool().Exec(ctx, q,
		w.URL,
		w.Events,
		w.Status,
		w.Description,
		w.UpdatedAt,
		w.ID,
		w.AppID,
	)
	return err
}

// RotateWebhookSecret replaces a webhook's signing secret (app-scoped). The
// secret is stored as AAD-bound ciphertext in secret_encrypted; the legacy
// plaintext column is cleared so a rotated webhook never leaves its old (or
// any) secret in plaintext at rest.
func (r *Repo) RotateWebhookSecret(ctx context.Context, webhookID, appID uuid.UUID, secretEncrypted []byte) error {
	const q = `UPDATE webhooks SET secret = '', secret_encrypted = $1, updated_at = now() WHERE id = $2 AND app_id = $3`
	return r.execAffectingOne(ctx, ErrNotFound, q, secretEncrypted, webhookID, appID)
}

func (r *Repo) DeleteWebhook(ctx context.Context, webhookID, appID uuid.UUID) error {
	const q = `
		DELETE FROM webhooks
		WHERE id = $1 AND app_id = $2
	`

	_, err := r.db.Pool().Exec(ctx, q, webhookID, appID)
	return err
}

func (r *Repo) GetActiveWebhooksForEvent(ctx context.Context, appID uuid.UUID, eventKey string) ([]core.Webhook, error) {
	const q = `
		SELECT id, project_id, app_id, url, secret, secret_encrypted, events, status, description, created_at, updated_at, created_by
		FROM webhooks
		WHERE app_id = $1
		  AND status = 'active'
		  AND $2 = ANY(events)
	`

	rows, err := r.db.Pool().Query(ctx, q, appID, eventKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.Webhook
	for rows.Next() {
		var w core.Webhook
		if err := scanWebhook(rows, &w); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// DeleteOldWebhookDeliveries removes terminal (success/failed) delivery rows
// older than olderThan. Pending/retrying rows are kept regardless of age so an
// in-flight retry schedule is never truncated. Each delivery's `payload` holds
// the full event body (emails, IPs, user/session IDs), so without this the
// table both grows unbounded and retains PII indefinitely.
func (r *Repo) DeleteOldWebhookDeliveries(ctx context.Context, olderThan time.Duration) (int64, error) {
	const q = `
		DELETE FROM webhook_deliveries
		WHERE status IN ('success', 'failed')
		  AND coalesce(completed_at, created_at) < now() - $1::interval;
	`
	tag, err := r.db.Pool().Exec(ctx, q, olderThan.String())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ---- Webhook Delivery CRUD ----

func (r *Repo) InsertWebhookDelivery(ctx context.Context, d core.WebhookDelivery) error {
	const q = `
		INSERT INTO webhook_deliveries (
			id, webhook_id, event, payload, status, status_code, response_body, attempts, next_retry_at, created_at, completed_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)
	`

	_, err := r.db.Pool().Exec(ctx, q,
		d.ID,
		d.WebhookID,
		d.Event,
		d.Payload,
		d.Status,
		d.StatusCode,
		d.ResponseBody,
		d.Attempts,
		d.NextRetryAt,
		d.CreatedAt,
		d.CompletedAt,
	)
	return err
}

func (r *Repo) UpdateWebhookDelivery(ctx context.Context, d core.WebhookDelivery) error {
	const q = `
		UPDATE webhook_deliveries
		SET status = $1, status_code = $2, response_body = $3, attempts = $4, next_retry_at = $5, completed_at = $6
		WHERE id = $7
	`

	_, err := r.db.Pool().Exec(ctx, q,
		d.Status,
		d.StatusCode,
		d.ResponseBody,
		d.Attempts,
		d.NextRetryAt,
		d.CompletedAt,
		d.ID,
	)
	return err
}

func (r *Repo) GetDeliveriesByWebhookID(ctx context.Context, webhookID uuid.UUID, limit, offset int) ([]core.WebhookDelivery, error) {
	const q = `
		SELECT id, webhook_id, event, payload, status, status_code, response_body, attempts, next_retry_at, created_at, completed_at
		FROM webhook_deliveries
		WHERE webhook_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.Pool().Query(ctx, q, webhookID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]core.WebhookDelivery, 0)
	for rows.Next() {
		var d core.WebhookDelivery
		if err := scanWebhookDelivery(rows, &d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (r *Repo) GetDeliveryByID(ctx context.Context, webhookID, deliveryID uuid.UUID) (core.WebhookDelivery, bool, error) {
	const q = `
		SELECT id, webhook_id, event, payload, status, status_code, response_body, attempts, next_retry_at, created_at, completed_at
		FROM webhook_deliveries
		WHERE id = $1 AND webhook_id = $2
	`

	row := r.db.Pool().QueryRow(ctx, q, deliveryID, webhookID)
	var d core.WebhookDelivery
	if err := scanWebhookDelivery(row, &d); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return d, false, nil
		}
		return d, false, fmt.Errorf("get delivery by id: %w", err)
	}
	return d, true, nil
}

func (r *Repo) GetPendingRetryDeliveries(ctx context.Context, limit int) ([]core.WebhookDelivery, error) {
	const q = `
		WITH locked AS (
			SELECT id
			FROM webhook_deliveries
			WHERE status = 'pending'
			  AND next_retry_at IS NOT NULL
			  AND next_retry_at <= now()
			ORDER BY next_retry_at
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE webhook_deliveries d
		SET next_retry_at = now() + interval '1 hour'
		FROM locked
		WHERE d.id = locked.id
		RETURNING d.id, d.webhook_id, d.event, d.payload, d.status, d.status_code, d.response_body, d.attempts, d.next_retry_at, d.created_at, d.completed_at
	`

	rows, err := r.db.Pool().Query(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.WebhookDelivery
	for rows.Next() {
		var d core.WebhookDelivery
		if err := scanWebhookDelivery(rows, &d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

/* -------------------------------------------------------------------------- */
/* Webhook health dashboard                                                    */
/* -------------------------------------------------------------------------- */

// GetAppWebhookHealth returns the stat-card numbers + recent failures list
// for the per-app Webhooks dashboard. Two queries: one aggregate summary
// and one paginated list of recent failures.
//
// All counts are scoped via webhooks.app_id (idx_webhooks_app_id) so this
// scales to apps with thousands of deliveries.
func (r *Repo) GetAppWebhookHealth(ctx context.Context, appID uuid.UUID, recentLimit int) (*core.WebhookHealth, error) {
	if recentLimit <= 0 {
		recentLimit = 25
	}

	out := &core.WebhookHealth{}

	const summaryQ = `
WITH wh AS (
  SELECT id, status FROM webhooks WHERE app_id = $1
)
SELECT
  (SELECT COUNT(*) FROM wh)::int AS total_webhooks,
  (SELECT COUNT(*) FROM wh WHERE status = 'active')::int AS active_webhooks,
  (SELECT COUNT(*) FROM webhook_deliveries d
     WHERE d.webhook_id IN (SELECT id FROM wh)
       AND d.created_at >= now() - interval '24 hours')::int AS deliveries_24h,
  (SELECT COUNT(*) FROM webhook_deliveries d
     WHERE d.webhook_id IN (SELECT id FROM wh)
       AND d.status = 'success'
       AND d.created_at >= now() - interval '24 hours')::int AS successes_24h,
  (SELECT COUNT(*) FROM webhook_deliveries d
     WHERE d.webhook_id IN (SELECT id FROM wh)
       AND d.status = 'failed'
       AND d.created_at >= now() - interval '24 hours')::int AS failures_24h,
  (SELECT COUNT(*) FROM webhook_deliveries d
     WHERE d.webhook_id IN (SELECT id FROM wh)
       AND d.status = 'pending'
       AND d.next_retry_at IS NOT NULL)::int AS pending_retries;
`
	if err := r.db.Pool().QueryRow(ctx, summaryQ, appID).Scan(
		&out.TotalWebhooks,
		&out.ActiveWebhooks,
		&out.Deliveries24h,
		&out.Successes24h,
		&out.Failures24h,
		&out.PendingRetries,
	); err != nil {
		return nil, err
	}

	const failuresQ = `
SELECT d.id, d.webhook_id, w.url, d.event, d.status_code, d.attempts, d.created_at
FROM webhook_deliveries d
JOIN webhooks w ON w.id = d.webhook_id
WHERE w.app_id = $1 AND d.status = 'failed'
ORDER BY d.created_at DESC
LIMIT $2;
`
	rows, err := r.db.Pool().Query(ctx, failuresQ, appID, recentLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var f core.WebhookDeliveryFailure
		var id, webhookID uuid.UUID
		var statusCode *int
		var createdAt time.Time
		if err := rows.Scan(&id, &webhookID, &f.WebhookURL, &f.Event, &statusCode, &f.Attempts, &createdAt); err != nil {
			return nil, err
		}
		f.ID = id.String()
		f.WebhookID = webhookID.String()
		f.StatusCode = statusCode
		f.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		out.RecentFailures = append(out.RecentFailures, f)
	}
	return out, rows.Err()
}
