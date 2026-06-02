package api_test

// Tests for the GetAppWebhookHealth repo function backing the per-app
// Webhooks dashboard. Live Postgres via testEnv; raw INSERTs let us
// control timestamps + statuses precisely.

import (
	"context"
	"testing"
	"time"

	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
)

// Helper: insert a webhook row directly. Returns the webhook ID.
func insertWebhook(t *testing.T, appID uuid.UUID, status string) uuid.UUID {
	t.Helper()
	id := utils.NewUUID()
	pool := testEnv.DB.Pool()

	// webhooks has both project_id and app_id; need a project for the FK.
	// Cheapest: pick the app's project_id from the apps table.
	var projectID uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`SELECT project_id FROM apps WHERE id = $1`, appID).Scan(&projectID); err != nil {
		t.Fatalf("look up project for app: %v", err)
	}

	// created_by FK → accounts; pick any.
	var createdBy uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`SELECT id FROM accounts LIMIT 1`).Scan(&createdBy); err != nil {
		t.Fatalf("look up an account for created_by: %v", err)
	}

	if _, err := pool.Exec(context.Background(), `
INSERT INTO webhooks (id, project_id, app_id, url, secret, events, status, description, created_at, updated_at, created_by)
VALUES ($1, $2, $3, 'https://example.test/hook', 'secret', ARRAY['user.login']::text[], $4, '', now(), now(), $5)
`, id, projectID, appID, status, createdBy); err != nil {
		t.Fatalf("insert webhook: %v", err)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_deliveries WHERE webhook_id = $1`, id)
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhooks WHERE id = $1`, id)
	})
	return id
}

func insertDelivery(t *testing.T, webhookID uuid.UUID, status string, statusCode *int, when time.Time, attempts int, nextRetry *time.Time) {
	t.Helper()
	_, err := testEnv.DB.Pool().Exec(context.Background(), `
INSERT INTO webhook_deliveries (id, webhook_id, event, payload, status, status_code, attempts, next_retry_at, created_at)
VALUES ($1, $2, 'user.login', '{}'::jsonb, $3, $4, $5, $6, $7)
`, utils.NewUUID(), webhookID, status, statusCode, attempts, nextRetry, when)
	if err != nil {
		t.Fatalf("insert delivery: %v", err)
	}
}

func newWebhookHealthApp(t *testing.T) (accID, wsID, appID uuid.UUID) {
	t.Helper()
	emailAddr := "wh-health-" + GenerateUniqueSlug("t") + "@example.com"
	a := testEnv.CreateTestAccount(t, emailAddr)
	w := testEnv.CreateTestWorkspace(t, a, "WH WS", GenerateUniqueSlug("ws"))
	ap := testEnv.CreateTestApp(t, w, a)

	t.Cleanup(func() {
		ctx := context.Background()
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM apps WHERE id = $1", ap.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM projects WHERE id = $1", ap.ProjectID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspace_admins WHERE workspace_id = $1", w.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspaces WHERE id = $1", w.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM accounts WHERE id = $1", a.ID)
	})

	return a.ID, w.ID, ap.ID
}

func intPtr(v int) *int              { return &v }
func timePtr(t time.Time) *time.Time { return &t }

/* -------------------------------------------------------------------------- */
/* Tests                                                                       */
/* -------------------------------------------------------------------------- */

func TestWebhookHealth_EmptyApp(t *testing.T) {
	_, _, appID := newWebhookHealthApp(t)

	health, err := testEnv.Repo.GetAppWebhookHealth(context.Background(), appID, 25)
	if err != nil {
		t.Fatalf("GetAppWebhookHealth: %v", err)
	}
	if health.TotalWebhooks != 0 || health.ActiveWebhooks != 0 {
		t.Errorf("empty app: webhooks = %d/%d, want 0/0",
			health.ActiveWebhooks, health.TotalWebhooks)
	}
	if health.Deliveries24h != 0 || health.Successes24h != 0 || health.Failures24h != 0 {
		t.Errorf("empty app: 24h counts = %d/%d/%d, want 0/0/0",
			health.Deliveries24h, health.Successes24h, health.Failures24h)
	}
	if health.PendingRetries != 0 {
		t.Errorf("empty app: pending = %d, want 0", health.PendingRetries)
	}
	if len(health.RecentFailures) != 0 {
		t.Errorf("empty app: recent failures = %d, want 0", len(health.RecentFailures))
	}
}

func TestWebhookHealth_ActiveAndDisabledCounts(t *testing.T) {
	_, _, appID := newWebhookHealthApp(t)
	insertWebhook(t, appID, "active")
	insertWebhook(t, appID, "active")
	insertWebhook(t, appID, "disabled")

	health, err := testEnv.Repo.GetAppWebhookHealth(context.Background(), appID, 25)
	if err != nil {
		t.Fatalf("GetAppWebhookHealth: %v", err)
	}
	if health.TotalWebhooks != 3 {
		t.Errorf("totalWebhooks = %d, want 3", health.TotalWebhooks)
	}
	if health.ActiveWebhooks != 2 {
		t.Errorf("activeWebhooks = %d, want 2", health.ActiveWebhooks)
	}
}

func TestWebhookHealth_DeliveryCountsAreScopedTo24h(t *testing.T) {
	_, _, appID := newWebhookHealthApp(t)
	wh := insertWebhook(t, appID, "active")

	now := time.Now().UTC()
	// 3 successes within 24h
	insertDelivery(t, wh, "success", intPtr(200), now.Add(-1*time.Hour), 1, nil)
	insertDelivery(t, wh, "success", intPtr(200), now.Add(-12*time.Hour), 1, nil)
	insertDelivery(t, wh, "success", intPtr(200), now.Add(-23*time.Hour), 1, nil)
	// 1 success outside 24h (should NOT count)
	insertDelivery(t, wh, "success", intPtr(200), now.Add(-30*time.Hour), 1, nil)
	// 2 failures within 24h
	insertDelivery(t, wh, "failed", intPtr(500), now.Add(-2*time.Hour), 3, nil)
	insertDelivery(t, wh, "failed", intPtr(503), now.Add(-5*time.Hour), 5, nil)

	health, err := testEnv.Repo.GetAppWebhookHealth(context.Background(), appID, 25)
	if err != nil {
		t.Fatalf("GetAppWebhookHealth: %v", err)
	}
	if health.Deliveries24h != 5 {
		t.Errorf("deliveries24h = %d, want 5 (3 success + 2 failed in window)", health.Deliveries24h)
	}
	if health.Successes24h != 3 {
		t.Errorf("successes24h = %d, want 3", health.Successes24h)
	}
	if health.Failures24h != 2 {
		t.Errorf("failures24h = %d, want 2", health.Failures24h)
	}
}

func TestWebhookHealth_PendingRetriesNeedNextRetryAt(t *testing.T) {
	_, _, appID := newWebhookHealthApp(t)
	wh := insertWebhook(t, appID, "active")
	now := time.Now().UTC()

	// Two pending retries scheduled, one without next_retry_at (terminal-ish).
	insertDelivery(t, wh, "pending", nil, now.Add(-1*time.Hour), 2, timePtr(now.Add(5*time.Minute)))
	insertDelivery(t, wh, "pending", nil, now.Add(-2*time.Hour), 1, timePtr(now.Add(10*time.Minute)))
	insertDelivery(t, wh, "pending", nil, now.Add(-3*time.Hour), 0, nil) // shouldn't count

	health, err := testEnv.Repo.GetAppWebhookHealth(context.Background(), appID, 25)
	if err != nil {
		t.Fatalf("GetAppWebhookHealth: %v", err)
	}
	if health.PendingRetries != 2 {
		t.Errorf("pendingRetries = %d, want 2 (only those with next_retry_at)", health.PendingRetries)
	}
}

func TestWebhookHealth_RecentFailuresOrderedDesc(t *testing.T) {
	_, _, appID := newWebhookHealthApp(t)
	wh := insertWebhook(t, appID, "active")
	now := time.Now().UTC()

	insertDelivery(t, wh, "failed", intPtr(500), now.Add(-3*time.Hour), 3, nil)
	insertDelivery(t, wh, "failed", intPtr(502), now.Add(-1*time.Hour), 5, nil) // newest
	insertDelivery(t, wh, "failed", intPtr(503), now.Add(-5*time.Hour), 2, nil) // oldest
	// Mixed in a success — should NOT appear in recent failures.
	insertDelivery(t, wh, "success", intPtr(200), now.Add(-2*time.Hour), 1, nil)

	health, err := testEnv.Repo.GetAppWebhookHealth(context.Background(), appID, 25)
	if err != nil {
		t.Fatalf("GetAppWebhookHealth: %v", err)
	}
	if len(health.RecentFailures) != 3 {
		t.Fatalf("recentFailures = %d, want 3", len(health.RecentFailures))
	}
	// Newest first.
	if *health.RecentFailures[0].StatusCode != 502 {
		t.Errorf("first failure status = %d, want 502 (newest)", *health.RecentFailures[0].StatusCode)
	}
	if *health.RecentFailures[2].StatusCode != 503 {
		t.Errorf("last failure status = %d, want 503 (oldest)", *health.RecentFailures[2].StatusCode)
	}
}

func TestWebhookHealth_RecentFailuresLimitHonored(t *testing.T) {
	_, _, appID := newWebhookHealthApp(t)
	wh := insertWebhook(t, appID, "active")
	now := time.Now().UTC()

	for i := 0; i < 10; i++ {
		insertDelivery(t, wh, "failed", intPtr(500), now.Add(-time.Duration(i)*time.Hour), i+1, nil)
	}

	health, err := testEnv.Repo.GetAppWebhookHealth(context.Background(), appID, 5)
	if err != nil {
		t.Fatalf("GetAppWebhookHealth: %v", err)
	}
	if len(health.RecentFailures) != 5 {
		t.Errorf("recentFailures with limit=5 = %d, want 5", len(health.RecentFailures))
	}
}

func TestWebhookHealth_CrossAppIsolation(t *testing.T) {
	_, _, appA := newWebhookHealthApp(t)
	_, _, appB := newWebhookHealthApp(t)

	whA := insertWebhook(t, appA, "active")
	whB := insertWebhook(t, appB, "active")
	now := time.Now().UTC()

	insertDelivery(t, whA, "failed", intPtr(500), now.Add(-1*time.Hour), 3, nil)
	insertDelivery(t, whB, "failed", intPtr(500), now.Add(-1*time.Hour), 3, nil)
	insertDelivery(t, whB, "failed", intPtr(500), now.Add(-2*time.Hour), 3, nil)

	healthA, _ := testEnv.Repo.GetAppWebhookHealth(context.Background(), appA, 25)
	healthB, _ := testEnv.Repo.GetAppWebhookHealth(context.Background(), appB, 25)

	if healthA.Failures24h != 1 {
		t.Errorf("appA failures24h = %d, want 1 (must not see appB's)", healthA.Failures24h)
	}
	if healthB.Failures24h != 2 {
		t.Errorf("appB failures24h = %d, want 2", healthB.Failures24h)
	}
	if len(healthA.RecentFailures) != 1 || len(healthB.RecentFailures) != 2 {
		t.Errorf("recent failures per app: A=%d B=%d, want 1 / 2",
			len(healthA.RecentFailures), len(healthB.RecentFailures))
	}
}
