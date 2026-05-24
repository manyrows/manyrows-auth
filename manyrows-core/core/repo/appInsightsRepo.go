package repo

import (
	"context"
	"errors"
	"time"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

/* -------------------------------------------------------------------------- */
/* App insights — summary card data                                            */
/* -------------------------------------------------------------------------- */

// GetAppInsightsSummary returns the stat-card numbers (current + prior period).
// rangeDays defines both windows: [now-rangeDays, now] and
// [now-2*rangeDays, now-rangeDays].
//
// Membership is the app_users row (post user-pool refactor). "Users
// in this app" means an app_users row exists; new-user metrics use
// app_users.joined_at so they reflect "joined this app" rather than
// the pool-level users.created_at (which could be ahead if the user
// was created in a sibling app first).
func (r *Repo) GetAppInsightsSummary(ctx context.Context, appID uuid.UUID, rangeDays int) (*core.AppInsightsSummary, error) {
	if rangeDays <= 0 {
		rangeDays = 30
	}
	now := time.Now().UTC()
	rangeStart := now.AddDate(0, 0, -rangeDays)
	prevStart := now.AddDate(0, 0, -2*rangeDays)

	out := &core.AppInsightsSummary{RangeDays: rangeDays}

	const totalQ = `SELECT COUNT(*) FROM app_users WHERE app_id = $1;`
	if err := r.db.Pool().QueryRow(ctx, totalQ, appID).Scan(&out.TotalUsers); err != nil {
		return nil, err
	}

	// New members in current vs prior windows, by app_users.joined_at.
	const newQ = `
SELECT
  COUNT(*) FILTER (WHERE joined_at >= $3 AND joined_at < $2) AS now_count,
  COUNT(*) FILTER (WHERE joined_at >= $4 AND joined_at < $3) AS prev_count
FROM app_users
WHERE app_id = $1;
`
	if err := r.db.Pool().QueryRow(ctx, newQ, appID, now, rangeStart, prevStart).
		Scan(&out.NewUsers, &out.NewUsersPrev); err != nil {
		return nil, err
	}

	// Active users (distinct successful logins) in current and prior windows.
	// Returns 0/0 cleanly if the events table has no rows yet.
	const activeQ = `
SELECT
  COUNT(DISTINCT subject_user_id) FILTER (WHERE created_at >= $2 AND created_at < $3) AS now_count,
  COUNT(DISTINCT subject_user_id) FILTER (WHERE created_at >= $4 AND created_at < $2) AS prev_count
FROM auth_logs
WHERE app_id = $1 AND event = 'login.success' AND subject_user_id IS NOT NULL;
`
	if err := r.db.Pool().QueryRow(ctx, activeQ, appID, rangeStart, now, prevStart).
		Scan(&out.ActiveUsers, &out.ActiveUsersPrev); err != nil {
		return nil, err
	}

	// Login failures in current and prior windows.
	const failQ = `
SELECT
  COUNT(*) FILTER (WHERE created_at >= $2 AND created_at < $3) AS now_count,
  COUNT(*) FILTER (WHERE created_at >= $4 AND created_at < $2) AS prev_count
FROM auth_logs
WHERE app_id = $1 AND event = 'login.failed';
`
	if err := r.db.Pool().QueryRow(ctx, failQ, appID, rangeStart, now, prevStart).
		Scan(&out.LoginFailures, &out.LoginFailuresPrev); err != nil {
		return nil, err
	}

	return out, nil
}

/* -------------------------------------------------------------------------- */
/* App insights — single-series timeseries                                     */
/* -------------------------------------------------------------------------- */

// GetAppSignupsTimeseries: daily count of new members joining this
// app (app_users.joined_at).
func (r *Repo) GetAppSignupsTimeseries(ctx context.Context, appID uuid.UUID, rangeDays int) ([]core.TimeseriesPoint, error) {
	const q = `
WITH days AS (
  SELECT generate_series(
    (now() AT TIME ZONE 'UTC')::date - ($2::int - 1),
    (now() AT TIME ZONE 'UTC')::date,
    '1 day'::interval
  )::date AS day
),
counts AS (
  SELECT (joined_at AT TIME ZONE 'UTC')::date AS day, COUNT(*) AS cnt
  FROM app_users
  WHERE app_id = $1
    AND joined_at >= (now() AT TIME ZONE 'UTC')::date - ($2::int - 1)
  GROUP BY 1
)
SELECT d.day::text, COALESCE(c.cnt, 0)::int
FROM days d
LEFT JOIN counts c ON c.day = d.day
ORDER BY d.day;
`
	return scanTimeseries(ctx, r, q, appID, rangeDays)
}

// GetAppCumulativeUsersTimeseries: running total of members in this app over time.
func (r *Repo) GetAppCumulativeUsersTimeseries(ctx context.Context, appID uuid.UUID, rangeDays int) ([]core.TimeseriesPoint, error) {
	const q = `
WITH scoped AS (
  SELECT joined_at FROM app_users WHERE app_id = $1
),
base AS (
  SELECT COUNT(*) AS baseline FROM scoped
  WHERE joined_at < (now() AT TIME ZONE 'UTC')::date - ($2::int - 1)
),
days AS (
  SELECT generate_series(
    (now() AT TIME ZONE 'UTC')::date - ($2::int - 1),
    (now() AT TIME ZONE 'UTC')::date,
    '1 day'::interval
  )::date AS day
),
daily_new AS (
  SELECT (joined_at AT TIME ZONE 'UTC')::date AS day, COUNT(*) AS cnt
  FROM scoped
  WHERE joined_at >= (now() AT TIME ZONE 'UTC')::date - ($2::int - 1)
  GROUP BY 1
)
SELECT d.day::text,
       (
         (SELECT baseline FROM base)
         + COALESCE((SELECT SUM(dn.cnt) FROM daily_new dn WHERE dn.day <= d.day), 0)
       )::int AS total
FROM days d
ORDER BY d.day;
`
	return scanTimeseries(ctx, r, q, appID, rangeDays)
}

// loginsTimeseries — daily count of successful logins.
func (r *Repo) GetAppLoginsTimeseries(ctx context.Context, appID uuid.UUID, rangeDays int) ([]core.TimeseriesPoint, error) {
	const q = `
WITH days AS (
  SELECT generate_series(
    (now() AT TIME ZONE 'UTC')::date - ($2::int - 1),
    (now() AT TIME ZONE 'UTC')::date,
    '1 day'::interval
  )::date AS day
),
counts AS (
  SELECT (created_at AT TIME ZONE 'UTC')::date AS day, COUNT(*) AS cnt
  FROM auth_logs
  WHERE app_id = $1 AND event = 'login.success'
    AND created_at >= (now() AT TIME ZONE 'UTC')::date - ($2::int - 1)
  GROUP BY 1
)
SELECT d.day::text, COALESCE(c.cnt, 0)::int
FROM days d
LEFT JOIN counts c ON c.day = d.day
ORDER BY d.day;
`
	return scanTimeseries(ctx, r, q, appID, rangeDays)
}

// loginFailuresTimeseries — daily count of failed login attempts.
func (r *Repo) GetAppLoginFailuresTimeseries(ctx context.Context, appID uuid.UUID, rangeDays int) ([]core.TimeseriesPoint, error) {
	const q = `
WITH days AS (
  SELECT generate_series(
    (now() AT TIME ZONE 'UTC')::date - ($2::int - 1),
    (now() AT TIME ZONE 'UTC')::date,
    '1 day'::interval
  )::date AS day
),
counts AS (
  SELECT (created_at AT TIME ZONE 'UTC')::date AS day, COUNT(*) AS cnt
  FROM auth_logs
  WHERE app_id = $1 AND event = 'login.failed'
    AND created_at >= (now() AT TIME ZONE 'UTC')::date - ($2::int - 1)
  GROUP BY 1
)
SELECT d.day::text, COALESCE(c.cnt, 0)::int
FROM days d
LEFT JOIN counts c ON c.day = d.day
ORDER BY d.day;
`
	return scanTimeseries(ctx, r, q, appID, rangeDays)
}

func scanTimeseries(ctx context.Context, r *Repo, q string, appID uuid.UUID, rangeDays int) ([]core.TimeseriesPoint, error) {
	if rangeDays <= 0 {
		rangeDays = 30
	}
	rows, err := r.db.Pool().Query(ctx, q, appID, rangeDays)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.TimeseriesPoint
	for rows.Next() {
		var p core.TimeseriesPoint
		if err := rows.Scan(&p.Date, &p.Count); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

/* -------------------------------------------------------------------------- */
/* App insights — DAU / WAU / MAU                                              */
/* -------------------------------------------------------------------------- */

// GetAppActivityTimeseries returns DAU/WAU/MAU for each day in the window.
//
// For each day D in [today - rangeDays + 1, today]:
//
//	DAU(D) = COUNT DISTINCT subject_user_id where event-day = D
//	WAU(D) = COUNT DISTINCT subject_user_id where event-day in (D-6, D]
//	MAU(D) = COUNT DISTINCT subject_user_id where event-day in (D-29, D]
//
// Cost: the LEFT JOIN matches every event in [D-29, D] for every day D in
// the window, so the intermediate row count is O(rangeDays × events_in_30d).
// Acceptable up to roughly (90d range × 100k events/30d) ≈ 9M rows. Beyond
// that, switch to a window-function variant or a per-day pre-aggregate.
func (r *Repo) GetAppActivityTimeseries(ctx context.Context, appID uuid.UUID, rangeDays int) ([]core.ActivityPoint, error) {
	if rangeDays <= 0 {
		rangeDays = 30
	}
	// We need MAU's 30-day rolling window, so look back rangeDays + 29 days.
	const q = `
WITH days AS (
  SELECT generate_series(
    (now() AT TIME ZONE 'UTC')::date - ($2::int - 1),
    (now() AT TIME ZONE 'UTC')::date,
    '1 day'::interval
  )::date AS day
),
events AS (
  SELECT DISTINCT subject_user_id, (created_at AT TIME ZONE 'UTC')::date AS day
  FROM auth_logs
  WHERE app_id = $1 AND event = 'login.success' AND subject_user_id IS NOT NULL
    AND created_at >= (now() AT TIME ZONE 'UTC')::date - ($2::int - 1) - 29
)
SELECT
  d.day::text,
  COUNT(DISTINCT e.subject_user_id) FILTER (WHERE e.day = d.day)::int AS dau,
  COUNT(DISTINCT e.subject_user_id) FILTER (WHERE e.day BETWEEN d.day - 6 AND d.day)::int AS wau,
  COUNT(DISTINCT e.subject_user_id) FILTER (WHERE e.day BETWEEN d.day - 29 AND d.day)::int AS mau
FROM days d
LEFT JOIN events e ON e.day BETWEEN d.day - 29 AND d.day
GROUP BY d.day
ORDER BY d.day;
`
	rows, err := r.db.Pool().Query(ctx, q, appID, rangeDays)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.ActivityPoint
	for rows.Next() {
		var p core.ActivityPoint
		if err := rows.Scan(&p.Date, &p.DAU, &p.WAU, &p.MAU); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

/* -------------------------------------------------------------------------- */
/* App insights — source breakdown                                             */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* Per-user activity (batch — for the user list columns)                       */
/* -------------------------------------------------------------------------- */

// UserActivityCounts is a small per-user stat bundle used to populate the
// "Sessions" and "Failures (7d)" columns on the AppUsers list. Returned as
// a map keyed by user ID for cheap join-side lookup.
type UserActivityCounts struct {
	ActiveSessions  int
	LoginFailures7d int
}

// GetProductMembersActivityCounts returns active session counts and recent
// failure counts for a batch of users in a single app. Two small queries
// (one per source table) — both index-friendly via the per-app indexes.
//
// Returns an empty map if appID is nil or userIDs is empty (callers should
// treat missing keys as zero counts).
func (r *Repo) GetProductMembersActivityCounts(ctx context.Context, appID uuid.UUID, userIDs []uuid.UUID) (map[uuid.UUID]UserActivityCounts, error) {
	out := map[uuid.UUID]UserActivityCounts{}
	if appID == uuid.Nil || len(userIDs) == 0 {
		return out, nil
	}

	// Active (non-expired) sessions per user, scoped to this app.
	const sessionsQ = `
SELECT user_id, COUNT(*)::int
FROM client_sessions
WHERE app_id = $1
  AND expires_at > now()
  AND user_id = ANY($2::uuid[])
GROUP BY user_id;
`
	sessRows, err := r.db.Pool().Query(ctx, sessionsQ, appID, userIDs)
	if err != nil {
		return nil, err
	}
	for sessRows.Next() {
		var uid uuid.UUID
		var cnt int
		if err := sessRows.Scan(&uid, &cnt); err != nil {
			sessRows.Close()
			return nil, err
		}
		entry := out[uid]
		entry.ActiveSessions = cnt
		out[uid] = entry
	}
	sessRows.Close()
	if err := sessRows.Err(); err != nil {
		return nil, err
	}

	// Failed login attempts in the last 7 days per user, scoped to this app.
	const failuresQ = `
SELECT subject_user_id, COUNT(*)::int
FROM auth_logs
WHERE app_id = $1
  AND event = 'login.failed'
  AND created_at >= now() - interval '7 days'
  AND subject_user_id = ANY($2::uuid[])
GROUP BY subject_user_id;
`
	failRows, err := r.db.Pool().Query(ctx, failuresQ, appID, userIDs)
	if err != nil {
		return nil, err
	}
	for failRows.Next() {
		var uid uuid.UUID
		var cnt int
		if err := failRows.Scan(&uid, &cnt); err != nil {
			failRows.Close()
			return nil, err
		}
		entry := out[uid]
		entry.LoginFailures7d = cnt
		out[uid] = entry
	}
	failRows.Close()
	return out, failRows.Err()
}

/* -------------------------------------------------------------------------- */
/* Per-user activity (drill-down dialog)                                       */
/* -------------------------------------------------------------------------- */

// GetUserActivityForApp returns the per-user activity payload for the
// drill-down dialog: login/failure counts in current vs prior window, last
// login details, active session count, daily series for the sparkline, and
// the most recent N events.
//
// Five small queries instead of one heroic CTE — each is index-friendly
// (idx_user_login_events_app_user_created), and the network roundtrips are
// negligible relative to the chart render.
func (r *Repo) GetUserActivityForApp(ctx context.Context, appID, userID uuid.UUID, rangeDays, recentLimit int) (*core.UserActivitySummary, error) {
	if rangeDays <= 0 {
		rangeDays = 30
	}
	if recentLimit <= 0 {
		recentLimit = 50
	}
	now := time.Now().UTC()
	rangeStart := now.AddDate(0, 0, -rangeDays)
	prevStart := now.AddDate(0, 0, -2*rangeDays)

	out := &core.UserActivitySummary{
		UserID:    userID.String(),
		RangeDays: rangeDays,
	}

	// Counts (current + prior period).
	const countsQ = `
SELECT
  COUNT(*) FILTER (WHERE event='login.success' AND created_at >= $3 AND created_at < $4) AS now_logins,
  COUNT(*) FILTER (WHERE event='login.success' AND created_at >= $5 AND created_at < $3) AS prev_logins,
  COUNT(*) FILTER (WHERE event='login.failed'  AND created_at >= $3 AND created_at < $4) AS now_fails,
  COUNT(*) FILTER (WHERE event='login.failed'  AND created_at >= $5 AND created_at < $3) AS prev_fails
FROM auth_logs
WHERE app_id = $1 AND subject_user_id = $2;
`
	if err := r.db.Pool().QueryRow(ctx, countsQ, appID, userID, rangeStart, now, prevStart).
		Scan(&out.Logins, &out.LoginsPrev, &out.Failures, &out.FailuresPrev); err != nil {
		return nil, err
	}

	// Last successful login details.
	const lastQ = `
SELECT created_at, COALESCE(method, ''), COALESCE(host(ip), ''), COALESCE(user_agent, '')
FROM auth_logs
WHERE app_id = $1 AND subject_user_id = $2 AND event = 'login.success'
ORDER BY created_at DESC
LIMIT 1;
`
	var lastAt time.Time
	var lastMethod, lastIP, lastUA string
	switch err := r.db.Pool().QueryRow(ctx, lastQ, appID, userID).
		Scan(&lastAt, &lastMethod, &lastIP, &lastUA); {
	case err == nil:
		out.LastLoginAt = lastAt.UTC().Format(time.RFC3339)
		out.LastLoginMethod = lastMethod
		out.LastLoginIP = lastIP
		out.LastLoginUA = lastUA
	case errors.Is(err, pgx.ErrNoRows):
		// No successful login yet — leave fields empty.
	default:
		return nil, err
	}

	// Active session count (non-expired).
	const sessionsQ = `
SELECT COUNT(*) FROM client_sessions
WHERE app_id = $1 AND user_id = $2 AND expires_at > now();
`
	if err := r.db.Pool().QueryRow(ctx, sessionsQ, appID, userID).Scan(&out.ActiveSessions); err != nil {
		return nil, err
	}

	// Daily login timeseries for the sparkline.
	const dailyQ = `
WITH days AS (
  SELECT generate_series(
    (now() AT TIME ZONE 'UTC')::date - ($3::int - 1),
    (now() AT TIME ZONE 'UTC')::date,
    '1 day'::interval
  )::date AS day
),
counts AS (
  SELECT (created_at AT TIME ZONE 'UTC')::date AS day, COUNT(*) AS cnt
  FROM auth_logs
  WHERE app_id = $1 AND subject_user_id = $2 AND event = 'login.success'
    AND created_at >= (now() AT TIME ZONE 'UTC')::date - ($3::int - 1)
  GROUP BY 1
)
SELECT d.day::text, COALESCE(c.cnt, 0)::int
FROM days d
LEFT JOIN counts c ON c.day = d.day
ORDER BY d.day;
`
	dailyRows, err := r.db.Pool().Query(ctx, dailyQ, appID, userID, rangeDays)
	if err != nil {
		return nil, err
	}
	for dailyRows.Next() {
		var p core.TimeseriesPoint
		if err := dailyRows.Scan(&p.Date, &p.Count); err != nil {
			dailyRows.Close()
			return nil, err
		}
		out.Daily = append(out.Daily, p)
	}
	dailyRows.Close()
	if err := dailyRows.Err(); err != nil {
		return nil, err
	}

	// Recent events (success + failed).
	const recentQ = `
SELECT outcome, COALESCE(method, ''), COALESCE(failure_reason, ''),
       COALESCE(host(ip), ''), COALESCE(user_agent, ''), created_at
FROM auth_logs
WHERE app_id = $1 AND subject_user_id = $2
ORDER BY created_at DESC
LIMIT $3;
`
	recentRows, err := r.db.Pool().Query(ctx, recentQ, appID, userID, recentLimit)
	if err != nil {
		return nil, err
	}
	defer recentRows.Close()
	for recentRows.Next() {
		var ev core.UserActivityEvent
		var ts time.Time
		if err := recentRows.Scan(&ev.Status, &ev.Method, &ev.FailureReason, &ev.IP, &ev.UserAgent, &ts); err != nil {
			return nil, err
		}
		ev.CreatedAt = ts.UTC().Format(time.RFC3339)
		out.RecentEvents = append(out.RecentEvents, ev)
	}
	if err := recentRows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

/* -------------------------------------------------------------------------- */
/* Source breakdown                                                            */
/* -------------------------------------------------------------------------- */

// GetAppSourceBreakdown returns the count of members in this app grouped
// by the membership source ("registered", "invited", "google", etc.) -
// reads app_users.source so the breakdown reflects how each membership
// was created, not how the underlying pool user was first created.
func (r *Repo) GetAppSourceBreakdown(ctx context.Context, appID uuid.UUID) ([]core.SourceBreakdownItem, error) {
	const q = `
SELECT COALESCE(NULLIF(au.source, ''), 'invited') AS source, COUNT(*)::int AS cnt
FROM app_users au
WHERE au.app_id = $1
GROUP BY 1
ORDER BY cnt DESC;
`
	rows, err := r.db.Pool().Query(ctx, q, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.SourceBreakdownItem
	for rows.Next() {
		var item core.SourceBreakdownItem
		if err := rows.Scan(&item.Source, &item.Count); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
