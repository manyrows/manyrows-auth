package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

/* -------------------------------------------------------------------------- */
/* Test scaffolding                                                            */
/* -------------------------------------------------------------------------- */

// setupInsightsRouter registers the four /insights endpoints under the same
// admin/workspace router scaffold the production code uses.
func setupInsightsRouter(t *testing.T) *chi.Mux {
	t.Helper()
	svc := NewTestServices(t)
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)

	wsRouter.Route("/projects/{projectId}/apps/{appId}", func(r chi.Router) {
		r.Get("/insights/summary", svc.Handler.HandleGetAppInsightsSummary)
		r.Get("/insights/timeseries", svc.Handler.HandleGetAppInsightsTimeseries)
		r.Get("/insights/activity", svc.Handler.HandleGetAppInsightsActivity)
		r.Get("/insights/sources", svc.Handler.HandleGetAppInsightsSourceBreakdown)
		r.Get("/users/{userId}/activity", svc.Handler.HandleGetAppUserActivity)
	})

	return r
}

// insightsFixture bundles the standard objects every test needs and registers
// cleanup for them.
type insightsFixture struct {
	router  *chi.Mux
	acc     *core.Account
	ws      *core.Workspace
	project *core.Project
	app     *core.App
	claims  core.TokenClaims
}

func newInsightsFixture(t *testing.T) *insightsFixture {
	t.Helper()
	router := setupInsightsRouter(t)

	emailAddr := "insights-" + GenerateUniqueSlug("t") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Insights WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Insights Project", GenerateUniqueSlug("proj"))
	app := testEnv.CreateTestApp(t, ws, acc)
	_, claims := testEnv.CreateTestSession(t, acc)

	t.Cleanup(func() {
		ctx := context.Background()
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM auth_logs WHERE app_id = $1", app.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM apps WHERE id = $1", app.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM projects WHERE id IN ($1, $2)", project.ID, app.ProjectID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspace_admins WHERE workspace_id = $1", ws.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspaces WHERE id = $1", ws.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM accounts WHERE id = $1", acc.ID)
	})

	return &insightsFixture{
		router:  router,
		acc:     acc,
		ws:      ws,
		project: project,
		app:     app,
		claims:  claims,
	}
}

// insertTestUser creates an app-scoped users row for tests that need a
// user but don't care about insights timing.
func insertTestUser(t *testing.T, source string, appID uuid.UUID) uuid.UUID {
	t.Helper()
	return insertSignupAt(t, appID, source, time.Now().UTC())
}

// insertSignupAt creates a pool-scoped user + app_users membership row
// with a controllable joined_at (the timestamp insights queries treat as
// "user joined this app on this day"). The pool is looked up via the app.
func insertSignupAt(t *testing.T, appID uuid.UUID, source string, createdAt time.Time) uuid.UUID {
	t.Helper()
	id := utils.NewUUID()
	emailAddr := "u-" + GenerateUniqueSlug("u") + "@example.com"

	var poolID uuid.UUID
	if err := testEnv.DB.Pool().QueryRow(context.Background(),
		`SELECT user_pool_id FROM apps WHERE id = $1`, appID,
	).Scan(&poolID); err != nil {
		t.Fatalf("insertSignupAt: lookup pool: %v", err)
	}

	_, err := testEnv.DB.Pool().Exec(context.Background(), `
		INSERT INTO users (id, email, enabled, source,
		                   user_pool_id,
		                   created_at, updated_at)
		VALUES ($1, $2, true, $3, $4, $5, $5)
	`, id, emailAddr, source, poolID, createdAt)
	if err != nil {
		t.Fatalf("insertSignupAt: %v", err)
	}

	if _, err := testEnv.DB.Pool().Exec(context.Background(), `
		INSERT INTO app_users (app_id, user_id, status, source, joined_at)
		VALUES ($1, $2, 'active', $3, $4)
	`, appID, id, source, createdAt); err != nil {
		t.Fatalf("insertSignupAt: insert app_users: %v", err)
	}

	t.Cleanup(func() {
		_, _ = testEnv.DB.Pool().Exec(context.Background(),
			"DELETE FROM users WHERE id = $1", id)
	})
	return id
}

// insertLoginEventAt inserts an auth_logs row with an explicit created_at.
// status is "success" or "failed" — mapped to event='login.success' /
// 'login.failed' and the matching outcome value. user_login_events was
// dropped in c41; insights now read from auth_logs.
func insertLoginEventAt(t *testing.T, appID uuid.UUID, userID *uuid.UUID, status, method string, createdAt time.Time) {
	t.Helper()
	event := "login.success"
	if status == "failed" {
		event = "login.failed"
	}
	ctx := context.Background()
	var workspaceID uuid.UUID
	if err := testEnv.DB.Pool().QueryRow(ctx,
		"SELECT workspace_id FROM apps WHERE id = $1", appID,
	).Scan(&workspaceID); err != nil {
		t.Fatalf("insertLoginEventAt: lookup workspace: %v", err)
	}
	_, err := testEnv.DB.Pool().Exec(ctx, `
		INSERT INTO auth_logs
		  (id, workspace_id, app_id, subject_user_id, event, method, outcome, actor_type, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'self', $8)
	`, utils.NewUUID(), workspaceID, appID, userID, event, method, status, createdAt)
	if err != nil {
		t.Fatalf("insertLoginEventAt: %v", err)
	}
}

// hitInsights performs a GET against the insights router and returns the
// recorder. Caller asserts status / body.
func hitInsights(t *testing.T, fix *insightsFixture, path string) *httptest.ResponseRecorder {
	t.Helper()
	url := fmt.Sprintf("/admin/workspace/%s/projects/%s/apps/%s%s",
		fix.ws.ID, fix.app.ProjectID, fix.app.ID, path)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	testEnv.SetSessionCookie(t, req, fix.claims)
	rr := httptest.NewRecorder()
	fix.router.ServeHTTP(rr, req)
	return rr
}

func dayStart(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 12, 0, 0, 0, time.UTC)
}

/* -------------------------------------------------------------------------- */
/* Empty-state tests — brand-new app, no signups, no events                    */
/* -------------------------------------------------------------------------- */

func TestInsightsSummary_EmptyApp(t *testing.T) {
	fix := newInsightsFixture(t)

	rr := hitInsights(t, fix, "/insights/summary?range=30d")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}

	var resp core.AppInsightsSummary
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if resp.RangeDays != 30 {
		t.Errorf("rangeDays = %d, want 30", resp.RangeDays)
	}
	if resp.TotalUsers != 0 || resp.NewUsers != 0 || resp.NewUsersPrev != 0 {
		t.Errorf("expected zero user counts, got total=%d new=%d prev=%d",
			resp.TotalUsers, resp.NewUsers, resp.NewUsersPrev)
	}
	if resp.ActiveUsers != 0 || resp.LoginFailures != 0 {
		t.Errorf("expected zero activity/failures, got active=%d failures=%d",
			resp.ActiveUsers, resp.LoginFailures)
	}
}

func TestInsightsTimeseries_EmptyAppReturnsAllZeros(t *testing.T) {
	fix := newInsightsFixture(t)

	for _, metric := range []string{"signups", "logins", "login_failures", "cumulative_users"} {
		t.Run(metric, func(t *testing.T) {
			rr := hitInsights(t, fix, "/insights/timeseries?metric="+metric+"&range=7d")
			if rr.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
			}
			var resp core.Timeseries
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Metric != metric {
				t.Errorf("metric = %q, want %q", resp.Metric, metric)
			}
			if len(resp.Points) != 7 {
				t.Errorf("got %d points, want 7 (one per day)", len(resp.Points))
			}
			for _, p := range resp.Points {
				if p.Count != 0 {
					t.Errorf("expected 0 on empty app, got %d on %s", p.Count, p.Date)
				}
			}
		})
	}
}

func TestInsightsActivity_EmptyAppReturnsAllZeros(t *testing.T) {
	fix := newInsightsFixture(t)

	rr := hitInsights(t, fix, "/insights/activity?range=14d")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp core.ActivityTimeseries
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Points) != 14 {
		t.Errorf("got %d points, want 14", len(resp.Points))
	}
	for _, p := range resp.Points {
		if p.DAU != 0 || p.WAU != 0 || p.MAU != 0 {
			t.Errorf("expected zeros on empty app, got DAU=%d WAU=%d MAU=%d on %s",
				p.DAU, p.WAU, p.MAU, p.Date)
		}
	}
}

func TestInsightsSources_EmptyAppReturnsEmptyList(t *testing.T) {
	fix := newInsightsFixture(t)

	rr := hitInsights(t, fix, "/insights/sources")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp core.SourceBreakdown
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Items) != 0 {
		t.Errorf("expected 0 items on empty app, got %d", len(resp.Items))
	}
}

/* -------------------------------------------------------------------------- */
/* Signup / cumulative / source tests                                          */
/* -------------------------------------------------------------------------- */

func TestInsightsSummary_NewUsersInWindow(t *testing.T) {
	fix := newInsightsFixture(t)
	now := time.Now().UTC()

	// 3 users this period, 1 in the prior period, 1 outside both.
	for i := 0; i < 3; i++ {
		insertSignupAt(t, fix.app.ID, "registered", now.AddDate(0, 0, -i-1))
	}
	insertSignupAt(t, fix.app.ID, "registered", now.AddDate(0, 0, -45))
	insertSignupAt(t, fix.app.ID, "registered", now.AddDate(0, 0, -120))

	rr := hitInsights(t, fix, "/insights/summary?range=30d")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp core.AppInsightsSummary
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp.TotalUsers != 5 {
		t.Errorf("totalUsers = %d, want 5", resp.TotalUsers)
	}
	if resp.NewUsers != 3 {
		t.Errorf("newUsers (last 30d) = %d, want 3", resp.NewUsers)
	}
	if resp.NewUsersPrev != 1 {
		t.Errorf("newUsersPrev (30–60d ago) = %d, want 1", resp.NewUsersPrev)
	}
}

func TestInsightsTimeseries_SignupsBucketCorrectly(t *testing.T) {
	fix := newInsightsFixture(t)
	now := time.Now().UTC()

	// 2 signups today, 1 signup 3 days ago, 1 signup 6 days ago.
	insertSignupAt(t, fix.app.ID, "registered", dayStart(now))
	insertSignupAt(t, fix.app.ID, "registered", dayStart(now))
	insertSignupAt(t, fix.app.ID, "registered", dayStart(now.AddDate(0, 0, -3)))
	insertSignupAt(t, fix.app.ID, "registered", dayStart(now.AddDate(0, 0, -6)))

	rr := hitInsights(t, fix, "/insights/timeseries?metric=signups&range=7d")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp core.Timeseries
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	if len(resp.Points) != 7 {
		t.Fatalf("got %d points, want 7", len(resp.Points))
	}

	total := 0
	for _, p := range resp.Points {
		total += p.Count
	}
	if total != 4 {
		t.Errorf("sum across 7 days = %d, want 4", total)
	}
	// Last day = today
	last := resp.Points[len(resp.Points)-1]
	if last.Count != 2 {
		t.Errorf("today's bucket = %d, want 2 (both today's signups)", last.Count)
	}
}

func TestInsightsTimeseries_CumulativeIncludesBaseline(t *testing.T) {
	fix := newInsightsFixture(t)
	now := time.Now().UTC()

	// 5 users from before the window (baseline), 2 inside the window.
	for i := 0; i < 5; i++ {
		insertSignupAt(t, fix.app.ID, "registered", now.AddDate(0, 0, -100))
	}
	insertSignupAt(t, fix.app.ID, "registered", dayStart(now.AddDate(0, 0, -2)))
	insertSignupAt(t, fix.app.ID, "registered", dayStart(now))

	rr := hitInsights(t, fix, "/insights/timeseries?metric=cumulative_users&range=7d")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp core.Timeseries
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	if len(resp.Points) != 7 {
		t.Fatalf("got %d points, want 7", len(resp.Points))
	}
	first := resp.Points[0]
	if first.Count != 5 {
		t.Errorf("day 0 (baseline only) = %d, want 5", first.Count)
	}
	last := resp.Points[len(resp.Points)-1]
	if last.Count != 7 {
		t.Errorf("today (baseline + 2 in window) = %d, want 7", last.Count)
	}
}

func TestInsightsSources_GroupsCorrectly(t *testing.T) {
	fix := newInsightsFixture(t)
	now := time.Now().UTC()

	// 3 registered, 2 google, 1 invited.
	for i := 0; i < 3; i++ {
		insertSignupAt(t, fix.app.ID, "registered", now.AddDate(0, 0, -i))
	}
	for i := 0; i < 2; i++ {
		insertSignupAt(t, fix.app.ID, "google", now.AddDate(0, 0, -i))
	}
	insertSignupAt(t, fix.app.ID, "invited", now)

	rr := hitInsights(t, fix, "/insights/sources")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp core.SourceBreakdown
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	got := map[string]int{}
	for _, item := range resp.Items {
		got[item.Source] = item.Count
	}
	if got["registered"] != 3 || got["google"] != 2 || got["invited"] != 1 {
		t.Errorf("source counts = %v, want registered:3 google:2 invited:1", got)
	}
}

/* -------------------------------------------------------------------------- */
/* Login event tests                                                           */
/* -------------------------------------------------------------------------- */

func TestInsightsTimeseries_LoginsAndFailures(t *testing.T) {
	fix := newInsightsFixture(t)
	now := time.Now().UTC()
	user := insertSignupAt(t, fix.app.ID, "registered", now.AddDate(0, 0, -10))

	// 2 successes today, 1 success yesterday, 1 success 5 days ago.
	insertLoginEventAt(t, fix.app.ID, &user, "success", "password", dayStart(now))
	insertLoginEventAt(t, fix.app.ID, &user, "success", "password", dayStart(now))
	insertLoginEventAt(t, fix.app.ID, &user, "success", "password", dayStart(now.AddDate(0, 0, -1)))
	insertLoginEventAt(t, fix.app.ID, &user, "success", "password", dayStart(now.AddDate(0, 0, -5)))

	// 3 failures today.
	for i := 0; i < 3; i++ {
		insertLoginEventAt(t, fix.app.ID, &user, "failed", "password", dayStart(now))
	}

	loginsResp := fetchTimeseries(t, fix, "logins", "7d")
	failuresResp := fetchTimeseries(t, fix, "login_failures", "7d")

	loginsTotal := sumPoints(loginsResp.Points)
	failuresTotal := sumPoints(failuresResp.Points)
	if loginsTotal != 4 {
		t.Errorf("logins total = %d, want 4", loginsTotal)
	}
	if failuresTotal != 3 {
		t.Errorf("failures total = %d, want 3", failuresTotal)
	}

	loginsToday := loginsResp.Points[len(loginsResp.Points)-1].Count
	if loginsToday != 2 {
		t.Errorf("today's logins = %d, want 2", loginsToday)
	}
	failuresToday := failuresResp.Points[len(failuresResp.Points)-1].Count
	if failuresToday != 3 {
		t.Errorf("today's failures = %d, want 3", failuresToday)
	}
}

func TestInsightsActivity_DAUWAUMAURollingWindows(t *testing.T) {
	fix := newInsightsFixture(t)
	now := time.Now().UTC()

	// Three distinct users with logins on different days:
	//   userA logs in today
	//   userB logs in 3 days ago
	//   userC logs in 25 days ago (inside MAU but outside WAU)
	userA := insertSignupAt(t, fix.app.ID, "registered", now.AddDate(0, 0, -30))
	userB := insertSignupAt(t, fix.app.ID, "registered", now.AddDate(0, 0, -30))
	userC := insertSignupAt(t, fix.app.ID, "registered", now.AddDate(0, 0, -30))

	insertLoginEventAt(t, fix.app.ID, &userA, "success", "password", dayStart(now))
	insertLoginEventAt(t, fix.app.ID, &userB, "success", "password", dayStart(now.AddDate(0, 0, -3)))
	insertLoginEventAt(t, fix.app.ID, &userC, "success", "password", dayStart(now.AddDate(0, 0, -25)))

	rr := hitInsights(t, fix, "/insights/activity?range=14d")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp core.ActivityTimeseries
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	if len(resp.Points) != 14 {
		t.Fatalf("got %d points, want 14", len(resp.Points))
	}
	last := resp.Points[len(resp.Points)-1] // today
	// DAU today: only userA logged in today → 1
	if last.DAU != 1 {
		t.Errorf("today's DAU = %d, want 1", last.DAU)
	}
	// WAU today: userA (today) + userB (3 days ago) → 2
	if last.WAU != 2 {
		t.Errorf("today's WAU = %d, want 2", last.WAU)
	}
	// MAU today: userA + userB + userC (25 days ago is within 30-day window) → 3
	if last.MAU != 3 {
		t.Errorf("today's MAU = %d, want 3", last.MAU)
	}
}

func TestInsightsSummary_ActiveUsersIsDistinct(t *testing.T) {
	fix := newInsightsFixture(t)
	now := time.Now().UTC()
	userA := insertSignupAt(t, fix.app.ID, "registered", now.AddDate(0, 0, -30))
	userB := insertSignupAt(t, fix.app.ID, "registered", now.AddDate(0, 0, -30))

	// userA logs in 5 times in the last 30d — should still count as 1 active.
	for i := 0; i < 5; i++ {
		insertLoginEventAt(t, fix.app.ID, &userA, "success", "password", now.AddDate(0, 0, -i))
	}
	insertLoginEventAt(t, fix.app.ID, &userB, "success", "password", now.AddDate(0, 0, -2))

	rr := hitInsights(t, fix, "/insights/summary?range=30d")
	var resp core.AppInsightsSummary
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp.ActiveUsers != 2 {
		t.Errorf("activeUsers = %d, want 2 (distinct user count, not event count)", resp.ActiveUsers)
	}
}

/* -------------------------------------------------------------------------- */
/* Per-user activity drill-down                                                */
/* -------------------------------------------------------------------------- */

func TestUserActivity_NoEvents(t *testing.T) {
	fix := newInsightsFixture(t)
	user := insertSignupAt(t, fix.app.ID, "registered", time.Now().UTC().AddDate(0, 0, -10))

	rr := hitInsights(t, fix, "/users/"+user.String()+"/activity?range=30d")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}

	var resp core.UserActivitySummary
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.UserID != user.String() {
		t.Errorf("userId = %q, want %q", resp.UserID, user)
	}
	if resp.Logins != 0 || resp.Failures != 0 {
		t.Errorf("expected 0/0 for fresh user, got logins=%d failures=%d", resp.Logins, resp.Failures)
	}
	if resp.LastLoginAt != "" {
		t.Errorf("lastLoginAt should be empty for never-logged-in user, got %q", resp.LastLoginAt)
	}
	if len(resp.Daily) != 30 {
		t.Errorf("expected 30 daily points, got %d", len(resp.Daily))
	}
	if len(resp.RecentEvents) != 0 {
		t.Errorf("expected 0 recent events, got %d", len(resp.RecentEvents))
	}
}

func TestUserActivity_CountsAndLastLogin(t *testing.T) {
	fix := newInsightsFixture(t)
	now := time.Now().UTC()
	user := insertSignupAt(t, fix.app.ID, "registered", now.AddDate(0, 0, -10))

	// 3 successful logins (latest yesterday) + 2 failures today.
	insertLoginEventAt(t, fix.app.ID, &user, "success", "password", now.AddDate(0, 0, -5))
	insertLoginEventAt(t, fix.app.ID, &user, "success", "password", now.AddDate(0, 0, -3))
	insertLoginEventAt(t, fix.app.ID, &user, "success", "google", now.AddDate(0, 0, -1))
	insertLoginEventAt(t, fix.app.ID, &user, "failed", "password", now)
	insertLoginEventAt(t, fix.app.ID, &user, "failed", "password", now)

	rr := hitInsights(t, fix, "/users/"+user.String()+"/activity?range=30d")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}

	var resp core.UserActivitySummary
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp.Logins != 3 {
		t.Errorf("logins = %d, want 3", resp.Logins)
	}
	if resp.Failures != 2 {
		t.Errorf("failures = %d, want 2", resp.Failures)
	}
	if resp.LastLoginMethod != "google" {
		t.Errorf("lastLoginMethod = %q, want %q (most recent success)", resp.LastLoginMethod, "google")
	}
	if resp.LastLoginAt == "" {
		t.Error("expected non-empty lastLoginAt")
	}
	if len(resp.RecentEvents) != 5 {
		t.Errorf("recentEvents = %d, want 5", len(resp.RecentEvents))
	}
	// Events should be ordered newest first.
	if resp.RecentEvents[0].Status != "failed" {
		t.Errorf("recentEvents[0].status = %q, want %q (newest first)", resp.RecentEvents[0].Status, "failed")
	}
}

func TestUserActivity_CrossUserIsolation(t *testing.T) {
	fix := newInsightsFixture(t)
	now := time.Now().UTC()
	userA := insertSignupAt(t, fix.app.ID, "registered", now.AddDate(0, 0, -10))
	userB := insertSignupAt(t, fix.app.ID, "registered", now.AddDate(0, 0, -10))

	// userB has 5 logins, userA has 0.
	for i := 0; i < 5; i++ {
		insertLoginEventAt(t, fix.app.ID, &userB, "success", "password", now.AddDate(0, 0, -i))
	}

	rr := hitInsights(t, fix, "/users/"+userA.String()+"/activity?range=30d")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp core.UserActivitySummary
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp.Logins != 0 {
		t.Errorf("userA's logins should be 0 (userB's 5 events shouldn't leak), got %d", resp.Logins)
	}
}

func TestUserActivity_DailyTimeseriesBuckets(t *testing.T) {
	fix := newInsightsFixture(t)
	now := time.Now().UTC()
	user := insertSignupAt(t, fix.app.ID, "registered", now.AddDate(0, 0, -30))

	// 3 logins today, 2 logins 3 days ago.
	insertLoginEventAt(t, fix.app.ID, &user, "success", "password", dayStart(now))
	insertLoginEventAt(t, fix.app.ID, &user, "success", "password", dayStart(now))
	insertLoginEventAt(t, fix.app.ID, &user, "success", "password", dayStart(now))
	insertLoginEventAt(t, fix.app.ID, &user, "success", "password", dayStart(now.AddDate(0, 0, -3)))
	insertLoginEventAt(t, fix.app.ID, &user, "success", "password", dayStart(now.AddDate(0, 0, -3)))

	rr := hitInsights(t, fix, "/users/"+user.String()+"/activity?range=7d")
	var resp core.UserActivitySummary
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	if len(resp.Daily) != 7 {
		t.Fatalf("daily points = %d, want 7", len(resp.Daily))
	}
	last := resp.Daily[len(resp.Daily)-1]
	if last.Count != 3 {
		t.Errorf("today's bucket = %d, want 3", last.Count)
	}
	total := 0
	for _, p := range resp.Daily {
		total += p.Count
	}
	if total != 5 {
		t.Errorf("daily total = %d, want 5", total)
	}
}

// TestGetProjectMembersActivityCounts exercises the per-user batch
// repo function directly. Previously its queries referenced
// client_sessions.subject_user_id — a column that doesn't exist; the
// correct column is user_id. No HTTP test reached this code path, so
// the bug only surfaced when the AppUsers list rendered with active
// sessions. This test pins both branches of the function (sessions +
// failed-login counts) so any future column rename gets caught here.
func TestGetProjectMembersActivityCounts(t *testing.T) {
	fix := newInsightsFixture(t)
	ctx := context.Background()
	pool := testEnv.DB.Pool()

	userA := insertTestUser(t, "registered", fix.app.ID)
	userB := insertTestUser(t, "registered", fix.app.ID)

	// Two active sessions for userA, none for userB.
	for i := 0; i < 2; i++ {
		sid := utils.NewUUID()
		if _, err := pool.Exec(ctx, `
			INSERT INTO client_sessions (id, user_id, app_id, expires_at, user_agent, ip)
			VALUES ($1, $2, $3, now() + interval '1 hour', '', '')
		`, sid, userA, fix.app.ID); err != nil {
			t.Fatalf("insert client_sessions: %v", err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE id = $1", sid)
		})
	}

	// Three failed logins in the last 7 days for userB, none for userA.
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		insertLoginEventAt(t, fix.app.ID, &userB, "failed", "password", now.AddDate(0, 0, -i))
	}
	// Stale failure (outside 7d window) — must NOT be counted.
	insertLoginEventAt(t, fix.app.ID, &userB, "failed", "password", now.AddDate(0, 0, -30))

	counts, err := testEnv.Repo.GetProjectMembersActivityCounts(ctx, fix.app.ID, []uuid.UUID{userA, userB})
	if err != nil {
		t.Fatalf("GetProjectMembersActivityCounts: %v", err)
	}

	if got := counts[userA].ActiveSessions; got != 2 {
		t.Errorf("userA ActiveSessions = %d, want 2", got)
	}
	if got := counts[userA].LoginFailures7d; got != 0 {
		t.Errorf("userA LoginFailures7d = %d, want 0", got)
	}
	if got := counts[userB].ActiveSessions; got != 0 {
		t.Errorf("userB ActiveSessions = %d, want 0", got)
	}
	if got := counts[userB].LoginFailures7d; got != 3 {
		t.Errorf("userB LoginFailures7d = %d, want 3 (the 30-day-old failure must be filtered out)", got)
	}
}

func TestUserActivity_InvalidUserIDReturns404(t *testing.T) {
	fix := newInsightsFixture(t)
	rr := hitInsights(t, fix, "/users/not-a-uuid/activity")
	// loadUserScopedToApp treats a malformed/unknown/foreign-pool user as 404,
	// consistent with the identity/passkey admin handlers.
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for bogus userId", rr.Code)
	}
}

/* -------------------------------------------------------------------------- */
/* Range parameter / handler-validation tests                                  */
/* -------------------------------------------------------------------------- */

func TestInsightsRange_ParsesVariants(t *testing.T) {
	fix := newInsightsFixture(t)

	cases := []struct {
		query string
		want  int
	}{
		{"", 30},
		{"?range=", 30},
		{"?range=7d", 7},
		{"?range=7", 7},
		{"?range=7D", 7},
		{"?range=90d", 90},
		{"?range=bogus", 30},
		{"?range=-5", 30},
		{"?range=99999", 365}, // clamped
	}

	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			rr := hitInsights(t, fix, "/insights/summary"+c.query)
			if rr.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
			}
			var resp core.AppInsightsSummary
			_ = json.Unmarshal(rr.Body.Bytes(), &resp)
			if resp.RangeDays != c.want {
				t.Errorf("range %q → rangeDays %d, want %d", c.query, resp.RangeDays, c.want)
			}
		})
	}
}

func TestInsightsTimeseries_InvalidMetricReturns400(t *testing.T) {
	fix := newInsightsFixture(t)
	rr := hitInsights(t, fix, "/insights/timeseries?metric=hax&range=30d")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for bogus metric", rr.Code)
	}
}

func TestInsightsTimeseries_MissingMetricReturns400(t *testing.T) {
	fix := newInsightsFixture(t)
	rr := hitInsights(t, fix, "/insights/timeseries?range=30d")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing metric", rr.Code)
	}
}

func TestInsightsCrossWorkspace_Returns404(t *testing.T) {
	// Two separate workspaces. Admin of A should not be able to read insights
	// for an app in workspace B.
	router := setupInsightsRouter(t)

	emailA := "ix-a-" + GenerateUniqueSlug("t") + "@example.com"
	emailB := "ix-b-" + GenerateUniqueSlug("t") + "@example.com"
	accA := testEnv.CreateTestAccount(t, emailA)
	accB := testEnv.CreateTestAccount(t, emailB)
	wsA := testEnv.CreateTestWorkspace(t, accA, "WS A", GenerateUniqueSlug("wsa"))
	wsB := testEnv.CreateTestWorkspace(t, accB, "WS B", GenerateUniqueSlug("wsb"))
	appB := testEnv.CreateTestApp(t, wsB, accB)
	_, claimsA := testEnv.CreateTestSession(t, accA)

	t.Cleanup(func() {
		ctx := context.Background()
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM apps WHERE id = $1", appB.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM projects WHERE id = $1", appB.ProjectID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspace_admins WHERE workspace_id IN ($1, $2)", wsA.ID, wsB.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspaces WHERE id IN ($1, $2)", wsA.ID, wsB.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM accounts WHERE id IN ($1, $2)", accA.ID, accB.ID)
	})

	// Admin of A asks for B's app via A's workspaceId — middleware blocks
	// (workspace ownership check returns 403).
	url := fmt.Sprintf("/admin/workspace/%s/projects/%s/apps/%s/insights/summary",
		wsA.ID, appB.ProjectID, appB.ID)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	testEnv.SetSessionCookie(t, req, claimsA)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Asking for an app under the wrong workspace should fail. The exact
	// status (403 from the middleware vs 404 from the handler) is less
	// important than "definitely not 200".
	if rr.Code == http.StatusOK {
		t.Errorf("cross-workspace request returned 200 (data leak); want 4xx")
	}
}

/* -------------------------------------------------------------------------- */
/* Helpers                                                                     */
/* -------------------------------------------------------------------------- */

func fetchTimeseries(t *testing.T, fix *insightsFixture, metric, rangeStr string) core.Timeseries {
	t.Helper()
	rr := hitInsights(t, fix, "/insights/timeseries?metric="+metric+"&range="+rangeStr)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp core.Timeseries
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return resp
}

func sumPoints(points []core.TimeseriesPoint) int {
	total := 0
	for _, p := range points {
		total += p.Count
	}
	return total
}
