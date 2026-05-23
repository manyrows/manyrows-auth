package api

import (
	"net/http"
	"strconv"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// Login event recording was removed in the auth_logs rebuild — every former
// caller of recordAppLoginSuccess / recordAppLoginFailure now writes a
// typed AuthLog entry via writeAuthLogFromRequest in authLogWriter.go.
// The user_login_events table itself was dropped in c41.

// parseRangeDays decodes the "range" query parameter ("7d" / "30d" / "90d")
// into a number of days. Defaults to 30 on missing/invalid input.
func parseRangeDays(r *http.Request) int {
	raw := r.URL.Query().Get("range")
	if raw == "" {
		return 30
	}
	// Accept "7", "7d", "30d", "90d"; clamp to a sane range.
	if len(raw) > 0 && (raw[len(raw)-1] == 'd' || raw[len(raw)-1] == 'D') {
		raw = raw[:len(raw)-1]
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 30
	}
	if n > 365 {
		n = 365
	}
	return n
}

// parseAppContext resolves and validates the (workspace, project, app)
// triple from the request.
func (handler *RequestHandler) parseAppContext(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, uuid.UUID, bool) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return uuid.Nil, uuid.Nil, uuid.Nil, false
	}

	productID, err := utils.GetPathUUID("productId", r)
	if err != nil || productID == uuid.Nil {
		log.Err(err).Msg("failed to parse project id")
		WriteError(w, r, "error.invalidProductId", http.StatusBadRequest)
		return uuid.Nil, uuid.Nil, uuid.Nil, false
	}

	appID, err := utils.GetPathUUID("appId", r)
	if err != nil || appID == uuid.Nil {
		log.Err(err).Msg("failed to parse app id")
		WriteError(w, r, "error.invalidAppId", http.StatusBadRequest)
		return uuid.Nil, uuid.Nil, uuid.Nil, false
	}

	// Validate the app belongs to the workspace + project. Reuses the same
	// existence check as HandleGetApp so we get consistent 404s.
	if _, err := handler.repo.GetAppByIDForProduct(r.Context(), ws.ID, productID, appID); err != nil {
		log.Err(err).Msg("failed to load app")
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return uuid.Nil, uuid.Nil, uuid.Nil, false
	}

	return ws.ID, productID, appID, true
}

// HandleGetAppInsightsSummary — GET /admin/workspace/{wsId}/products/{productId}/apps/{appId}/insights/summary?range=30d
//
// Returns the four stat-card numbers plus their prior-period equivalents for
// delta computation.
func (handler *RequestHandler) HandleGetAppInsightsSummary(w http.ResponseWriter, r *http.Request) {
	_, _, appID, ok := handler.parseAppContext(w, r)
	if !ok {
		return
	}

	rangeDays := parseRangeDays(r)
	summary, err := handler.repo.GetAppInsightsSummary(r.Context(), appID, rangeDays)
	if err != nil {
		log.Err(err).Msg("failed to load app insights summary")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, summary, http.StatusOK)
}

// HandleGetAppInsightsTimeseries — GET /admin/.../apps/{appId}/insights/timeseries?metric=signups&range=30d
//
// Supported metrics:
//
//	signups          — daily count of new users joining the app
//	cumulative_users — running total of app users by day
//	logins           — daily count of successful logins
//	login_failures   — daily count of failed login attempts
func (handler *RequestHandler) HandleGetAppInsightsTimeseries(w http.ResponseWriter, r *http.Request) {
	_, _, appID, ok := handler.parseAppContext(w, r)
	if !ok {
		return
	}

	rangeDays := parseRangeDays(r)
	metric := r.URL.Query().Get("metric")

	var (
		points []core.TimeseriesPoint
		err    error
	)

	switch metric {
	case "signups":
		points, err = handler.repo.GetAppSignupsTimeseries(r.Context(), appID, rangeDays)
	case "cumulative_users":
		points, err = handler.repo.GetAppCumulativeUsersTimeseries(r.Context(), appID, rangeDays)
	case "logins":
		points, err = handler.repo.GetAppLoginsTimeseries(r.Context(), appID, rangeDays)
	case "login_failures":
		points, err = handler.repo.GetAppLoginFailuresTimeseries(r.Context(), appID, rangeDays)
	default:
		WriteError(w, r, "error.invalidMetric", http.StatusBadRequest)
		return
	}

	if err != nil {
		log.Err(err).Str("metric", metric).Msg("failed to load app insights timeseries")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, core.Timeseries{
		Metric: metric,
		Points: points,
	}, http.StatusOK)
}

// HandleGetAppInsightsActivity — GET /admin/.../apps/{appId}/insights/activity?range=30d
//
// Returns DAU/WAU/MAU per day for the requested window.
func (handler *RequestHandler) HandleGetAppInsightsActivity(w http.ResponseWriter, r *http.Request) {
	_, _, appID, ok := handler.parseAppContext(w, r)
	if !ok {
		return
	}

	rangeDays := parseRangeDays(r)
	points, err := handler.repo.GetAppActivityTimeseries(r.Context(), appID, rangeDays)
	if err != nil {
		log.Err(err).Msg("failed to load app activity timeseries")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, core.ActivityTimeseries{Points: points}, http.StatusOK)
}

// HandleGetAppUserActivity — GET /admin/.../apps/{appId}/users/{userId}/activity?range=30d
//
// Per-user drill-down used by the user-list "click row" dialog. Returns
// counts, last login details, active session count, daily sparkline data,
// and the most recent ~50 events for this user in this app.
func (handler *RequestHandler) HandleGetAppUserActivity(w http.ResponseWriter, r *http.Request) {
	_, _, appID, ok := handler.parseAppContext(w, r)
	if !ok {
		return
	}

	user, ok := handler.loadUserScopedToApp(w, r, appID)
	if !ok {
		return
	}

	rangeDays := parseRangeDays(r)
	summary, err := handler.repo.GetUserActivityForApp(r.Context(), appID, user.ID, rangeDays, 50)
	if err != nil {
		log.Err(err).Str("userId", user.ID.String()).Msg("failed to load user activity")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, summary, http.StatusOK)
}

// HandleGetAppInsightsSourceBreakdown — GET /admin/.../apps/{appId}/insights/sources
//
// Returns the user count grouped by `source` for the donut chart.
func (handler *RequestHandler) HandleGetAppInsightsSourceBreakdown(w http.ResponseWriter, r *http.Request) {
	_, _, appID, ok := handler.parseAppContext(w, r)
	if !ok {
		return
	}

	items, err := handler.repo.GetAppSourceBreakdown(r.Context(), appID)
	if err != nil {
		log.Err(err).Msg("failed to load app source breakdown")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, core.SourceBreakdown{Items: items}, http.StatusOK)
}
