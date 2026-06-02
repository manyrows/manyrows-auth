package api

import (
	"encoding/csv"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

type ServerAuthLogEntry struct {
	ID            string    `json:"id"`
	CreatedAt     time.Time `json:"createdAt"`
	Event         string    `json:"event"`
	Method        string    `json:"method,omitempty"`
	Outcome       string    `json:"outcome"`
	FailureReason string    `json:"failureReason,omitempty"`
	ActorType     string    `json:"actorType"`
	IP            string    `json:"ip,omitempty"`
	UserAgent     string    `json:"userAgent,omitempty"`
	RequestID     string    `json:"requestId,omitempty"`
}

type ServerAuthLogsResponse struct {
	Logs     []ServerAuthLogEntry `json:"logs"`
	Total    int                  `json:"total"`
	Page     int                  `json:"page"`
	PageSize int                  `json:"pageSize"`
}

// ServerListAppAuthLogs returns the app's authentication-event history (all
// users), newest first, paginated — for backends ingesting auth events into a
// SIEM/analytics pipeline. Supports incremental pulls via `since`/`until`
// (RFC3339) and an optional `outcome` filter (success|failure).
// GET /x/{workspaceSlug}/api/v1/apps/{appId}/auth-logs
func (handler *RequestHandler) ServerListAppAuthLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	q := r.URL.Query()
	page, pageSize, ok := parseAuthLogPaging(w, r, q)
	if !ok {
		return
	}

	params := repo.ListAuthLogsParams{
		WorkspaceID: ws.ID,
		AppID:       &app.ID,
		Page:        page,
		PageSize:    pageSize,
	}
	if v := strings.TrimSpace(q.Get("since")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		params.Since = &t
	}
	if v := strings.TrimSpace(q.Get("until")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		params.Until = &t
	}
	if v := strings.TrimSpace(q.Get("outcome")); v != "" {
		params.Outcome = core.AuthLogOutcome(v)
	}

	logs, total, err := handler.repo.ListAuthLogs(ctx, params)
	if err != nil {
		log.Err(err).Msg("ServerListAppAuthLogs: ListAuthLogs failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	entries := toServerAuthLogEntries(logs)
	if strings.EqualFold(strings.TrimSpace(q.Get("format")), "csv") {
		writeAuthLogsCSV(w, entries)
		return
	}
	utils.WriteJson(w, ServerAuthLogsResponse{Logs: entries, Total: total, Page: page, PageSize: pageSize})
}

// ServerGetUserAuthLogs returns a member's authentication-event history for
// this app (sign-ins, password changes, status changes, etc.), newest first,
// paginated.
// GET /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/auth-logs
func (handler *RequestHandler) ServerGetUserAuthLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}
	if !handler.requireAppMember(w, r, app.ID, userID) {
		return
	}

	q := r.URL.Query()
	page, pageSize, ok := parseAuthLogPaging(w, r, q)
	if !ok {
		return
	}

	uid := userID
	logs, total, err := handler.repo.ListAuthLogs(ctx, repo.ListAuthLogsParams{
		WorkspaceID:   ws.ID,
		AppID:         &app.ID,
		SubjectUserID: &uid,
		Page:          page,
		PageSize:      pageSize,
	})
	if err != nil {
		log.Err(err).Msg("ServerGetUserAuthLogs: ListAuthLogs failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	entries := toServerAuthLogEntries(logs)
	if strings.EqualFold(strings.TrimSpace(q.Get("format")), "csv") {
		writeAuthLogsCSV(w, entries)
		return
	}
	utils.WriteJson(w, ServerAuthLogsResponse{Logs: entries, Total: total, Page: page, PageSize: pageSize})
}

// parseAuthLogPaging reads page/pageSize query params (page>=0, pageSize 1..200,
// default 50). On a bad value it writes a 400 and returns ok=false.
func parseAuthLogPaging(w http.ResponseWriter, r *http.Request, q url.Values) (page, pageSize int, ok bool) {
	page = 0
	if v := strings.TrimSpace(q.Get("page")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			WriteError(w, r, "error.invalidPage", http.StatusBadRequest)
			return 0, 0, false
		}
		page = n
	}
	pageSize = 50
	if v := strings.TrimSpace(q.Get("pageSize")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			WriteError(w, r, "error.invalidPageSize", http.StatusBadRequest)
			return 0, 0, false
		}
		if n > 200 {
			n = 200
		}
		pageSize = n
	}
	return page, pageSize, true
}

// writeAuthLogsCSV streams the entries as CSV (one header row + a row each),
// honouring the same filters/paging as the JSON response. encoding/csv handles
// quoting of commas, quotes, and newlines (e.g. in user-agent strings).
func writeAuthLogsCSV(w http.ResponseWriter, entries []ServerAuthLogEntry) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="auth-logs.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "createdAt", "event", "method", "outcome", "failureReason", "actorType", "ip", "userAgent", "requestId"})
	for _, e := range entries {
		_ = cw.Write([]string{
			e.ID,
			e.CreatedAt.UTC().Format(time.RFC3339),
			e.Event, e.Method, e.Outcome, e.FailureReason, e.ActorType, e.IP, e.UserAgent, e.RequestID,
		})
	}
	cw.Flush()
}

func toServerAuthLogEntries(logs []core.AuthLog) []ServerAuthLogEntry {
	out := make([]ServerAuthLogEntry, 0, len(logs))
	for _, l := range logs {
		e := ServerAuthLogEntry{
			ID:            l.ID.String(),
			CreatedAt:     l.CreatedAt,
			Event:         string(l.Event),
			Method:        string(l.Method),
			Outcome:       string(l.Outcome),
			FailureReason: string(l.FailureReason),
			ActorType:     string(l.ActorType),
			UserAgent:     l.UserAgent,
			RequestID:     l.RequestID,
		}
		if l.IP != nil {
			e.IP = l.IP.String()
		}
		out = append(out, e)
	}
	return out
}
