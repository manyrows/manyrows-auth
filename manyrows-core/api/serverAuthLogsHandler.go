package api

import (
	"net/http"
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
	page := 0
	if v := strings.TrimSpace(q.Get("page")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			WriteError(w, r, "error.invalidPage", http.StatusBadRequest)
			return
		}
		page = n
	}
	pageSize := 50
	if v := strings.TrimSpace(q.Get("pageSize")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			WriteError(w, r, "error.invalidPageSize", http.StatusBadRequest)
			return
		}
		if n > 200 {
			n = 200
		}
		pageSize = n
	}

	appID := app.ID
	uid := userID
	logs, total, err := handler.repo.ListAuthLogs(ctx, repo.ListAuthLogsParams{
		WorkspaceID:   ws.ID,
		AppID:         &appID,
		SubjectUserID: &uid,
		Page:          page,
		PageSize:      pageSize,
	})
	if err != nil {
		log.Err(err).Msg("ServerGetUserAuthLogs: ListAuthLogs failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

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

	utils.WriteJson(w, ServerAuthLogsResponse{Logs: out, Total: total, Page: page, PageSize: pageSize})
}
