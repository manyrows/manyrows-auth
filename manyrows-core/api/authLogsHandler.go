package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// parseIntClamp parses a query-string int with a default and inclusive
// bounds. Used by handlers that take page/pageSize-style numeric params.
func parseIntClamp(raw string, def, min, max int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

// AuthLogsResponse is the wire shape of the AuthLogs admin list endpoint.
// `logs` plus pagination metadata. Filter values are echoed back so the
// UI can re-derive its filter state from the response (no client-side
// "did this match what I asked for?" guessing).
type AuthLogsResponse struct {
	Logs []core.AuthLog `json:"logs"`

	Total    int `json:"total"`
	Page     int `json:"page"`
	PageSize int `json:"pageSize"`

	// Echoed filters
	WorkspaceID    uuid.UUID `json:"workspaceId"`
	AppID          string    `json:"appId,omitempty"`
	Events         []string  `json:"events,omitempty"`
	Methods        []string  `json:"methods,omitempty"`
	Outcome        string    `json:"outcome,omitempty"`
	FailureReasons []string  `json:"failureReasons,omitempty"`
	ActorTypes     []string  `json:"actorTypes,omitempty"`
	SubjectUserID  string    `json:"subjectUserId,omitempty"`
	EmailLike      string    `json:"emailLike,omitempty"`
	SessionID      string    `json:"sessionId,omitempty"`
	RequestID      string    `json:"requestId,omitempty"`
	Since          string    `json:"since,omitempty"`
	Until          string    `json:"until,omitempty"`
}

// HandleListAuthLogs is the admin endpoint behind the AuthLogs page.
// Workspace-scoped; the workspace is resolved by the admin middleware.
//
// Query params:
//   - page (0-based; default 0)
//   - pageSize (default 25; max 200)
//   - appId (filters to a single app)
//   - event (repeatable; e.g. ?event=login.success&event=login.failed)
//   - method (repeatable)
//   - outcome (success | failed)
//   - failureReason (repeatable)
//   - actorType (repeatable; self | admin | api_key | system)
//   - subjectUserId (exact)
//   - emailLike (substring; case-insensitive)
//   - sessionId / requestId (correlation drilldown)
//   - since / until (RFC3339)
//
// Multi-value filters use repeated query parameters rather than
// comma-separated values — repeated params survive UI form-encoding
// without escaping rules and chi's url.Values gives them to us
// directly via Query()[name].
func (handler *RequestHandler) HandleListAuthLogs(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	qp := r.URL.Query()

	page := parseIntClamp(qp.Get("page"), 0, 0, 1_000_000)
	pageSize := parseIntClamp(qp.Get("pageSize"), 25, 1, 200)

	params := repo.ListAuthLogsParams{
		WorkspaceID: ws.ID,
		Page:        page,
		PageSize:    pageSize,
	}

	if v := strings.TrimSpace(qp.Get("appId")); v != "" {
		appID, err := uuid.FromString(v)
		if err != nil {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		params.AppID = &appID
	}

	for _, v := range qp["event"] {
		v = strings.TrimSpace(v)
		if v != "" {
			params.Events = append(params.Events, core.AuthLogEvent(v))
		}
	}
	for _, v := range qp["method"] {
		v = strings.TrimSpace(v)
		if v != "" {
			params.Methods = append(params.Methods, core.AuthLogMethod(v))
		}
	}
	if v := strings.TrimSpace(qp.Get("outcome")); v != "" {
		switch core.AuthLogOutcome(v) {
		case core.AuthOutcomeSuccess, core.AuthOutcomeFailed:
			params.Outcome = core.AuthLogOutcome(v)
		default:
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
	}
	for _, v := range qp["failureReason"] {
		v = strings.TrimSpace(v)
		if v != "" {
			params.FailureReasons = append(params.FailureReasons, core.AuthLogFailureReason(v))
		}
	}
	for _, v := range qp["actorType"] {
		v = strings.TrimSpace(v)
		if v != "" {
			params.ActorTypes = append(params.ActorTypes, core.AuthLogActorType(v))
		}
	}

	if v := strings.TrimSpace(qp.Get("subjectUserId")); v != "" {
		uid, err := uuid.FromString(v)
		if err != nil {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		params.SubjectUserID = &uid
	}
	if v := strings.TrimSpace(qp.Get("emailLike")); v != "" {
		params.EmailAttemptedLike = v
	}
	if v := strings.TrimSpace(qp.Get("sessionId")); v != "" {
		sid, err := uuid.FromString(v)
		if err != nil {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		params.SessionID = &sid
	}
	if v := strings.TrimSpace(qp.Get("requestId")); v != "" {
		params.RequestID = v
	}

	if v := strings.TrimSpace(qp.Get("since")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		params.Since = &t
	}
	if v := strings.TrimSpace(qp.Get("until")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		params.Until = &t
	}

	logs, total, err := handler.repo.ListAuthLogs(r.Context(), params)
	if err != nil {
		log.Err(err).Msg("ListAuthLogs failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	resp := AuthLogsResponse{
		Logs:           logs,
		Total:          total,
		Page:           page,
		PageSize:       pageSize,
		WorkspaceID:    ws.ID,
		Events:         eventsToStringsHandler(params.Events),
		Methods:        methodsToStringsHandler(params.Methods),
		Outcome:        string(params.Outcome),
		FailureReasons: failuresToStringsHandler(params.FailureReasons),
		ActorTypes:     actorTypesToStringsHandler(params.ActorTypes),
		EmailLike:      params.EmailAttemptedLike,
		RequestID:      params.RequestID,
	}
	if params.AppID != nil {
		resp.AppID = params.AppID.String()
	}
	if params.SubjectUserID != nil {
		resp.SubjectUserID = params.SubjectUserID.String()
	}
	if params.SessionID != nil {
		resp.SessionID = params.SessionID.String()
	}
	if params.Since != nil {
		resp.Since = params.Since.Format(time.RFC3339)
	}
	if params.Until != nil {
		resp.Until = params.Until.Format(time.RFC3339)
	}

	utils.WriteJson(w, resp)
}

// HandleListAuthLogsForUser is the per-user variant used by the User
// detail dialog's "Auth activity" tab. Same response shape as the main
// list endpoint but pre-filtered to one subject user. The route binds
// {userId} from the URL; everything else flows through the normal
// query-param filters in case the UI wants to scope further (e.g. only
// failed events for one user).
func (handler *RequestHandler) HandleListAuthLogsForUser(w http.ResponseWriter, r *http.Request) {
	uidStr := strings.TrimSpace(chi.URLParam(r, "userId"))
	uid, err := uuid.FromString(uidStr)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Override subjectUserId on the URL params so the shared handler
	// path can do its work. Cheaper than duplicating the parsing.
	q := r.URL.Query()
	q.Set("subjectUserId", uid.String())
	r.URL.RawQuery = q.Encode()

	handler.HandleListAuthLogs(w, r)
}

// echoBack helpers — separate from repo's *toStrings to avoid coupling
// the handler's wire shape to the repo's internals.
func eventsToStringsHandler(in []core.AuthLogEvent) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}
func methodsToStringsHandler(in []core.AuthLogMethod) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}
func failuresToStringsHandler(in []core.AuthLogFailureReason) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}
func actorTypesToStringsHandler(in []core.AuthLogActorType) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}
