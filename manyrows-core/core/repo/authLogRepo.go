package repo

import (
	"context"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
)

// InsertAuthLog persists a row in auth_logs. Validation here is minimal —
// the typed core.AuthLogEntry already enforces the closed vocabularies on
// the Go side, and the Postgres CHECK constraint on outcome catches the
// only field that callers can pass as a free string. Failing to write
// must never block the calling auth flow; the writer in the api package
// calls this best-effort and logs on failure.
func (r *Repo) InsertAuthLog(ctx context.Context, l core.AuthLog) (*core.AuthLog, error) {
	if l.WorkspaceID == uuid.Nil {
		return nil, ErrBadRequest
	}
	if l.Event == "" {
		return nil, ErrBadRequest
	}
	if l.Outcome == "" {
		return nil, ErrBadRequest
	}
	if l.ActorType == "" {
		return nil, ErrBadRequest
	}

	if l.ID == uuid.Nil {
		l.ID = utils.NewUUID()
	}
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now().UTC()
	}

	emailAttempted := strings.TrimSpace(strings.ToLower(l.EmailAttempted))
	actorLabel := strings.TrimSpace(l.ActorLabel)
	userAgent := strings.TrimSpace(l.UserAgent)
	requestID := strings.TrimSpace(l.RequestID)

	var ipText *string
	if l.IP != nil {
		s := l.IP.String()
		ipText = &s
	}

	var metadataJSON []byte
	if len(l.Metadata) > 0 && string(l.Metadata) != "null" {
		metadataJSON = l.Metadata
	}

	const q = `
INSERT INTO auth_logs (
  id, workspace_id, app_id, created_at,
  event, method, outcome, failure_reason,
  subject_user_id, subject_account_id, email_attempted,
  actor_type, actor_account_id, actor_api_key_id, actor_label,
  ip, user_agent, session_id, request_id,
  metadata
) VALUES (
  $1, $2, $3, $4,
  $5, NULLIF($6,''), $7, NULLIF($8,''),
  $9, $10, NULLIF($11,''),
  $12, $13, $14, NULLIF($15,''),
  $16::inet, NULLIF($17,''), $18, NULLIF($19,''),
  $20
)
RETURNING id, created_at`

	row := r.db.Pool().QueryRow(ctx, q,
		l.ID, l.WorkspaceID, l.AppID, l.CreatedAt,
		string(l.Event), string(l.Method), string(l.Outcome), string(l.FailureReason),
		l.SubjectUserID, l.SubjectAccountID, emailAttempted,
		string(l.ActorType), l.ActorAccountID, l.ActorAPIKeyID, actorLabel,
		ipText, userAgent, l.SessionID, requestID,
		metadataJSON,
	)

	var (
		outID uuid.UUID
		outCA time.Time
	)
	if err := row.Scan(&outID, &outCA); err != nil {
		return nil, err
	}
	l.ID = outID
	l.CreatedAt = outCA
	return &l, nil
}

// scanAuthLog scans a single auth_logs row into core.AuthLog. The select
// list MUST be the SELECT_AUTH_LOG_COLS constant for column ordering to
// stay in sync with this scanner.
func scanAuthLog(row interface {
	Scan(dest ...any) error
}) (*core.AuthLog, error) {
	var (
		l              core.AuthLog
		method         *string
		failure        *string
		emailAttempted *string
		actorLabel     *string
		ipText         *string
		userAgent      *string
		requestID      *string
		metadataRaw    []byte
	)
	if err := row.Scan(
		&l.ID, &l.WorkspaceID, &l.AppID, &l.CreatedAt,
		&l.Event, &method, &l.Outcome, &failure,
		&l.SubjectUserID, &l.SubjectAccountID, &emailAttempted,
		&l.ActorType, &l.ActorAccountID, &l.ActorAPIKeyID, &actorLabel,
		&ipText, &userAgent, &l.SessionID, &requestID,
		&metadataRaw,
	); err != nil {
		return nil, err
	}
	if method != nil {
		l.Method = core.AuthLogMethod(*method)
	}
	if failure != nil {
		l.FailureReason = core.AuthLogFailureReason(*failure)
	}
	if emailAttempted != nil {
		l.EmailAttempted = *emailAttempted
	}
	if actorLabel != nil {
		l.ActorLabel = *actorLabel
	}
	if userAgent != nil {
		l.UserAgent = *userAgent
	}
	if requestID != nil {
		l.RequestID = *requestID
	}
	if ipText != nil {
		if addr, err := netip.ParseAddr(*ipText); err == nil {
			l.IP = &addr
		}
	}
	if len(metadataRaw) > 0 {
		l.Metadata = json.RawMessage(metadataRaw)
	}
	return &l, nil
}

// selectAuthLogCols is the canonical SELECT list used by every read path.
// Keep ordering in sync with scanAuthLog.
//
// host(ip) is used instead of ip::text because Postgres' default inet→text
// rendering for an address without an explicit netmask is "::1" but for
// many client/driver combinations comes back as "::1/128" — netip.ParseAddr
// rejects the slash form ("ParseAddr requires no port or zone"). host()
// strips the netmask unconditionally, returning the plain address text.
const selectAuthLogCols = `
  id, workspace_id, app_id, created_at,
  event, method, outcome, failure_reason,
  subject_user_id, subject_account_id, email_attempted,
  actor_type, actor_account_id, actor_api_key_id, actor_label,
  host(ip), user_agent, session_id, request_id,
  metadata`

// ListAuthLogsParams describes a single page of the AuthLogs admin view.
// All filter fields are optional; an empty/zero value disables that filter.
// AppID == nil means "all apps in the workspace including workspace-scope
// rows where app_id IS NULL"; pass an explicit empty string sentinel via
// AppIDOnly = true to filter for workspace-scope rows specifically.
type ListAuthLogsParams struct {
	WorkspaceID uuid.UUID
	AppID       *uuid.UUID

	// Time window. Both bounds are inclusive at the start, exclusive at
	// the end (standard half-open interval).
	Since *time.Time
	Until *time.Time

	// Vocabularies — pass nil/empty to skip. Multi-select on each.
	Events         []core.AuthLogEvent
	Methods        []core.AuthLogMethod
	Outcome        core.AuthLogOutcome // empty = both
	FailureReasons []core.AuthLogFailureReason
	ActorTypes     []core.AuthLogActorType

	// Subject filters. SubjectUserID/SubjectAccountID are exact matches;
	// EmailAttemptedLike is a case-insensitive substring matched against
	// the typed email_attempted AND the subject's actual email
	// (subject_user → users.email, subject_account → accounts.email), so
	// searching a known user/admin by email also finds rows where
	// email_attempted is null (OAuth, session events, admin actions).
	SubjectUserID      *uuid.UUID
	SubjectAccountID   *uuid.UUID
	EmailAttemptedLike string

	// Correlation filters — given by the UI's "show this session" /
	// "show this request" affordances on a row drilldown.
	SessionID *uuid.UUID
	RequestID string

	// Pagination. Page is 0-based.
	Page     int
	PageSize int
}

// ListAuthLogs returns a single page plus the total matching the same
// filters (for pagination UI). The query layout — one base WHERE + LIMIT
// for the page and a parallel COUNT(*) — is intentionally simple; if a
// customer's workspace grows past the point where COUNT(*) is the
// expensive part, switch to a keyset-paginated variant rather than
// trying to optimize this one.
func (r *Repo) ListAuthLogs(ctx context.Context, p ListAuthLogsParams) (logs []core.AuthLog, total int, err error) {
	if p.WorkspaceID == uuid.Nil {
		return nil, 0, ErrBadRequest
	}
	if p.PageSize <= 0 {
		p.PageSize = 25
	}
	if p.PageSize > 200 {
		p.PageSize = 200
	}
	if p.Page < 0 {
		p.Page = 0
	}

	where, args := buildAuthLogWhere(p)

	// COUNT(*) over the same predicate. We don't reuse the rows — a
	// separate query is cheaper than fetching every row to count them.
	countQ := "SELECT COUNT(*) FROM auth_logs WHERE " + where
	if err := r.db.Pool().QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listQ := "SELECT" + selectAuthLogCols +
		"\nFROM auth_logs WHERE " + where +
		"\nORDER BY created_at DESC, id DESC" +
		"\nLIMIT $" + strconv.Itoa(len(args)+1) +
		" OFFSET $" + strconv.Itoa(len(args)+2)

	args = append(args, p.PageSize, p.Page*p.PageSize)

	rows, err := r.db.Pool().Query(ctx, listQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		row, err := scanAuthLog(rows)
		if err != nil {
			return nil, 0, err
		}
		logs = append(logs, *row)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

// buildAuthLogWhere assembles the WHERE fragment + args from a
// ListAuthLogsParams. Returns "TRUE" with no args when no filters apply
// (other than workspace_id, which is always required).
func buildAuthLogWhere(p ListAuthLogsParams) (string, []any) {
	var clauses []string
	var args []any

	add := func(clause string, vals ...any) {
		// Renumber $N placeholders relative to current arg count.
		n := len(args)
		out := clause
		for i := range vals {
			out = strings.Replace(out, "?", "$"+strconv.Itoa(n+i+1), 1)
		}
		clauses = append(clauses, out)
		args = append(args, vals...)
	}

	add("workspace_id = ?", p.WorkspaceID)

	if p.AppID != nil {
		add("app_id = ?", *p.AppID)
	}
	if p.Since != nil {
		add("created_at >= ?", *p.Since)
	}
	if p.Until != nil {
		add("created_at < ?", *p.Until)
	}
	if len(p.Events) > 0 {
		add("event = ANY(?)", asTextArray(eventsToStrings(p.Events)))
	}
	if len(p.Methods) > 0 {
		add("method = ANY(?)", asTextArray(methodsToStrings(p.Methods)))
	}
	if p.Outcome != "" {
		add("outcome = ?", string(p.Outcome))
	}
	if len(p.FailureReasons) > 0 {
		add("failure_reason = ANY(?)", asTextArray(failuresToStrings(p.FailureReasons)))
	}
	if len(p.ActorTypes) > 0 {
		add("actor_type = ANY(?)", asTextArray(actorTypesToStrings(p.ActorTypes)))
	}
	if p.SubjectUserID != nil {
		add("subject_user_id = ?", *p.SubjectUserID)
	}
	if p.SubjectAccountID != nil {
		add("subject_account_id = ?", *p.SubjectAccountID)
	}
	if e := strings.TrimSpace(strings.ToLower(p.EmailAttemptedLike)); e != "" {
		// Match the typed email OR the subject's actual email so a
		// known user/admin is found even when email_attempted is null.
		// Escape ILIKE wildcards so an email containing a literal '%' or '_'
		// matches exactly rather than expanding (matches the user-search paths).
		arg := emailILIKEArg(e)
		add(
			"(email_attempted ILIKE ? ESCAPE '\\'"+
				" OR EXISTS (SELECT 1 FROM users u WHERE u.id = auth_logs.subject_user_id AND u.email ILIKE ? ESCAPE '\\')"+
				" OR EXISTS (SELECT 1 FROM accounts a WHERE a.id = auth_logs.subject_account_id AND a.email ILIKE ? ESCAPE '\\'))",
			arg, arg, arg,
		)
	}
	if p.SessionID != nil {
		add("session_id = ?", *p.SessionID)
	}
	if rid := strings.TrimSpace(p.RequestID); rid != "" {
		add("request_id = ?", rid)
	}

	return strings.Join(clauses, " AND "), args
}

func eventsToStrings(in []core.AuthLogEvent) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}
func methodsToStrings(in []core.AuthLogMethod) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}
func failuresToStrings(in []core.AuthLogFailureReason) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}
func actorTypesToStrings(in []core.AuthLogActorType) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

// asTextArray wraps a []string for pgx's text[] binding without forcing
// the caller to import pgtype directly. pgx natively binds []string to
// text[] in v5, so this is just a marker for clarity.
func asTextArray(s []string) []string { return s }
