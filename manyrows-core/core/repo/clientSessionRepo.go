package repo

import (
	"context"
	"errors"
	"manyrows-core/core"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

var (
	ErrClientSessionNotFound = errors.New("client session not found")
	ErrClientSessionExpired  = errors.New("client session expired")
)

// InsertClientSession inserts a new client session row.
func (r *Repo) InsertClientSession(ctx context.Context, s *core.ClientSession) error {
	if s == nil {
		return errors.New("client session is nil")
	}
	if s.ID == uuid.Nil {
		return errors.New("client session ID must be set")
	}
	if s.UserID == uuid.Nil {
		return errors.New("user_id must be set")
	}
	if s.CreatedAt.IsZero() {
		return errors.New("created_at must be set")
	}
	if s.LastSeenAt.IsZero() {
		return errors.New("last_seen_at must be set")
	}
	if s.ExpiresAt.IsZero() {
		return errors.New("expires_at must be set")
	}

	const q = `
insert into client_sessions (
  id,
  user_id,
  app_id,
  created_at,
  expires_at,
  last_seen_at,
  user_agent,
  ip,
  remember_me
) values ($1,$2,$3,$4,$5,$6,$7,$8,$9);
`
	_, err := r.db.Pool().Exec(
		ctx,
		q,
		s.ID,
		s.UserID,
		s.AppID,
		s.CreatedAt,
		s.ExpiresAt,
		s.LastSeenAt,
		s.UserAgent,
		s.IP,
		s.RememberMe,
	)
	return err
}

// PruneOldestSessionsByUserAndApp keeps at most `keep` active sessions
// for a user+app, deleting the oldest by last_seen_at.
func (r *Repo) PruneOldestSessionsByUserAndApp(ctx context.Context, userID, appID uuid.UUID, keep int) error {
	if userID == uuid.Nil || appID == uuid.Nil {
		return nil
	}
	const q = `
DELETE FROM client_sessions
WHERE id IN (
  SELECT id FROM client_sessions
  WHERE user_id = $1 AND app_id = $2 AND expires_at > now()
  ORDER BY last_seen_at DESC
  OFFSET $3
);
`
	_, err := r.db.Pool().Exec(ctx, q, userID, appID, keep)
	return err
}

// DeleteOtherSessionsBySameDevice hard-deletes any *other* active
// session for this user+app that came from the same device — same
// (ip, user_agent) pair — keeping only keepID (the just-created one).
// This collapses the per-device session to one: re-authenticating from
// a browser you already had a session in replaces it instead of
// stacking a ghost that lingers until its TTL.
//
// No-op when ip or userAgent is blank: an empty fingerprint isn't a
// device match, and collapsing every blank-UA session together would
// nuke unrelated logins.
func (r *Repo) DeleteOtherSessionsBySameDevice(ctx context.Context, userID, appID uuid.UUID, ip, userAgent string, keepID uuid.UUID) error {
	if userID == uuid.Nil || appID == uuid.Nil {
		return nil
	}
	ip = strings.TrimSpace(ip)
	userAgent = strings.TrimSpace(userAgent)
	if ip == "" || userAgent == "" {
		return nil
	}
	const q = `
delete from client_sessions
 where user_id = $1
   and app_id = $2
   and ip = $3
   and user_agent = $4
   and id <> $5
   and expires_at > now();
`
	_, err := r.db.Pool().Exec(ctx, q, userID, appID, ip, userAgent, keepID)
	return err
}

// GetClientSessionByID loads a client session by id and enforces expiry.
func (r *Repo) GetClientSessionByID(ctx context.Context, id uuid.UUID) (*core.ClientSession, error) {
	if id == uuid.Nil {
		return nil, ErrClientSessionNotFound
	}

	const q = `
select
  id,
  user_id,
  app_id,
  created_at,
  expires_at,
  last_seen_at,
  user_agent,
  ip,
  remember_me
from client_sessions
where id = $1
limit 1;
`

	var s core.ClientSession
	err := r.db.Pool().QueryRow(ctx, q, id).Scan(
		&s.ID,
		&s.UserID,
		&s.AppID,
		&s.CreatedAt,
		&s.ExpiresAt,
		&s.LastSeenAt,
		&s.UserAgent,
		&s.IP,
		&s.RememberMe,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrClientSessionNotFound
		}
		return nil, err
	}

	now := time.Now().UTC()
	if !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt) {
		return nil, ErrClientSessionExpired
	}

	return &s, nil
}

// DeleteClientSession hard-deletes a client session row.
func (r *Repo) DeleteClientSession(ctx context.Context, id uuid.UUID) (bool, error) {
	if id == uuid.Nil {
		return false, nil
	}
	const q = `delete from client_sessions where id = $1;`
	ct, err := r.db.Pool().Exec(ctx, q, id)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

// TouchClientSessionLastSeen updates last_seen_at to now().
func (r *Repo) TouchClientSessionLastSeen(ctx context.Context, id uuid.UUID) (bool, error) {
	if id == uuid.Nil {
		return false, nil
	}
	const q = `update client_sessions set last_seen_at = now() where id = $1;`
	ct, err := r.db.Pool().Exec(ctx, q, id)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

// CountActiveClientSessionsForWorkspace returns count of active sessions across all apps in a workspace.
func (r *Repo) CountActiveClientSessionsForWorkspace(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	if workspaceID == uuid.Nil {
		return 0, nil
	}
	const q = `
select count(*)
from client_sessions cs
join apps a on a.id = cs.app_id
join projects p on p.id = a.project_id
where p.workspace_id = $1
  and cs.expires_at > now();
`
	return r.scalarCount(ctx, q, workspaceID)
}

// GetActiveClientSessionResourcesForWorkspace returns paginated active sessions for a workspace.
func (r *Repo) GetActiveClientSessionResourcesForWorkspace(
	ctx context.Context,
	workspaceID uuid.UUID,
	limit int,
	offset int,
) ([]core.ClientSessionResource, error) {
	if workspaceID == uuid.Nil {
		return []core.ClientSessionResource{}, nil
	}
	if limit <= 0 {
		limit = 25
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}

	const q = `
select
  cs.id,
  cs.user_id,
  cs.created_at,
  cs.expires_at,
  cs.last_seen_at,
  coalesce(cs.user_agent, ''),
  coalesce(cs.ip, ''),
  u.id,
  u.email,
  a.id,
  p.name,
  a.type
from client_sessions cs
join users u on u.id = cs.user_id
left join apps a on a.id = cs.app_id
join projects p on p.id = a.project_id
where p.workspace_id = $1
  and cs.expires_at > now()
order by
  cs.last_seen_at desc nulls last,
  cs.created_at desc,
  cs.id desc
limit $2 offset $3;
`

	rows, err := r.db.Pool().Query(ctx, q, workspaceID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]core.ClientSessionResource, 0, limit)
	for rows.Next() {
		var sr core.ClientSessionResource
		var usr core.ClientSessionUser
		var appID *uuid.UUID
		var projectName *string
		var appType *string
		if err := rows.Scan(
			&sr.ID,
			&sr.UserID,
			&sr.CreatedAt,
			&sr.ExpiresAt,
			&sr.LastSeenAt,
			&sr.UserAgent,
			&sr.IP,
			&usr.ID,
			&usr.Email,
			&appID,
			&projectName,
			&appType,
		); err != nil {
			return nil, err
		}
		sr.User = &usr
		if appID != nil && *appID != uuid.Nil && projectName != nil && appType != nil {
			sr.App = &core.ClientSessionApp{ID: *appID, Name: core.AppDisplayName(*projectName, *appType)}
		}
		out = append(out, sr)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// CountActiveClientSessionsForWorkspaceByEmail counts active sessions filtered by user email.
func (r *Repo) CountActiveClientSessionsForWorkspaceByEmail(
	ctx context.Context,
	workspaceID uuid.UUID,
	email string,
) (int, error) {
	if workspaceID == uuid.Nil {
		return 0, nil
	}
	const q = `
select count(*)
from client_sessions cs
join users u on u.id = cs.user_id
join apps a on a.id = cs.app_id
join projects p on p.id = a.project_id
where p.workspace_id = $1
  and cs.expires_at > now()
  and u.email ilike $2 escape '\';
`
	escaped := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(email) + "%"
	return r.scalarCount(ctx, q, workspaceID, escaped)
}

// GetActiveClientSessionResourcesForWorkspaceByEmail returns paginated active sessions filtered by email.
func (r *Repo) GetActiveClientSessionResourcesForWorkspaceByEmail(
	ctx context.Context,
	workspaceID uuid.UUID,
	email string,
	limit int,
	offset int,
) ([]core.ClientSessionResource, error) {
	if workspaceID == uuid.Nil {
		return []core.ClientSessionResource{}, nil
	}
	if limit <= 0 {
		limit = 25
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}

	const q = `
select
  cs.id,
  cs.user_id,
  cs.created_at,
  cs.expires_at,
  cs.last_seen_at,
  coalesce(cs.user_agent, ''),
  coalesce(cs.ip, ''),
  u.id,
  u.email,
  a.id,
  p.name,
  a.type
from client_sessions cs
join users u on u.id = cs.user_id
left join apps a on a.id = cs.app_id
join projects p on p.id = a.project_id
where p.workspace_id = $1
  and cs.expires_at > now()
  and u.email ilike $2 escape '\'
order by
  cs.last_seen_at desc nulls last,
  cs.created_at desc,
  cs.id desc
limit $3 offset $4;
`

	escaped := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(email) + "%"
	rows, err := r.db.Pool().Query(ctx, q, workspaceID, escaped, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]core.ClientSessionResource, 0, limit)
	for rows.Next() {
		var sr core.ClientSessionResource
		var usr core.ClientSessionUser
		var appID *uuid.UUID
		var projectName *string
		var appType *string
		if err := rows.Scan(
			&sr.ID,
			&sr.UserID,
			&sr.CreatedAt,
			&sr.ExpiresAt,
			&sr.LastSeenAt,
			&sr.UserAgent,
			&sr.IP,
			&usr.ID,
			&usr.Email,
			&appID,
			&projectName,
			&appType,
		); err != nil {
			return nil, err
		}
		sr.User = &usr
		if appID != nil && *appID != uuid.Nil && projectName != nil && appType != nil {
			sr.App = &core.ClientSessionApp{ID: *appID, Name: core.AppDisplayName(*projectName, *appType)}
		}
		out = append(out, sr)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteExpiredClientSessions hard-deletes all expired client sessions for a workspace.
func (r *Repo) DeleteExpiredClientSessions(ctx context.Context, workspaceID uuid.UUID) (int64, error) {
	if workspaceID == uuid.Nil {
		return 0, nil
	}
	const q = `
DELETE FROM client_sessions cs
USING apps a, projects p
WHERE cs.app_id = a.id
  AND a.project_id = p.id
  AND p.workspace_id = $1
  AND cs.expires_at <= now();
`
	ct, err := r.db.Pool().Exec(ctx, q, workspaceID)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

// GetActiveClientSessionsByUserID returns all active (non-expired) sessions for a user.
func (r *Repo) GetActiveClientSessionsByUserID(ctx context.Context, userID uuid.UUID) ([]core.ClientSession, error) {
	const q = `
		select id, user_id, app_id, created_at, expires_at, last_seen_at, user_agent, ip
		from client_sessions
		where user_id = $1 and expires_at > now()
		order by last_seen_at desc
	`
	rows, err := r.db.Pool().Query(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.ClientSession
	for rows.Next() {
		var s core.ClientSession
		if err := rows.Scan(&s.ID, &s.UserID, &s.AppID, &s.CreatedAt, &s.ExpiresAt, &s.LastSeenAt, &s.UserAgent, &s.IP); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// DeleteClientSessionsByUserAndApp deletes all sessions for a user on a given app.
func (r *Repo) DeleteClientSessionsByUserAndApp(
	ctx context.Context,
	userID uuid.UUID,
	appID uuid.UUID,
) (int64, error) {
	if userID == uuid.Nil || appID == uuid.Nil {
		return 0, nil
	}
	const q = `
delete from client_sessions
where user_id = $1
  and app_id = $2;
`
	ct, err := r.db.Pool().Exec(ctx, q, userID, appID)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

// DeleteClientSessionsByUser deletes all sessions for a user,
// optionally excluding a specific session.
func (r *Repo) DeleteClientSessionsByUser(
	ctx context.Context,
	userID uuid.UUID,
	excludeSessionID *uuid.UUID,
) (int64, error) {
	if userID == uuid.Nil {
		return 0, nil
	}

	var q string
	var args []any

	if excludeSessionID != nil && *excludeSessionID != uuid.Nil {
		q = `delete from client_sessions where user_id = $1 and id != $2;`
		args = []any{userID, *excludeSessionID}
	} else {
		q = `delete from client_sessions where user_id = $1;`
		args = []any{userID}
	}

	ct, err := r.db.Pool().Exec(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}
