package repo

import (
	"context"
	"fmt"
	"strings"
	"time"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
)

// GetProjectMembers returns users who are members of at least one app
// in the given project. Membership is the app_users row, not the
// presence of any user_roles row, so members with zero roles still
// appear.
// - page is 0-based
// - email is optional substring match (case-insensitive)
// Returns: members, totalCount
func (r *Repo) GetProjectMembers(
	ctx context.Context,
	projectID uuid.UUID,
	page int,
	pageSize int,
	email string,
) ([]core.MemberResource, int, error) {
	if page < 0 {
		page = 0
	}
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 200 {
		pageSize = 200
	}
	offset := page * pageSize

	email = strings.TrimSpace(email)
	emailPattern := email
	if email != "" {
		emailPattern = "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(email) + "%"
	}

	const qCount = `
		select count(distinct u.id)
		from apps a
		join app_users au on au.app_id = a.id
		join users u on u.id = au.user_id
		where a.project_id = $1
		  and ($2 = '' or lower(u.email) like lower($2) escape '\')
	`
	var total int
	if err := r.db.Pool().QueryRow(ctx, qCount, projectID, emailPattern).Scan(&total); err != nil {
		return nil, 0, err
	}

	const q = `
		select distinct on (u.id)
			u.id,
			u.email,
			'' as name,
			u.enabled,
			u.email_verified_at,
			u.password_set_at,
			u.last_login_at,
			u.source,
			u.created_at
		from apps a
		join app_users au on au.app_id = a.id
		join users u on u.id = au.user_id
		where a.project_id = $1
		  and ($2 = '' or lower(u.email) like lower($2) escape '\')
		order by u.id, u.created_at asc
		limit $3 offset $4
	`

	rows, err := r.db.Pool().Query(ctx, q, projectID, emailPattern, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]core.MemberResource, 0, pageSize)
	for rows.Next() {
		var m core.MemberResource
		if err := rows.Scan(&m.UserID, &m.Email, &m.Name, &m.Enabled, &m.EmailVerifiedAt, &m.PasswordSetAt, &m.LastLoginAt, &m.Source, &m.AddedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return out, total, nil
}

// MemberEnabledFilter narrows the members list by users.enabled.
type MemberEnabledFilter string

const (
	MemberEnabledFilterAny      MemberEnabledFilter = ""
	MemberEnabledFilterEnabled  MemberEnabledFilter = "enabled"
	MemberEnabledFilterDisabled MemberEnabledFilter = "disabled"
)

// MemberRoleFilter narrows the members list by role assignment.
//
//   - Kind="" / RoleID=nil   : no filter (any role state, including none)
//   - Kind="without"         : members with no user_roles row in the app
//     (or project, when no app is specified)
//   - Kind="specific"        : members with a user_roles row whose
//     role_id matches RoleID
type MemberRoleFilter struct {
	Kind   string
	RoleID uuid.UUID
}

func (f MemberRoleFilter) Any() bool { return f.Kind == "" }

// GetProjectMembersByApp returns members of (project_id, app_id) when
// appID is non-nil, otherwise all members across the project's apps.
//   - page is 0-based
//   - email is optional substring match (case-insensitive)
//   - inactiveDays: if > 0, only return users whose last_login_at is older
//     than N days (or null). Powers the "inactive users" segment in the admin UI.
//   - enabledFilter: filter by users.enabled. "" = no filter.
//
// Returns: members, totalCount (distinct users)
func (r *Repo) GetProjectMembersByApp(
	ctx context.Context,
	projectID uuid.UUID,
	appID uuid.UUID,
	page int,
	pageSize int,
	email string,
	inactiveDays int,
	enabledFilter MemberEnabledFilter,
	roleFilter MemberRoleFilter,
) ([]core.MemberResource, int, error) {
	if page < 0 {
		page = 0
	}
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 200 {
		pageSize = 200
	}
	offset := page * pageSize

	email = strings.TrimSpace(email)
	emailPattern := email
	if email != "" {
		emailPattern = "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(email) + "%"
	}

	hasApp := appID != uuid.Nil

	var appFilter, emailParam, limitParam, offsetParam string
	var countArgs, queryArgs []any

	if hasApp {
		appFilter = "and au.app_id = $2"
		emailParam = "$3"
		limitParam = "$4"
		offsetParam = "$5"
		countArgs = []any{projectID, appID, emailPattern}
		queryArgs = []any{projectID, appID, emailPattern, pageSize, offset}
	} else {
		appFilter = ""
		emailParam = "$2"
		limitParam = "$3"
		offsetParam = "$4"
		countArgs = []any{projectID, emailPattern}
		queryArgs = []any{projectID, emailPattern, pageSize, offset}
	}

	var countInactiveFilter, queryInactiveFilter string
	if inactiveDays > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -inactiveDays)
		countArgs = append(countArgs, cutoff)
		queryArgs = append(queryArgs, cutoff)
		countInactiveFilter = fmt.Sprintf("and (u.last_login_at is null or u.last_login_at < $%d)", len(countArgs))
		queryInactiveFilter = fmt.Sprintf("and (u.last_login_at is null or u.last_login_at < $%d)", len(queryArgs))
	}

	var enabledClause string
	switch enabledFilter {
	case MemberEnabledFilterEnabled:
		enabledClause = "and u.enabled = true"
	case MemberEnabledFilterDisabled:
		enabledClause = "and u.enabled = false"
	}

	// Role filter. App-scoped when appID is set, otherwise project-scoped.
	// "without" needs no extra arg; "specific" appends the role UUID and
	// builds separate count/query clauses since the data query has extra
	// args (limit/offset) so positional indexes diverge.
	var countRoleClause, queryRoleClause string
	switch roleFilter.Kind {
	case "without":
		if hasApp {
			clause := "and not exists (select 1 from user_roles ur where ur.user_id = u.id and ur.app_id = au.app_id)"
			countRoleClause = clause
			queryRoleClause = clause
		} else {
			clause := "and not exists (select 1 from user_roles ur where ur.user_id = u.id and ur.app_id in (select id from apps where project_id = $1))"
			countRoleClause = clause
			queryRoleClause = clause
		}
	case "specific":
		countArgs = append(countArgs, roleFilter.RoleID)
		queryArgs = append(queryArgs, roleFilter.RoleID)
		if hasApp {
			countRoleClause = fmt.Sprintf("and exists (select 1 from user_roles ur where ur.user_id = u.id and ur.app_id = au.app_id and ur.role_id = $%d)", len(countArgs))
			queryRoleClause = fmt.Sprintf("and exists (select 1 from user_roles ur where ur.user_id = u.id and ur.app_id = au.app_id and ur.role_id = $%d)", len(queryArgs))
		} else {
			countRoleClause = fmt.Sprintf("and exists (select 1 from user_roles ur where ur.user_id = u.id and ur.app_id in (select id from apps where project_id = $1) and ur.role_id = $%d)", len(countArgs))
			queryRoleClause = fmt.Sprintf("and exists (select 1 from user_roles ur where ur.user_id = u.id and ur.app_id in (select id from apps where project_id = $1) and ur.role_id = $%d)", len(queryArgs))
		}
	}

	qCount := fmt.Sprintf(`
		select count(distinct u.id)
		from apps a
		join app_users au on au.app_id = a.id %s
		join users u on u.id = au.user_id
		where a.project_id = $1
		  and (%s = '' or lower(u.email) like lower(%s) escape '\')
		  %s
		  %s
		  %s
	`, appFilter, emailParam, emailParam, countInactiveFilter, enabledClause, countRoleClause)

	var total int
	if err := r.db.Pool().QueryRow(ctx, qCount, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := fmt.Sprintf(`
		select distinct on (u.id)
			u.id,
			u.email,
			'' as name,
			u.enabled,
			u.email_verified_at,
			u.password_set_at,
			u.last_login_at,
			u.source,
			u.created_at
		from apps a
		join app_users au on au.app_id = a.id %s
		join users u on u.id = au.user_id
		where a.project_id = $1
		  and (%s = '' or lower(u.email) like lower(%s) escape '\')
		  %s
		  %s
		  %s
		order by u.id, u.created_at asc
		limit %s offset %s
	`, appFilter, emailParam, emailParam, queryInactiveFilter, enabledClause, queryRoleClause, limitParam, offsetParam)

	rows, err := r.db.Pool().Query(ctx, q, queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]core.MemberResource, 0, pageSize)
	for rows.Next() {
		var m core.MemberResource
		if err := rows.Scan(&m.UserID, &m.Email, &m.Name, &m.Enabled, &m.EmailVerifiedAt, &m.PasswordSetAt, &m.LastLoginAt, &m.Source, &m.AddedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return out, total, nil
}
