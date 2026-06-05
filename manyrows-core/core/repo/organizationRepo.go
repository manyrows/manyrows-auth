package repo

import (
	"context"
	"errors"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// CreateOrganization inserts an org under an app and returns the row.
func (r *Repo) CreateOrganization(ctx context.Context, appID uuid.UUID, name, slug string, createdBy *uuid.UUID) (*core.Organization, error) {
	name = strings.TrimSpace(name)
	slug = strings.TrimSpace(slug)
	if appID == uuid.Nil || name == "" || slug == "" {
		return nil, errors.New("invalid organization")
	}
	id := utils.NewUUID()
	const q = `
INSERT INTO organizations (id, app_id, name, slug, status, created_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'active', $5, now(), now())
RETURNING id, app_id, name, slug, status, created_by, created_at, updated_at;
`
	var o core.Organization
	if err := r.db.Pool().QueryRow(ctx, q, id, appID, name, slug, createdBy).Scan(
		&o.ID, &o.AppID, &o.Name, &o.Slug, &o.Status, &o.CreatedBy, &o.CreatedAt, &o.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &o, nil
}

// GetOrganizationByID returns an org by id, or ErrNotFound.
func (r *Repo) GetOrganizationByID(ctx context.Context, id uuid.UUID) (*core.Organization, error) {
	const q = `
SELECT id, app_id, name, slug, status, created_by, created_at, updated_at
FROM organizations WHERE id = $1 LIMIT 1;
`
	var o core.Organization
	if err := r.db.Pool().QueryRow(ctx, q, id).Scan(
		&o.ID, &o.AppID, &o.Name, &o.Slug, &o.Status, &o.CreatedBy, &o.CreatedAt, &o.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &o, nil
}

// AddOrganizationMember inserts a membership with the given tier and returns it.
func (r *Repo) AddOrganizationMember(ctx context.Context, orgID, userID uuid.UUID, orgRole string) (*core.OrganizationMember, error) {
	if orgID == uuid.Nil || userID == uuid.Nil {
		return nil, errors.New("invalid membership")
	}
	if orgRole == "" {
		orgRole = core.OrgRoleMember
	}
	id := utils.NewUUID()
	const q = `
INSERT INTO organization_members (id, org_id, user_id, org_role, status, joined_at)
VALUES ($1, $2, $3, $4, 'active', now())
RETURNING id, org_id, user_id, org_role, status, joined_at;
`
	var m core.OrganizationMember
	if err := r.db.Pool().QueryRow(ctx, q, id, orgID, userID, orgRole).Scan(
		&m.ID, &m.OrgID, &m.UserID, &m.OrgRole, &m.Status, &m.JoinedAt,
	); err != nil {
		return nil, err
	}
	return &m, nil
}

// GetOrganizationMember returns the membership for (org, user), or ErrNotFound.
func (r *Repo) GetOrganizationMember(ctx context.Context, orgID, userID uuid.UUID) (*core.OrganizationMember, error) {
	const q = `
SELECT id, org_id, user_id, org_role, status, joined_at
FROM organization_members
WHERE org_id = $1 AND user_id = $2
LIMIT 1;
`
	var m core.OrganizationMember
	if err := r.db.Pool().QueryRow(ctx, q, orgID, userID).Scan(
		&m.ID, &m.OrgID, &m.UserID, &m.OrgRole, &m.Status, &m.JoinedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &m, nil
}

// SetOrganizationMemberRoles replaces a membership's project-role assignment
// with exactly roleIDs (delete-then-insert in one transaction).
func (r *Repo) SetOrganizationMemberRoles(ctx context.Context, memberID uuid.UUID, roleIDs []uuid.UUID) error {
	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM organization_member_roles WHERE member_id = $1;`, memberID); err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, rid := range roleIDs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO organization_member_roles (id, member_id, role_id, created_at) VALUES ($1, $2, $3, $4);`,
			utils.NewUUID(), memberID, rid, now,
		); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// GetOrgMemberRoleIDs returns the project-role IDs assigned to a membership.
func (r *Repo) GetOrgMemberRoleIDs(ctx context.Context, memberID uuid.UUID) ([]uuid.UUID, error) {
	const q = `SELECT role_id FROM organization_member_roles WHERE member_id = $1;`
	rows, err := r.db.Pool().Query(ctx, q, memberID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ListOrganizationsForUserInApp returns the active orgs a user belongs to in an
// app, with the user's tier in each. Drives the client org switcher.
func (r *Repo) ListOrganizationsForUserInApp(ctx context.Context, appID, userID uuid.UUID) ([]core.OrganizationMembershipView, error) {
	const q = `
SELECT o.id, o.name, o.slug, m.org_role
FROM organization_members m
JOIN organizations o ON o.id = m.org_id
WHERE o.app_id = $1 AND m.user_id = $2 AND m.status = 'active' AND o.status = 'active'
ORDER BY o.name ASC;
`
	rows, err := r.db.Pool().Query(ctx, q, appID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.OrganizationMembershipView
	for rows.Next() {
		var v core.OrganizationMembershipView
		if err := rows.Scan(&v.ID, &v.Name, &v.Slug, &v.OrgRole); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
