package repo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// CreateOrganizationWithUniqueSlug creates an org, appending -2, -3 … to the
// slug on (app_id, slug) collision. The server API derives slugs from a display
// name that may repeat, so creation must not fail on a duplicate name.
func (r *Repo) CreateOrganizationWithUniqueSlug(ctx context.Context, appID uuid.UUID, name, baseSlug string, createdBy *uuid.UUID) (*core.Organization, error) {
	baseSlug = strings.TrimSpace(baseSlug)
	if baseSlug == "" {
		baseSlug = "org"
	}
	slug := baseSlug
	for attempt := 2; attempt < 100; attempt++ {
		o, err := r.CreateOrganization(ctx, appID, name, slug, createdBy)
		if err == nil {
			return o, nil
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
			return nil, err
		}
		slug = fmt.Sprintf("%s-%d", baseSlug, attempt)
	}
	return nil, errors.New("could not allocate unique organization slug")
}

// UpdateOrganization renames/re-slugs an org. ErrNotFound if missing. A slug
// collision surfaces as a 23505 pgconn error for the caller to map to 409.
func (r *Repo) UpdateOrganization(ctx context.Context, id uuid.UUID, name, slug string) (*core.Organization, error) {
	const q = `
UPDATE organizations SET name = $2, slug = $3, updated_at = now()
WHERE id = $1
RETURNING id, app_id, name, slug, status, created_by, created_at, updated_at;`
	var o core.Organization
	if err := r.db.Pool().QueryRow(ctx, q, id, name, slug).Scan(
		&o.ID, &o.AppID, &o.Name, &o.Slug, &o.Status, &o.CreatedBy, &o.CreatedAt, &o.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &o, nil
}

// ArchiveOrganization sets status='archived'. ErrNotFound if missing.
func (r *Repo) ArchiveOrganization(ctx context.Context, id uuid.UUID) error {
	const q = `UPDATE organizations SET status = 'archived', updated_at = now() WHERE id = $1;`
	ct, err := r.db.Pool().Exec(ctx, q, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// OrganizationMemberView is one member with their email + tier, for admin listing.
type OrganizationMemberView struct {
	UserID  uuid.UUID `json:"userId"`
	Email   string    `json:"email"`
	OrgRole string    `json:"orgRole"`
	Status  string    `json:"status"`
}

// ListOrganizationMembers returns all members of an org with their email + tier.
func (r *Repo) ListOrganizationMembers(ctx context.Context, orgID uuid.UUID) ([]OrganizationMemberView, error) {
	const q = `
SELECT m.user_id, u.email, m.org_role, m.status
FROM organization_members m
JOIN users u ON u.id = m.user_id
WHERE m.org_id = $1
ORDER BY u.email ASC;`
	rows, err := r.db.Pool().Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OrganizationMemberView
	for rows.Next() {
		var v OrganizationMemberView
		if err := rows.Scan(&v.UserID, &v.Email, &v.OrgRole, &v.Status); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// SetOrganizationMemberRole updates a member's tier. ErrNotFound if no such member.
func (r *Repo) SetOrganizationMemberRole(ctx context.Context, orgID, userID uuid.UUID, orgRole string) error {
	const q = `UPDATE organization_members SET org_role = $3 WHERE org_id = $1 AND user_id = $2;`
	return r.execAffectingOne(ctx, ErrNotFound, q, orgID, userID, orgRole)
}

// RemoveOrganizationMember deletes a membership. ErrNotFound if no such member.
func (r *Repo) RemoveOrganizationMember(ctx context.Context, orgID, userID uuid.UUID) error {
	const q = `DELETE FROM organization_members WHERE org_id = $1 AND user_id = $2;`
	return r.execAffectingOne(ctx, ErrNotFound, q, orgID, userID)
}

// CountActiveOrgOwners counts active owner-tier members — drives the last-owner guard.
func (r *Repo) CountActiveOrgOwners(ctx context.Context, orgID uuid.UUID) (int, error) {
	const q = `SELECT count(*) FROM organization_members WHERE org_id = $1 AND org_role = 'owner' AND status = 'active';`
	return r.scalarCount(ctx, q, orgID)
}
