package repo

import (
	"context"
	"encoding/json"
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

// CreateOrganizationWithOwner creates an org AND seeds ownerID as an active
// owner member atomically (both inserts in one transaction). Slug collisions
// retry the whole transaction with a -2, -3 … suffix. Used by the server
// provisioning API so a failed owner-seed can never leave an ownerless org.
func (r *Repo) CreateOrganizationWithOwner(ctx context.Context, appID uuid.UUID, name, baseSlug string, ownerID uuid.UUID) (*core.Organization, error) {
	name = strings.TrimSpace(name)
	baseSlug = strings.TrimSpace(baseSlug)
	if appID == uuid.Nil || ownerID == uuid.Nil || name == "" {
		return nil, errors.New("invalid organization")
	}
	if baseSlug == "" {
		baseSlug = "org"
	}
	slug := baseSlug
	for attempt := 2; attempt < 100; attempt++ {
		org, err := r.createOrgWithOwnerOnce(ctx, appID, name, slug, ownerID)
		if err == nil {
			return org, nil
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// Only the org (app_id, slug) unique index can collide here (the
			// member row is for a brand-new org), so retry with a new slug.
			slug = fmt.Sprintf("%s-%d", baseSlug, attempt)
			continue
		}
		return nil, err
	}
	return nil, errors.New("could not allocate unique organization slug")
}

func (r *Repo) createOrgWithOwnerOnce(ctx context.Context, appID uuid.UUID, name, slug string, ownerID uuid.UUID) (*core.Organization, error) {
	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var o core.Organization
	if err := tx.QueryRow(ctx, `
INSERT INTO organizations (id, app_id, name, slug, status, created_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'active', $5, now(), now())
RETURNING id, app_id, name, slug, status, created_by, created_at, updated_at;`,
		utils.NewUUID(), appID, name, slug, ownerID,
	).Scan(&o.ID, &o.AppID, &o.Name, &o.Slug, &o.Status, &o.CreatedBy, &o.CreatedAt, &o.UpdatedAt); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO organization_members (id, org_id, user_id, org_role, status, joined_at)
VALUES ($1, $2, $3, 'owner', 'active', now());`,
		utils.NewUUID(), o.ID, ownerID,
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &o, nil
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

// UpdateOrganizationWithUniqueSlug renames an org and sets its slug, appending
// -2, -3 … to baseSlug on an (app_id, slug) collision with *another* org —
// mirroring CreateOrganizationWithUniqueSlug so a rename can never fail on a
// duplicate slug. Updating a row to its own current slug is not a collision, so
// renaming to the same name (or a name whose slug is unchanged) is idempotent
// and never grows a suffix. ErrNotFound if the org is missing.
func (r *Repo) UpdateOrganizationWithUniqueSlug(ctx context.Context, id uuid.UUID, name, baseSlug string) (*core.Organization, error) {
	name = strings.TrimSpace(name)
	baseSlug = strings.TrimSpace(baseSlug)
	if baseSlug == "" {
		baseSlug = "org"
	}
	slug := baseSlug
	for attempt := 2; attempt < 100; attempt++ {
		o, err := r.UpdateOrganization(ctx, id, name, slug)
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

// RestoreOrganization sets status='active' (inverse of ArchiveOrganization).
// Idempotent for an already-active org (the row still matches). ErrNotFound if
// the org no longer exists.
func (r *Repo) RestoreOrganization(ctx context.Context, id uuid.UUID) error {
	const q = `UPDATE organizations SET status = 'active', updated_at = now() WHERE id = $1;`
	ct, err := r.db.Pool().Exec(ctx, q, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteOrganization hard-deletes an org row. Members, member-roles and invites
// cascade (FK ON DELETE CASCADE); client_sessions.organization_id is set NULL.
// ErrNotFound if the org doesn't exist. Used by the server API when a consuming
// app deletes its tenant (the admin panel's archive is separate).
func (r *Repo) DeleteOrganization(ctx context.Context, id uuid.UUID) error {
	const q = `DELETE FROM organizations WHERE id = $1;`
	ct, err := r.db.Pool().Exec(ctx, q, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// OrgMemberRoleRef is a project (app RBAC) role assigned to an org membership,
// in the shape the member listings expose for display.
type OrgMemberRoleRef struct {
	ID   uuid.UUID `json:"id"`
	Slug string    `json:"slug"`
	Name string    `json:"name"`
}

// OrganizationMemberView is one member with their email, org tier, and the
// project roles assigned to that membership (Roles is the per-org RBAC the org
// tier owner/admin/member is distinct from). Roles is always non-nil.
type OrganizationMemberView struct {
	UserID  uuid.UUID          `json:"userId"`
	Email   string             `json:"email"`
	OrgRole string             `json:"orgRole"`
	Status  string             `json:"status"`
	Roles   []OrgMemberRoleRef `json:"roles"`
}

// ListOrganizationMembers returns all members of an org with their email, org
// tier, and the project roles assigned to each membership (so callers can show
// per-org RBAC, not just the owner/admin/member tier). Roles is always non-nil.
func (r *Repo) ListOrganizationMembers(ctx context.Context, orgID uuid.UUID) ([]OrganizationMemberView, error) {
	const q = `
SELECT m.user_id, u.email, m.org_role, m.status,
       COALESCE(
         (SELECT json_agg(json_build_object('id', rl.id, 'slug', rl.slug, 'name', rl.name) ORDER BY rl.name)
          FROM organization_member_roles mr
          JOIN roles rl ON rl.id = mr.role_id
          WHERE mr.member_id = m.id),
         '[]'
       ) AS roles
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
		var rolesJSON []byte
		if err := rows.Scan(&v.UserID, &v.Email, &v.OrgRole, &v.Status, &rolesJSON); err != nil {
			return nil, err
		}
		if len(rolesJSON) > 0 {
			if err := json.Unmarshal(rolesJSON, &v.Roles); err != nil {
				return nil, err
			}
		}
		if v.Roles == nil {
			v.Roles = []OrgMemberRoleRef{}
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

// CountActiveOrgsCreatedByUserInApp counts the active orgs a user created in an
// app. Drives the self-serve per-user creation cap (abuse guard).
func (r *Repo) CountActiveOrgsCreatedByUserInApp(ctx context.Context, appID, createdBy uuid.UUID) (int, error) {
	const q = `SELECT count(*) FROM organizations WHERE app_id = $1 AND created_by = $2 AND status = 'active';`
	return r.scalarCount(ctx, q, appID, createdBy)
}

// CountActiveOrgOwners counts active owner-tier members — drives the last-owner guard.
func (r *Repo) CountActiveOrgOwners(ctx context.Context, orgID uuid.UUID) (int, error) {
	const q = `SELECT count(*) FROM organization_members WHERE org_id = $1 AND org_role = 'owner' AND status = 'active';`
	return r.scalarCount(ctx, q, orgID)
}

// RemoveOrganizationMemberGuarded removes a member, refusing (ErrLastOwner) to
// remove the last active owner. The owner-count and the delete run in one
// transaction that first locks the organizations row FOR UPDATE, so concurrent
// guarded mutations on the same org serialize and the count can't go stale
// (fixes the TOCTOU where two concurrent removals each see 2 owners). Returns
// ErrNotFound if the membership doesn't exist.
func (r *Repo) RemoveOrganizationMemberGuarded(ctx context.Context, orgID, userID uuid.UUID) error {
	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Serialize all guarded member mutations for this org.
	var lockedOrg uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id = $1 FOR UPDATE`, orgID).Scan(&lockedOrg); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}

	var role, status string
	if err := tx.QueryRow(ctx, `SELECT org_role, status FROM organization_members WHERE org_id = $1 AND user_id = $2`, orgID, userID).Scan(&role, &status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}

	if role == core.OrgRoleOwner && status == core.OrgMemberStatusActive {
		var owners int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM organization_members WHERE org_id = $1 AND org_role = 'owner' AND status = 'active'`, orgID).Scan(&owners); err != nil {
			return err
		}
		if owners <= 1 {
			return ErrLastOwner
		}
	}

	if _, err := tx.Exec(ctx, `DELETE FROM organization_members WHERE org_id = $1 AND user_id = $2`, orgID, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SetOrganizationMemberRoleGuarded sets a member's tier, refusing (ErrLastOwner)
// to demote the last active owner. Same per-org serialization as
// RemoveOrganizationMemberGuarded. Returns ErrNotFound if the membership is missing.
func (r *Repo) SetOrganizationMemberRoleGuarded(ctx context.Context, orgID, userID uuid.UUID, newRole string) error {
	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var lockedOrg uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id = $1 FOR UPDATE`, orgID).Scan(&lockedOrg); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}

	var role, status string
	if err := tx.QueryRow(ctx, `SELECT org_role, status FROM organization_members WHERE org_id = $1 AND user_id = $2`, orgID, userID).Scan(&role, &status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}

	if role == core.OrgRoleOwner && newRole != core.OrgRoleOwner && status == core.OrgMemberStatusActive {
		var owners int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM organization_members WHERE org_id = $1 AND org_role = 'owner' AND status = 'active'`, orgID).Scan(&owners); err != nil {
			return err
		}
		if owners <= 1 {
			return ErrLastOwner
		}
	}

	if _, err := tx.Exec(ctx, `UPDATE organization_members SET org_role = $3 WHERE org_id = $1 AND user_id = $2`, orgID, userID, newRole); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// OrganizationAdminView is one org with its active-member count, for the admin
// org list. Includes archived orgs (status carries the state).
type OrganizationAdminView struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Status      string    `json:"status"`
	MemberCount int       `json:"memberCount"`
	CreatedAt   time.Time `json:"createdAt"`
}

// ListOrganizationsForApp returns every org in an app (active + archived) with a
// count of active members, newest first. Drives the admin Organizations page.
func (r *Repo) ListOrganizationsForApp(ctx context.Context, appID uuid.UUID) ([]OrganizationAdminView, error) {
	const q = `
SELECT o.id, o.name, o.slug, o.status, o.created_at,
       (SELECT count(*) FROM organization_members m
        WHERE m.org_id = o.id AND m.status = 'active') AS member_count
FROM organizations o
WHERE o.app_id = $1
ORDER BY o.created_at DESC;`
	rows, err := r.db.Pool().Query(ctx, q, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OrganizationAdminView
	for rows.Next() {
		var v OrganizationAdminView
		if err := rows.Scan(&v.ID, &v.Name, &v.Slug, &v.Status, &v.CreatedAt, &v.MemberCount); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// OrganizationInviteView is a pending invite with the inviter's email, for listing.
type OrganizationInviteView struct {
	ID             uuid.UUID `json:"id"`
	Email          string    `json:"email"`
	OrgRole        string    `json:"orgRole"`
	Status         string    `json:"status"`
	InvitedByEmail *string   `json:"invitedByEmail,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

// CreateOrganizationInvite inserts a pending invite. A 23505 on the
// (org_id, lower(email)) WHERE pending partial-unique index surfaces as
// ErrInvitePending. token_hash must be unique.
func (r *Repo) CreateOrganizationInvite(ctx context.Context, orgID uuid.UUID, email, orgRole string, roleIDs []uuid.UUID, invitedBy *uuid.UUID, tokenHash string, expiresAt time.Time) (*core.OrganizationInvite, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if orgRole == "" {
		orgRole = core.OrgRoleMember
	}
	if roleIDs == nil {
		roleIDs = []uuid.UUID{}
	}
	const q = `
INSERT INTO organization_invites (id, org_id, email, org_role, role_ids, invited_by, token_hash, status, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8, now())
RETURNING id, org_id, email, org_role, role_ids, invited_by, token_hash, status, expires_at, created_at, accepted_at;`
	var inv core.OrganizationInvite
	err := r.db.Pool().QueryRow(ctx, q, utils.NewUUID(), orgID, email, orgRole, roleIDs, invitedBy, tokenHash, expiresAt).Scan(
		&inv.ID, &inv.OrgID, &inv.Email, &inv.OrgRole, &inv.RoleIDs, &inv.InvitedBy, &inv.TokenHash, &inv.Status, &inv.ExpiresAt, &inv.CreatedAt, &inv.AcceptedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && strings.Contains(pgErr.ConstraintName, "uq_org_invites_pending") {
			return nil, ErrInvitePending
		}
		return nil, err
	}
	return &inv, nil
}

// GetOrganizationInviteByTokenHash returns an invite by its token hash, or ErrNotFound.
func (r *Repo) GetOrganizationInviteByTokenHash(ctx context.Context, tokenHash string) (*core.OrganizationInvite, error) {
	const q = `
SELECT id, org_id, email, org_role, role_ids, invited_by, token_hash, status, expires_at, created_at, accepted_at
FROM organization_invites WHERE token_hash = $1 LIMIT 1;`
	var inv core.OrganizationInvite
	if err := r.db.Pool().QueryRow(ctx, q, tokenHash).Scan(
		&inv.ID, &inv.OrgID, &inv.Email, &inv.OrgRole, &inv.RoleIDs, &inv.InvitedBy, &inv.TokenHash, &inv.Status, &inv.ExpiresAt, &inv.CreatedAt, &inv.AcceptedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &inv, nil
}

// ListPendingOrgInvites lists pending invites for an org, newest first, with inviter email.
func (r *Repo) ListPendingOrgInvites(ctx context.Context, orgID uuid.UUID) ([]OrganizationInviteView, error) {
	const q = `
SELECT i.id, i.email, i.org_role, i.status, u.email AS invited_by_email, i.created_at, i.expires_at
FROM organization_invites i
LEFT JOIN users u ON u.id = i.invited_by
WHERE i.org_id = $1 AND i.status = 'pending'
ORDER BY i.created_at DESC;`
	rows, err := r.db.Pool().Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OrganizationInviteView
	for rows.Next() {
		var v OrganizationInviteView
		if err := rows.Scan(&v.ID, &v.Email, &v.OrgRole, &v.Status, &v.InvitedByEmail, &v.CreatedAt, &v.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// RevokeOrganizationInvite marks a pending invite revoked. ErrNotFound if no
// pending invite of that org matched.
func (r *Repo) RevokeOrganizationInvite(ctx context.Context, orgID, inviteID uuid.UUID) error {
	const q = `UPDATE organization_invites SET status='revoked' WHERE id=$1 AND org_id=$2 AND status='pending';`
	ct, err := r.db.Pool().Exec(ctx, q, inviteID, orgID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AcceptOrganizationInviteTx accepts a pending invite for userID atomically:
// re-reads the invite FOR UPDATE, verifies it is still pending and unexpired,
// adds the org membership (idempotent) with the invite's tier + role_ids, and
// marks the invite accepted. Returns ErrNotFound if missing, or a typed error
// if not pending / expired.
func (r *Repo) AcceptOrganizationInviteTx(ctx context.Context, inviteID, userID uuid.UUID) error {
	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var orgID uuid.UUID
	var orgRole, status string
	var roleIDs []uuid.UUID
	var expiresAt time.Time
	err = tx.QueryRow(ctx, `SELECT org_id, org_role, role_ids, status, expires_at FROM organization_invites WHERE id=$1 FOR UPDATE`, inviteID).
		Scan(&orgID, &orgRole, &roleIDs, &status, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	switch status {
	case core.OrgInviteStatusPending:
		// ok, continue
	case core.OrgInviteStatusRevoked:
		return ErrInviteRevoked
	case core.OrgInviteStatusExpired:
		// Distinct from ErrInviteNotPending on purpose: the handler treats
		// ErrInviteNotPending as "already accepted → the invitee is a member,
		// sign them in", which is only safe for an 'accepted' invite. A stored
		// 'expired' status (e.g. from a future sweeper) never added a
		// membership, so it must fail the accept, not mint a session.
		return ErrInviteExpired
	case core.OrgInviteStatusAccepted:
		return ErrInviteNotPending
	default: // any other non-pending status — never sign in off it
		return ErrInviteNotPending
	}
	if time.Now().After(expiresAt) {
		return ErrInviteExpired
	}

	// Add membership (idempotent if already a member).
	memberID := utils.NewUUID()
	if _, err := tx.Exec(ctx, `
INSERT INTO organization_members (id, org_id, user_id, org_role, status, joined_at)
VALUES ($1, $2, $3, $4, 'active', now())
ON CONFLICT (org_id, user_id) DO NOTHING;`, memberID, orgID, userID, orgRole); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE organization_invites SET status='accepted', accepted_at=now() WHERE id=$1;`, inviteID); err != nil {
		return err
	}
	// Apply the invite's project roles to the membership. The create path
	// already validated these role_ids belong to the app's project, so we just
	// attach them. Resolve the real member id first (the INSERT above may have
	// hit ON CONFLICT and left memberID unused for a pre-existing member).
	// Additive (ON CONFLICT DO NOTHING) so re-processing the same invite is
	// idempotent and an existing member never loses roles. No-op when empty.
	if len(roleIDs) > 0 {
		var memberRowID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM organization_members WHERE org_id=$1 AND user_id=$2`, orgID, userID).Scan(&memberRowID); err != nil {
			return err
		}
		for _, rid := range roleIDs {
			if _, err := tx.Exec(ctx, `
INSERT INTO organization_member_roles (id, member_id, role_id, created_at)
VALUES ($1, $2, $3, now())
ON CONFLICT (member_id, role_id) DO NOTHING;`, utils.NewUUID(), memberRowID, rid); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

// CountRolesInProject returns how many of roleIDs belong to projectID. Callers
// assigning org-member project roles compare this to len(unique roleIDs) to
// reject ids that don't belong to the app's catalog.
func (r *Repo) CountRolesInProject(ctx context.Context, projectID uuid.UUID, roleIDs []uuid.UUID) (int, error) {
	if len(roleIDs) == 0 {
		return 0, nil
	}
	var n int
	err := r.db.Pool().QueryRow(ctx,
		`SELECT count(*) FROM roles WHERE project_id = $1 AND id = ANY($2::uuid[])`,
		projectID, roleIDs,
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}
