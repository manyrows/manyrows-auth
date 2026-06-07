package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

// Org membership tiers (decision C: fixed system tier gating org management;
// project roles drive in-app feature authz). Ordered owner > admin > member.
const (
	OrgRoleOwner  = "owner"
	OrgRoleAdmin  = "admin"
	OrgRoleMember = "member"
)

// Organization status.
const (
	OrgStatusActive   = "active"
	OrgStatusArchived = "archived"
)

// Organization membership status.
const (
	OrgMemberStatusActive   = "active"
	OrgMemberStatusPending  = "pending"
	OrgMemberStatusDisabled = "disabled"
)

// Per-app org creation policy (apps.org_creation_policy).
const (
	OrgCreationSelfServe  = "self_serve"
	OrgCreationInviteOnly = "invite_only"
	OrgCreationAdminOnly  = "admin_only"
)

// Organization invite status.
const (
	OrgInviteStatusPending  = "pending"
	OrgInviteStatusAccepted = "accepted"
	OrgInviteStatusRevoked  = "revoked"
	OrgInviteStatusExpired  = "expired"
)

// Organization is a tenant inside an app's end-user base.
type Organization struct {
	ID        uuid.UUID  `db:"id" json:"id"`
	AppID     uuid.UUID  `db:"app_id" json:"appId"`
	Name      string     `db:"name" json:"name"`
	Slug      string     `db:"slug" json:"slug"`
	Status    string     `db:"status" json:"status"`
	CreatedBy *uuid.UUID `db:"created_by" json:"createdBy,omitempty"`
	CreatedAt time.Time  `db:"created_at" json:"createdAt"`
	UpdatedAt time.Time  `db:"updated_at" json:"updatedAt"`
}

// OrganizationMember is one user's membership in one org, with the system tier.
type OrganizationMember struct {
	ID       uuid.UUID `db:"id" json:"id"`
	OrgID    uuid.UUID `db:"org_id" json:"orgId"`
	UserID   uuid.UUID `db:"user_id" json:"userId"`
	OrgRole  string    `db:"org_role" json:"orgRole"`
	Status   string    `db:"status" json:"status"`
	JoinedAt time.Time `db:"joined_at" json:"joinedAt"`
}

// OrganizationMemberRole assigns a project role to a membership.
type OrganizationMemberRole struct {
	ID        uuid.UUID `db:"id" json:"id"`
	MemberID  uuid.UUID `db:"member_id" json:"memberId"`
	RoleID    uuid.UUID `db:"role_id" json:"roleId"`
	CreatedAt time.Time `db:"created_at" json:"createdAt"`
}

// OrganizationInvite is a pending invitation to join an org (used by Plan 2).
type OrganizationInvite struct {
	ID         uuid.UUID   `db:"id" json:"id"`
	OrgID      uuid.UUID   `db:"org_id" json:"orgId"`
	Email      string      `db:"email" json:"email"`
	OrgRole    string      `db:"org_role" json:"orgRole"`
	RoleIDs    []uuid.UUID `db:"role_ids" json:"roleIds"`
	InvitedBy  *uuid.UUID  `db:"invited_by" json:"invitedBy,omitempty"`
	TokenHash  string      `db:"token_hash" json:"-"`
	Status     string      `db:"status" json:"status"`
	ExpiresAt  time.Time   `db:"expires_at" json:"expiresAt"`
	CreatedAt  time.Time   `db:"created_at" json:"createdAt"`
	AcceptedAt *time.Time  `db:"accepted_at" json:"acceptedAt,omitempty"`
}

// OrganizationMembershipView is the per-org summary returned to clients for the
// org switcher: which orgs a user belongs to and their tier in each.
type OrganizationMembershipView struct {
	ID      uuid.UUID `json:"id"`
	Name    string    `json:"name"`
	Slug    string    `json:"slug"`
	OrgRole string    `json:"orgRole"`
}
