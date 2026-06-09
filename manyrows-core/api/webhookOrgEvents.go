package api

import (
	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
)

// Organization webhook event names. Kept as constants so the dispatch
// sites and the validWebhookEvents allowlist can't drift apart.
const (
	whOrgCreated    = "organization.created"
	whOrgUpdated    = "organization.updated"
	whOrgArchived   = "organization.archived"
	whOrgUnarchived = "organization.unarchived"
	whOrgDeleted    = "organization.deleted"

	whOrgMemberAdded   = "organization.member_added"
	whOrgMemberRemoved = "organization.member_removed"
	whOrgMemberUpdated = "organization.member_updated"

	whOrgInviteCreated  = "organization.invite_created"
	whOrgInviteAccepted = "organization.invite_accepted"
	whOrgInviteRevoked  = "organization.invite_revoked"
)

// dispatchOrgLifecycleEvent fires an organization.* lifecycle webhook for
// the org's app. Org webhooks are emitted from every surface that mutates
// orgs (admin dashboard, server API, end-user self-serve) so a subscriber
// sees the change regardless of what triggered it.
func (h *RequestHandler) dispatchOrgLifecycleEvent(event string, org *core.Organization) {
	if org == nil || org.AppID == uuid.Nil {
		return
	}
	h.dispatchWebhook(org.AppID, event, map[string]any{
		"appId":   org.AppID,
		"orgId":   org.ID,
		"orgSlug": org.Slug,
		"orgName": org.Name,
	})
}

// dispatchOrgMemberEvent fires an organization.member_* webhook.
func (h *RequestHandler) dispatchOrgMemberEvent(event string, appID, orgID, userID uuid.UUID) {
	if appID == uuid.Nil {
		return
	}
	h.dispatchWebhook(appID, event, map[string]any{
		"appId":  appID,
		"orgId":  orgID,
		"userId": userID,
	})
}

// dispatchOrgInviteEvent fires an organization.invite_* webhook.
func (h *RequestHandler) dispatchOrgInviteEvent(event string, appID, orgID uuid.UUID, email string) {
	if appID == uuid.Nil {
		return
	}
	h.dispatchWebhook(appID, event, map[string]any{
		"appId": appID,
		"orgId": orgID,
		"email": email,
	})
}
