package api

import "testing"

// The org/member/invite lifecycle events must be subscribable (in the
// allowlist) so backends can react to tenant changes — not just user.* events.
func TestValidateWebhookEvents_OrgAndSecurityEvents(t *testing.T) {
	events := []string{
		"organization.created",
		"organization.updated",
		"organization.archived",
		"organization.unarchived",
		"organization.deleted",
		"organization.member_added",
		"organization.member_removed",
		"organization.member_updated",
		"organization.invite_created",
		"organization.invite_accepted",
		"organization.invite_revoked",
	}
	for _, e := range events {
		if !validateWebhookEvents([]string{e}) {
			t.Errorf("event %q should be a valid (subscribable) webhook event", e)
		}
	}
	// Sanity: an unknown event is still rejected, and the existing user.*
	// events still validate.
	if validateWebhookEvents([]string{"organization.bogus"}) {
		t.Error("unknown event must be rejected")
	}
	if !validateWebhookEvents([]string{"user.login"}) {
		t.Error("existing user.login event must remain valid")
	}
}
