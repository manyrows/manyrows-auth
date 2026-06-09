package api

import (
	"net/http"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
)

// auditOrg records an organization management action to auth_logs. The
// workspace and actor are derived from the request context: an admin
// account → admin actor; an API key → api_key actor; otherwise self
// (end-user self-serve). targetUserID is the affected member for member.*
// events (nil for org-level events). Best-effort, like every audit write.
func (h *RequestHandler) auditOrg(r *http.Request, event core.AuthLogEvent, org *core.Organization, targetUserID *uuid.UUID) {
	if org == nil {
		return
	}
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		return
	}
	appID := org.AppID
	in := AuthLogInput{
		WorkspaceID:   ws.ID,
		AppID:         &appID,
		Event:         event,
		Outcome:       core.AuthOutcomeSuccess,
		SubjectUserID: targetUserID,
		Metadata:      core.OrganizationMetadata{OrgID: org.ID, OrgName: org.Name, OrgSlug: org.Slug},
	}
	if acc, ok := core.AdminAccountFromContext(r.Context()); ok && acc != nil {
		in.ActorType = core.AuthActorAdmin
		in.ActorAccountID = &acc.ID
		in.ActorLabel = acc.Email
	} else if key, ok := core.APIKeyFromContext(r.Context()); ok && key != nil {
		in.ActorType = core.AuthActorAPIKey
		in.ActorAPIKeyID = &key.ID
		in.ActorLabel = key.Name
	} else {
		in.ActorType = core.AuthActorSelf
	}
	h.writeAuthLogFromRequest(r, in)
}
