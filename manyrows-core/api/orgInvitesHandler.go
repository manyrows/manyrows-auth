package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/email"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

const orgInviteTTL = 7 * 24 * time.Hour

type createOrgInviteRequest struct {
	Email           string      `json:"email"`
	OrgRole         string      `json:"orgRole"`
	RoleIDs         []uuid.UUID `json:"roleIds"`
	InvitedByUserID *uuid.UUID  `json:"invitedByUserId"`
}

type orgInviteResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	OrgRole   string `json:"orgRole"`
	Status    string `json:"status"`
	CreatedAt string `json:"createdAt"`
	ExpiresAt string `json:"expiresAt"`
}

var (
	errOrgInviteAppURLMissing = errors.New("org invite: app url required")
	errOrgInviteMemberExists  = errors.New("org invite: already an active member")
	errOrgInviteEmailFailed   = errors.New("org invite: email send failed")
)

// createAndEmailOrgInvite creates a pending invite and emails the accept link,
// rolling the invite back if the email fails. Shared by the server-API and
// client self-serve invite handlers.
func (handler *RequestHandler) createAndEmailOrgInvite(
	ctx context.Context, app *core.App, ws *core.Workspace, org *core.Organization,
	emailAddr, orgRole string, roleIDs []uuid.UUID, invitedBy *uuid.UUID,
) (*core.OrganizationInvite, error) {
	if app.AppURL == nil || strings.TrimSpace(*app.AppURL) == "" {
		return nil, errOrgInviteAppURLMissing
	}
	if existing, _ := handler.repo.GetUserByEmail(ctx, emailAddr, app); existing != nil {
		if m, _ := handler.repo.GetOrganizationMember(ctx, org.ID, existing.ID); m != nil && m.Status == core.OrgMemberStatusActive {
			return nil, errOrgInviteMemberExists
		}
	}
	rawToken, tokenHash, err := handler.adminAuthService.NewMagicToken()
	if err != nil {
		return nil, err
	}
	inv, err := handler.repo.CreateOrganizationInvite(ctx, org.ID, emailAddr, orgRole, roleIDs, invitedBy, tokenHash, time.Now().UTC().Add(orgInviteTTL))
	if err != nil {
		return nil, err // may be repo.ErrInvitePending
	}
	acceptLink := buildOrgInviteAcceptURL(handler.AppBaseURL(app), ws.Slug, app.ID, rawToken)
	msg := email.BuildOrgInviteEmail("en", emailAddr, email.WorkspaceFrom(app.DisplayName()), app.DisplayName(), org.Name, acceptLink)
	if sendErr := handler.sendWorkspaceEmail(ctx, app.WorkspaceID, msg); sendErr != nil {
		_ = handler.repo.RevokeOrganizationInvite(ctx, org.ID, inv.ID)
		return nil, errOrgInviteEmailFailed
	}
	return inv, nil
}

// ServerCreateOrgInvite: POST /v1/apps/{appId}/organizations/{orgId}/invites
func (handler *RequestHandler) ServerCreateOrgInvite(w http.ResponseWriter, r *http.Request) {
	app, org, ok := handler.serverOrgFromURL(w, r)
	if !ok {
		return
	}
	var req createOrgInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	emailAddr := strings.TrimSpace(strings.ToLower(req.Email))
	if emailAddr == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	orgRole := strings.TrimSpace(req.OrgRole)
	if orgRole == "" {
		orgRole = core.OrgRoleAdmin
	}
	if !validOrgRole(orgRole) {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	ws, _ := core.WorkspaceFromContext(r.Context())
	inv, err := handler.createAndEmailOrgInvite(r.Context(), app, ws, org, emailAddr, orgRole, req.RoleIDs, req.InvitedByUserID)
	if err != nil {
		switch {
		case errors.Is(err, errOrgInviteAppURLMissing):
			WriteError(w, r, "error.appUrlRequired", http.StatusBadRequest)
		case errors.Is(err, errOrgInviteMemberExists):
			WriteError(w, r, "error.conflict", http.StatusConflict)
		case errors.Is(err, repo.ErrInvitePending):
			WriteError(w, r, "error.invitePending", http.StatusConflict)
		case errors.Is(err, errOrgInviteEmailFailed):
			WriteError(w, r, "error.inviteEmailFailed", http.StatusInternalServerError)
		default:
			log.Err(err).Msg("ServerCreateOrgInvite failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		}
		return
	}
	utils.WriteJsonWithStatusCode(w, orgInviteResponse{
		ID: inv.ID.String(), Email: inv.Email, OrgRole: inv.OrgRole, Status: inv.Status,
		CreatedAt: inv.CreatedAt.Format(time.RFC3339), ExpiresAt: inv.ExpiresAt.Format(time.RFC3339),
	}, http.StatusCreated)
}

type orgInvitesListResponse struct {
	Invites []orgInviteListItem `json:"invites"`
}
type orgInviteListItem struct {
	ID             string  `json:"id"`
	Email          string  `json:"email"`
	OrgRole        string  `json:"orgRole"`
	Status         string  `json:"status"`
	InvitedByEmail *string `json:"invitedByEmail,omitempty"`
	CreatedAt      string  `json:"createdAt"`
	ExpiresAt      string  `json:"expiresAt"`
}

// ServerListOrgInvites: GET …/invites (pending only)
func (handler *RequestHandler) ServerListOrgInvites(w http.ResponseWriter, r *http.Request) {
	_, org, ok := handler.serverOrgFromURL(w, r)
	if !ok {
		return
	}
	views, err := handler.repo.ListPendingOrgInvites(r.Context(), org.ID)
	if err != nil {
		log.Err(err).Msg("ServerListOrgInvites failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	out := orgInvitesListResponse{Invites: make([]orgInviteListItem, 0, len(views))}
	for _, v := range views {
		out.Invites = append(out.Invites, orgInviteListItem{
			ID: v.ID.String(), Email: v.Email, OrgRole: v.OrgRole, Status: v.Status,
			InvitedByEmail: v.InvitedByEmail, CreatedAt: v.CreatedAt.Format(time.RFC3339), ExpiresAt: v.ExpiresAt.Format(time.RFC3339),
		})
	}
	utils.WriteJsonWithStatusCode(w, out, http.StatusOK)
}

// ServerRevokeOrgInvite: DELETE …/invites/{inviteId}
func (handler *RequestHandler) ServerRevokeOrgInvite(w http.ResponseWriter, r *http.Request) {
	_, org, ok := handler.serverOrgFromURL(w, r)
	if !ok {
		return
	}
	inviteID, err := utils.GetPathUUID("inviteId", r)
	if err != nil || inviteID == uuid.Nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if err := handler.repo.RevokeOrganizationInvite(r.Context(), org.ID, inviteID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerRevokeOrgInvite failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// buildOrgInviteAcceptURL builds the public accept link (lands on the auth server).
func buildOrgInviteAcceptURL(baseURL, workspaceSlug string, appID uuid.UUID, token string) string {
	baseURL = strings.TrimRight(baseURL, "/")
	return baseURL + "/x/" + workspaceSlug + "/apps/" + appID.String() + "/auth/org-invite?token=" + token
}

// AcceptOrgInvite: GET /x/{workspaceSlug}/apps/{appId}/auth/org-invite?token=
// Public (no API key). Validates the invite token, onboards the invitee
// (bypassing AllowRegistration — an invite is explicit consent, scoped only to
// the invited email), adds the org membership, marks the invite accepted, and
// signs the invitee in by reusing the shared magic-link sign-in tail (so 2FA is
// still enforced). On any validation failure it redirects to the app URL with
// mr_invite_error=<code> (or 400 error.invalidInvite if no app URL is set).
func (handler *RequestHandler) AcceptOrgInvite(w http.ResponseWriter, r *http.Request) {
	ws, wsOk := core.WorkspaceFromContext(r.Context())
	app, appOk := core.AppFromContext(r.Context())
	if !wsOk || ws == nil || !appOk || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	appURL := ""
	if app.AppURL != nil {
		appURL = strings.TrimSpace(*app.AppURL)
	}
	// On any failure: bounce to the app URL with mr_invite_error so AppKit can
	// surface it. With no app URL configured there is nowhere to bounce, so we
	// emit a plain 400.
	failRedirect := func(code string) {
		if appURL == "" {
			WriteError(w, r, "error.invalidInvite", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, appendFragment(appURL, "mr_invite_error="+url.QueryEscape(code)), http.StatusFound)
	}

	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		failRedirect("invalid_token")
		return
	}

	inv, err := handler.repo.GetOrganizationInviteByTokenHash(r.Context(), handler.adminAuthService.HashMagicToken(token))
	if err != nil || inv == nil {
		failRedirect("invalid_token")
		return
	}
	if inv.Status != core.OrgInviteStatusPending || time.Now().After(inv.ExpiresAt) {
		failRedirect("invite_expired")
		return
	}

	// Confirm the invite's org belongs to this app and is active. Guards
	// against a token leaking across apps and against accepting into a
	// suspended/deleted org.
	org, err := handler.repo.GetOrganizationByID(r.Context(), inv.OrgID)
	if err != nil || org == nil || org.AppID != app.ID || org.Status != core.OrgStatusActive {
		failRedirect("invalid_token")
		return
	}

	// Onboard the invitee, bypassing AllowRegistration — the invite IS the
	// consent, and it is scoped to exactly inv.Email (not arbitrary signups).
	user, created, err := handler.repo.GetOrCreateUser(r.Context(), inv.Email, app, core.UserSourceInvited)
	if err != nil {
		log.Err(err).Msg("AcceptOrgInvite: GetOrCreateUser failed")
		failRedirect("server_error")
		return
	}
	appMember, _, err := handler.repo.EnsureAppMember(r.Context(), app.ID, user.ID, core.UserSourceInvited)
	if err != nil {
		log.Err(err).Msg("AcceptOrgInvite: EnsureAppMember failed")
		failRedirect("server_error")
		return
	}
	// Uphold app-level suspension. EnsureAppMember leaves a pre-existing
	// disabled membership disabled (ON CONFLICT DO NOTHING), so a suspended
	// (app_users.status='disabled') member reaches here. Every other sign-in
	// path refuses such a member via ResolveSignInIdentity (ErrAppUserDisabled);
	// the invite path must too, or an org invite becomes a backdoor around an
	// app-level suspension. Refuse BEFORE adding the org membership or minting a
	// session (fail closed if the row is somehow missing); the invite stays
	// pending so it can be accepted once the suspension is lifted.
	if appMember == nil || !appMember.IsActive() {
		failRedirect("account_disabled")
		return
	}
	if !user.IsEmailVerified() {
		if verr := handler.repo.SetUserEmailVerified(r.Context(), user.ID, time.Now().UTC()); verr != nil {
			log.Err(verr).Msg("AcceptOrgInvite: SetUserEmailVerified failed")
		}
	}

	// Add the org membership + mark the invite accepted (atomic). The tx re-reads
	// the invite FOR UPDATE, so a revoke/expiry landing in the race window after
	// the pre-check above is caught here. Only an already-ACCEPTED invite (the
	// invitee IS a member) may fall through to sign-in; a revoked/expired invite
	// must NEVER mint a session.
	if err := handler.repo.AcceptOrganizationInviteTx(r.Context(), inv.ID, user.ID); err != nil {
		switch {
		case errors.Is(err, repo.ErrInviteNotPending):
			// Already accepted (e.g. a concurrent double-click of the same
			// link) — the invitee is already a member; fall through and sign
			// them in.
		case errors.Is(err, repo.ErrInviteRevoked):
			failRedirect("invite_revoked")
			return
		case errors.Is(err, repo.ErrInviteExpired):
			failRedirect("invite_expired")
			return
		case errors.Is(err, repo.ErrNotFound):
			failRedirect("invalid_token")
			return
		default:
			log.Err(err).Msg("AcceptOrgInvite: accept tx failed")
			failRedirect("server_error")
			return
		}
	}

	// Reload the user so the sign-in tail sees the freshly-verified flag.
	signedIn, lerr := handler.repo.GetUserByID(r.Context(), user.ID)
	if lerr != nil || signedIn == nil {
		log.Err(lerr).Msg("AcceptOrgInvite: reload user failed")
		failRedirect("server_error")
		return
	}

	// rememberMe=false for invites. Reuse AuthMethodMagicLink for the auth-log
	// method (no dedicated org-invite method const exists).
	handler.finishClientSignInRedirect(w, r, ws, app, signedIn, created, false, appURL, core.AuthMethodMagicLink, inv.Email, failRedirect)
}
