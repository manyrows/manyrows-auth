package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog/log"
)

// parseOrgListParams reads page/pageSize/search query params for the paginated
// org member/invite listings. page defaults to 0; pageSize defaults to 50 and is
// capped at 200 (matching the app-members listing). The returned values reflect
// what the repo will actually use, so callers can echo them back in the response.
func parseOrgListParams(r *http.Request) (page, pageSize int, search string) {
	q := r.URL.Query()
	if v := strings.TrimSpace(q.Get("page")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	pageSize = 50
	if v := strings.TrimSpace(q.Get("pageSize")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			pageSize = n
		}
	}
	if pageSize > 200 {
		pageSize = 200
	}
	search = strings.TrimSpace(q.Get("search"))
	return page, pageSize, search
}

// updateAppOrganizationsEnabledRequest toggles per-app org mode from the admin
// panel. Pointer so a missing field is rejected, not silently treated as false.
type updateAppOrganizationsEnabledRequest struct {
	OrganizationsEnabled *bool `json:"organizationsEnabled"`
}

// adminAppScope runs the admin/workspace gate, parses the path ids, AND verifies
// the app belongs to the caller's workspace+project — failing safe (404) if not.
// resolvePathIDs alone only PARSES the ids; without this ownership check a
// workspace-A admin could reach an app in workspace B by supplying its id. Every
// org-management handler must go through this.
func (handler *RequestHandler) adminAppScope(w http.ResponseWriter, r *http.Request) (projectID, appID uuid.UUID, ok bool) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return uuid.Nil, uuid.Nil, false
	}
	projectID, appID, ok = handler.resolvePathIDs(w, r)
	if !ok {
		return uuid.Nil, uuid.Nil, false
	}
	if _, err := handler.repo.GetAppByIDForProject(r.Context(), ws.ID, projectID, appID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return uuid.Nil, uuid.Nil, false
		}
		log.Err(err).Msg("failed to load app for org admin scope")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return uuid.Nil, uuid.Nil, false
	}
	return projectID, appID, true
}

// HandleUpdateAppOrganizationsEnabled flips organizations_enabled for the whole
// project the addressed app belongs to. The flag is conceptually project-level
// but stored per-app (duplicated across the project's apps); this keeps every
// copy in sync. The endpoint is still addressed via one app's id (the admin UI
// lives on an app's Organizations page) and returns that app.
func (handler *RequestHandler) HandleUpdateAppOrganizationsEnabled(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	projectID, appID, ok := handler.resolvePathIDs(w, r)
	if !ok {
		return
	}

	var req updateAppOrganizationsEnabledRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode json")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if req.OrganizationsEnabled == nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Validate the addressed app belongs to this workspace+project before
	// mutating anything (404 otherwise) — so a bad app id can't trigger a
	// project-wide write.
	out, err := handler.repo.GetAppByIDForProject(r.Context(), ws.ID, projectID, appID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to load app for organizations flag update")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if err := handler.repo.SetProjectOrganizationsEnabled(r.Context(), ws.ID, projectID, *req.OrganizationsEnabled); err != nil {
		log.Err(err).Msg("failed to update project organizations flag")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Reflect the new value on the addressed app we return (every app in the
	// project now carries it).
	out.OrganizationsEnabled = *req.OrganizationsEnabled
	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, ws), http.StatusOK)
}

type setAppOrgMemberRolesRequest struct {
	RoleIDs []uuid.UUID `json:"roleIds"`
}

// HandleSetAppOrganizationMemberRoles replaces an org member's project-role
// assignment from the admin panel. App-scoped + ownership-checked via
// adminAppScope/adminOrgFromURL; the target must be a member of the org. Role
// ids are validated against the app's project catalog (a stray id -> 400).
// Replace semantics: the posted set becomes the membership's exact project
// roles, and an empty array clears them. Independent of the org tier
// (owner/admin/member), which this endpoint does not touch.
func (handler *RequestHandler) HandleSetAppOrganizationMemberRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	projectID, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	org, ok := handler.adminActiveOrgFromURL(w, r, appID)
	if !ok {
		return
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}
	member, err := handler.repo.GetOrganizationMember(ctx, org.ID, userID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("HandleSetAppOrganizationMemberRoles: load member failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	var body setAppOrgMemberRolesRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	roleIDs := dedupeUUIDs(body.RoleIDs)
	if len(roleIDs) > 0 {
		n, err := handler.repo.CountRolesInProject(ctx, projectID, roleIDs)
		if err != nil {
			log.Err(err).Msg("HandleSetAppOrganizationMemberRoles: role validation failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if n != len(roleIDs) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest) // stray role id
			return
		}
	}
	if err := handler.repo.SetOrganizationMemberRoles(ctx, member.ID, roleIDs); err != nil {
		log.Err(err).Msg("HandleSetAppOrganizationMemberRoles: set roles failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	handler.dispatchOrgMemberEvent(whOrgMemberUpdated, appID, org.ID, userID)
	handler.auditOrg(r, core.AuthEventOrgMemberRoleChanged, org, &userID)
	w.WriteHeader(http.StatusNoContent)
}

type createAppOrganizationRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// HandleCreateAppOrganization seeds an org from the admin panel (ownerless;
// the operator then adds members + sets an owner). Requires organizations
// enabled (fail loud — provisioning into a disabled app makes rows runtime
// resolution never reads). Slug collisions get a -2, -3 … suffix.
func (handler *RequestHandler) HandleCreateAppOrganization(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	projectID, appID, ok := handler.resolvePathIDs(w, r)
	if !ok {
		return
	}
	appRow, err := handler.repo.GetAppByIDForProject(r.Context(), ws.ID, projectID, appID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("HandleCreateAppOrganization: load app failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !appRow.OrganizationsEnabled {
		WriteError(w, r, "error.conflict", http.StatusConflict)
		return
	}
	var body createAppOrganizationRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(body.Name)
	if len(name) > maxOrgNameLen || len(strings.TrimSpace(body.Slug)) > maxOrgNameLen {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	slug := strings.TrimSpace(body.Slug)
	if slug == "" {
		slug = simpleSlug(name)
	}
	org, err := handler.repo.CreateOrganizationWithUniqueSlug(r.Context(), appID, name, slug, nil)
	if err != nil {
		log.Err(err).Msg("HandleCreateAppOrganization: create failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	handler.dispatchOrgLifecycleEvent(whOrgCreated, org)
	handler.auditOrg(r, core.AuthEventOrgCreated, org, nil)
	utils.WriteJsonWithStatusCode(w, adminOrgResponse{
		ID: org.ID.String(), Name: org.Name, Slug: org.Slug, Status: org.Status,
	}, http.StatusCreated)
}

type addAppOrgMemberRequest struct {
	UserID  string `json:"userId"`
	Email   string `json:"email"`
	OrgRole string `json:"orgRole"`
}

// HandleAddAppOrganizationMember adds an existing app user to an org from the
// admin panel. The target must already be a member of this app's pool (invites
// onboard new emails). Defaults to the member tier; 409 if already a member.
func (handler *RequestHandler) HandleAddAppOrganizationMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	org, ok := handler.adminActiveOrgFromURL(w, r, appID)
	if !ok {
		return
	}
	appRow, err := handler.repo.GetAppByID(ctx, appID)
	if err != nil {
		log.Err(err).Msg("HandleAddAppOrganizationMember: load app failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !appRow.OrganizationsEnabled {
		WriteError(w, r, "error.conflict", http.StatusConflict)
		return
	}
	var body addAppOrgMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	role := strings.TrimSpace(body.OrgRole)
	if role == "" {
		role = core.OrgRoleMember
	}
	if !validOrgRole(role) {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Resolve the target user by id or email; either way they must be an
	// existing member of this app.
	var user *core.User
	if s := strings.TrimSpace(body.UserID); s != "" {
		uid, perr := uuid.FromString(s)
		if perr != nil || uid == uuid.Nil {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		u, uerr := handler.repo.GetUserByID(ctx, uid)
		if errors.Is(uerr, repo.ErrNotFound) || u == nil {
			WriteError(w, r, "error.userNotSignedIn", http.StatusConflict)
			return
		}
		if uerr != nil {
			log.Err(uerr).Msg("HandleAddAppOrganizationMember: user lookup failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		user = u
	} else if e := strings.TrimSpace(strings.ToLower(body.Email)); e != "" {
		u, uerr := handler.repo.GetUserByEmail(ctx, e, &appRow)
		if uerr != nil {
			log.Err(uerr).Msg("HandleAddAppOrganizationMember: email lookup failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if u == nil {
			WriteError(w, r, "error.userNotSignedIn", http.StatusConflict)
			return
		}
		user = u
	} else {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	member, err := handler.repo.GetAppUser(ctx, appID, user.ID)
	if err != nil {
		log.Err(err).Msg("HandleAddAppOrganizationMember: membership check failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if member == nil {
		WriteError(w, r, "error.userNotSignedIn", http.StatusConflict) // not an app member
		return
	}

	m, err := handler.repo.AddOrganizationMember(ctx, org.ID, user.ID, role)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			WriteError(w, r, "error.conflict", http.StatusConflict) // already a member
			return
		}
		log.Err(err).Msg("HandleAddAppOrganizationMember: add failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	handler.dispatchOrgMemberEvent(whOrgMemberAdded, appID, org.ID, user.ID)
	handler.auditOrg(r, core.AuthEventOrgMemberAdded, org, &user.ID)
	utils.WriteJsonWithStatusCode(w, repo.OrganizationMemberView{
		UserID: user.ID, Email: user.Email, OrgRole: m.OrgRole, Status: m.Status, Roles: []repo.OrgMemberRoleRef{},
	}, http.StatusCreated)
}

// HandleListAppOrganizationInvites lists an org's pending invites (admin
// visibility). App/workspace-scoped via adminAppScope + adminOrgFromURL.
func (handler *RequestHandler) HandleListAppOrganizationInvites(w http.ResponseWriter, r *http.Request) {
	_, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	org, ok := handler.adminOrgFromURL(w, r, appID)
	if !ok {
		return
	}
	page, pageSize, search := parseOrgListParams(r)
	views, total, err := handler.repo.ListPendingOrgInvites(r.Context(), org.ID, page, pageSize, search)
	if err != nil {
		log.Err(err).Msg("HandleListAppOrganizationInvites failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJsonWithStatusCode(w, map[string]any{
		"invites": views, "total": total, "page": page, "pageSize": pageSize,
	}, http.StatusOK)
}

type createAppOrgInviteRequest struct {
	Email   string      `json:"email"`
	OrgRole string      `json:"orgRole"`
	RoleIDs []uuid.UUID `json:"roleIds"`
}

// HandleCreateAppOrganizationInvite creates + emails an org invite from the
// admin panel (reuses the shared invite helper). Defaults to the member tier;
// role ids are validated against the app's project catalog.
func (handler *RequestHandler) HandleCreateAppOrganizationInvite(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	projectID, appID, ok := handler.resolvePathIDs(w, r)
	if !ok {
		return
	}
	appRow, err := handler.repo.GetAppByIDForProject(ctx, ws.ID, projectID, appID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("HandleCreateAppOrganizationInvite: load app failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !appRow.OrganizationsEnabled {
		WriteError(w, r, "error.conflict", http.StatusConflict)
		return
	}
	org, ok := handler.adminActiveOrgFromURL(w, r, appID)
	if !ok {
		return
	}
	var body createAppOrgInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	emailAddr := strings.TrimSpace(strings.ToLower(body.Email))
	if emailAddr == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	orgRole := strings.TrimSpace(body.OrgRole)
	if orgRole == "" {
		orgRole = core.OrgRoleMember
	}
	if !validOrgRole(orgRole) {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	roleIDs := dedupeUUIDs(body.RoleIDs)
	if len(roleIDs) > 0 {
		n, cerr := handler.repo.CountRolesInProject(ctx, projectID, roleIDs)
		if cerr != nil {
			log.Err(cerr).Msg("HandleCreateAppOrganizationInvite: role validation failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if n != len(roleIDs) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
	}
	inv, err := handler.createAndEmailOrgInvite(ctx, &appRow, ws, org, emailAddr, orgRole, roleIDs, nil)
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
			log.Err(err).Msg("HandleCreateAppOrganizationInvite failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		}
		return
	}
	utils.WriteJsonWithStatusCode(w, map[string]any{
		"id": inv.ID.String(), "email": inv.Email, "orgRole": inv.OrgRole, "status": inv.Status,
		"createdAt": inv.CreatedAt.Format(time.RFC3339), "expiresAt": inv.ExpiresAt.Format(time.RFC3339),
	}, http.StatusCreated)
}

// HandleRevokeAppOrganizationInvite revokes a pending org invite (admin).
func (handler *RequestHandler) HandleRevokeAppOrganizationInvite(w http.ResponseWriter, r *http.Request) {
	_, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	org, ok := handler.adminActiveOrgFromURL(w, r, appID)
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
		log.Err(err).Msg("HandleRevokeAppOrganizationInvite failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type updateAppOrgCreationPolicyRequest struct {
	OrgCreationPolicy *string `json:"orgCreationPolicy"`
}

func validOrgCreationPolicy(s string) bool {
	return s == core.OrgCreationSelfServe || s == core.OrgCreationInviteOnly || s == core.OrgCreationAdminOnly
}

// HandleUpdateAppOrgCreationPolicy sets org_creation_policy for the whole
// project the addressed app belongs to (mirrors organizations_enabled:
// project-level, stored per-app). Gates who may create an org:
// self_serve | invite_only | admin_only. Without this there was no way to set
// the policy, so it was stuck at the 'invite_only' default and the self-serve
// create path was unreachable.
func (handler *RequestHandler) HandleUpdateAppOrgCreationPolicy(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	projectID, appID, ok := handler.resolvePathIDs(w, r)
	if !ok {
		return
	}
	var req updateAppOrgCreationPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if req.OrgCreationPolicy == nil || !validOrgCreationPolicy(strings.TrimSpace(*req.OrgCreationPolicy)) {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	policy := strings.TrimSpace(*req.OrgCreationPolicy)

	// Validate the addressed app belongs to this workspace+project before the
	// project-wide write (404 otherwise).
	out, err := handler.repo.GetAppByIDForProject(r.Context(), ws.ID, projectID, appID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to load app for org creation policy update")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if err := handler.repo.SetProjectOrgCreationPolicy(r.Context(), ws.ID, projectID, policy); err != nil {
		log.Err(err).Msg("failed to update project org creation policy")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	out.OrgCreationPolicy = policy
	utils.WriteJsonWithStatusCode(w, handler.toAdminAppResponse(out, ws), http.StatusOK)
}

type setAppOrgMemberTierRequest struct {
	OrgRole string `json:"orgRole"`
}

// HandleSetAppOrganizationMemberTier changes an org member's tier
// (owner/admin/member) from the admin panel. The operator acts above the org,
// so no §7 admin-vs-owner matrix applies — only the last-owner guard (409),
// which lets an operator promote a replacement owner then demote the old one.
func (handler *RequestHandler) HandleSetAppOrganizationMemberTier(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	org, ok := handler.adminActiveOrgFromURL(w, r, appID)
	if !ok {
		return
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}
	var body setAppOrgMemberTierRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	newRole := strings.TrimSpace(body.OrgRole)
	if !validOrgRole(newRole) {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if err := handler.repo.SetOrganizationMemberRoleGuarded(ctx, org.ID, userID, newRole); err != nil {
		switch {
		case errors.Is(err, repo.ErrNotFound):
			WriteError(w, r, "error.notFound", http.StatusNotFound)
		case errors.Is(err, repo.ErrLastOwner):
			WriteError(w, r, "error.conflict", http.StatusConflict)
		default:
			log.Err(err).Msg("HandleSetAppOrganizationMemberTier: update failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		}
		return
	}
	handler.dispatchOrgMemberEvent(whOrgMemberUpdated, appID, org.ID, userID)
	handler.auditOrg(r, core.AuthEventOrgMemberRoleChanged, org, &userID)
	w.WriteHeader(http.StatusNoContent)
}

// HandleRemoveAppOrganizationMember removes a member from an org from the admin
// panel. Last-owner protected (409) so an org can't be left ownerless.
func (handler *RequestHandler) HandleRemoveAppOrganizationMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	org, ok := handler.adminActiveOrgFromURL(w, r, appID)
	if !ok {
		return
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}
	if err := handler.repo.RemoveOrganizationMemberGuarded(ctx, org.ID, userID); err != nil {
		switch {
		case errors.Is(err, repo.ErrNotFound):
			WriteError(w, r, "error.notFound", http.StatusNotFound)
		case errors.Is(err, repo.ErrLastOwner):
			WriteError(w, r, "error.conflict", http.StatusConflict)
		default:
			log.Err(err).Msg("HandleRemoveAppOrganizationMember: delete failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		}
		return
	}
	handler.dispatchOrgMemberEvent(whOrgMemberRemoved, appID, org.ID, userID)
	handler.auditOrg(r, core.AuthEventOrgMemberRemoved, org, &userID)
	w.WriteHeader(http.StatusNoContent)
}

// adminOrgListItem is one row of the admin org list.
type adminOrgListItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Status      string `json:"status"`
	MemberCount int    `json:"memberCount"`
	CreatedAt   string `json:"createdAt"`
}

type adminOrgListResponse struct {
	Organizations []adminOrgListItem `json:"organizations"`
}

// HandleListAppOrganizations lists every org in the app (active + archived) with
// active-member counts. App-scoped via the path appId.
func (handler *RequestHandler) HandleListAppOrganizations(w http.ResponseWriter, r *http.Request) {
	_, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	views, err := handler.repo.ListOrganizationsForApp(r.Context(), appID)
	if err != nil {
		log.Err(err).Msg("failed to list organizations for app")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	out := adminOrgListResponse{Organizations: make([]adminOrgListItem, 0, len(views))}
	for _, v := range views {
		out.Organizations = append(out.Organizations, adminOrgListItem{
			ID:          v.ID.String(),
			Name:        v.Name,
			Slug:        v.Slug,
			Status:      v.Status,
			MemberCount: v.MemberCount,
			CreatedAt:   v.CreatedAt.Format(time.RFC3339),
		})
	}
	utils.WriteJsonWithStatusCode(w, out, http.StatusOK)
}

// adminOrgFromURL loads {orgId} and enforces it belongs to appID, returning 404
// otherwise. Archived orgs pass (admin must view/rename/archive them); only
// cross-app access is denied. Caller has already run adminAndWorkspace +
// resolvePathIDs.
func (handler *RequestHandler) adminOrgFromURL(w http.ResponseWriter, r *http.Request, appID uuid.UUID) (*core.Organization, bool) {
	orgID, err := utils.GetPathUUID("orgId", r)
	if err != nil || orgID == uuid.Nil {
		WriteError(w, r, "error.organizationNotFound", http.StatusNotFound)
		return nil, false
	}
	org, err := handler.repo.GetOrganizationByID(r.Context(), orgID)
	if err != nil || org == nil || org.AppID != appID {
		WriteError(w, r, "error.organizationNotFound", http.StatusNotFound)
		return nil, false
	}
	return org, true
}

// adminActiveOrgFromURL is adminOrgFromURL but additionally requires the org to
// be active (409 otherwise). Used by every handler that builds up or changes
// membership/invite state, so an archived org can't accrue ghost members or
// invitations — archived orgs are frozen (view/rename/archive/restore/delete
// only). Mirrors serverOrgFromURL / requireOrgRole, which also reject non-active.
func (handler *RequestHandler) adminActiveOrgFromURL(w http.ResponseWriter, r *http.Request, appID uuid.UUID) (*core.Organization, bool) {
	org, ok := handler.adminOrgFromURL(w, r, appID)
	if !ok {
		return nil, false
	}
	if org.Status != core.OrgStatusActive {
		WriteError(w, r, "error.organizationArchived", http.StatusConflict)
		return nil, false
	}
	return org, true
}

// HandleListAppOrganizationMembers returns a page of an org's members.
func (handler *RequestHandler) HandleListAppOrganizationMembers(w http.ResponseWriter, r *http.Request) {
	_, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	org, ok := handler.adminOrgFromURL(w, r, appID)
	if !ok {
		return
	}
	page, pageSize, search := parseOrgListParams(r)
	members, total, err := handler.repo.ListOrganizationMembers(r.Context(), org.ID, page, pageSize, search)
	if err != nil {
		log.Err(err).Msg("failed to list organization members")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJsonWithStatusCode(w, map[string]any{
		"members": members, "total": total, "page": page, "pageSize": pageSize,
	}, http.StatusOK)
}

type renameAppOrganizationRequest struct {
	Name string `json:"name"`
}

type adminOrgResponse struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Status string `json:"status"`
}

// HandleRenameAppOrganization renames an org (name only; slug is preserved so
// downstream mirrors keyed on id/slug don't drift).
func (handler *RequestHandler) HandleRenameAppOrganization(w http.ResponseWriter, r *http.Request) {
	_, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	org, ok := handler.adminOrgFromURL(w, r, appID)
	if !ok {
		return
	}
	var req renameAppOrganizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode json")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > maxOrgNameLen {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	updated, err := handler.repo.UpdateOrganization(r.Context(), org.ID, name, org.Slug)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.organizationNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to rename organization")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	handler.dispatchOrgLifecycleEvent(whOrgUpdated, updated)
	handler.auditOrg(r, core.AuthEventOrgUpdated, updated, nil)
	utils.WriteJsonWithStatusCode(w, adminOrgResponse{
		ID:     updated.ID.String(),
		Name:   updated.Name,
		Slug:   updated.Slug,
		Status: updated.Status,
	}, http.StatusOK)
}

// HandleArchiveAppOrganization archives an org (status='archived'). Idempotent:
// archiving an already-archived org still returns 204.
func (handler *RequestHandler) HandleArchiveAppOrganization(w http.ResponseWriter, r *http.Request) {
	_, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	org, ok := handler.adminOrgFromURL(w, r, appID)
	if !ok {
		return
	}
	if err := handler.repo.ArchiveOrganization(r.Context(), org.ID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			// Row physically gone — treat as already-archived (idempotent).
			// (Re-archiving an existing archived row returns nil, not ErrNotFound.)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		log.Err(err).Msg("failed to archive organization")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	handler.dispatchOrgLifecycleEvent(whOrgArchived, org)
	handler.auditOrg(r, core.AuthEventOrgArchived, org, nil)
	w.WriteHeader(http.StatusNoContent)
}

// HandleRestoreAppOrganization restores an archived org (status='active').
// Idempotent for an already-active org. adminOrgFromURL has already loaded and
// ownership-checked the org, so the ErrNotFound->404 branch below is a defensive
// guard against a concurrent hard-delete between that load and the update
// (restoring a gone row is an error, unlike archive's idempotent-gone 204).
func (handler *RequestHandler) HandleRestoreAppOrganization(w http.ResponseWriter, r *http.Request) {
	_, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	org, ok := handler.adminOrgFromURL(w, r, appID)
	if !ok {
		return
	}
	if err := handler.repo.RestoreOrganization(r.Context(), org.ID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.organizationNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to restore organization")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	handler.dispatchOrgLifecycleEvent(whOrgUnarchived, org)
	handler.auditOrg(r, core.AuthEventOrgUnarchived, org, nil)
	w.WriteHeader(http.StatusNoContent)
}

// HandleDeleteAppOrganization permanently hard-deletes an org. Gated to archived
// orgs: an active org returns 409 (must archive first). Members, member-roles and
// invites cascade; client_sessions.organization_id is set NULL. adminOrgFromURL has
// already loaded and ownership-checked the org, so the ErrNotFound->404 branch is a
// defensive guard against a concurrent delete.
func (handler *RequestHandler) HandleDeleteAppOrganization(w http.ResponseWriter, r *http.Request) {
	_, appID, ok := handler.adminAppScope(w, r)
	if !ok {
		return
	}
	org, ok := handler.adminOrgFromURL(w, r, appID)
	if !ok {
		return
	}
	if org.Status != core.OrgStatusArchived {
		WriteError(w, r, "error.organizationNotArchived", http.StatusConflict)
		return
	}
	if err := handler.repo.DeleteOrganization(r.Context(), org.ID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.organizationNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to delete organization")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	handler.dispatchOrgLifecycleEvent(whOrgDeleted, org)
	handler.auditOrg(r, core.AuthEventOrgDeleted, org, nil)
	w.WriteHeader(http.StatusNoContent)
}
