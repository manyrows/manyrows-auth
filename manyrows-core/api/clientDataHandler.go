package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/crypto/passwordhash"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// =====================
// Response shapes
// =====================

// AppMeResponse is the combined identity response: workspace user + app
// claims in one payload. Replaces the previous /a/me + /a/app/me split.
// Route: GET /x/{workspaceSlug}/apps/{appId}/a/app/me
type AppMeResponse struct {
	User          *core.UserResource `json:"user,omitempty"`
	WorkspaceName string             `json:"workspaceName"`
	App           AppMeAppPart       `json:"app"`
}

// AppMeAppPart is the app-scoped slice of AppMeResponse. transportMode
// is included so AppKit can configure itself on boot — no separate
// `cookieMode` prop required on the React adapter.
type AppMeAppPart struct {
	Name          string   `json:"name"`
	HasAccess     bool     `json:"hasAccess"`
	Roles         []string `json:"roles"`
	Permissions   []string `json:"permissions"`
	TransportMode string   `json:"transportMode"`
}

// CheckPermissionResponse is returned by the permission-check endpoint.
type CheckPermissionResponse struct {
	Allowed    bool   `json:"allowed"`
	Permission string `json:"permission"`
}

// ServerCheckPermissionResponse is returned by the server-to-server permission-check endpoint.
type ServerCheckPermissionResponse struct {
	Allowed    bool   `json:"allowed"`
	Permission string `json:"permission"`
	AccountID  string `json:"accountId"`
}

// AppData is the runtime delivery response.
type AppData struct {
	FeatureFlags []core.EvaluatedFeatureFlag `json:"featureFlags"`
	Config       []core.PublicConfigItem     `json:"config"`
}

// =====================
// Shared auth helpers
// =====================

// clientSessionIdentity holds the user info from a client session.
type clientSessionIdentity struct {
	User *core.User
}

// requireActiveClientSession validates:
// - workspace in context
// - active client session (JWT)
// - user exists
//
// It does NOT require project/env.
func (handler *RequestHandler) requireActiveClientSession(
	w http.ResponseWriter,
	r *http.Request,
) (*core.ClientSession, *clientSessionIdentity, *core.Workspace, bool) {
	ctx := r.Context()

	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return nil, nil, nil, false
	}

	// Prefer context session (workspaceAuthMiddleware should inject it),
	// fall back to parsing via service if needed.
	var ses *core.ClientSession
	if s2, ok := core.ClientSessionFromContext(ctx); ok && s2 != nil {
		ses = s2
	} else {
		s3, err := handler.clientAuthService.GetSession(r)
		if err != nil {
			log.Err(err).Msg("Could not resolve client session")
			WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
			return nil, nil, nil, false
		}
		ses = s3
	}

	if ses == nil || !ses.IsActive(time.Now().UTC()) {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return nil, nil, nil, false
	}

	// Load user (with TOTP fields for profile/2FA status)
	user, err := handler.repo.GetUserByIDWithTOTP(ctx, ses.UserID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
			return nil, nil, nil, false
		}
		log.Err(err).Msg("Could not get user for client session")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return nil, nil, nil, false
	}

	identity := &clientSessionIdentity{
		User: user,
	}

	return ses, identity, ws, true
}

// requireActiveClientSessionApp validates active session + user,
// and additionally requires app + project in context (set by appMiddleware).
func (handler *RequestHandler) requireActiveClientSessionApp(
	w http.ResponseWriter,
	r *http.Request,
) (*core.ClientSession, *clientSessionIdentity, *core.Workspace, *core.App, *core.Project, bool) {
	ctx := r.Context()

	ses, identity, ws, ok := handler.requireActiveClientSession(w, r)
	if !ok {
		return nil, nil, nil, nil, nil, false
	}

	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return nil, nil, nil, nil, nil, false
	}

	project, ok := core.ProjectFromContext(ctx)
	if !ok || project == nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return nil, nil, nil, nil, nil, false
	}

	return ses, identity, ws, app, project, true
}

// =====================
// Role/permission resolution
// =====================

func (handler *RequestHandler) resolveRolesAndPermissions(
	ctx context.Context, projectID, userID, appID uuid.UUID,
) ([]string, []string, error) {
	memberRoles, err := handler.repo.GetUserRolesByUserAndAppID(
		ctx, projectID, userID, appID,
	)
	if err != nil {
		return nil, nil, err
	}

	var roles []string
	var perms []string

	if len(memberRoles) > 0 {
		roleIDs := make([]uuid.UUID, len(memberRoles))
		for i, mr := range memberRoles {
			roleIDs[i] = mr.RoleID
		}

		roles, perms, err = handler.repo.GetRoleSlugsAndPermissionSlugsForRoleIDs(ctx, projectID, roleIDs)
		if err != nil {
			return nil, nil, err
		}
	}

	// Merge direct user permissions
	directPerms, err := handler.repo.GetDirectPermissionSlugs(ctx, projectID, userID, appID)
	if err != nil {
		return nil, nil, err
	}
	if len(directPerms) > 0 {
		seen := make(map[string]struct{}, len(perms))
		for _, p := range perms {
			seen[p] = struct{}{}
		}
		for _, p := range directPerms {
			if _, ok := seen[p]; !ok {
				perms = append(perms, p)
			}
		}
	}

	if roles == nil {
		roles = []string{}
	}
	if perms == nil {
		perms = []string{}
	}

	return roles, perms, nil
}

// =====================
// Handlers
// =====================

// GetAppMe returns the combined identity response: workspace user info +
// app-scoped claims (roles, permissions). Replaces the previous /a/me +
// /a/app/me split — AppKit's bootstrap flow only needs one round trip.
// GET /x/{workspaceSlug}/apps/{appId}/a/app/me
func (handler *RequestHandler) GetAppMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ses, identity, ws, app, project, ok := handler.requireActiveClientSessionApp(w, r)
	if !ok {
		return
	}

	roles, perms, err := handler.resolveRolesAndPermissions(ctx, project.ID, identity.User.ID, app.ID)
	if err != nil {
		log.Err(err).Msg("Could not resolve roles/permissions")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	transportMode := app.TransportMode
	if transportMode == "" {
		transportMode = core.TransportModeLocal
	}
	out := AppMeResponse{
		User:          core.ToUserResource(identity.User),
		WorkspaceName: ws.Name,
		App: AppMeAppPart{
			Name:          app.DisplayName(),
			HasAccess:     true,
			Roles:         roles,
			Permissions:   perms,
			TransportMode: transportMode,
		},
	}

	// Touch client session last_seen
	if _, err := handler.repo.TouchClientSessionLastSeen(ctx, ses.ID); err != nil {
		log.Err(err).Msg("Could not touch client session last seen")
	}

	utils.WriteJson(w, out)
}

// GetAppData returns runtime delivery (feature flags + public config).
// GET /x/{workspaceSlug}/a/apps/{appId}/
func (handler *RequestHandler) GetAppData(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ses, identity, _, app, project, ok := handler.requireActiveClientSessionApp(w, r)
	if !ok {
		return
	}

	resp := AppData{
		FeatureFlags: []core.EvaluatedFeatureFlag{},
		Config:       []core.PublicConfigItem{},
	}

	// Feature flags (public only), filtered by user's roles
	flags, err := handler.repo.GetEvaluatedFeatureFlagsForProjectAndApp(ctx, project.ID, app.ID)
	if err != nil {
		log.Err(err).Msg("Could not get evaluated feature flags")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Get user's role IDs for role-based flag filtering
	memberRoles, _ := handler.repo.GetUserRolesByUserAndAppID(ctx, project.ID, identity.User.ID, app.ID)
	userRoleIDs := make(map[uuid.UUID]struct{}, len(memberRoles))
	for _, mr := range memberRoles {
		userRoleIDs[mr.RoleID] = struct{}{}
	}

	filtered := make([]core.EvaluatedFeatureFlag, 0, len(flags))
	for _, f := range flags {
		if len(f.RoleIDs) == 0 {
			// No role restriction — applies to everyone
			filtered = append(filtered, f)
		} else if f.Enabled {
			// Role-restricted and enabled — check if user has one of the roles
			hasRole := false
			for _, rid := range f.RoleIDs {
				if _, ok := userRoleIDs[rid]; ok {
					hasRole = true
					break
				}
			}
			if hasRole {
				filtered = append(filtered, f)
			} else {
				// User doesn't have the role — flag is disabled for them
				filtered = append(filtered, core.EvaluatedFeatureFlag{Key: f.Key, Enabled: false})
			}
		} else {
			// Role-restricted but disabled — still disabled for everyone
			filtered = append(filtered, f)
		}
	}
	resp.FeatureFlags = filtered

	// Public config (public exposure only)
	cfg, err := handler.repo.GetPublicConfigForProjectAndApp(ctx, project.ID, app.ID)
	if err != nil {
		log.Err(err).Msg("Could not get public config")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if cfg == nil {
		cfg = []core.PublicConfigItem{}
	}
	resp.Config = cfg

	// Touch client session last_seen
	if _, err := handler.repo.TouchClientSessionLastSeen(ctx, ses.ID); err != nil {
		log.Err(err).Msg("Could not touch client session last seen")
	}

	utils.WriteJson(w, resp)
}

// CheckPermission checks whether the current user has a specific permission.
// GET /x/{workspaceSlug}/a/apps/{appId}/check-permission?permission=posts:read
func (handler *RequestHandler) CheckPermission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ses, identity, _, app, project, ok := handler.requireActiveClientSessionApp(w, r)
	if !ok {
		return
	}

	permission := strings.TrimSpace(r.URL.Query().Get("permission"))
	if permission == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	_, perms, err := handler.resolveRolesAndPermissions(ctx, project.ID, identity.User.ID, app.ID)
	if err != nil {
		log.Err(err).Msg("Could not resolve permissions")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	allowed := slices.Contains(perms, permission)

	// Touch client session last_seen
	if _, err := handler.repo.TouchClientSessionLastSeen(ctx, ses.ID); err != nil {
		log.Err(err).Msg("Could not touch client session last seen")
	}

	utils.WriteJson(w, CheckPermissionResponse{
		Allowed:    allowed,
		Permission: permission,
	})
}

// ServerCheckPermission checks whether a specific user has a permission.
// GET /x/{workspaceSlug}/api/v1/apps/{appId}/check-permission?accountId=<uuid>&permission=posts:read
//
// This is the server-to-server equivalent of CheckPermission. Instead of using the
// caller's JWT session, the caller specifies which user to check via query param.
func (handler *RequestHandler) ServerCheckPermission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, ok := core.WorkspaceFromContext(ctx)
	if !ok {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}
	project, ok := core.ProjectFromContext(ctx)
	if !ok || project == nil {
		WriteError(w, r, "error.forbidden", http.StatusForbidden)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.forbidden", http.StatusForbidden)
		return
	}
	accountIDStr := strings.TrimSpace(r.URL.Query().Get("accountId"))
	if accountIDStr == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	accountID, err := uuid.FromString(accountIDStr)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	permission := strings.TrimSpace(r.URL.Query().Get("permission"))
	if permission == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Only answer for members of the calling app (see requireAppMember).
	if !handler.requireAppMember(w, r, app.ID, accountID) {
		return
	}

	_, perms, err := handler.resolveRolesAndPermissions(ctx, project.ID, accountID, app.ID)
	if err != nil {
		log.Err(err).Msg("Could not resolve permissions for server check-permission")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	allowed := slices.Contains(perms, permission)

	utils.WriteJson(w, ServerCheckPermissionResponse{
		Allowed:    allowed,
		Permission: permission,
		AccountID:  accountID.String(),
	})
}

func (handler *RequestHandler) ServerGetAppMembers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, ok := core.WorkspaceFromContext(ctx)
	if !ok {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}
	project, ok := core.ProjectFromContext(ctx)
	if !ok || project == nil {
		WriteError(w, r, "error.forbidden", http.StatusForbidden)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.forbidden", http.StatusForbidden)
		return
	}
	q := r.URL.Query()

	page := 0
	if v := strings.TrimSpace(q.Get("page")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			WriteError(w, r, "error.invalidPage", http.StatusBadRequest)
			return
		}
		page = n
	}

	pageSize := 50
	if v := strings.TrimSpace(q.Get("pageSize")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			WriteError(w, r, "error.invalidPageSize", http.StatusBadRequest)
			return
		}
		if n > 200 {
			n = 200
		}
		pageSize = n
	}

	// Substring filter on email. Named "search" (not "email") because on the
	// /users collection ?email= is the exact single-user lookup.
	search := strings.TrimSpace(q.Get("search"))

	members, total, err := handler.repo.GetProjectMembersByApp(
		ctx, project.ID, app.ID, page, pageSize, search, 0, repo.MemberEnabledFilterAny, repo.MemberRoleFilter{},
	)
	if err != nil {
		log.Err(err).Msg("Could not get app members")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Resolve roles for each member
	type memberWithRoles struct {
		core.MemberResource
		Roles []string `json:"roles"`
	}

	out := make([]memberWithRoles, 0, len(members))
	for _, m := range members {
		roles, _, err := handler.resolveRolesAndPermissions(ctx, project.ID, m.UserID, app.ID)
		if err != nil {
			log.Err(err).Msg("Could not resolve roles for app member")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		out = append(out, memberWithRoles{MemberResource: m, Roles: roles})
	}

	utils.WriteJson(w, map[string]any{
		"members":  out,
		"total":    total,
		"page":     page,
		"pageSize": pageSize,
	})
}

// GetMyUserFields returns client-visible user fields for the current user.
// GET /x/{workspaceSlug}/a/apps/{appId}/app/me/fields
func (handler *RequestHandler) GetMyUserFields(w http.ResponseWriter, r *http.Request) {
	_, identity, _, _, _, ok := handler.requireActiveClientSessionApp(w, r)
	if !ok {
		return
	}

	items, err := handler.repo.GetClientUserFieldsForUser(r.Context(), identity.User.ID)
	if err != nil {
		log.Err(err).Msg("GetMyUserFields: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, map[string]any{"fields": items}, http.StatusOK)
}

// GetMySessions returns active sessions for the current user.
// GET /x/{workspaceSlug}/a/me/sessions
func (handler *RequestHandler) GetMySessions(w http.ResponseWriter, r *http.Request) {
	ses, identity, _, ok := handler.requireActiveClientSession(w, r)
	if !ok {
		return
	}

	sessions, err := handler.repo.GetActiveClientSessionsByUserID(r.Context(), identity.User.ID)
	if err != nil {
		log.Err(err).Msg("GetMySessions: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	type sessionItem struct {
		ID         string `json:"id"`
		CreatedAt  string `json:"createdAt"`
		LastSeenAt string `json:"lastSeenAt"`
		UserAgent  string `json:"userAgent,omitempty"`
		IP         string `json:"ip,omitempty"`
		Current    bool   `json:"current"`
	}

	items := make([]sessionItem, 0, len(sessions))
	for _, s := range sessions {
		items = append(items, sessionItem{
			ID:         s.ID.String(),
			CreatedAt:  s.CreatedAt.Format(time.RFC3339),
			LastSeenAt: s.LastSeenAt.Format(time.RFC3339),
			UserAgent:  s.UserAgent,
			IP:         s.IP,
			Current:    s.ID == ses.ID,
		})
	}

	utils.WriteJsonWithStatusCode(w, map[string]any{"sessions": items}, http.StatusOK)
}

// DeleteMySession revokes one of the current user's sessions.
// DELETE /x/{workspaceSlug}/a/me/sessions/{sessionId}
func (handler *RequestHandler) DeleteMySession(w http.ResponseWriter, r *http.Request) {
	ses, identity, _, ok := handler.requireActiveClientSession(w, r)
	if !ok {
		return
	}

	sessionID, err := utils.GetPathUUID("sessionId", r)
	if err != nil || sessionID == uuid.Nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Don't allow revoking current session (use logout instead)
	if sessionID == ses.ID {
		WriteErrorMsg(w, r, "Cannot revoke current session. Use logout instead.", http.StatusBadRequest)
		return
	}

	// Verify the session belongs to this user
	target, err := handler.repo.GetClientSessionByID(r.Context(), sessionID)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if target.UserID != identity.User.ID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	// Revoke tokens then delete
	_ = handler.clientAuthService.RevokeAllSessionTokens(r.Context(), sessionID)
	_ = handler.clientAuthService.DeleteSession(r.Context(), sessionID)

	w.WriteHeader(http.StatusNoContent)
}

// GetMyIdentities returns the social/OAuth identities currently linked
// to the signed-in user (Google, Apple, Microsoft, GitHub).
// GET /x/{workspaceSlug}/a/me/identities
func (handler *RequestHandler) GetMyIdentities(w http.ResponseWriter, r *http.Request) {
	_, identity, _, ok := handler.requireActiveClientSession(w, r)
	if !ok {
		return
	}

	rows, err := handler.repo.ListUserIdentities(r.Context(), identity.User.ID)
	if err != nil {
		log.Err(err).Msg("GetMyIdentities: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	items := make([]*core.UserIdentityResource, 0, len(rows))
	for _, row := range rows {
		items = append(items, core.ToUserIdentityResource(row))
	}
	utils.WriteJsonWithStatusCode(w, map[string]any{"identities": items}, http.StatusOK)
}

// DeleteMyIdentity unlinks one social provider from the signed-in user.
// No lock-out gate: every user has a verified email and can recover via
// the email-based flows (magic link / email OTP) the app exposes, plus
// password reset if a password is set.
// DELETE /x/{workspaceSlug}/a/me/identities/{provider}
func (handler *RequestHandler) DeleteMyIdentity(w http.ResponseWriter, r *http.Request) {
	_, identity, _, ok := handler.requireActiveClientSession(w, r)
	if !ok {
		return
	}

	provider := core.UserSource(utils.GetPathString("provider", r))
	switch provider {
	case core.UserSourceGoogle, core.UserSourceApple,
		core.UserSourceMicrosoft, core.UserSourceGithub:
		// bespoke provider — ok
	default:
		// generic external IdP identities ("idp:<uuid>") are also
		// disconnectable; anything else is a bad request.
		if !core.IsExternalIDPProviderKey(string(provider)) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
	}

	if err := handler.repo.DeleteUserIdentity(r.Context(), identity.User.ID, provider); err != nil {
		log.Err(err).Msg("DeleteMyIdentity: delete failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// UpdateMyUserFields updates user-editable fields for the current user.
// PATCH /x/{workspaceSlug}/a/apps/{appId}/app/me/fields
func (handler *RequestHandler) UpdateMyUserFields(w http.ResponseWriter, r *http.Request) {
	_, identity, _, _, _, ok := handler.requireActiveClientSessionApp(w, r)
	if !ok {
		return
	}

	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	fields, err := handler.repo.GetUserFieldsByUserPoolID(r.Context(), identity.User.UserPoolID)
	if err != nil {
		log.Err(err).Msg("UpdateMyUserFields: failed to get fields")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	fieldByKey := make(map[string]core.UserField, len(fields))
	for _, f := range fields {
		fieldByKey[f.Key] = f
	}

	now := time.Now().UTC()
	for key, val := range body {
		f, ok := fieldByKey[key]
		if !ok || f.Status != "active" {
			continue // skip unknown or archived fields
		}
		if !f.UserEditable || f.Visibility != core.UserFieldVisibilityClient {
			WriteError(w, r, "error.forbidden", http.StatusForbidden)
			return
		}

		if msg := core.ValidateFieldValue(f.ValueType, val); msg != "" {
			WriteErrorMsg(w, r, msg, http.StatusBadRequest)
			return
		}

		v := core.UserFieldValue{
			UserID:      identity.User.ID,
			UserFieldID: f.ID,
			UpdatedAt:   now,
			UpdatedBy:   identity.User.ID,
		}
		if _, err := handler.repo.UpsertUserFieldValue(r.Context(), v, val); err != nil {
			log.Err(err).Msg("UpdateMyUserFields: failed to upsert value")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
	}

	// Return updated fields
	items, err := handler.repo.GetClientUserFieldsForUser(r.Context(), identity.User.ID)
	if err != nil {
		log.Err(err).Msg("UpdateMyUserFields: failed to get updated fields")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, map[string]any{"fields": items}, http.StatusOK)
}

// DeleteMyAccount permanently deletes the current user's account.
// POST /x/{workspaceSlug}/a/me/delete
// Requires password confirmation in request body.
//
// Gated by app.AllowAccountDeletion — if the admin has flipped that
// off in the General tab, the endpoint refuses regardless of what
// the AppKit UI exposes. AppKit also hides the delete button when
// the flag is false; this is the defense-in-depth check.
func (handler *RequestHandler) DeleteMyAccount(w http.ResponseWriter, r *http.Request) {
	ses, identity, _, ok := handler.requireActiveClientSession(w, r)
	if !ok {
		return
	}

	if app, appOk := core.AppFromContext(r.Context()); appOk && app != nil && !app.AllowAccountDeletion {
		WriteError(w, r, "error.forbidden", http.StatusForbidden)
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(body.Password) == "" {
		WriteErrorMsg(w, r, "Password is required", http.StatusBadRequest)
		return
	}

	// Verify password
	var passwordHash string
	err := handler.repo.DB().Pool().QueryRow(r.Context(),
		`SELECT COALESCE(password_hash, '') FROM users WHERE id = $1`, identity.User.ID,
	).Scan(&passwordHash)
	if err != nil {
		log.Err(err).Msg("DeleteMyAccount: failed to get password hash")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if passwordHash == "" {
		WriteErrorMsg(w, r, "Cannot delete account without a password. Set a password first.", http.StatusBadRequest)
		return
	}

	ok, vErr := passwordhash.Verify(passwordHash, body.Password)
	if vErr != nil || !ok {
		WriteErrorMsg(w, r, "Incorrect password", http.StatusForbidden)
		return
	}

	// Delete the user — cascades to user_field_values, user_roles, client_sessions, refresh_tokens
	if err := handler.repo.DeleteUser(r.Context(), identity.User.ID); err != nil {
		log.Err(err).Msg("DeleteMyAccount: failed to delete user")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Fire webhook before session cleanup
	if ses.AppID != nil {
		if app, err := handler.repo.GetAppByID(r.Context(), *ses.AppID); err == nil {
			handler.dispatchWebhook(app.ID, "user.delete", map[string]any{"userId": identity.User.ID, "email": identity.User.Email, "appId": app.ID})
		}
	}

	if ws, ok := core.WorkspaceFromContext(r.Context()); ok && ws != nil {
		userID := identity.User.ID
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:    ws.ID,
			AppID:          ses.AppID,
			Event:          core.AuthEventAccountDeleted,
			Outcome:        core.AuthOutcomeSuccess,
			SubjectUserID:  &userID,
			EmailAttempted: identity.User.Email,
			ActorType:      core.AuthActorSelf,
			ActorLabel:     identity.User.Email,
			SessionID:      &ses.ID,
		})
	}

	// Invalidate current session tokens (best effort, session row already cascaded)
	_ = handler.clientAuthService.RevokeAllSessionTokens(r.Context(), ses.ID)

	w.WriteHeader(http.StatusNoContent)
}
