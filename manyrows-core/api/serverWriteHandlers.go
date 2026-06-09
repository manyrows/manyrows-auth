package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// Write side of the server-to-server API. Everything here is app-scoped
// (the app is resolved by middleware) and gated so a key for one app can
// only touch users who are MEMBERS of that app — see requireAppMember.

// requireAppMember writes a 404 (and returns false) unless userID has an
// app_users row for appID. The server API scopes to app membership: the user
// pool only shares credentials/identity across apps (SSO), it is NOT an
// access boundary, so a key for one app must not see or act on users who only
// belong to a sibling app in the same pool. A missing/cross-pool/never-joined
// user all collapse to the same 404, which also avoids leaking existence.
func (handler *RequestHandler) requireAppMember(w http.ResponseWriter, r *http.Request, appID, userID uuid.UUID) bool {
	member, err := handler.repo.GetAppUser(r.Context(), appID, userID)
	if err != nil {
		log.Err(err).Msg("requireAppMember: GetAppUser failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return false
	}
	if member == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return false
	}
	return true
}

// apiKeyActorID returns the calling API key's ID for attributing audit-log
// rows (ActorAPIKeyID), or nil if no key is in context.
func apiKeyActorID(ctx context.Context) *uuid.UUID {
	if key, ok := core.APIKeyFromContext(ctx); ok && key != nil {
		id := key.ID
		return &id
	}
	return nil
}

// resolveRoleSlugs maps role slugs to role IDs within the project,
// de-duplicating. An unknown slug or a DB error writes the HTTP response and
// returns ok=false; an empty input is valid and yields empty slices (clears
// roles). Returns the resolved IDs and the canonical slugs (1:1, order
// preserved) so callers can echo what they set without a read-back.
func (handler *RequestHandler) resolveRoleSlugs(w http.ResponseWriter, r *http.Request, projectID uuid.UUID, rawSlugs []string) (roleIDs []uuid.UUID, slugs []string, ok bool) {
	roleIDs = []uuid.UUID{}
	slugs = []string{}
	if len(rawSlugs) == 0 {
		return roleIDs, slugs, true
	}

	projectRoles, err := handler.repo.GetRolesByProjectID(r.Context(), projectID)
	if err != nil {
		log.Err(err).Msg("resolveRoleSlugs: GetRolesByProjectID failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return nil, nil, false
	}
	bySlug := make(map[string]uuid.UUID, len(projectRoles))
	for _, role := range projectRoles {
		bySlug[role.Slug] = role.ID
	}

	seen := make(map[string]bool, len(rawSlugs))
	for _, raw := range rawSlugs {
		slug := strings.TrimSpace(raw)
		id, known := bySlug[slug]
		if !known {
			WriteError(w, r, "error.rolesInvalid", http.StatusBadRequest)
			return nil, nil, false
		}
		if seen[slug] {
			continue
		}
		seen[slug] = true
		roleIDs = append(roleIDs, id)
		slugs = append(slugs, slug)
	}
	return roleIDs, slugs, true
}

// serverActorID returns the account to record as the actor for a write
// made via an API key. The key has no session/account of its own, so we
// attribute the change to whoever provisioned the key (a real account),
// which renders sensibly anywhere updated_by/created_by is shown.
func serverActorID(ctx context.Context) uuid.UUID {
	if key, ok := core.APIKeyFromContext(ctx); ok && key != nil {
		return key.CreatedBy
	}
	return uuid.Nil
}

type ServerRevokeSessionsResponse struct {
	Revoked int64 `json:"revoked"`
}

// ServerRevokeUserSessions force-logs-out a user from this app by deleting
// all of their client sessions for it.
// DELETE /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/sessions
func (handler *RequestHandler) ServerRevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}

	if !handler.requireAppMember(w, r, app.ID, userID) {
		return
	}

	revoked, err := handler.repo.DeleteClientSessionsByUserAndApp(ctx, userID, app.ID)
	if err != nil {
		log.Err(err).Msg("ServerRevokeUserSessions: delete failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if revoked > 0 {
		// Bulk force-logout: one event per user (no single session to name).
		handler.dispatchSessionRevoked(app.ID, userID, nil)
	}
	utils.WriteJson(w, ServerRevokeSessionsResponse{Revoked: revoked})
}

// ServerUpsertUserFieldValue sets a user's metadata field value.
// PUT /x/{workspaceSlug}/api/v1/apps/{appId}/user-fields/{userFieldId}/users/{userId}
func (handler *RequestHandler) ServerUpsertUserFieldValue(w http.ResponseWriter, r *http.Request) {
	app, ok := core.AppFromContext(r.Context())
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	fieldID, err := uuid.FromString(chi.URLParam(r, "userFieldId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}

	if !handler.requireAppMember(w, r, app.ID, userID) {
		return
	}

	handler.upsertUserFieldValueScoped(w, r, app.UserPoolID, fieldID, userID, serverActorID(r.Context()))
}

// ServerDeleteUserFieldValue clears a user's metadata field value.
// DELETE /x/{workspaceSlug}/api/v1/apps/{appId}/user-fields/{userFieldId}/users/{userId}
func (handler *RequestHandler) ServerDeleteUserFieldValue(w http.ResponseWriter, r *http.Request) {
	app, ok := core.AppFromContext(r.Context())
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	fieldID, err := uuid.FromString(chi.URLParam(r, "userFieldId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}

	if !handler.requireAppMember(w, r, app.ID, userID) {
		return
	}

	handler.deleteUserFieldValueScoped(w, r, app.UserPoolID, fieldID, userID)
}

type ServerReplaceRolesRequest struct {
	// Roles is the full set of role slugs the user should have in this
	// app (replace semantics, not merge). An empty array clears all roles.
	Roles []string `json:"roles"`
}

type ServerRolesResponse struct {
	Roles []string `json:"roles"`
}

// ServerReplaceUserRoles replaces a user's role assignments in this app.
// Accepts role slugs (consistent with the read API, which returns slugs).
// PUT /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/roles
func (handler *RequestHandler) ServerReplaceUserRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	project, ok := core.ProjectFromContext(ctx)
	if !ok || project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}

	// Only assign roles to existing members of this app (pool ≠ access
	// boundary). Provisioning roles before a user joins is intentionally
	// not supported on the server API.
	if !handler.requireAppMember(w, r, app.ID, userID) {
		return
	}

	var req ServerReplaceRolesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	roleIDs, slugs, ok := handler.resolveRoleSlugs(w, r, project.ID, req.Roles)
	if !ok {
		return
	}

	if err := handler.repo.ReplaceUserRoles(ctx, repo.ReplaceUserRolesParams{
		ProjectID: project.ID,
		AppID:     app.ID,
		UserID:    userID,
		RoleIDs:   roleIDs,
		Now:       time.Now().UTC(),
	}); err != nil {
		if errors.Is(err, repo.ErrBadRequest) {
			WriteError(w, r, "error.rolesInvalid", http.StatusBadRequest)
			return
		}
		log.Err(err).Msg("ServerReplaceUserRoles: ReplaceUserRoles failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Clearing all roles removes the user's access; revoke their live
	// sessions so the change takes effect immediately rather than at token
	// expiry. Mirrors the admin member-roles handler.
	if len(roleIDs) == 0 {
		if n, err := handler.repo.DeleteClientSessionsByUserAndApp(ctx, userID, app.ID); err != nil {
			log.Err(err).Msg("ServerReplaceUserRoles: failed to revoke sessions after clearing roles")
		} else if n > 0 {
			log.Info().Int64("deleted", n).Str("userId", userID.String()).Str("appId", app.ID.String()).
				Msg("Revoked sessions after clearing roles via server API")
		}
	}

	// Echo the assigned slugs: they are exactly what was just stored, so no
	// read-back query is needed.
	utils.WriteJson(w, ServerRolesResponse{Roles: slugs})
}

// serverChangeUserRole is the shared body for the incremental add/remove role
// endpoints: gate on membership, resolve+validate the {slug}, mutate, then
// echo the user's resulting roles. add=true grants, add=false revokes.
func (handler *RequestHandler) serverChangeUserRole(w http.ResponseWriter, r *http.Request, add bool) {
	ctx := r.Context()

	project, ok := core.ProjectFromContext(ctx)
	if !ok || project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}
	if !handler.requireAppMember(w, r, app.ID, userID) {
		return
	}

	// Resolve the single slug through the same validator the replace path
	// uses — an unknown slug is a 400 before any write.
	slug := chi.URLParam(r, "slug")
	roleIDs, _, ok := handler.resolveRoleSlugs(w, r, project.ID, []string{slug})
	if !ok {
		return
	}

	var err error
	if add {
		err = handler.repo.AddUserRole(ctx, app.ID, userID, roleIDs[0])
	} else {
		err = handler.repo.RemoveUserRole(ctx, app.ID, userID, roleIDs[0])
	}
	if err != nil {
		log.Err(err).Bool("add", add).Msg("serverChangeUserRole: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Echo the resulting role set (a read-back, since this is a delta).
	roles, _, err := handler.resolveRolesAndPermissions(ctx, project.ID, userID, app.ID)
	if err != nil {
		log.Err(err).Msg("serverChangeUserRole: resolve roles failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, ServerRolesResponse{Roles: roles})
}

// ServerAddUserRole grants one role to a member (idempotent), without
// disturbing their other roles. Complements PUT /roles (full replace).
// POST /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/roles/{slug}
func (handler *RequestHandler) ServerAddUserRole(w http.ResponseWriter, r *http.Request) {
	handler.serverChangeUserRole(w, r, true)
}

// ServerRemoveUserRole revokes one role from a member (idempotent).
// DELETE /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/roles/{slug}
func (handler *RequestHandler) ServerRemoveUserRole(w http.ResponseWriter, r *http.Request) {
	handler.serverChangeUserRole(w, r, false)
}

type ServerCreateUserRequest struct {
	Email string `json:"email"`
	// EmailVerified marks the address as already verified — the customer
	// vouches for it (e.g. they verified it on their side). Omitted/false
	// creates the user unverified.
	EmailVerified bool     `json:"emailVerified"`
	Roles         []string `json:"roles"`
	// SendInvite emails the user a branded invitation after provisioning.
	// Requires the app to have an App URL configured.
	SendInvite bool `json:"sendInvite"`
}

type ServerCreateUserResponse struct {
	User    *core.UserResource `json:"user"`
	Created bool               `json:"created"`
	Roles   []string           `json:"roles"`
	// Invited is true when SendInvite was requested and the email was sent.
	Invited bool `json:"invited,omitempty"`
}

// ServerCreateUser provisions a user into the app's pool and adds them to the
// app. The pool is the identity boundary, so an existing user with the same
// email in the pool is reused (created=false) and ensured to be a member —
// the call is idempotent.
//
// Role semantics on re-provision: a non-empty `roles` list REPLACES the user's
// roles in this app; omitting `roles` (or sending []) PRESERVES existing roles
// — so a roleless re-invite never silently strips a member's roles. Use
// PUT /users/{userId}/roles to authoritatively clear them. The response's
// `roles` echoes what this call set (the resolved input), not necessarily the
// user's full current set.
// POST /x/{workspaceSlug}/api/v1/apps/{appId}/users
func (handler *RequestHandler) ServerCreateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	project, ok := core.ProjectFromContext(ctx)
	if !ok || project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	var req ServerCreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	email, vr := auth.ValidateEmail(req.Email)
	if !vr.Ok() {
		WriteValidationError(w, r, vr)
		return
	}

	// Resolve roles before creating anything, so a bad slug fails fast.
	roleIDs, slugs, ok := handler.resolveRoleSlugs(w, r, project.ID, req.Roles)
	if !ok {
		return
	}

	// An invite email links to the app, so it needs an App URL. Fail fast
	// before provisioning rather than create-then-can't-notify.
	if req.SendInvite && (app.AppURL == nil || strings.TrimSpace(*app.AppURL) == "") {
		WriteError(w, r, "error.appUrlRequired", http.StatusBadRequest)
		return
	}

	user, created, err := handler.provisionUser(r, project, app, email, req.EmailVerified, roleIDs)
	if err != nil {
		if errors.Is(err, repo.ErrBadRequest) {
			WriteError(w, r, "error.rolesInvalid", http.StatusBadRequest)
			return
		}
		log.Err(err).Msg("ServerCreateUser: provision failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Best-effort invite email: the user is provisioned regardless, so a send
	// failure is logged and reflected in `invited`, not surfaced as an error.
	invited := false
	if req.SendInvite {
		if err := handler.sendUserInviteEmail(ctx, app.WorkspaceID, user.Email, app.DisplayName(), *app.AppURL, GetLanguageFromRequest(r)); err != nil {
			log.Err(err).Msg("ServerCreateUser: sendUserInviteEmail failed")
		} else {
			invited = true
		}
	}

	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	utils.WriteJsonWithStatusCode(w, ServerCreateUserResponse{
		User:    core.ToUserResource(user),
		Created: created,
		Roles:   slugs,
		Invited: invited,
	}, status)
}

// provisionUser find-or-creates the user in the app's pool, optionally marks
// the email verified, ensures app membership, and assigns the given (already
// resolved) roles. It fires the user.created webhook and an audit log for any
// real change. roleIDs must be pre-resolved by the caller so a bad slug fails
// fast before any writes. Errors are returned raw for the caller to map.
func (handler *RequestHandler) provisionUser(r *http.Request, project *core.Project, app *core.App, email string, emailVerified bool, roleIDs []uuid.UUID) (*core.User, bool, error) {
	ctx := r.Context()

	user, created, err := handler.repo.GetOrCreateUser(ctx, email, app, core.UserSourceInvited)
	if err != nil {
		return nil, false, err
	}

	if emailVerified && user.EmailVerifiedAt == nil {
		now := time.Now().UTC()
		if err := handler.repo.SetUserEmailVerified(ctx, user.ID, now); err != nil {
			return nil, false, err
		}
		user.EmailVerifiedAt = &now
	}

	_, membershipCreated, err := handler.repo.EnsureAppMember(ctx, app.ID, user.ID, core.UserSourceInvited)
	if err != nil {
		return nil, false, err
	}

	if len(roleIDs) > 0 {
		if err := handler.repo.ReplaceUserRoles(ctx, repo.ReplaceUserRolesParams{
			ProjectID: project.ID, AppID: app.ID, UserID: user.ID, RoleIDs: roleIDs, Now: time.Now().UTC(),
		}); err != nil {
			return nil, false, err
		}
	}

	// Fire user.created only for a brand-new identity, matching the admin
	// create path (workspaceAccountsHandler).
	if created {
		handler.dispatchWebhook(app.ID, "user.created", map[string]any{"userId": user.ID, "email": email, "appId": app.ID})
	}

	// Audit any real change, not an idempotent no-op re-provision.
	if created || membershipCreated {
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:    app.WorkspaceID,
			AppID:          &app.ID,
			Event:          core.AuthEventRegisterSuccess,
			Outcome:        core.AuthOutcomeSuccess,
			SubjectUserID:  &user.ID,
			EmailAttempted: email,
			ActorType:      core.AuthActorAPIKey,
			ActorAPIKeyID:  apiKeyActorID(ctx),
			Metadata:       core.RegisterMetadata{Source: core.RegisterSourceAdminAdded},
		})
	}

	return user, created, nil
}

const maxBatchUsers = 100

type ServerBatchCreateUsersRequest struct {
	Emails        []string `json:"emails"`
	EmailVerified bool     `json:"emailVerified"`
	Roles         []string `json:"roles"`
}

type ServerBatchUserResult struct {
	Email   string `json:"email"`
	UserID  string `json:"userId,omitempty"`
	Created bool   `json:"created"`
	Error   string `json:"error,omitempty"`
}

type ServerBatchCreateUsersResponse struct {
	Results []ServerBatchUserResult `json:"results"`
}

// ServerBatchCreateUsers provisions many users in one call, all with the same
// optional role set. Roles are resolved once (a bad slug fails the whole
// request); each email is then provisioned independently and reported in
// results, so one bad email doesn't sink the rest. Idempotent per email.
// POST /x/{workspaceSlug}/api/v1/apps/{appId}/users:batch
func (handler *RequestHandler) ServerBatchCreateUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	project, ok := core.ProjectFromContext(ctx)
	if !ok || project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	var req ServerBatchCreateUsersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if len(req.Emails) == 0 {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if len(req.Emails) > maxBatchUsers {
		WriteErrorf(w, r, "error.batchTooLarge", http.StatusBadRequest, maxBatchUsers)
		return
	}

	// Resolve roles once — a bad slug fails the whole batch (fail-fast before
	// any writes), consistent with the single-create path.
	roleIDs, _, ok := handler.resolveRoleSlugs(w, r, project.ID, req.Roles)
	if !ok {
		return
	}

	results := make([]ServerBatchUserResult, 0, len(req.Emails))
	for _, raw := range req.Emails {
		email, vr := auth.ValidateEmail(raw)
		if !vr.Ok() {
			results = append(results, ServerBatchUserResult{Email: raw, Error: "error.invalidEmail"})
			continue
		}
		user, created, err := handler.provisionUser(r, project, app, email, req.EmailVerified, roleIDs)
		if err != nil {
			log.Err(err).Str("email", email).Msg("ServerBatchCreateUsers: provision failed")
			results = append(results, ServerBatchUserResult{Email: email, Error: "error.internalError"})
			continue
		}
		results = append(results, ServerBatchUserResult{Email: email, UserID: user.ID.String(), Created: created})
	}

	utils.WriteJson(w, ServerBatchCreateUsersResponse{Results: results})
}

type ServerRemoveUserResponse struct {
	RemovedFromApp  bool `json:"removedFromApp"`
	IdentityDeleted bool `json:"identityDeleted"`
}

// ServerRemoveUser removes a user from this app. If that leaves the user with
// no remaining app memberships, the pool identity is deleted too (orphan
// prune); otherwise the identity is kept because it's still used by another
// app sharing the pool. The response says which happened.
// DELETE /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}
func (handler *RequestHandler) ServerRemoveUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	project, ok := core.ProjectFromContext(ctx)
	if !ok || project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}

	if !handler.requireAppMember(w, r, app.ID, userID) {
		return
	}

	// Capture the email before any deletion, for the user.delete webhook
	// (best-effort — the row is about to potentially go away).
	var email string
	if u, _ := handler.repo.GetUserByID(ctx, userID); u != nil {
		email = u.Email
	}

	if err := handler.removeAppMembership(ctx, project.ID, app.ID, userID); err != nil {
		log.Err(err).Msg("ServerRemoveUser: remove membership failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Orphan prune: delete the identity only if the user now belongs to no
	// app. The guard lives in the DELETE predicate, so it's atomic against a
	// concurrent re-add.
	identityDeleted, err := handler.repo.DeleteUserIfOrphanInPool(ctx, userID, app.UserPoolID)
	if err != nil {
		log.Err(err).Msg("ServerRemoveUser: orphan prune failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if identityDeleted {
		handler.dispatchWebhook(app.ID, "user.delete", map[string]any{"userId": userID, "email": email, "appId": app.ID})
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:   app.WorkspaceID,
			AppID:         &app.ID,
			Event:         core.AuthEventAccountDeleted,
			Outcome:       core.AuthOutcomeSuccess,
			SubjectUserID: &userID,
			ActorType:     core.AuthActorAPIKey,
			ActorAPIKeyID: apiKeyActorID(ctx),
		})
	}

	utils.WriteJson(w, ServerRemoveUserResponse{RemovedFromApp: true, IdentityDeleted: identityDeleted})
}

type ServerSetUserStatusRequest struct {
	Status string `json:"status"` // "active" | "disabled"
}

type ServerUserStatusResponse struct {
	UserID string `json:"userId"`
	Status string `json:"status"`
}

// ServerSetUserStatus suspends or re-enables a user IN THIS APP by setting the
// app_users membership status. A disabled member is blocked from signing in to
// this app (enforced in ResolveSignInIdentity) while staying untouched in any
// sibling app that shares the pool. Disabling also revokes the app's live
// sessions so the change takes effect immediately.
// PATCH /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}
func (handler *RequestHandler) ServerSetUserStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}

	var req ServerSetUserStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	status := core.AppUserStatus(strings.TrimSpace(req.Status))
	if status != core.AppUserStatusActive && status != core.AppUserStatusDisabled {
		WriteError(w, r, "error.invalidStatus", http.StatusBadRequest)
		return
	}

	// Load the membership both to gate (must be a member of this app) and to
	// capture the prior status for the audit row.
	member, err := handler.repo.GetAppUser(ctx, app.ID, userID)
	if err != nil {
		log.Err(err).Msg("ServerSetUserStatus: GetAppUser failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if member == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if member.Status == status {
		// No-op: report current state without re-writing or auditing.
		utils.WriteJson(w, ServerUserStatusResponse{UserID: userID.String(), Status: string(status)})
		return
	}

	if err := handler.repo.SetAppUserStatus(ctx, app.ID, userID, status); err != nil {
		log.Err(err).Msg("ServerSetUserStatus: SetAppUserStatus failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Disabling cuts access; revoke the app's live sessions so it's immediate.
	if status == core.AppUserStatusDisabled {
		if n, err := handler.repo.DeleteClientSessionsByUserAndApp(ctx, userID, app.ID); err != nil {
			log.Err(err).Msg("ServerSetUserStatus: revoke sessions failed")
		} else if n > 0 {
			log.Info().Int64("deleted", n).Str("userId", userID.String()).Str("appId", app.ID.String()).
				Msg("Revoked sessions after disabling app member")
		}
	}

	handler.writeAuthLogFromRequest(r, AuthLogInput{
		WorkspaceID:   app.WorkspaceID,
		AppID:         &app.ID,
		Event:         core.AuthEventAccountStatusChanged,
		Outcome:       core.AuthOutcomeSuccess,
		SubjectUserID: &userID,
		ActorType:     core.AuthActorAPIKey,
		ActorAPIKeyID: apiKeyActorID(ctx),
		Metadata:      core.AccountStatusChangedMetadata{From: string(member.Status), To: string(status)},
	})

	utils.WriteJson(w, ServerUserStatusResponse{UserID: userID.String(), Status: string(status)})
}
