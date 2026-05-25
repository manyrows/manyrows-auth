package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	emailpkg "manyrows-core/email"
	"manyrows-core/utils"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// HandleGetWorkspaceAccounts lists users in the workspace (paginated).
// GET /admin/workspace/{workspaceId}/accounts
func (handler *RequestHandler) HandleGetWorkspaceAccounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	// Optional filters: productId or poolId, plus an email substring.
	//
	// Pagination is opt-in via page/pageSize: when either is present we
	// return a page slice plus a real `total` (full filtered count).
	// When absent we keep the legacy behaviour — return every matching
	// row, with the optional `limit` cap still honoured for the
	// add-user autocomplete — so existing/unmigrated callers are
	// unaffected.
	q := r.URL.Query()
	emailQuery := strings.TrimSpace(q.Get("email"))

	limit := 0
	offset := 0
	paginated := false
	if s := strings.TrimSpace(q.Get("pageSize")); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		if n > 200 {
			n = 200
		}
		limit = n
		paginated = true
	}
	page := 0
	if s := strings.TrimSpace(q.Get("page")); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		page = n
		paginated = true
	}
	if paginated {
		if limit <= 0 {
			limit = 50 // page given without an explicit pageSize
		}
		offset = page * limit
	} else if s := strings.TrimSpace(q.Get("limit")); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}

	var users []core.User
	total := 0
	if poolIDStr := strings.TrimSpace(q.Get("poolId")); poolIDStr != "" {
		poolID, err := uuid.FromString(poolIDStr)
		if err != nil {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		// Pool must belong to this workspace. Otherwise an admin in
		// workspace A could enumerate users in workspace B by guessing
		// a poolId.
		pool, err := handler.repo.GetUserPoolByID(ctx, poolID)
		if err != nil || pool == nil || pool.WorkspaceID != ws.ID {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		users, err = handler.repo.ListUsersInPool(ctx, poolID, emailQuery, limit, offset)
		if err != nil {
			log.Error().Err(err).Msg("failed to list pool users")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if paginated {
			total, err = handler.repo.CountUsersInPool(ctx, poolID, emailQuery)
			if err != nil {
				log.Error().Err(err).Msg("failed to count pool users")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
		}
	} else if productIDStr := strings.TrimSpace(q.Get("productId")); productIDStr != "" {
		productID, err := uuid.FromString(productIDStr)
		if err != nil {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		users, err = handler.repo.ListUsersInProduct(ctx, productID, ws.ID, emailQuery, limit, offset)
		if err != nil {
			log.Error().Err(err).Msg("failed to list project users")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if paginated {
			total, err = handler.repo.CountUsersInProduct(ctx, productID, ws.ID, emailQuery)
			if err != nil {
				log.Error().Err(err).Msg("failed to count project users")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
		}
	} else {
		var err error
		users, err = handler.repo.ListUsersInWorkspace(ctx, ws.ID, emailQuery, limit, offset)
		if err != nil {
			log.Error().Err(err).Msg("failed to list workspace members")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if paginated {
			total, err = handler.repo.CountUsersInWorkspace(ctx, ws.ID, emailQuery)
			if err != nil {
				log.Error().Err(err).Msg("failed to count workspace members")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
		}
	}

	// Get app access per user (single query).
	appAccess, err := handler.repo.GetUserAppAccessForWorkspace(ctx, ws.ID)
	if err != nil {
		log.Error().Err(err).Msg("failed to get user app access")
		// Non-fatal — return users without app info.
		appAccess = nil
	}

	// Resolve pool names in one shot so each row's scope can show the
	// pool's display name, not just the UUID.
	poolNameByID := map[uuid.UUID]string{}
	if pools, err := handler.repo.ListUserPoolsByWorkspace(ctx, ws.ID); err == nil {
		for _, p := range pools {
			poolNameByID[p.ID] = p.Name
		}
	}

	type appRef struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		ProductID string `json:"productId"`
	}
	type scopeRef struct {
		Type     string  `json:"type"` // "pool" post user-pool refactor
		PoolID   *string `json:"poolId,omitempty"`
		PoolName string  `json:"poolName,omitempty"`
	}
	type accountResponse struct {
		ID              string     `json:"id"`
		Email           string     `json:"email"`
		Enabled         bool       `json:"enabled"`
		CreatedAt       string     `json:"createdAt"`
		LastLoginAt     *string    `json:"lastLoginAt,omitempty"`
		EmailVerifiedAt *string    `json:"emailVerifiedAt,omitempty"`
		PasswordSetAt   *string    `json:"passwordSetAt,omitempty"`
		Source          string     `json:"source,omitempty"`
		Apps            []appRef   `json:"apps"`
		Scopes          []scopeRef `json:"scopes,omitempty"`
	}

	accounts := make([]accountResponse, 0, len(users))
	for _, u := range users {
		var apps []appRef
		if access, ok := appAccess[u.ID]; ok {
			apps = make([]appRef, 0, len(access))
			for _, a := range access {
				apps = append(apps, appRef{ID: a.AppID.String(), Name: a.AppName, ProductID: a.ProductID.String()})
			}
		}
		if apps == nil {
			apps = []appRef{}
		}
		// Each user is pool-scoped. Returned as a single-element array
		// for forward-compat with existing UI consumers; the "apps"
		// field above lists per-app membership separately.
		poolIDStr := u.UserPoolID.String()
		scopes := []scopeRef{{
			Type:     "pool",
			PoolID:   &poolIDStr,
			PoolName: poolNameByID[u.UserPoolID],
		}}

		acc := accountResponse{
			ID:        u.ID.String(),
			Email:     u.Email,
			Enabled:   u.Enabled,
			CreatedAt: u.CreatedAt.Format(time.RFC3339),
			Source:    string(u.Source),
			Apps:      apps,
			Scopes:    scopes,
		}
		if u.LastLoginAt != nil && !u.LastLoginAt.IsZero() {
			s := u.LastLoginAt.Format(time.RFC3339)
			acc.LastLoginAt = &s
		}
		if u.EmailVerifiedAt != nil && !u.EmailVerifiedAt.IsZero() {
			s := u.EmailVerifiedAt.Format(time.RFC3339)
			acc.EmailVerifiedAt = &s
		}
		if u.PasswordSetAt != nil && !u.PasswordSetAt.IsZero() {
			s := u.PasswordSetAt.Format(time.RFC3339)
			acc.PasswordSetAt = &s
		}
		accounts = append(accounts, acc)
	}

	// Non-paginated callers get the legacy meaning of total: rows
	// returned. Paginated callers get the full filtered count so the
	// client can size its pager.
	if !paginated {
		total = len(accounts)
	}
	resp := map[string]any{
		"accounts": accounts,
		"total":    total,
	}

	utils.WriteJson(w, resp)
}

// HandleCreateWorkspaceAccount creates a user (invited) for an app.
// POST /admin/workspace/{workspaceId}/accounts
func (handler *RequestHandler) HandleCreateWorkspaceAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		Email      string      `json:"email"`
		AppID      uuid.UUID   `json:"appId"`
		SendInvite bool        `json:"sendInvite"`
		RoleIDs    []uuid.UUID `json:"roleIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(strings.ToLower(body.Email))

	// Validate email
	if _, err := mail.ParseAddress(email); err != nil {
		utils.WriteJsonWithStatusCode(w, map[string]any{
			"error": "valid email is required",
			"field": "email",
		}, http.StatusBadRequest)
		return
	}

	if body.AppID == uuid.Nil {
		utils.WriteJsonWithStatusCode(w, map[string]any{
			"error": "appId is required",
			"field": "appId",
		}, http.StatusBadRequest)
		return
	}

	// Check plan limits
	// Load the app for scope-aware user lookup
	loadedApp, err := handler.repo.GetAppByID(ctx, body.AppID)
	// Scope the body-supplied appId to the caller's workspace. The
	// workspace middleware only proves membership in the path workspace,
	// not that this app belongs to it; without this an admin of one
	// workspace could provision users/roles into — and fire webhooks for
	// — another workspace's app. Collapse not-found and cross-workspace
	// into a single 404 so we don't reveal apps in other workspaces.
	if err != nil || loadedApp.WorkspaceID != ws.ID {
		if err != nil && !errors.Is(err, repo.ErrNotFound) {
			log.Error().Err(err).Msg("failed to load app")
		}
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	// Resolve roles. Optional now (zero roles is a valid invite); when
	// neither admin-supplied nor the app's DefaultRoleID is set, the
	// user gets a membership row with no roles and the customer
	// backend decides what a roleless token can do.
	roleIDs, err := handler.resolveInviteRoles(ctx, &loadedApp, body.RoleIDs)
	if err != nil {
		WriteError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	// Ensure the pool-level identity exists.
	user, created, err := handler.repo.GetOrCreateUser(ctx, email, &loadedApp, core.UserSourceInvited)
	if err != nil {
		log.Error().Err(err).Msg("failed to create user")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Ensure the per-app membership row. Idempotent: if the user is
	// already a member (e.g. re-invite), the existing row's status and
	// source are preserved.
	if _, _, err := handler.repo.EnsureAppMember(ctx, loadedApp.ID, user.ID, core.UserSourceInvited); err != nil {
		log.Error().Err(err).Msg("failed to create app membership")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Replace role rows for this membership. Empty roleIDs is valid -
	// the user is still a member, just with no roles assigned.
	if err := handler.repo.ReplaceUserRoles(ctx, repo.ReplaceUserRolesParams{
		ProductID: loadedApp.ProductID,
		AppID:     loadedApp.ID,
		UserID:    user.ID,
		RoleIDs:   roleIDs,
		Now:       time.Now().UTC(),
	}); err != nil {
		log.Error().Err(err).Msg("failed to assign invite roles")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if created {
		handler.dispatchWebhook(loadedApp.ID, "user.created", map[string]any{"userId": user.ID, "email": email, "appId": loadedApp.ID})
	}

	// Send the invite email if requested. Done synchronously (before the
	// response) so a delivery failure is reported back to the caller
	// instead of being silently swallowed in a goroutine — the
	// membership is created either way; only the email outcome varies.
	inviteSent := false
	inviteErr := ""
	if body.SendInvite {
		if loadedApp.AppURL == nil || *loadedApp.AppURL == "" {
			inviteErr = "App URL is not configured for this app — set it in app settings to send invite emails."
		} else if err := handler.sendUserInviteEmail(ctx, ws.ID, email, loadedApp.DisplayName(), *loadedApp.AppURL, GetLanguageFromRequest(r)); err != nil {
			log.Error().Err(err).Str("email", email).Msg("failed to send invite email")
			inviteErr = err.Error()
		} else {
			inviteSent = true
		}
	}

	// Return user (created or existing)
	resp := map[string]any{
		"id":        user.ID.String(),
		"email":     user.Email,
		"created":   created,
		"createdAt": user.CreatedAt.Format(time.RFC3339),
	}
	if body.SendInvite {
		resp["inviteEmailSent"] = inviteSent
		if inviteErr != "" {
			resp["inviteEmailError"] = inviteErr
		}
	}

	utils.WriteJsonWithStatusCode(w, resp, http.StatusCreated)
}

// HandleBulkImportWorkspaceAccounts imports multiple users at once.
// POST /admin/workspace/{workspaceId}/accounts/bulk-import
func (handler *RequestHandler) HandleBulkImportWorkspaceAccounts(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	// Any workspace admin may bulk-import, matching single-user create
	// (HandleCreateWorkspaceAccount) — bulk import is just non-destructive
	// creation, so gating it to owner-only was an inconsistency.

	ctx := r.Context()

	var body struct {
		AppID    uuid.UUID   `json:"appId"`
		RoleIDs  []uuid.UUID `json:"roleIds"`
		Accounts []struct {
			Email string `json:"email"`
		} `json:"accounts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	if body.AppID == uuid.Nil {
		utils.WriteJsonWithStatusCode(w, map[string]any{
			"error": "appId is required",
		}, http.StatusBadRequest)
		return
	}

	if len(body.Accounts) > 1000 {
		utils.WriteJsonWithStatusCode(w, map[string]any{
			"error": "maximum 1000 accounts per request",
		}, http.StatusBadRequest)
		return
	}

	// Load the app for scope-aware user lookup
	bulkApp, err := handler.repo.GetAppByID(ctx, body.AppID)
	// Scope the body-supplied appId to the caller's workspace — see
	// HandleCreateWorkspaceAccount. Blocks cross-workspace bulk
	// provisioning (up to 1000 users/roles + webhook fan-out per call).
	if err != nil || bulkApp.WorkspaceID != ws.ID {
		if err != nil && !errors.Is(err, repo.ErrNotFound) {
			log.Error().Err(err).Msg("failed to load app for bulk import")
		}
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	// Resolve once for the whole batch — every imported user gets the
	// same role assignment. See HandleCreateWorkspaceAccount for the
	// reasoning behind requiring a role at write time.
	bulkRoleIDs, err := handler.resolveInviteRoles(ctx, &bulkApp, body.RoleIDs)
	if err != nil {
		WriteError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	type failureEntry struct {
		Email  string `json:"email"`
		Reason string `json:"reason"`
		Row    int    `json:"row"`
	}

	imported := 0
	skipped := 0
	failed := 0
	var failures []failureEntry

	for i, entry := range body.Accounts {
		email := strings.TrimSpace(strings.ToLower(entry.Email))

		if _, err := mail.ParseAddress(email); err != nil {
			failed++
			failures = append(failures, failureEntry{
				Email:  entry.Email,
				Reason: "invalid email format",
				Row:    i + 1,
			})
			continue
		}

		bulkUser, created, err := handler.repo.GetOrCreateUser(ctx, email, &bulkApp, core.UserSourceInvited)
		if err != nil {
			failed++
			failures = append(failures, failureEntry{
				Email:  email,
				Reason: "internal error",
				Row:    i + 1,
			})
			log.Error().Err(err).Str("email", email).Msg("failed to create user during bulk import")
			continue
		}

		if _, _, err := handler.repo.EnsureAppMember(ctx, bulkApp.ID, bulkUser.ID, core.UserSourceInvited); err != nil {
			failed++
			failures = append(failures, failureEntry{
				Email:  email,
				Reason: "membership creation failed",
				Row:    i + 1,
			})
			log.Error().Err(err).Str("email", email).Msg("failed to create app membership during bulk import")
			continue
		}

		if err := handler.repo.ReplaceUserRoles(ctx, repo.ReplaceUserRolesParams{
			ProductID: bulkApp.ProductID,
			AppID:     bulkApp.ID,
			UserID:    bulkUser.ID,
			RoleIDs:   bulkRoleIDs,
			Now:       time.Now().UTC(),
		}); err != nil {
			failed++
			failures = append(failures, failureEntry{
				Email:  email,
				Reason: "role assignment failed",
				Row:    i + 1,
			})
			log.Error().Err(err).Str("email", email).Msg("failed to assign roles during bulk import")
			continue
		}

		if created {
			imported++
			// Match the single-create path (and S2S): notify integrations of
			// each new identity. dispatchWebhook is fire-and-forget, and an
			// app with no webhooks (the common case) makes this nearly free.
			handler.dispatchWebhook(bulkApp.ID, "user.created", map[string]any{"userId": bulkUser.ID, "email": email, "appId": bulkApp.ID})
		} else {
			skipped++
		}
	}

	summary := map[string]any{
		"imported": imported,
		"skipped":  skipped,
		"failed":   failed,
		"total":    len(body.Accounts),
		"failures": failures,
	}

	utils.WriteJsonWithStatusCode(w, summary, http.StatusCreated)
}

// requireUserInWorkspace loads an end-user by ID and confirms they belong to a
// user pool owned by wsID. Users carry no workspace_id of their own (tenant is
// transitive via user_pool_id -> user_pools.workspace_id), so the flat
// /accounts/{accountId} routes MUST gate on this — otherwise an admin of one
// workspace could read/mutate any user on the install by id. A foreign-tenant
// or unknown id yields 404.
func (handler *RequestHandler) requireUserInWorkspace(w http.ResponseWriter, r *http.Request, wsID, userID uuid.UUID) (*core.User, bool) {
	user, err := handler.repo.GetUserByID(r.Context(), userID)
	if err != nil || user == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return nil, false
	}
	pool, err := handler.repo.GetUserPoolByID(r.Context(), user.UserPoolID)
	if err != nil || pool == nil || pool.WorkspaceID != wsID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return nil, false
	}
	return user, true
}

// HandleDeleteWorkspaceAccount deletes a user by ID.
// DELETE /admin/workspace/{workspaceId}/accounts/{accountId}
func (handler *RequestHandler) HandleDeleteWorkspaceAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	accountIDStr := chi.URLParam(r, "accountId")
	accountID, err := uuid.FromString(accountIDStr)
	if err != nil {
		WriteError(w, r, "error.invalidAccountId", http.StatusBadRequest)
		return
	}

	// Scope the target to this workspace (users carry no workspace_id), then
	// capture email before delete so the auth-log row carries it.
	user, ok := handler.requireUserInWorkspace(w, r, ws.ID, accountID)
	if !ok {
		return
	}
	subjectEmail := user.Email

	// Delete the user (cascades to profiles and sessions)
	if err := handler.repo.DeleteUser(ctx, accountID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Msg("failed to delete user")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	in := AuthLogInput{
		WorkspaceID:    ws.ID,
		Event:          core.AuthEventAccountDeleted,
		Outcome:        core.AuthOutcomeSuccess,
		SubjectUserID:  &accountID,
		EmailAttempted: subjectEmail,
		ActorType:      core.AuthActorAdmin,
	}
	if admin, ok := core.AdminAccountFromContext(ctx); ok && admin != nil {
		in.ActorAccountID = &admin.ID
		in.ActorLabel = admin.Email
	}
	handler.writeAuthLogFromRequest(r, in)

	w.WriteHeader(http.StatusNoContent)
}

// HandleGetWorkspaceAccount returns a single user by ID.
// GET /admin/workspace/{workspaceId}/accounts/{accountId}
func (handler *RequestHandler) HandleGetWorkspaceAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	accountIDStr := chi.URLParam(r, "accountId")
	accountID, err := uuid.FromString(accountIDStr)
	if err != nil {
		WriteError(w, r, "error.invalidAccountId", http.StatusBadRequest)
		return
	}

	user, ok := handler.requireUserInWorkspace(w, r, ws.ID, accountID)
	if !ok {
		return
	}

	resp := map[string]any{
		"id":        user.ID.String(),
		"email":     user.Email,
		"createdAt": user.CreatedAt.Format(time.RFC3339),
	}

	utils.WriteJson(w, resp)
}

// HandleUpdateWorkspaceAccount updates a user (email only in new model).
// PATCH /admin/workspace/{workspaceId}/accounts/{accountId}
func (handler *RequestHandler) HandleUpdateWorkspaceAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	accountIDStr := chi.URLParam(r, "accountId")
	accountID, err := uuid.FromString(accountIDStr)
	if err != nil {
		WriteError(w, r, "error.invalidAccountId", http.StatusBadRequest)
		return
	}

	var body struct{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	// Scope the target to this workspace.
	user, ok := handler.requireUserInWorkspace(w, r, ws.ID, accountID)
	if !ok {
		return
	}

	resp := map[string]any{
		"id":        user.ID.String(),
		"email":     user.Email,
		"createdAt": user.CreatedAt.Format(time.RFC3339),
	}

	utils.WriteJson(w, resp)
}

// HandleSetWorkspaceAccountStatus enables or disables a user.
// PATCH /admin/workspace/{workspaceId}/accounts/{accountId}/status
func (handler *RequestHandler) HandleSetWorkspaceAccountStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	accountIDStr := chi.URLParam(r, "accountId")
	accountID, err := uuid.FromString(accountIDStr)
	if err != nil {
		WriteError(w, r, "error.invalidAccountId", http.StatusBadRequest)
		return
	}

	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if body.Enabled == nil {
		utils.WriteJsonWithStatusCode(w, map[string]any{
			"error": "enabled is required",
		}, http.StatusBadRequest)
		return
	}

	user, ok := handler.requireUserInWorkspace(w, r, ws.ID, accountID)
	if !ok {
		return
	}

	wasEnabled := user.Enabled

	if err := handler.repo.SetUserEnabled(ctx, accountID, *body.Enabled); err != nil {
		log.Error().Err(err).Msg("failed to set user enabled")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// If disabling, revoke all active sessions
	if !*body.Enabled {
		if _, err := handler.repo.DeleteClientSessionsByUser(ctx, accountID, nil); err != nil {
			log.Error().Err(err).Msg("failed to delete sessions for disabled user")
		}
	}

	if wasEnabled != *body.Enabled {
		in := AuthLogInput{
			WorkspaceID:   ws.ID,
			Event:         core.AuthEventAccountStatusChanged,
			Outcome:       core.AuthOutcomeSuccess,
			SubjectUserID: &accountID,
			ActorType:     core.AuthActorAdmin,
			Metadata: core.AccountStatusChangedMetadata{
				From: statusLabel(wasEnabled),
				To:   statusLabel(*body.Enabled),
			},
		}
		if admin, ok := core.AdminAccountFromContext(ctx); ok && admin != nil {
			in.ActorAccountID = &admin.ID
			in.ActorLabel = admin.Email
		}
		handler.writeAuthLogFromRequest(r, in)
	}

	utils.WriteJson(w, map[string]any{
		"id":      user.ID.String(),
		"email":   user.Email,
		"enabled": *body.Enabled,
	})
}

func statusLabel(enabled bool) string {
	if enabled {
		return "active"
	}
	return "disabled"
}

// HandleClearUserPassword unsets the user's password. After this, the
// user can no longer sign in via email+password until they go through
// /auth/forgot-password to set a new one. OAuth + passkey sign-in are
// unaffected. Useful for support workflows where a user is locked out
// of their account.
//
// All active client sessions are revoked too so any in-flight bearer
// tokens lose authority — important so the workflow doesn't accidentally
// leave a session belonging to an attacker who set a backdoor password.
//
// DELETE /admin/workspace/{workspaceId}/accounts/{accountId}/password
func (handler *RequestHandler) HandleClearUserPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	accountIDStr := chi.URLParam(r, "accountId")
	accountID, err := uuid.FromString(accountIDStr)
	if err != nil {
		WriteError(w, r, "error.invalidAccountId", http.StatusBadRequest)
		return
	}

	if _, ok := handler.requireUserInWorkspace(w, r, ws.ID, accountID); !ok {
		return
	}

	if err := handler.repo.ClearUserPassword(ctx, accountID); err != nil {
		log.Error().Err(err).Msg("failed to clear user password")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if _, err := handler.repo.DeleteClientSessionsByUser(ctx, accountID, nil); err != nil {
		log.Error().Err(err).Msg("failed to revoke sessions after password clear")
		// Non-fatal — the password is already cleared.
	}

	in := AuthLogInput{
		WorkspaceID:   ws.ID,
		Event:         core.AuthEventPasswordCleared,
		Outcome:       core.AuthOutcomeSuccess,
		SubjectUserID: &accountID,
		ActorType:     core.AuthActorAdmin,
	}
	if admin, ok := core.AdminAccountFromContext(ctx); ok && admin != nil {
		in.ActorAccountID = &admin.ID
		in.ActorLabel = admin.Email
	}
	handler.writeAuthLogFromRequest(r, in)

	utils.WriteJson(w, map[string]any{"ok": true})
}

// resolveInviteRoles decides which role IDs to assign to an invited user.
//
// Roles are optional post user-pool refactor: membership lives in
// app_users now, not in "the user has any user_roles row." If the admin
// supplies roleIds they're validated against the app's project. If they
// don't, the app's DefaultRoleID is applied when set; otherwise the
// invite proceeds with zero roles (the customer's backend decides what
// a roleless token can do).
//
// When roleIds are supplied, each is validated against the app's project
// so the caller can't grant a role from an unrelated project.
func (handler *RequestHandler) resolveInviteRoles(ctx context.Context, app *core.App, requestedRoleIDs []uuid.UUID) ([]uuid.UUID, error) {
	if len(requestedRoleIDs) > 0 {
		seen := make(map[uuid.UUID]struct{}, len(requestedRoleIDs))
		out := make([]uuid.UUID, 0, len(requestedRoleIDs))
		for _, rid := range requestedRoleIDs {
			if rid == uuid.Nil {
				continue
			}
			if _, dup := seen[rid]; dup {
				continue
			}
			if _, err := handler.repo.GetRoleByID(ctx, app.ProductID, rid); err != nil {
				if errors.Is(err, repo.ErrNotFound) {
					return nil, errors.New("error.invalidRole")
				}
				return nil, err
			}
			seen[rid] = struct{}{}
			out = append(out, rid)
		}
		if len(out) > 0 {
			return out, nil
		}
	}

	if app.DefaultRoleID != nil && *app.DefaultRoleID != uuid.Nil {
		return []uuid.UUID{*app.DefaultRoleID}, nil
	}

	return nil, nil
}

// sendUserInviteEmail sends a welcome email to a newly added app user.
func (handler *RequestHandler) sendUserInviteEmail(ctx context.Context, workspaceID uuid.UUID, toEmail, appName, appURL, lang string) error {
	subject := fmt.Sprintf(emailpkg.T(lang, "user_invite.subject"), appName)
	body := fmt.Sprintf(emailpkg.T(lang, "user_invite.body"), appName, appURL)

	e := &emailpkg.Email{
		To:      toEmail,
		From:    emailpkg.WorkspaceFrom(appName),
		Subject: subject,
		Body:    body,
	}
	return handler.sendWorkspaceEmail(ctx, workspaceID, e)
}
