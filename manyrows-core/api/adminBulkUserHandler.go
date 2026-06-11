package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"

	"manyrows-core/core"
	"manyrows-core/utils"
)

type bulkUserRequest struct {
	Action  string   `json:"action"`
	UserIDs []string `json:"userIds"`
	Enabled *bool    `json:"enabled"`
}

type bulkUserResult struct {
	UserID string `json:"userId"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

// HandleAdminBulkUserAction fans a single recovery action out over many app
// users. Best-effort: a per-user failure is recorded, not aborted. Each
// action reuses the same repo effects as its single-user counterpart.
// POST /admin/workspace/{workspaceId}/projects/{projectId}/apps/{appId}/users:bulk
func (handler *RequestHandler) HandleAdminBulkUserAction(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wsID, _, appID, ok := handler.parseAppContext(w, r)
	if !ok {
		return
	}

	var req bulkUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	switch req.Action {
	case "unlock", "resetTotp", "clearPassword", "setStatus":
	default:
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if req.Action == "setStatus" && req.Enabled == nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if len(req.UserIDs) == 0 || len(req.UserIDs) > maxBatchUsers {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	seen := make(map[string]bool, len(req.UserIDs))
	results := make([]bulkUserResult, 0, len(req.UserIDs))
	succeeded, failed := 0, 0

	for _, idStr := range req.UserIDs {
		if seen[idStr] {
			continue
		}
		seen[idStr] = true

		res := bulkUserResult{UserID: idStr}
		uid, err := uuid.FromString(idStr)
		if err != nil {
			res.Error = "invalid id"
			results, failed = append(results, res), failed+1
			continue
		}
		user, found, lookupErr := handler.lookupUserScopedToApp(ctx, appID, uid)
		if lookupErr != nil || !found {
			// Both a transient load error and a genuine miss are recorded
			// as a per-user failure; a transient error on one user must not
			// abort the rest of the batch (best-effort).
			res.Error = "not found"
			results, failed = append(results, res), failed+1
			continue
		}

		// Capture the prior enabled state before applying — the setStatus
		// audit log only fires when the status actually changes (mirrors the
		// single-user HandleSetWorkspaceAccountStatus handler).
		wasEnabled := user.Enabled

		if err := handler.applyBulkUserAction(ctx, req.Action, appID, user, req.Enabled); err != nil {
			log.Err(err).Str("action", req.Action).Str("user_id", idStr).Msg("bulk user action failed")
			res.Error = "internal error"
			results, failed = append(results, res), failed+1
			continue
		}

		// On success, emit the same per-user auth-log entry the single-user
		// admin handlers write so bulk recovery leaves an identical audit
		// trail. unlock/resetTotp single-user handlers don't log, so only
		// clearPassword/setStatus are mirrored here.
		handler.logBulkUserAction(r, wsID, req.Action, user.ID, wasEnabled, req.Enabled)

		res.OK = true
		results, succeeded = append(results, res), succeeded+1
	}

	utils.WriteJsonWithStatusCode(w, map[string]any{
		"results":   results,
		"succeeded": succeeded,
		"failed":    failed,
	}, http.StatusOK)
}

// logBulkUserAction writes the per-user auth-log row that mirrors the
// single-user admin handlers, for the actions that log:
//   - clearPassword -> AuthEventPasswordCleared (always, on success)
//   - setStatus     -> AuthEventAccountStatusChanged (only when the
//     enabled state actually changes), matching
//     HandleSetWorkspaceAccountStatus / HandleClearUserPassword.
//
// unlock and resetTotp are intentionally not logged (their single-user
// counterparts don't log either). Best-effort: writeAuthLogFromRequest
// never blocks the caller on a log-write failure.
func (handler *RequestHandler) logBulkUserAction(
	r *http.Request, wsID uuid.UUID, action string, userID uuid.UUID, wasEnabled bool, enabled *bool,
) {
	var in AuthLogInput
	switch action {
	case "clearPassword":
		in = AuthLogInput{
			WorkspaceID:   wsID,
			Event:         core.AuthEventPasswordCleared,
			Outcome:       core.AuthOutcomeSuccess,
			SubjectUserID: &userID,
			ActorType:     core.AuthActorAdmin,
		}
	case "setStatus":
		if enabled == nil || wasEnabled == *enabled {
			return
		}
		in = AuthLogInput{
			WorkspaceID:   wsID,
			Event:         core.AuthEventAccountStatusChanged,
			Outcome:       core.AuthOutcomeSuccess,
			SubjectUserID: &userID,
			ActorType:     core.AuthActorAdmin,
			Metadata: core.AccountStatusChangedMetadata{
				From: statusLabel(wasEnabled),
				To:   statusLabel(*enabled),
			},
		}
	default:
		return
	}
	if admin, ok := core.AdminAccountFromContext(r.Context()); ok && admin != nil {
		in.ActorAccountID = &admin.ID
		in.ActorLabel = admin.Email
	}
	handler.writeAuthLogFromRequest(r, in)
}

// applyBulkUserAction performs one recovery action against one user. Each
// branch replicates the side-effects of its single-user admin handler
// counterpart (see adminUserRecoveryHandler.go / workspaceAccountsHandler.go).
func (handler *RequestHandler) applyBulkUserAction(ctx context.Context, action string, appID uuid.UUID, user *core.User, enabled *bool) error {
	switch action {
	case "unlock":
		return handler.unlockUserAccount(ctx, user)
	case "resetTotp":
		if err := handler.repo.DisableUserTOTP(ctx, user.ID); err != nil {
			return err
		}
		handler.dispatchMFAEvent(whMFADisabled, appID, user.ID)
		return nil
	case "clearPassword":
		if err := handler.repo.ClearUserPassword(ctx, user.ID); err != nil {
			return err
		}
		if _, err := handler.repo.DeleteClientSessionsByUser(ctx, user.ID, nil); err != nil {
			log.Err(err).Str("user_id", user.ID.String()).Msg("bulk clearPassword: session revoke failed (non-fatal)")
		}
		return nil
	case "setStatus":
		if err := handler.repo.SetUserEnabled(ctx, user.ID, *enabled); err != nil {
			return err
		}
		if !*enabled {
			if _, err := handler.repo.DeleteClientSessionsByUser(ctx, user.ID, nil); err != nil {
				log.Err(err).Str("user_id", user.ID.String()).Msg("bulk setStatus disable: session revoke failed (non-fatal)")
			}
		}
		return nil
	}
	return nil
}
