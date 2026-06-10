package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

type ServerUserResponse struct {
	User        *core.UserResource    `json:"user"`
	Roles       []string              `json:"roles"`
	Permissions []string              `json:"permissions"`
	Fields      []core.UserFieldValue `json:"fields,omitempty"`
}

// HandleServerGetUser serves GET /x/{workspaceSlug}/api/v1/apps/{appId}/users.
// With ?email=<addr> it returns that one member (deep: roles, permissions,
// fields) — email is unique within the pool, so it's a single-result lookup.
// With no email it lists the app's members (paginated, ?search= substring
// filter); see ServerGetAppMembers.
func (handler *RequestHandler) HandleServerGetUser(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("email")))
	if email == "" {
		handler.ServerGetAppMembers(w, r)
		return
	}

	ctx := r.Context()
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	user, err := handler.repo.GetUserByEmail(ctx, email, app)
	if err != nil {
		log.Err(err).Msg("HandleServerGetUser: lookup by email failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	handler.respondServerUser(w, r, user)
}

// ServerGetUserByID serves GET /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}
// — one member by ID (deep).
func (handler *RequestHandler) ServerGetUserByID(w http.ResponseWriter, r *http.Request) {
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}

	user, err := handler.repo.GetUserByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerGetUserByID: lookup failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	handler.respondServerUser(w, r, user)
}

// respondServerUser gates the resolved user to app membership and writes the
// deep user response. The server API scopes to app membership: the pool only
// shares credentials, so a pool user who hasn't joined this app — including a
// foreign-pool id — gets 404 here.
func (handler *RequestHandler) respondServerUser(w http.ResponseWriter, r *http.Request, user *core.User) {
	ctx := r.Context()

	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}
	project, ok := core.ProjectFromContext(ctx)
	if !ok || project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return
	}

	if user == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if !handler.requireAppMember(w, r, app.ID, user.ID) {
		return
	}

	roles, permissions, _ := handler.resolveRolesAndPermissions(ctx, project.ID, user.ID, app.ID)
	fields, _ := handler.repo.GetUserFieldValuesByUser(ctx, user.ID)

	resp := ServerUserResponse{
		User:        core.ToUserResource(user),
		Roles:       roles,
		Permissions: permissions,
		Fields:      fields,
	}
	if resp.Roles == nil {
		resp.Roles = []string{}
	}
	if resp.Permissions == nil {
		resp.Permissions = []string{}
	}
	if resp.Fields == nil {
		resp.Fields = []core.UserFieldValue{}
	}

	utils.WriteJsonWithStatusCode(w, resp, http.StatusOK)
}

// ---------------------------------------------------------------------------
// Bulk email lookup
// ---------------------------------------------------------------------------

const maxLookupUsers = 1000 // reads are one indexed query; deliberately larger than maxBatchUsers

// ServerUsersLookupRequest is the request body for the :lookup custom method.
type ServerUsersLookupRequest struct {
	Emails []string `json:"emails"`
}

// ServerUsersLookupResponse is the response body for the :lookup custom method.
type ServerUsersLookupResponse struct {
	Users   []*core.UserResource `json:"users"`
	Missing []string             `json:"missing"`
}

// ServerUsersLookup resolves up to maxLookupUsers emails to user resources
// in one call. Read-only despite the POST verb (Google-style custom method
// — the body carries the email list; see the :lookup exception in the API
// key scope gate). Duplicate emails dedupe silently; unknown emails are
// reported in "missing" (normalized form).
// POST /x/{workspaceSlug}/api/v1/apps/{appId}/users:lookup
func (handler *RequestHandler) ServerUsersLookup(w http.ResponseWriter, r *http.Request) {
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

	var req ServerUsersLookupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if len(req.Emails) == 0 {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if len(req.Emails) > maxLookupUsers {
		WriteErrorf(w, r, "error.batchTooLarge", http.StatusBadRequest, maxLookupUsers)
		return
	}

	// Normalize and dedupe (preserve first-seen order).
	seen := make(map[string]struct{}, len(req.Emails))
	normalized := make([]string, 0, len(req.Emails))
	for _, raw := range req.Emails {
		email, vr := auth.ValidateEmail(raw)
		if !vr.Ok() {
			// Invalid emails are treated as unknown (they can never match).
			email = strings.TrimSpace(strings.ToLower(raw))
		}
		if email == "" {
			continue
		}
		if _, dup := seen[email]; dup {
			continue
		}
		seen[email] = struct{}{}
		normalized = append(normalized, email)
	}

	users, err := handler.repo.GetUsersByEmails(ctx, app, normalized)
	if err != nil {
		log.Err(err).Msg("ServerUsersLookup: GetUsersByEmails failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Build found set and resources slice.
	foundSet := make(map[string]struct{}, len(users))
	resources := make([]*core.UserResource, 0, len(users))
	for _, u := range users {
		foundSet[strings.ToLower(u.Email)] = struct{}{}
		resources = append(resources, core.ToUserResource(u))
	}

	// Missing = normalized emails not in found set.
	missing := make([]string, 0)
	for _, e := range normalized {
		if _, found := foundSet[e]; !found {
			missing = append(missing, e)
		}
	}

	resp := ServerUsersLookupResponse{
		Users:   resources,
		Missing: missing,
	}
	if resp.Users == nil {
		resp.Users = []*core.UserResource{}
	}
	utils.WriteJsonWithStatusCode(w, resp, http.StatusOK)
}
