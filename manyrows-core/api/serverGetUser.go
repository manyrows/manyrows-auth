package api

import (
	"errors"
	"net/http"
	"strings"

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
	project, ok := core.ProductFromContext(ctx)
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
