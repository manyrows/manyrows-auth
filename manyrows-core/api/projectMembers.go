package api

import (
	"net/http"
	"strconv"
	"strings"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

type ProjectMembersResponse struct {
	Members []core.MemberResource `json:"members"`

	// paging metadata
	MembersTotal int    `json:"membersTotal"`
	Page         int    `json:"page"`
	PageSize     int    `json:"pageSize"`
	Email        string `json:"email,omitempty"`

	AppID uuid.UUID `json:"appId"`
}

// HandleGetProjectMembers returns ONLY members that have at least one role
// in the given project + app.
// Supports paging + email substring search.
// Query params:
//   - appId (REQUIRED; uuid)
//   - page (0-based)
//   - pageSize
//   - email (substring match on account email)
func (handler *RequestHandler) HandleGetProjectMembers(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProject(w, r)
	if !ok {
		return
	}

	q := r.URL.Query()

	rawEnv := strings.TrimSpace(q.Get("appId"))
	var appID uuid.UUID
	if rawEnv != "" {
		var err error
		appID, err = uuid.FromString(rawEnv)
		if err != nil {
			WriteError(w, r, "error.invalidAppId", http.StatusBadRequest)
			return
		}
	}

	if appID == uuid.Nil {
		WriteError(w, r, "error.appIdRequired", http.StatusBadRequest)
		return
	}
	_ = project

	page := 0
	pageSize := 50

	if v := strings.TrimSpace(q.Get("page")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			WriteError(w, r, "error.invalidPage", http.StatusBadRequest)
			return
		}
		page = n
	}

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

	email := strings.TrimSpace(q.Get("email"))

	// Optional "inactive users" filter: only users whose last_login_at is
	// older than N days, or who have never logged in. Powers the "show
	// inactive users" segment in the admin UI.
	inactiveDays := 0
	if v := strings.TrimSpace(q.Get("inactiveDays")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			WriteError(w, r, "error.invalidInactiveDays", http.StatusBadRequest)
			return
		}
		if n > 3650 {
			n = 3650
		}
		inactiveDays = n
	}

	// Optional enabled/disabled filter. Values: "enabled", "disabled", "".
	enabledFilter := repo.MemberEnabledFilter("")
	switch strings.TrimSpace(q.Get("enabled")) {
	case "enabled":
		enabledFilter = repo.MemberEnabledFilterEnabled
	case "disabled":
		enabledFilter = repo.MemberEnabledFilterDisabled
	}

	// Optional role filter. Values:
	//   ""        -> any (no filter)
	//   "without" -> members with no user_roles row in this app
	//   "<uuid>"  -> members assigned that specific role
	roleFilter := repo.MemberRoleFilter{}
	switch v := strings.TrimSpace(q.Get("role")); v {
	case "":
		// no filter
	case "without":
		roleFilter = repo.MemberRoleFilter{Kind: "without"}
	default:
		roleID, err := uuid.FromString(v)
		if err != nil {
			WriteError(w, r, "error.invalidRoleFilter", http.StatusBadRequest)
			return
		}
		roleFilter = repo.MemberRoleFilter{Kind: "specific", RoleID: roleID}
	}

	members, total, err := handler.repo.GetProjectMembersByApp(
		r.Context(),
		project.ID,
		appID,
		page,
		pageSize,
		email,
		inactiveDays,
		enabledFilter,
		roleFilter,
	)
	if err != nil {
		log.Err(err).Msg("Could not get project members by app")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Populate per-user activity stats + tags for the AppUsers list columns.
	// Best-effort: if any query fails, leave the fields zero/empty rather
	// than failing the whole request.
	if appID != uuid.Nil && len(members) > 0 {
		userIDs := make([]uuid.UUID, len(members))
		for i, m := range members {
			userIDs[i] = m.UserID
		}
		if counts, err := handler.repo.GetProjectMembersActivityCounts(r.Context(), appID, userIDs); err == nil {
			for i := range members {
				if c, ok := counts[members[i].UserID]; ok {
					members[i].ActiveSessions = c.ActiveSessions
					members[i].LoginFailures7d = c.LoginFailures7d
				}
			}
		} else {
			log.Err(err).Msg("Could not load member activity counts (non-fatal)")
		}

		if tagsByUser, err := handler.repo.GetUserTagsForUsers(r.Context(), appID, userIDs); err == nil {
			for i := range members {
				if tags, ok := tagsByUser[members[i].UserID]; ok {
					members[i].Tags = tags
				}
			}
		} else {
			log.Err(err).Msg("Could not load member tags (non-fatal)")
		}
	}

	resp := ProjectMembersResponse{
		Members:      members,
		MembersTotal: total,
		Page:         page,
		PageSize:     pageSize,
	}
	if email != "" {
		resp.Email = email
	}

	utils.WriteJson(w, resp)
}
