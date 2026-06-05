package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog/log"
)

// serverOrgResponse is the API shape for an organization.
type serverOrgResponse struct {
	ID        uuid.UUID `json:"id"`
	AppID     uuid.UUID `json:"appId"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
}

func toServerOrg(o *core.Organization) serverOrgResponse {
	return serverOrgResponse{ID: o.ID, AppID: o.AppID, Name: o.Name, Slug: o.Slug, Status: o.Status, CreatedAt: o.CreatedAt}
}

// simpleSlug derives a url-safe slug from a display name (lowercase, runs of
// non-alphanumerics → single dash, trimmed). Falls back to "org".
func simpleSlug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	dash := false
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
			dash = false
		} else if b.Len() > 0 && !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "org"
	}
	return out
}

// serverAppFromCtx returns the app set by appMiddleware, or writes 404.
func (handler *RequestHandler) serverAppFromCtx(w http.ResponseWriter, r *http.Request) (*core.App, bool) {
	app, ok := core.AppFromContext(r.Context())
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return nil, false
	}
	return app, true
}

// serverOrgFromURL loads {orgId} and enforces it belongs to the context app.
func (handler *RequestHandler) serverOrgFromURL(w http.ResponseWriter, r *http.Request) (*core.App, *core.Organization, bool) {
	app, ok := handler.serverAppFromCtx(w, r)
	if !ok {
		return nil, nil, false
	}
	orgID, err := uuid.FromString(chi.URLParam(r, "orgId"))
	if err != nil || orgID == uuid.Nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return nil, nil, false
	}
	org, err := handler.repo.GetOrganizationByID(r.Context(), orgID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return nil, nil, false
		}
		log.Err(err).Msg("serverOrgFromURL: load failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return nil, nil, false
	}
	if org.AppID != app.ID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return nil, nil, false
	}
	return app, org, true
}

type createOrgRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	OwnerUserID string `json:"ownerUserId"`
}

// ServerCreateOrganization: POST /v1/apps/{appId}/organizations
func (handler *RequestHandler) ServerCreateOrganization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app, ok := handler.serverAppFromCtx(w, r)
	if !ok {
		return
	}
	var body createOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	ownerID, err := uuid.FromString(strings.TrimSpace(body.OwnerUserID))
	if err != nil || ownerID == uuid.Nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	owner, err := handler.repo.GetUserByID(ctx, ownerID)
	if err != nil || owner == nil || owner.UserPoolID != app.UserPoolID {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	slug := strings.TrimSpace(body.Slug)
	if slug == "" {
		slug = simpleSlug(body.Name)
	}
	org, err := handler.repo.CreateOrganizationWithOwner(ctx, app.ID, strings.TrimSpace(body.Name), slug, ownerID)
	if err != nil {
		log.Err(err).Msg("ServerCreateOrganization: create failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJsonWithStatusCode(w, toServerOrg(org), http.StatusCreated)
}

// ServerListOrganizationsForUser: GET /v1/apps/{appId}/organizations?userId=
func (handler *RequestHandler) ServerListOrganizationsForUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app, ok := handler.serverAppFromCtx(w, r)
	if !ok {
		return
	}
	userID, err := uuid.FromString(strings.TrimSpace(r.URL.Query().Get("userId")))
	if err != nil || userID == uuid.Nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	orgs, err := handler.repo.ListOrganizationsForUserInApp(ctx, app.ID, userID)
	if err != nil {
		log.Err(err).Msg("ServerListOrganizationsForUser failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if orgs == nil {
		orgs = []core.OrganizationMembershipView{}
	}
	utils.WriteJson(w, map[string]any{"organizations": orgs})
}

// ServerGetOrganization: GET /v1/apps/{appId}/organizations/{orgId}
func (handler *RequestHandler) ServerGetOrganization(w http.ResponseWriter, r *http.Request) {
	_, org, ok := handler.serverOrgFromURL(w, r)
	if !ok {
		return
	}
	utils.WriteJson(w, toServerOrg(org))
}

type updateOrgRequest struct {
	Name *string `json:"name"`
	Slug *string `json:"slug"`
}

// ServerUpdateOrganization: PATCH /v1/apps/{appId}/organizations/{orgId}
func (handler *RequestHandler) ServerUpdateOrganization(w http.ResponseWriter, r *http.Request) {
	_, org, ok := handler.serverOrgFromURL(w, r)
	if !ok {
		return
	}
	var body updateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	name, slug := org.Name, org.Slug
	if body.Name != nil && strings.TrimSpace(*body.Name) != "" {
		name = strings.TrimSpace(*body.Name)
	}
	if body.Slug != nil && strings.TrimSpace(*body.Slug) != "" {
		slug = strings.TrimSpace(*body.Slug)
	}
	updated, err := handler.repo.UpdateOrganization(r.Context(), org.ID, name, slug)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		}
		log.Err(err).Msg("ServerUpdateOrganization failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, toServerOrg(updated))
}

// ServerArchiveOrganization: DELETE /v1/apps/{appId}/organizations/{orgId}
func (handler *RequestHandler) ServerArchiveOrganization(w http.ResponseWriter, r *http.Request) {
	_, org, ok := handler.serverOrgFromURL(w, r)
	if !ok {
		return
	}
	if err := handler.repo.ArchiveOrganization(r.Context(), org.ID); err != nil {
		log.Err(err).Msg("ServerArchiveOrganization failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type addMemberRequest struct {
	UserID  string `json:"userId"`
	Email   string `json:"email"`
	OrgRole string `json:"orgRole"`
}

func validOrgRole(s string) bool {
	return s == core.OrgRoleOwner || s == core.OrgRoleAdmin || s == core.OrgRoleMember
}

// ServerListOrgMembers: GET …/organizations/{orgId}/members
func (handler *RequestHandler) ServerListOrgMembers(w http.ResponseWriter, r *http.Request) {
	_, org, ok := handler.serverOrgFromURL(w, r)
	if !ok {
		return
	}
	members, err := handler.repo.ListOrganizationMembers(r.Context(), org.ID)
	if err != nil {
		log.Err(err).Msg("ServerListOrgMembers failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if members == nil {
		members = []repo.OrganizationMemberView{}
	}
	utils.WriteJson(w, map[string]any{"members": members})
}

// ServerAddOrgMember: POST …/organizations/{orgId}/members
func (handler *RequestHandler) ServerAddOrgMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app, org, ok := handler.serverOrgFromURL(w, r)
	if !ok {
		return
	}
	var body addMemberRequest
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

	// Resolve the target user: by id, or by email (must already exist in the
	// app's pool — invites are a fast-follow, so an unknown email is a 409).
	var user *core.User
	if s := strings.TrimSpace(body.UserID); s != "" {
		uid, err := uuid.FromString(s)
		if err != nil || uid == uuid.Nil {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		u, err := handler.repo.GetUserByID(ctx, uid)
		if err != nil || u == nil || u.UserPoolID != app.UserPoolID {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		user = u
	} else if e := strings.TrimSpace(strings.ToLower(body.Email)); e != "" {
		u, err := handler.repo.GetUserByEmail(ctx, e, app)
		if err != nil && !errors.Is(err, repo.ErrNotFound) {
			log.Err(err).Msg("ServerAddOrgMember: email lookup failed")
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

	m, err := handler.repo.AddOrganizationMember(ctx, org.ID, user.ID, role)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			WriteError(w, r, "error.conflict", http.StatusConflict) // already a member
			return
		}
		log.Err(err).Msg("ServerAddOrgMember: add failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJsonWithStatusCode(w, repo.OrganizationMemberView{UserID: user.ID, Email: user.Email, OrgRole: m.OrgRole, Status: m.Status}, http.StatusCreated)
}

// ServerGetOrgMember: GET …/organizations/{orgId}/members/{userId}
// Used by a customer app's per-request middleware: returns the member's tier or 404.
func (handler *RequestHandler) ServerGetOrgMember(w http.ResponseWriter, r *http.Request) {
	_, org, ok := handler.serverOrgFromURL(w, r)
	if !ok {
		return
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}
	m, err := handler.repo.GetOrganizationMember(r.Context(), org.ID, userID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerGetOrgMember failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, map[string]any{"userId": m.UserID, "orgRole": m.OrgRole, "status": m.Status})
}

type setMemberRoleRequest struct {
	OrgRole string `json:"orgRole"`
}

// ServerSetOrgMemberRole: PATCH …/organizations/{orgId}/members/{userId}
func (handler *RequestHandler) ServerSetOrgMemberRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, org, ok := handler.serverOrgFromURL(w, r)
	if !ok {
		return
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}
	var body setMemberRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !validOrgRole(strings.TrimSpace(body.OrgRole)) {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	newRole := strings.TrimSpace(body.OrgRole)

	current, err := handler.repo.GetOrganizationMember(ctx, org.ID, userID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerSetOrgMemberRole: load failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	// Last-owner guard: never demote the final active owner.
	if current.OrgRole == core.OrgRoleOwner && newRole != core.OrgRoleOwner && current.Status == core.OrgMemberStatusActive {
		if owners, err := handler.repo.CountActiveOrgOwners(ctx, org.ID); err == nil && owners <= 1 {
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		}
	}
	if err := handler.repo.SetOrganizationMemberRole(ctx, org.ID, userID, newRole); err != nil {
		log.Err(err).Msg("ServerSetOrgMemberRole: update failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ServerRemoveOrgMember: DELETE …/organizations/{orgId}/members/{userId}
func (handler *RequestHandler) ServerRemoveOrgMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, org, ok := handler.serverOrgFromURL(w, r)
	if !ok {
		return
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}
	current, err := handler.repo.GetOrganizationMember(ctx, org.ID, userID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerRemoveOrgMember: load failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	// Last-owner guard: never remove the final active owner.
	if current.OrgRole == core.OrgRoleOwner && current.Status == core.OrgMemberStatusActive {
		if owners, err := handler.repo.CountActiveOrgOwners(ctx, org.ID); err == nil && owners <= 1 {
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		}
	}
	if err := handler.repo.RemoveOrganizationMember(ctx, org.ID, userID); err != nil {
		log.Err(err).Msg("ServerRemoveOrgMember: delete failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
