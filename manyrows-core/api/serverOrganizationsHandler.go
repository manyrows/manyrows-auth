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
