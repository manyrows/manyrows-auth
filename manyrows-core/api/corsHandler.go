package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

const maxCorsOriginsPerApp = 20

func (handler *RequestHandler) HandleGetCorsOrigins(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	appID, err := utils.GetPathUUID("appId", r)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	app, err := handler.repo.GetAppByID(r.Context(), appID)
	if err != nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if app.WorkspaceID != ws.ID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	origins, err := handler.repo.GetCorsOrigins(r.Context(), app.ID)
	if err != nil {
		log.Err(err).Msg("failed to get CORS origins")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, origins, http.StatusOK)
}

func (handler *RequestHandler) HandleDeleteCorsOrigin(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	if !handler.requireOwner(w, r) {
		return
	}

	appID, err := utils.GetPathUUID("appId", r)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	app, err := handler.repo.GetAppByID(r.Context(), appID)
	if err != nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if app.WorkspaceID != ws.ID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	// ROUTE IS {id}
	id, err := utils.GetPathUUID("id", r)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	if err := handler.repo.DeleteCorsOrigin(r.Context(), app.ID, id); err != nil {
		log.Err(err).Msg("failed to delete CORS origin")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type UpdateCorsOriginRequest struct {
	Origin *string `json:"origin"`
}

func (handler *RequestHandler) HandleUpdateCorsOrigin(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	if !handler.requireOwner(w, r) {
		return
	}

	appID, err := utils.GetPathUUID("appId", r)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	app, err := handler.repo.GetAppByID(r.Context(), appID)
	if err != nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if app.WorkspaceID != ws.ID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	// ROUTE IS {id}
	id, err := utils.GetPathUUID("id", r)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	var req UpdateCorsOriginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode update CORS origin request")
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	if req.Origin == nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	origin := strings.TrimSpace(*req.Origin)
	if origin == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	u, err := url.Parse(origin)
	if err != nil || u == nil {
		WriteError(w, r, "error.invalidOriginUrl", http.StatusBadRequest)
		return
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		WriteError(w, r, "error.originRequiresScheme", http.StatusBadRequest)
		return
	}
	if u.Host == "" {
		WriteError(w, r, "error.originRequiresHost", http.StatusBadRequest)
		return
	}
	if u.Path != "" && u.Path != "/" {
		WriteError(w, r, "error.originNoPath", http.StatusBadRequest)
		return
	}
	if u.RawQuery != "" || u.Fragment != "" {
		WriteError(w, r, "error.originNoQueryFragment", http.StatusBadRequest)
		return
	}
	if u.User != nil {
		WriteError(w, r, "error.originNoUserInfo", http.StatusBadRequest)
		return
	}

	normalized := u.Scheme + "://" + u.Host

	if err := handler.ensureCorsChangeKeepsPasskeysValid(r.Context(), app.ID, normalized, &id); err != nil {
		WriteErrorf(w, r, "error.invalidRPID", http.StatusBadRequest, err.Error())
		return
	}

	if err := handler.repo.UpdateCORSOrigin(r.Context(), app.ID, id, normalized); err != nil {
		switch {
		case errors.Is(err, repo.ErrNotFound):
			WriteError(w, r, "error.notFound", http.StatusNotFound)
		case errors.Is(err, repo.ErrConflict):
			WriteError(w, r, "error.originAlreadyExists", http.StatusConflict)
		default:
			log.Err(err).Msg("failed to update CORS origin")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		}
		return
	}

	utils.WriteJsonWithStatusCode(w, map[string]any{
		"id":     id,
		"origin": normalized,
	}, http.StatusOK)
}

type CreateCorsOriginRequest struct {
	Origin string `json:"origin"` // a URL
}

func (handler *RequestHandler) HandleCreateCorsOrigin(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	if !handler.requireOwner(w, r) {
		return
	}

	appID, err := utils.GetPathUUID("appId", r)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	app, err := handler.repo.GetAppByID(r.Context(), appID)
	if err != nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if app.WorkspaceID != ws.ID {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	var req CreateCorsOriginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode CORS origin request")
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	origin := strings.TrimSpace(req.Origin)
	if origin == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	u, err := url.Parse(origin)
	if err != nil || u == nil {
		WriteError(w, r, "error.invalidOriginUrl", http.StatusBadRequest)
		return
	}

	// Origins should be scheme + host only. Require http/https and a host.
	if u.Scheme != "http" && u.Scheme != "https" {
		WriteError(w, r, "error.originRequiresScheme", http.StatusBadRequest)
		return
	}
	if u.Host == "" {
		WriteError(w, r, "error.originRequiresHost", http.StatusBadRequest)
		return
	}

	// Disallow path/query/fragment for an origin. Normalize to scheme://host[:port]
	if u.Path != "" && u.Path != "/" {
		WriteError(w, r, "error.originNoPath", http.StatusBadRequest)
		return
	}
	if u.RawQuery != "" || u.Fragment != "" {
		WriteError(w, r, "error.originNoQueryFragment", http.StatusBadRequest)
		return
	}
	if u.User != nil {
		WriteError(w, r, "error.originNoUserInfo", http.StatusBadRequest)
		return
	}

	normalized := u.Scheme + "://" + u.Host

	if err := handler.ensureCorsChangeKeepsPasskeysValid(r.Context(), app.ID, normalized, nil); err != nil {
		WriteErrorf(w, r, "error.invalidRPID", http.StatusBadRequest, err.Error())
		return
	}

	corsOrigin := core.CorsOrigin{
		ID:        utils.NewUUID(),
		AppID:     app.ID,
		Origin:    normalized,
		CreatedAt: time.Now().UTC(),
	}

	inserted, err := handler.repo.InsertCorsOriginWithLimit(r.Context(), corsOrigin, maxCorsOriginsPerApp)
	if err != nil {
		log.Err(err).Msg("failed to insert CORS origin")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !inserted {
		WriteErrorf(w, r, "error.limitReached", http.StatusConflict, "CORS origins", maxCorsOriginsPerApp)
		return
	}

	utils.WriteJsonWithStatusCode(w, corsOrigin, http.StatusCreated)
}
