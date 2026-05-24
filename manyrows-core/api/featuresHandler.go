package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

type FeatureFlagsResponse struct {
	FeatureFlags []core.FeatureFlag `json:"featureFlags"`
}

type FeatureFlagResponse struct {
	FeatureFlag core.FeatureFlag `json:"featureFlag"`
}

type FeatureFlagOverridesResponse struct {
	FeatureFlagOverrides []core.FeatureFlagOverride `json:"featureFlagOverrides"`
}

type CreateFeatureFlagRequest struct {
	Key            string                 `json:"key"`
	Description    *string                `json:"description"`
	Scope          *core.FeatureFlagScope `json:"scope"` // "server" (default) | "client"
	DefaultEnabled bool                   `json:"defaultEnabled"`
	Status         string                 `json:"status"` // "active" (default), "archived"
}

type UpdateFeatureFlagRequest struct {
	Description    *string                `json:"description"`
	Scope          *core.FeatureFlagScope `json:"scope"` // "server" | "client"
	DefaultEnabled *bool                  `json:"defaultEnabled"`
	Status         *string                `json:"status"` // "active", "archived"
}

type UpsertFeatureFlagOverrideRequest struct {
	Enabled *bool       `json:"enabled"`
	Status  *string     `json:"status"`            // "active" (default), "disabled"
	RoleIDs []uuid.UUID `json:"roleIds,omitempty"` // restrict to users with one of these roles
}

func parseUUIDParam(r *http.Request, key string) (uuid.UUID, error) {
	raw := chi.URLParam(r, key)
	if raw == "" {
		return uuid.Nil, errors.New("missing param: " + key)
	}
	id, err := uuid.FromString(raw)
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

func normalizeKey(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}

func isValidFlagKey(key string) bool {
	// keep in sync with frontend: ^[a-z][a-z0-9_]*$
	if key == "" {
		return false
	}
	for i, r := range key {
		if i == 0 {
			if r < 'a' || r > 'z' {
				return false
			}
			continue
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return false
	}
	return true
}

func normalizeFeatureStatus(s string, def string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return def
	}
	return s
}

func isAllowedFlagStatus(s string) bool {
	return s == "active" || s == "archived"
}

func isAllowedOverrideStatus(s string) bool {
	return s == "active" || s == "disabled"
}

func normalizeScope(v core.FeatureFlagScope, def core.FeatureFlagScope) core.FeatureFlagScope {
	s := strings.TrimSpace(strings.ToLower(string(v)))
	if s == "" {
		return def
	}
	return core.FeatureFlagScope(s)
}

func isAllowedFlagScope(v core.FeatureFlagScope) bool {
	return v == core.FeatureFlagScopeServer || v == core.FeatureFlagScopeClient
}

// ---------------------------
// feature flags (project-level)
// ---------------------------

func (handler *RequestHandler) HandleGetFeatureFlags(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProduct(w, r)
	if !ok {
		return
	}

	flags, err := handler.repo.GetFeatureFlagsByProductID(r.Context(), project.ID)
	if err != nil {
		log.Err(err).Msg("Could not get feature flags")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, FeatureFlagsResponse{FeatureFlags: flags}, http.StatusOK)
}

func (handler *RequestHandler) HandleGetFeatureFlag(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProduct(w, r)
	if !ok {
		return
	}

	flagID, err := parseUUIDParam(r, "featureFlagId")
	if err != nil {
		WriteError(w, r, "error.invalidFeatureFlagId", http.StatusBadRequest)
		return
	}

	flag, err := handler.repo.GetFeatureFlagByID(r.Context(), project.ID, flagID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.featureFlagNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("Could not get feature flag")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, FeatureFlagResponse{FeatureFlag: flag}, http.StatusOK)
}

func (handler *RequestHandler) HandleCreateFeatureFlag(w http.ResponseWriter, r *http.Request) {
	acc, _, project, ok := handler.adminAndProduct(w, r)
	if !ok {
		return
	}

	var req CreateFeatureFlagRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	req.Key = normalizeKey(req.Key)
	if req.Description != nil {
		d := strings.TrimSpace(*req.Description)
		if d == "" {
			req.Description = nil
		} else {
			req.Description = &d
		}
	}

	if req.Key == "" || !isValidFlagKey(req.Key) {
		WriteError(w, r, "error.keyInvalid", http.StatusBadRequest)
		return
	}

	status := normalizeFeatureStatus(req.Status, "active")
	if !isAllowedFlagStatus(status) {
		WriteError(w, r, "error.statusInvalid", http.StatusBadRequest)
		return
	}

	// scope (default: server)
	scope := core.FeatureFlagScopeServer
	if req.Scope != nil {
		scope = normalizeScope(*req.Scope, core.FeatureFlagScopeServer)
		if !isAllowedFlagScope(scope) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
	}

	now := time.Now().UTC()
	id := utils.NewUUID()

	flag := core.FeatureFlag{
		ID:             id,
		ProductID:      project.ID,
		Key:            req.Key,
		Description:    req.Description,
		Scope:          scope,
		DefaultEnabled: req.DefaultEnabled,
		Status:         status,
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      acc.ID,
	}

	created, err := handler.repo.CreateFeatureFlag(r.Context(), flag)
	if err != nil {
		if errors.Is(err, repo.ErrConflict) || repo.IsUniqueViolation(err) {
			WriteError(w, r, "error.keyExists", http.StatusConflict)
			return
		}
		if errors.Is(err, repo.ErrBadRequest) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		log.Err(err).Msg("Could not create feature flag")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, FeatureFlagResponse{FeatureFlag: created}, http.StatusCreated)
}

func (handler *RequestHandler) HandleUpdateFeatureFlag(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProduct(w, r)
	if !ok {
		return
	}

	flagID, err := parseUUIDParam(r, "featureFlagId")
	if err != nil {
		WriteError(w, r, "error.invalidFeatureFlagId", http.StatusBadRequest)
		return
	}

	_, err = handler.repo.GetFeatureFlagByID(r.Context(), project.ID, flagID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.featureFlagNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("Could not get feature flag (before update)")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	var req UpdateFeatureFlagRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	var changed []string

	if req.Description != nil {
		d := strings.TrimSpace(*req.Description)
		if d == "" {
			empty := ""
			req.Description = &empty // repo interprets "" as NULL
		} else {
			req.Description = &d
		}
		changed = append(changed, "description")
	}

	if req.Scope != nil {
		s := normalizeScope(*req.Scope, core.FeatureFlagScopeServer)
		if !isAllowedFlagScope(s) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		req.Scope = &s
		changed = append(changed, "scope")
	}

	if req.DefaultEnabled != nil {
		changed = append(changed, "defaultEnabled")
	}

	if req.Status != nil {
		s := normalizeFeatureStatus(*req.Status, "")
		req.Status = &s
		if !isAllowedFlagStatus(s) {
			WriteError(w, r, "error.statusInvalid", http.StatusBadRequest)
			return
		}
		changed = append(changed, "status")
	}

	updated, err := handler.repo.UpdateFeatureFlag(
		r.Context(),
		project.ID,
		flagID,
		req.Description,
		req.Scope,
		req.DefaultEnabled,
		req.Status,
	)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.featureFlagNotFound", http.StatusNotFound)
			return
		}
		if errors.Is(err, repo.ErrBadRequest) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		if errors.Is(err, repo.ErrConflict) || repo.IsUniqueViolation(err) {
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		}
		log.Err(err).Msg("Could not update feature flag")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, FeatureFlagResponse{FeatureFlag: updated}, http.StatusOK)
}

func (handler *RequestHandler) HandleDeleteFeatureFlag(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProduct(w, r)
	if !ok {
		return
	}

	flagID, err := parseUUIDParam(r, "featureFlagId")
	if err != nil {
		WriteError(w, r, "error.invalidFeatureFlagId", http.StatusBadRequest)
		return
	}

	_, err = handler.repo.GetFeatureFlagByID(r.Context(), project.ID, flagID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.featureFlagNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("Could not get feature flag (before delete)")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	err = handler.repo.DeleteFeatureFlag(r.Context(), project.ID, flagID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.featureFlagNotFound", http.StatusNotFound)
			return
		}
		if errors.Is(err, repo.ErrBadRequest) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		log.Err(err).Msg("Could not delete feature flag")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --------------------------------------------
// list all overrides for a project (bulk fetch)
// --------------------------------------------

func (handler *RequestHandler) HandleGetFeatureFlagOverrides(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProduct(w, r)
	if !ok {
		return
	}

	rows, err := handler.repo.GetFeatureFlagOverridesByProductID(r.Context(), project.ID)
	if err != nil {
		log.Err(err).Msg("Could not get feature flag overrides")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, FeatureFlagOverridesResponse{FeatureFlagOverrides: rows}, http.StatusOK)
}

// -------------------------
// upsert override (PUT)
// -------------------------

func (handler *RequestHandler) HandleUpsertFeatureFlagOverride(w http.ResponseWriter, r *http.Request) {
	acc, _, project, ok := handler.adminAndProduct(w, r)
	if !ok {
		return
	}

	flagID, err := parseUUIDParam(r, "featureFlagId")
	if err != nil {
		WriteError(w, r, "error.invalidFeatureFlagId", http.StatusBadRequest)
		return
	}
	appID, err := parseUUIDParam(r, "appId")
	if err != nil {
		WriteError(w, r, "error.invalidAppId", http.StatusBadRequest)
		return
	}
	var req UpsertFeatureFlagOverrideRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if req.Enabled == nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	status := "active"
	if req.Status != nil && strings.TrimSpace(*req.Status) != "" {
		status = normalizeFeatureStatus(*req.Status, "active")
	}
	if !isAllowedOverrideStatus(status) {
		WriteError(w, r, "error.statusInvalid", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()

	newID := utils.NewUUID()

	override := core.FeatureFlagOverride{
		ID:            newID, // used if insert; repo can ignore on update
		ProductID:     project.ID,
		AppID:         appID,
		FeatureFlagID: flagID,
		Enabled:       *req.Enabled,
		RoleIDs:       req.RoleIDs,
		Status:        status,
		UpdatedAt:     now,
		UpdatedBy:     acc.ID,
	}

	saved, err := handler.repo.UpsertFeatureFlagOverride(r.Context(), override)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.featureFlagNotFound", http.StatusNotFound)
			return
		}
		if errors.Is(err, repo.ErrBadRequest) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		if errors.Is(err, repo.ErrConflict) || repo.IsUniqueViolation(err) {
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		}
		log.Err(err).Msg("Could not upsert feature flag override")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, saved, http.StatusOK)
}

// ----------------------------------
// delete override (revert to default)
// ----------------------------------

func (handler *RequestHandler) HandleDeleteFeatureFlagOverride(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProduct(w, r)
	if !ok {
		return
	}

	flagID, err := parseUUIDParam(r, "featureFlagId")
	if err != nil {
		WriteError(w, r, "error.invalidFeatureFlagId", http.StatusBadRequest)
		return
	}
	appID, err := parseUUIDParam(r, "appId")
	if err != nil {
		WriteError(w, r, "error.invalidAppId", http.StatusBadRequest)
		return
	}
	err = handler.repo.DeleteFeatureFlagOverride(r.Context(), project.ID, flagID, appID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.featureFlagNotFound", http.StatusNotFound)
			return
		}
		if errors.Is(err, repo.ErrBadRequest) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		log.Err(err).Msg("Could not delete feature flag override")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
