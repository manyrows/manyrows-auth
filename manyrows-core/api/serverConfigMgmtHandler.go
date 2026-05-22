package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
)

type ServerSetConfigValueRequest struct {
	// Value is the config value as raw JSON (string/number/bool/array/object,
	// matching the key's configured value type).
	Value json.RawMessage `json:"value"`
}

// ServerSetConfigValue sets this app's value for a public or private config key
// (looked up by its string key within the app's product). Secret keys are
// rejected — their values are sealed client-side against the workspace key, so
// they must be set in the dashboard.
// PUT /x/{workspaceSlug}/api/v1/apps/{appId}/config/{configKey}
func (handler *RequestHandler) ServerSetConfigValue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}
	project, ok := core.ProductFromContext(ctx)
	if !ok || project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	ck, err := handler.repo.GetConfigKeyByProductIDAndKey(ctx, project.ID, chi.URLParam(r, "configKey"))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.configKeyNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerSetConfigValue: GetConfigKeyByProductIDAndKey failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if ck.Exposure == core.ConfigExposureSecret {
		WriteError(w, r, "error.secretsNotSupportedViaAPI", http.StatusBadRequest)
		return
	}

	var req ServerSetConfigValueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if len(req.Value) == 0 {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	cv := core.ConfigValue{
		ID:          utils.NewUUID(),
		ProductID:   project.ID,
		AppID:       app.ID,
		ConfigKeyID: ck.ID,
		UpdatedAt:   time.Now().UTC(),
		UpdatedBy:   serverActorID(ctx),
	}
	if _, err := handler.repo.UpsertConfigValueJSON(ws.ID, ctx, cv, req.Value, nil); err != nil {
		switch {
		case errors.Is(err, repo.ErrBadRequest):
			// Value didn't match the key's value type.
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		case errors.Is(err, repo.ErrNotFound):
			WriteError(w, r, "error.configKeyNotFound", http.StatusNotFound)
		default:
			log.Err(err).Msg("ServerSetConfigValue: UpsertConfigValueJSON failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ServerDeleteConfigValue clears this app's value for a config key (the key
// definition itself is untouched). Idempotent.
// DELETE /x/{workspaceSlug}/api/v1/apps/{appId}/config/{configKey}
func (handler *RequestHandler) ServerDeleteConfigValue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	project, ok := core.ProductFromContext(ctx)
	if !ok || project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	ck, err := handler.repo.GetConfigKeyByProductIDAndKey(ctx, project.ID, chi.URLParam(r, "configKey"))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.configKeyNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerDeleteConfigValue: GetConfigKeyByProductIDAndKey failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if err := handler.repo.DeleteConfigValue(ctx, project.ID, ck.ID, app.ID); err != nil && !errors.Is(err, repo.ErrNotFound) {
		log.Err(err).Msg("ServerDeleteConfigValue: DeleteConfigValue failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type ServerSetFeatureFlagRequest struct {
	Enabled bool `json:"enabled"`
	// Roles optionally restricts the override to users with one of these role
	// slugs. Empty/omitted applies to everyone.
	Roles []string `json:"roles"`
}

// ServerSetFeatureFlag sets this app's override for a feature flag (looked up by
// its string key within the app's product) — enabled/disabled, optionally
// targeted at a set of roles.
// PUT /x/{workspaceSlug}/api/v1/apps/{appId}/features/{flagKey}
func (handler *RequestHandler) ServerSetFeatureFlag(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	project, ok := core.ProductFromContext(ctx)
	if !ok || project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	flag, err := handler.repo.GetFeatureFlagByProductIDAndKey(ctx, project.ID, chi.URLParam(r, "flagKey"))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.featureFlagNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerSetFeatureFlag: GetFeatureFlagByProductIDAndKey failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	var req ServerSetFeatureFlagRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	roleIDs, _, ok := handler.resolveRoleSlugs(w, r, project.ID, req.Roles)
	if !ok {
		return
	}

	override := core.FeatureFlagOverride{
		ID:            utils.NewUUID(),
		ProductID:     project.ID,
		AppID:         app.ID,
		FeatureFlagID: flag.ID,
		Enabled:       req.Enabled,
		RoleIDs:       roleIDs,
		Status:        "active",
		UpdatedAt:     time.Now().UTC(),
		UpdatedBy:     serverActorID(ctx),
	}
	if _, err := handler.repo.UpsertFeatureFlagOverride(ctx, override); err != nil {
		switch {
		case errors.Is(err, repo.ErrNotFound):
			WriteError(w, r, "error.featureFlagNotFound", http.StatusNotFound)
		case errors.Is(err, repo.ErrBadRequest):
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		default:
			log.Err(err).Msg("ServerSetFeatureFlag: UpsertFeatureFlagOverride failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ServerDeleteFeatureFlag clears this app's override for a flag, so it falls
// back to the flag's default. Idempotent.
// DELETE /x/{workspaceSlug}/api/v1/apps/{appId}/features/{flagKey}
func (handler *RequestHandler) ServerDeleteFeatureFlag(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	project, ok := core.ProductFromContext(ctx)
	if !ok || project == nil {
		WriteError(w, r, "error.projectNotFound", http.StatusNotFound)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}

	flag, err := handler.repo.GetFeatureFlagByProductIDAndKey(ctx, project.ID, chi.URLParam(r, "flagKey"))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.featureFlagNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerDeleteFeatureFlag: GetFeatureFlagByProductIDAndKey failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if err := handler.repo.DeleteFeatureFlagOverride(ctx, project.ID, flag.ID, app.ID); err != nil && !errors.Is(err, repo.ErrNotFound) {
		log.Err(err).Msg("ServerDeleteFeatureFlag: DeleteFeatureFlagOverride failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
