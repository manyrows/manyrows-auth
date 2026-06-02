package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

type ServerSetConfigValueRequest struct {
	// Value is the config value as raw JSON (string/number/bool/array/object,
	// matching the key's configured value type).
	Value json.RawMessage `json:"value"`
}

// ServerSetConfigValue sets this app's value for a public or private config key
// (looked up by its string key within the app's project). Secret keys are
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

	ck, err := handler.repo.GetConfigKeyByProjectIDAndKey(ctx, project.ID, chi.URLParam(r, "configKey"))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.configKeyNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerSetConfigValue: GetConfigKeyByProjectIDAndKey failed")
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
		ProjectID:   project.ID,
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

	// Echo the stored value (200), consistent with the other value-setting PUTs.
	utils.WriteJson(w, ServerConfigValueResponse{Key: ck.Key, Value: req.Value})
}

// ServerDeleteConfigValue clears this app's value for a config key (the key
// definition itself is untouched). Idempotent.
// DELETE /x/{workspaceSlug}/api/v1/apps/{appId}/config/{configKey}
func (handler *RequestHandler) ServerDeleteConfigValue(w http.ResponseWriter, r *http.Request) {
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

	ck, err := handler.repo.GetConfigKeyByProjectIDAndKey(ctx, project.ID, chi.URLParam(r, "configKey"))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.configKeyNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerDeleteConfigValue: GetConfigKeyByProjectIDAndKey failed")
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
// its string key within the app's project) — enabled/disabled, optionally
// targeted at a set of roles.
// PUT /x/{workspaceSlug}/api/v1/apps/{appId}/features/{flagKey}
func (handler *RequestHandler) ServerSetFeatureFlag(w http.ResponseWriter, r *http.Request) {
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

	flag, err := handler.repo.GetFeatureFlagByProjectIDAndKey(ctx, project.ID, chi.URLParam(r, "flagKey"))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.featureFlagNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerSetFeatureFlag: GetFeatureFlagByProjectIDAndKey failed")
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
		ProjectID:     project.ID,
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

	// Echo the resulting override (200), with the targeted roles as slugs.
	roles := req.Roles
	if roles == nil {
		roles = []string{}
	}
	utils.WriteJson(w, ServerFeatureOverrideResponse{Enabled: req.Enabled, Roles: roles, Status: "active"})
}

// ServerDeleteFeatureFlag clears this app's override for a flag, so it falls
// back to the flag's default. Idempotent.
// DELETE /x/{workspaceSlug}/api/v1/apps/{appId}/features/{flagKey}
func (handler *RequestHandler) ServerDeleteFeatureFlag(w http.ResponseWriter, r *http.Request) {
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

	flag, err := handler.repo.GetFeatureFlagByProjectIDAndKey(ctx, project.ID, chi.URLParam(r, "flagKey"))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.featureFlagNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerDeleteFeatureFlag: GetFeatureFlagByProjectIDAndKey failed")
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

type ServerConfigValueResponse struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
}

// ServerGetConfigValue reads this app's value for a config key (the raw value
// you set, for read-modify-write). Secret keys are sealed client-side and can't
// be read back here. 404 if the key has no value set for this app.
// GET /x/{workspaceSlug}/api/v1/apps/{appId}/config/{configKey}
func (handler *RequestHandler) ServerGetConfigValue(w http.ResponseWriter, r *http.Request) {
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
	ck, err := handler.repo.GetConfigKeyByProjectIDAndKey(ctx, project.ID, chi.URLParam(r, "configKey"))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.configKeyNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerGetConfigValue: lookup failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if ck.Exposure == core.ConfigExposureSecret {
		WriteError(w, r, "error.secretsNotSupportedViaAPI", http.StatusBadRequest)
		return
	}
	values, err := handler.repo.GetConfigValuesByProjectID(ctx, project.ID)
	if err != nil {
		log.Err(err).Msg("ServerGetConfigValue: GetConfigValuesByProjectID failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	for _, cv := range values {
		if cv.AppID == app.ID && cv.ConfigKeyID == ck.ID {
			utils.WriteJson(w, ServerConfigValueResponse{Key: ck.Key, Value: cv.ValueJSON})
			return
		}
	}
	WriteError(w, r, "error.notFound", http.StatusNotFound)
}

type ServerFeatureOverrideResponse struct {
	Enabled bool     `json:"enabled"`
	Roles   []string `json:"roles"`
	Status  string   `json:"status"`
}

// ServerGetFeatureFlagOverride reads this app's override for a flag (enabled,
// targeted role slugs, status). 404 if no override is set for this app.
// GET /x/{workspaceSlug}/api/v1/apps/{appId}/features/{flagKey}
func (handler *RequestHandler) ServerGetFeatureFlagOverride(w http.ResponseWriter, r *http.Request) {
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
	flag, err := handler.repo.GetFeatureFlagByProjectIDAndKey(ctx, project.ID, chi.URLParam(r, "flagKey"))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.featureFlagNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerGetFeatureFlagOverride: lookup failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	override, err := handler.repo.GetFeatureFlagOverride(ctx, project.ID, flag.ID, app.ID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.notFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerGetFeatureFlagOverride: GetFeatureFlagOverride failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if override == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	slugs, err := handler.roleSlugsForIDs(ctx, project.ID, override.RoleIDs)
	if err != nil {
		log.Err(err).Msg("ServerGetFeatureFlagOverride: role slug map failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, ServerFeatureOverrideResponse{Enabled: override.Enabled, Roles: slugs, Status: override.Status})
}

// roleSlugsForIDs maps role IDs to their slugs within a project (for echoing a
// stored override's targeted roles as slugs, matching the write API).
func (handler *RequestHandler) roleSlugsForIDs(ctx context.Context, projectID uuid.UUID, ids []uuid.UUID) ([]string, error) {
	if len(ids) == 0 {
		return []string{}, nil
	}
	roles, err := handler.repo.GetRolesByProjectID(ctx, projectID)
	if err != nil {
		return nil, err
	}
	bySlug := make(map[uuid.UUID]string, len(roles))
	for _, role := range roles {
		bySlug[role.ID] = role.Slug
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if slug, ok := bySlug[id]; ok {
			out = append(out, slug)
		}
	}
	return out, nil
}
