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

// Definition CRUD for config keys and feature flags over the S2S API. These
// manage the *schema* (the keys/flags themselves); per-app values and overrides
// are managed by /config/{key} and /features/{key} (serverConfigMgmtHandler.go).
// Project-scoped, like the catalog — no per-user gate.

type ServerConfigKey struct {
	Key         string `json:"key"`
	Exposure    string `json:"exposure"`
	ValueType   string `json:"valueType"`
	Status      string `json:"status"`
	Description string `json:"description,omitempty"`
}

func toServerConfigKey(ck core.ConfigKey) ServerConfigKey {
	desc := ""
	if ck.Description != nil {
		desc = *ck.Description
	}
	return ServerConfigKey{Key: ck.Key, Exposure: ck.Exposure, ValueType: string(ck.ValueType), Status: ck.Status, Description: desc}
}

func validConfigExposure(e string) bool {
	switch e {
	case core.ConfigExposurePublic, core.ConfigExposurePrivate, core.ConfigExposureSecret:
		return true
	}
	return false
}

type ServerConfigKeysResponse struct {
	ConfigKeys []ServerConfigKey `json:"configKeys"`
}

// ServerListConfigKeys lists the project's config-key definitions.
// GET /x/{workspaceSlug}/api/v1/apps/{appId}/config-keys
func (handler *RequestHandler) ServerListConfigKeys(w http.ResponseWriter, r *http.Request) {
	project, ok := handler.serverProjectCtx(w, r)
	if !ok {
		return
	}
	keys, err := handler.repo.GetConfigKeysByProjectID(r.Context(), project.ID)
	if err != nil {
		log.Err(err).Msg("ServerListConfigKeys: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	out := make([]ServerConfigKey, 0, len(keys))
	for _, ck := range keys {
		out = append(out, toServerConfigKey(ck))
	}
	utils.WriteJson(w, ServerConfigKeysResponse{ConfigKeys: out})
}

// ServerGetConfigKey fetches one config-key definition by key.
// GET /x/{workspaceSlug}/api/v1/apps/{appId}/config-keys/{key}
func (handler *RequestHandler) ServerGetConfigKey(w http.ResponseWriter, r *http.Request) {
	project, ok := handler.serverProjectCtx(w, r)
	if !ok {
		return
	}
	ck, err := handler.repo.GetConfigKeyByProjectIDAndKey(r.Context(), project.ID, chi.URLParam(r, "key"))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.configKeyNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerGetConfigKey: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, toServerConfigKey(ck))
}

type ServerCreateConfigKeyRequest struct {
	Key         string  `json:"key"`
	Exposure    string  `json:"exposure"`
	ValueType   string  `json:"valueType"`
	Description *string `json:"description"`
}

// ServerCreateConfigKey defines a new config key in the project.
// POST /x/{workspaceSlug}/api/v1/apps/{appId}/config-keys
func (handler *RequestHandler) ServerCreateConfigKey(w http.ResponseWriter, r *http.Request) {
	project, ok := handler.serverProjectCtx(w, r)
	if !ok {
		return
	}
	var req ServerCreateConfigKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if req.Key == "" || !validConfigExposure(req.Exposure) || !core.ConfigValueType(req.ValueType).IsValid() {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	created, err := handler.repo.CreateConfigKey(r.Context(), core.ConfigKey{
		ID:          utils.NewUUID(),
		ProjectID:   project.ID,
		Key:         req.Key,
		Exposure:    req.Exposure,
		ValueType:   core.ConfigValueType(req.ValueType),
		Status:      "active",
		Description: req.Description,
		CreatedAt:   now,
		UpdatedAt:   now,
		CreatedBy:   serverActorID(r.Context()),
	})
	if err != nil {
		if errors.Is(err, repo.ErrConflict) || repo.IsUniqueViolation(err) {
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		}
		log.Err(err).Msg("ServerCreateConfigKey: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJsonWithStatusCode(w, toServerConfigKey(created), http.StatusCreated)
}

type ServerUpdateConfigKeyRequest struct {
	Description *string `json:"description"`
	Exposure    *string `json:"exposure"`
	ValueType   *string `json:"valueType"`
	Status      *string `json:"status"`
}

// ServerUpdateConfigKey updates a config key's metadata.
// PATCH /x/{workspaceSlug}/api/v1/apps/{appId}/config-keys/{key}
func (handler *RequestHandler) ServerUpdateConfigKey(w http.ResponseWriter, r *http.Request) {
	project, ok := handler.serverProjectCtx(w, r)
	if !ok {
		return
	}
	ck, err := handler.repo.GetConfigKeyByProjectIDAndKey(r.Context(), project.ID, chi.URLParam(r, "key"))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.configKeyNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerUpdateConfigKey: lookup failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	var req ServerUpdateConfigKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if req.Exposure != nil && !validConfigExposure(*req.Exposure) {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	var vt *core.ConfigValueType
	if req.ValueType != nil {
		t := core.ConfigValueType(*req.ValueType)
		if !t.IsValid() {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		vt = &t
	}
	if req.Status != nil && *req.Status != "active" && *req.Status != "archived" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	updated, err := handler.repo.UpdateConfigKey(r.Context(), project.ID, ck.ID, req.Description, req.Exposure, vt, req.Status)
	if err != nil {
		log.Err(err).Msg("ServerUpdateConfigKey: update failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, toServerConfigKey(updated))
}

// ServerDeleteConfigKey deletes a config key and its per-app values.
// DELETE /x/{workspaceSlug}/api/v1/apps/{appId}/config-keys/{key}
func (handler *RequestHandler) ServerDeleteConfigKey(w http.ResponseWriter, r *http.Request) {
	project, ok := handler.serverProjectCtx(w, r)
	if !ok {
		return
	}
	ck, err := handler.repo.GetConfigKeyByProjectIDAndKey(r.Context(), project.ID, chi.URLParam(r, "key"))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.configKeyNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerDeleteConfigKey: lookup failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if err := handler.repo.DeleteConfigKey(r.Context(), project.ID, ck.ID); err != nil {
		log.Err(err).Msg("ServerDeleteConfigKey: delete failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type ServerFeatureFlagDef struct {
	Key            string `json:"key"`
	Scope          string `json:"scope"`
	DefaultEnabled bool   `json:"defaultEnabled"`
	Status         string `json:"status"`
	Description    string `json:"description,omitempty"`
}

func toServerFeatureFlagDef(ff core.FeatureFlag) ServerFeatureFlagDef {
	desc := ""
	if ff.Description != nil {
		desc = *ff.Description
	}
	return ServerFeatureFlagDef{Key: ff.Key, Scope: string(ff.Scope), DefaultEnabled: ff.DefaultEnabled, Status: ff.Status, Description: desc}
}

func validFlagScope(s string) bool {
	return s == string(core.FeatureFlagScopeServer) || s == string(core.FeatureFlagScopeClient)
}

type ServerFeatureFlagDefsResponse struct {
	FeatureFlags []ServerFeatureFlagDef `json:"featureFlags"`
}

// ServerListFeatureFlagDefs lists the project's feature-flag definitions.
// GET /x/{workspaceSlug}/api/v1/apps/{appId}/feature-flags
func (handler *RequestHandler) ServerListFeatureFlagDefs(w http.ResponseWriter, r *http.Request) {
	project, ok := handler.serverProjectCtx(w, r)
	if !ok {
		return
	}
	flags, err := handler.repo.GetFeatureFlagsByProjectID(r.Context(), project.ID)
	if err != nil {
		log.Err(err).Msg("ServerListFeatureFlagDefs: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	out := make([]ServerFeatureFlagDef, 0, len(flags))
	for _, ff := range flags {
		out = append(out, toServerFeatureFlagDef(ff))
	}
	utils.WriteJson(w, ServerFeatureFlagDefsResponse{FeatureFlags: out})
}

// ServerGetFeatureFlagDef fetches one feature-flag definition by key.
// GET /x/{workspaceSlug}/api/v1/apps/{appId}/feature-flags/{key}
func (handler *RequestHandler) ServerGetFeatureFlagDef(w http.ResponseWriter, r *http.Request) {
	project, ok := handler.serverProjectCtx(w, r)
	if !ok {
		return
	}
	ff, err := handler.repo.GetFeatureFlagByProjectIDAndKey(r.Context(), project.ID, chi.URLParam(r, "key"))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.featureFlagNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerGetFeatureFlagDef: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, toServerFeatureFlagDef(ff))
}

type ServerCreateFeatureFlagRequest struct {
	Key            string  `json:"key"`
	Scope          string  `json:"scope"`
	DefaultEnabled bool    `json:"defaultEnabled"`
	Description    *string `json:"description"`
}

// ServerCreateFeatureFlag defines a new feature flag in the project.
// POST /x/{workspaceSlug}/api/v1/apps/{appId}/feature-flags
func (handler *RequestHandler) ServerCreateFeatureFlagDef(w http.ResponseWriter, r *http.Request) {
	project, ok := handler.serverProjectCtx(w, r)
	if !ok {
		return
	}
	var req ServerCreateFeatureFlagRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if req.Key == "" || !validFlagScope(req.Scope) {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	created, err := handler.repo.CreateFeatureFlag(r.Context(), core.FeatureFlag{
		ID:             utils.NewUUID(),
		ProjectID:      project.ID,
		Key:            req.Key,
		Scope:          core.FeatureFlagScope(req.Scope),
		DefaultEnabled: req.DefaultEnabled,
		Status:         "active",
		Description:    req.Description,
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      serverActorID(r.Context()),
	})
	if err != nil {
		if errors.Is(err, repo.ErrConflict) || repo.IsUniqueViolation(err) {
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		}
		log.Err(err).Msg("ServerCreateFeatureFlag: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJsonWithStatusCode(w, toServerFeatureFlagDef(created), http.StatusCreated)
}

type ServerUpdateFeatureFlagRequest struct {
	Description    *string `json:"description"`
	Scope          *string `json:"scope"`
	DefaultEnabled *bool   `json:"defaultEnabled"`
	Status         *string `json:"status"`
}

// ServerUpdateFeatureFlag updates a feature flag's metadata.
// PATCH /x/{workspaceSlug}/api/v1/apps/{appId}/feature-flags/{key}
func (handler *RequestHandler) ServerUpdateFeatureFlagDef(w http.ResponseWriter, r *http.Request) {
	project, ok := handler.serverProjectCtx(w, r)
	if !ok {
		return
	}
	ff, err := handler.repo.GetFeatureFlagByProjectIDAndKey(r.Context(), project.ID, chi.URLParam(r, "key"))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.featureFlagNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerUpdateFeatureFlag: lookup failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	var req ServerUpdateFeatureFlagRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	var scope *core.FeatureFlagScope
	if req.Scope != nil {
		if !validFlagScope(*req.Scope) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		s := core.FeatureFlagScope(*req.Scope)
		scope = &s
	}
	if req.Status != nil && *req.Status != "active" && *req.Status != "archived" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	updated, err := handler.repo.UpdateFeatureFlag(r.Context(), project.ID, ff.ID, req.Description, scope, req.DefaultEnabled, req.Status)
	if err != nil {
		log.Err(err).Msg("ServerUpdateFeatureFlag: update failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, toServerFeatureFlagDef(updated))
}

// ServerDeleteFeatureFlag deletes a feature flag and its per-app overrides.
// DELETE /x/{workspaceSlug}/api/v1/apps/{appId}/feature-flags/{key}
func (handler *RequestHandler) ServerDeleteFeatureFlagDef(w http.ResponseWriter, r *http.Request) {
	project, ok := handler.serverProjectCtx(w, r)
	if !ok {
		return
	}
	ff, err := handler.repo.GetFeatureFlagByProjectIDAndKey(r.Context(), project.ID, chi.URLParam(r, "key"))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.featureFlagNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("ServerDeleteFeatureFlag: lookup failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if err := handler.repo.DeleteFeatureFlag(r.Context(), project.ID, ff.ID); err != nil {
		log.Err(err).Msg("ServerDeleteFeatureFlag: delete failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
