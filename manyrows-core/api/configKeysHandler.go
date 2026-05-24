package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// Keep this aligned with the frontend:
// - non-empty
// - allows letters, numbers, underscore, dash, dot
var configKeyRegex = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// --------------------
// Request / Responses
// --------------------

type ConfigKeysResponse struct {
	ConfigKeys []core.ConfigKey `json:"configKeys"`
}

type ConfigKeyResponse struct {
	ConfigKey core.ConfigKey `json:"configKey"`
}

type ConfigValuesResponse struct {
	ConfigValues []core.ConfigValue `json:"configValues"`
}

type ConfigValueResponse struct {
	ConfigValue core.ConfigValue `json:"configValue"`
}

type CreateConfigKeyRequest struct {
	Key         string               `json:"key"`
	Description *string              `json:"description"` // optional
	Exposure    string               `json:"exposure"`    // "public" | "private" | "secret"
	ValueType   core.ConfigValueType `json:"valueType"`   // default "string"
	Status      string               `json:"status"`      // optional; defaults to "active"
}

type UpdateConfigKeyRequest struct {
	// nil => no change
	// ""  => clear (set NULL)
	// otherwise => set trimmed string
	Description *string               `json:"description"` // optional
	Exposure    *string               `json:"exposure"`
	ValueType   *core.ConfigValueType `json:"valueType"`
	Status      *string               `json:"status"`
}

type UpsertConfigValueRequest struct {
	// For public/private keys: JSON value (string/number/bool/array/etc)
	Value json.RawMessage `json:"value"`

	// For secret keys: JSON value to encrypt
	Secret json.RawMessage `json:"secret"`
}

// --------------------
// Helpers
// --------------------

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return false
	}
	return true
}

func normalizeExposure(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}

func isAllowedExposure(s string) bool {
	return s == core.ConfigExposurePublic || s == core.ConfigExposurePrivate || s == core.ConfigExposureSecret
}

func normalizeStatus(s string, def string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return def
	}
	return s
}

func isAllowedStatus(s string) bool {
	return s == "active" || s == "archived"
}

func normalizeValueType(t core.ConfigValueType) core.ConfigValueType {
	s := strings.TrimSpace(strings.ToLower(string(t)))
	if s == "" {
		return core.ConfigValueTypeString
	}
	return core.ConfigValueType(s)
}

func isNonEmptyJSON(b json.RawMessage) bool {
	b = bytes.TrimSpace(b)
	return len(b) > 0 && string(b) != "null"
}

func normalizeDescriptionCreate(p *string) *string {
	if p == nil {
		return nil
	}
	s := strings.TrimSpace(*p)
	if s == "" {
		return nil
	}
	return &s
}

// normalizeDescriptionPatch preserves "clear" intent:
// - nil => no change
// - "" (or whitespace) => clear (repo will interpret "" as NULL)
// - otherwise => trimmed value
func normalizeDescriptionPatch(p *string) *string {
	if p == nil {
		return nil
	}
	s := strings.TrimSpace(*p)
	if s == "" {
		empty := ""
		return &empty
	}
	return &s
}

// --------------------
// Handlers
// --------------------

// GET /admin/workspace/{workspaceId}/products/{productId}/configKeys
func (handler *RequestHandler) HandleGetConfigKeys(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProduct(w, r)
	if !ok {
		return
	}

	keys, err := handler.repo.GetConfigKeysByProductID(r.Context(), project.ID)
	if err != nil {
		log.Err(err).Msg("failed to get config keys by project ID")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, ConfigKeysResponse{ConfigKeys: keys}, http.StatusOK)
}

// POST /admin/workspace/{workspaceId}/products/{productId}/configKeys
func (handler *RequestHandler) HandleCreateConfigKey(w http.ResponseWriter, r *http.Request) {
	acc, _, project, ok := handler.adminAndProduct(w, r)
	if !ok {
		return
	}

	var req CreateConfigKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	req.Key = strings.TrimSpace(req.Key)
	if req.Key == "" || !configKeyRegex.MatchString(req.Key) {
		WriteError(w, r, "error.keyInvalid", http.StatusBadRequest)
		return
	}

	desc := normalizeDescriptionCreate(req.Description)

	exp := normalizeExposure(req.Exposure)
	if exp == "" {
		exp = core.ConfigExposurePrivate
	}
	if !isAllowedExposure(exp) {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	vt := normalizeValueType(req.ValueType)
	if !vt.IsValid() {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	status := normalizeStatus(req.Status, "active")
	if !isAllowedStatus(status) {
		WriteError(w, r, "error.statusInvalid", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()

	ck := core.ConfigKey{
		ID:          utils.NewUUID(),
		ProductID:   project.ID,
		Key:         req.Key,
		Description: desc,
		Exposure:    exp,
		ValueType:   vt,
		Status:      status,
		CreatedAt:   now,
		UpdatedAt:   now,
		CreatedBy:   acc.ID,
	}

	out, err := handler.repo.CreateConfigKey(r.Context(), ck)
	if err != nil {
		if errors.Is(err, repo.ErrConflict) {
			WriteError(w, r, "error.keyExists", http.StatusConflict)
			return
		} else if errors.Is(err, repo.ErrBadRequest) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		} else {
			log.Err(err).Msg("failed to create config key")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
	}

	utils.WriteJsonWithStatusCode(w, ConfigKeyResponse{ConfigKey: out}, http.StatusCreated)
}

// GET /admin/workspace/{workspaceId}/products/{productId}/configKeys/{configKeyId}
func (handler *RequestHandler) HandleGetConfigKey(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProduct(w, r)
	if !ok {
		return
	}

	configKeyID, err := uuid.FromString(chi.URLParam(r, "configKeyId"))
	if err != nil {
		WriteError(w, r, "error.invalidConfigKeyId", http.StatusBadRequest)
		return
	}

	ck, err := handler.repo.GetConfigKeyByID(r.Context(), project.ID, configKeyID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.configKeyNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to get config key by ID")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, ConfigKeyResponse{ConfigKey: ck}, http.StatusOK)
}

// PATCH /admin/workspace/{workspaceId}/products/{productId}/configKeys/{configKeyId}
func (handler *RequestHandler) HandleUpdateConfigKey(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProduct(w, r)
	if !ok {
		return
	}

	configKeyID, err := uuid.FromString(chi.URLParam(r, "configKeyId"))
	if err != nil {
		WriteError(w, r, "error.invalidConfigKeyId", http.StatusBadRequest)
		return
	}

	// best-effort before snapshot

	var req UpdateConfigKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	var changed []string

	desc := normalizeDescriptionPatch(req.Description)
	if desc != nil {
		changed = append(changed, "description")
	}

	if req.Exposure != nil {
		e := normalizeExposure(*req.Exposure)
		if !isAllowedExposure(e) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		req.Exposure = &e
		changed = append(changed, "exposure")
	}

	if req.ValueType != nil {
		vt := normalizeValueType(*req.ValueType)
		if !vt.IsValid() {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		req.ValueType = &vt
		changed = append(changed, "valueType")
	}

	if req.Status != nil {
		s := normalizeStatus(*req.Status, "")
		if !isAllowedStatus(s) {
			WriteError(w, r, "error.statusInvalid", http.StatusBadRequest)
			return
		}
		req.Status = &s
		changed = append(changed, "status")
	}

	ck, err := handler.repo.UpdateConfigKey(
		r.Context(),
		project.ID,
		configKeyID,
		desc,
		req.Exposure,
		req.ValueType,
		req.Status,
	)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.configKeyNotFound", http.StatusNotFound)
			return
		} else if errors.Is(err, repo.ErrConflict) {
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		} else if errors.Is(err, repo.ErrBadRequest) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		} else {
			log.Err(err).Msg("failed to update config key")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
	}

	utils.WriteJsonWithStatusCode(w, ConfigKeyResponse{ConfigKey: ck}, http.StatusOK)
}

// DELETE /admin/workspace/{workspaceId}/products/{productId}/configKeys/{configKeyId}
func (handler *RequestHandler) HandleDeleteConfigKey(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProduct(w, r)
	if !ok {
		return
	}

	configKeyID, err := uuid.FromString(chi.URLParam(r, "configKeyId"))
	if err != nil {
		WriteError(w, r, "error.invalidConfigKeyId", http.StatusBadRequest)
		return
	}

	var before any
	if existing, err := handler.repo.GetConfigKeyByID(r.Context(), project.ID, configKeyID); err == nil {
		before = existing
	}

	err = handler.repo.DeleteConfigKey(r.Context(), project.ID, configKeyID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.configKeyNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to delete config key")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if before != nil {
	}

	w.WriteHeader(http.StatusNoContent)
}

// GET /admin/workspace/{workspaceId}/products/{productId}/configValues
func (handler *RequestHandler) HandleGetConfigValues(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProduct(w, r)
	if !ok {
		return
	}

	vals, err := handler.repo.GetConfigValuesByProductID(r.Context(), project.ID)
	if err != nil {
		log.Err(err).Msg("failed to get config values by project ID")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, ConfigValuesResponse{ConfigValues: vals}, http.StatusOK)
}

// PUT /admin/workspace/{workspaceId}/products/{productId}/configKeys/{configKeyId}/apps/{appId}
func (handler *RequestHandler) HandleUpsertConfigValue(w http.ResponseWriter, r *http.Request) {
	acc, ws, project, ok := handler.adminAndProduct(w, r)
	if !ok {
		return
	}

	configKeyID, err := uuid.FromString(chi.URLParam(r, "configKeyId"))
	if err != nil {
		WriteError(w, r, "error.invalidConfigKeyId", http.StatusBadRequest)
		return
	}
	appID, err := uuid.FromString(chi.URLParam(r, "appId"))
	if err != nil {
		WriteError(w, r, "error.invalidAppId", http.StatusBadRequest)
		return
	}

	var req UpsertConfigValueRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	// Ensure not ambiguous:
	valProvided := isNonEmptyJSON(req.Value)
	secProvided := isNonEmptyJSON(req.Secret)

	if !valProvided && !secProvided {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if valProvided && secProvided {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()

	cv := core.ConfigValue{
		ID:          utils.NewUUID(),
		ProductID:   project.ID,
		AppID:       appID,
		ConfigKeyID: configKeyID,
		UpdatedAt:   now,
		UpdatedBy:   acc.ID,
	}

	out, err := handler.repo.UpsertConfigValueJSON(ws.ID, r.Context(), cv, req.Value, req.Secret)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.configKeyNotFound", http.StatusNotFound)
			return
		} else if errors.Is(err, repo.ErrConflict) {
			WriteError(w, r, "error.conflict", http.StatusConflict)
			return
		} else if errors.Is(err, repo.ErrBadRequest) {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		} else {
			log.Err(err).Msg("failed to upsert config value")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
	}

	utils.WriteJsonWithStatusCode(w, ConfigValueResponse{ConfigValue: out}, http.StatusOK)
}

// DELETE /admin/workspace/{workspaceId}/products/{productId}/configKeys/{configKeyId}/apps/{appId}
func (handler *RequestHandler) HandleDeleteConfigValue(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProduct(w, r)
	if !ok {
		return
	}

	configKeyID, err := uuid.FromString(chi.URLParam(r, "configKeyId"))
	if err != nil {
		WriteError(w, r, "error.invalidConfigKeyId", http.StatusBadRequest)
		return
	}
	appID, err := uuid.FromString(chi.URLParam(r, "appId"))
	if err != nil {
		WriteError(w, r, "error.invalidAppId", http.StatusBadRequest)
		return
	}

	err = handler.repo.DeleteConfigValue(r.Context(), project.ID, configKeyID, appID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.configKeyNotFound", http.StatusNotFound)
			return
		}
		log.Err(err).Msg("failed to delete config value")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
