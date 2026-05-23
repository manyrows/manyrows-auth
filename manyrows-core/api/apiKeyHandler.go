package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

const maxAPIKeysPerApp = 5

func (handler *RequestHandler) HandleGetApiKeys(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	appIDStr := r.URL.Query().Get("appId")
	if appIDStr != "" {
		appID, err := uuid.FromString(appIDStr)
		if err != nil {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		keys, err := handler.repo.GetAPIKeysForApp(r.Context(), ws.ID, appID)
		if err != nil {
			log.Err(err).Msg("failed to get API keys for app")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		utils.WriteJsonWithStatusCode(w, keys, http.StatusOK)
		return
	}

	keys, err := handler.repo.GetAPIKeys(r.Context(), ws.ID)
	if err != nil {
		log.Err(err).Msg("failed to get API keys")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJsonWithStatusCode(w, keys, http.StatusOK)
}

func (handler *RequestHandler) HandleGetApiKey(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	// ROUTE IS {id}
	keyIDStr := chi.URLParam(r, "id")
	keyID, err := uuid.FromString(keyIDStr)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	key, err := handler.repo.GetAPIKey(r.Context(), ws.ID, keyID)
	if err != nil {
		log.Err(err).Msg("failed to get API key")
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	utils.WriteJsonWithStatusCode(w, key, http.StatusOK)
}

type UpdateAPIKeyRequest struct {
	Name *string `json:"name"`
}

func (handler *RequestHandler) HandleUpdateApiKey(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	if !handler.requireOwner(w, r) {
		return
	}

	keyIDStr := chi.URLParam(r, "id")
	keyID, err := uuid.FromString(keyIDStr)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	var req UpdateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	if req.Name == nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(*req.Name)
	if name == "" || len(name) > 255 {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	key, err := handler.repo.GetAPIKey(r.Context(), ws.ID, keyID)
	if err != nil {
		log.Err(err).Msg("failed to get API key before update")
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}


	if err := handler.repo.UpdateAPIKeyName(r.Context(), ws.ID, keyID, name); err != nil {
		log.Err(err).Msg("failed to update API key name")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	key.Name = name

	utils.WriteJsonWithStatusCode(w, key, http.StatusOK)
}

func (handler *RequestHandler) HandleDeleteApiKey(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	if !handler.requireOwner(w, r) {
		return
	}

	// ROUTE IS {id}
	keyIDStr := chi.URLParam(r, "id")
	keyID, err := uuid.FromString(keyIDStr)
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	if _, err = handler.repo.GetAPIKey(r.Context(), ws.ID, keyID); err != nil {
		// Match HandleGetApiKey: a missing key (or one in another workspace) is 404.
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	if err := handler.repo.DeleteAPIKey(r.Context(), ws.ID, keyID); err != nil {
		log.Err(err).Msg("failed to delete API key")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type CreateAPIKeyRequest struct {
	Name  string `json:"name"`
	AppID string `json:"appId"`
}

type NewApiKeyResponse struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Key  string    `json:"key"` // full API key shown once
}

func (handler *RequestHandler) HandleCreateApiKey(w http.ResponseWriter, r *http.Request) {
	acc, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	if !handler.requireOwner(w, r) {
		return
	}

	var req CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode create API key request")
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	var appID *uuid.UUID
	if req.AppID != "" {
		parsed, err := uuid.FromString(req.AppID)
		if err != nil {
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		appID = &parsed
	}

	// Enforce max keys per app (or workspace if no app)
	if appID != nil {
		count, err := handler.repo.CountAPIKeysForApp(r.Context(), ws.ID, *appID)
		if err != nil {
			log.Err(err).Msg("failed to count API keys for app")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if count >= maxAPIKeysPerApp {
			WriteErrorf(w, r, "error.limitReached", http.StatusConflict, "API keys", maxAPIKeysPerApp)
			return
		}
	} else {
		count, err := handler.repo.CountAPIKeysForWorkspace(r.Context(), ws.ID)
		if err != nil {
			log.Err(err).Msg("failed to count API keys for workspace")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if count >= maxAPIKeysPerApp {
			WriteErrorf(w, r, "error.limitReached", http.StatusConflict, "API keys", maxAPIKeysPerApp)
			return
		}
	}

	generatedKey, prefix, hashed, err := generateApiKey()
	if err != nil {
		log.Err(err).Msg("failed to generate API key")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	key := &core.APIKey{
		ID:          utils.NewUUID(),
		WorkspaceID: ws.ID,
		AppID:       appID,
		Name:        req.Name,
		Prefix:      prefix,
		Hash:        hashed,
		CreatedAt:   time.Now().UTC(),
		CreatedBy:   acc.ID,
	}

	if err := handler.repo.InsertAPIKey(r.Context(), key); err != nil {
		log.Err(err).Msg("failed to insert API key")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	resp := NewApiKeyResponse{
		ID:   key.ID,
		Name: key.Name,
		Key:  generatedKey,
	}

	utils.WriteJsonWithStatusCode(w, resp, http.StatusCreated)
}

func generateApiKey() (fullKey string, prefix string, hashed string, err error) {
	// 32 bytes of entropy ≈ 256-bit key
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", "", "", e
	}

	// URL-safe base64 (no padding) for the secret part
	secret := base64.RawURLEncoding.EncodeToString(b)

	// Small prefix (first 8 chars) for identification & logging
	if len(secret) < 8 {
		return "", "", "", errors.New("generated secret too short")
	}
	prefix = secret[:8]

	// Final key format, e.g. "mr_<prefix>_<secret>"
	fullKey = "mr_" + prefix + "_" + secret

	// Hash the full key (what we store)
	sum := sha256.Sum256([]byte(fullKey))
	hashed = hex.EncodeToString(sum[:])

	return fullKey, prefix, hashed, nil
}
