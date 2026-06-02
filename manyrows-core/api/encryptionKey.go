package api

import (
	"encoding/json"
	"errors"
	"manyrows-core/core/repo"
	"net/http"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

// GET /encryption-key
func (handler *RequestHandler) GetWorkspaceEncryptionKey(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	key, err := handler.repo.GetWorkspaceEncryptionKey(r.Context(), ws.ID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.WriteJson(w, map[string]any{
				"key": nil,
			})
			return
		}

		log.Error().
			Err(err).
			Str("workspaceId", ws.ID.String()).
			Msg("failed to load workspace encryption key")

		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{
		"key": key,
	})
}

// POST /encryption-key
func (handler *RequestHandler) SetWorkspaceEncryptionKey(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	acc, ok := core.AdminAccountFromContext(r.Context())
	if !ok || acc == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	if !handler.requireOwner(w, r) {
		return
	}

	var req struct {
		PublicKeyJWK      json.RawMessage `json:"publicKeyJwk"`
		FingerprintSha256 string          `json:"fingerprintSha256"`
	}

	if ok := utils.ReadJson(w, r, &req); !ok {
		return
	}

	if len(req.PublicKeyJWK) == 0 {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	req.FingerprintSha256 = strings.TrimSpace(req.FingerprintSha256)
	if req.FingerprintSha256 == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	key := core.WorkspaceEncryptionKey{
		ID:           utils.NewUUID(),
		WorkspaceID:  ws.ID,
		PublicKeyJWK: req.PublicKeyJWK,
		Fingerprint:  req.FingerprintSha256,
		CreatedAt:    time.Now().UTC(),
		CreatedBy:    &acc.ID,
	}

	if err := handler.repo.UpsertWorkspaceEncryptionKey(r.Context(), key); err != nil {
		log.Error().
			Err(err).
			Str("workspaceId", ws.ID.String()).
			Msg("failed to save workspace encryption key")

		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{
		"ok": true,
	})
}
