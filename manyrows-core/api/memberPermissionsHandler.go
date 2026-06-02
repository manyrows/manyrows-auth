package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

func (handler *RequestHandler) HandleGetMemberPermissions(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProject(w, r)
	if !ok {
		return
	}

	userID, err := uuid.FromString(chi.URLParam(r, "userId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	appID, err := uuid.FromString(r.URL.Query().Get("appId"))
	if err != nil || appID == uuid.Nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	permIDs, err := handler.repo.GetDirectPermissionIDs(r.Context(), project.ID, userID, appID)
	if err != nil {
		log.Err(err).Msg("failed to get direct permissions")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if permIDs == nil {
		permIDs = []uuid.UUID{}
	}

	utils.WriteJson(w, map[string]any{"permissionIds": permIDs})
}

func (handler *RequestHandler) HandleSetMemberPermissions(w http.ResponseWriter, r *http.Request) {
	_, _, project, ok := handler.adminAndProject(w, r)
	if !ok {
		return
	}

	userID, err := uuid.FromString(chi.URLParam(r, "userId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	var body struct {
		AppID         uuid.UUID   `json:"appId"`
		PermissionIDs []uuid.UUID `json:"permissionIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	if body.AppID == uuid.Nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	if body.PermissionIDs == nil {
		body.PermissionIDs = []uuid.UUID{}
	}

	if err := handler.repo.SetDirectPermissions(r.Context(), project.ID, userID, body.AppID, body.PermissionIDs); err != nil {
		if errors.Is(err, repo.ErrBadRequest) {
			// appId or a permissionId doesn't belong to this project.
			WriteError(w, r, "error.badRequest", http.StatusBadRequest)
			return
		}
		log.Err(err).Msg("failed to set direct permissions")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{"ok": true})
}
