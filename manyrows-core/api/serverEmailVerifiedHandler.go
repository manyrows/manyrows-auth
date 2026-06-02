package api

import (
	"encoding/json"
	"net/http"
	"time"

	"manyrows-core/core"

	"github.com/rs/zerolog/log"
)

type ServerSetEmailVerifiedRequest struct {
	Verified bool `json:"verified"`
}

// ServerSetUserEmailVerified marks a member's email as verified or unverified.
// Use it when your own flow has confirmed (or invalidated) the address. This is
// a pool-level attribute, so it applies to the identity across every app that
// shares the pool.
// PUT /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/email-verified
func (handler *RequestHandler) ServerSetUserEmailVerified(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}
	if !handler.requireAppMember(w, r, app.ID, userID) {
		return
	}

	var req ServerSetEmailVerifiedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	var err error
	if req.Verified {
		err = handler.repo.SetUserEmailVerified(ctx, userID, time.Now().UTC())
	} else {
		err = handler.repo.ClearUserEmailVerified(ctx, userID)
	}
	if err != nil {
		log.Err(err).Msg("ServerSetUserEmailVerified: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
