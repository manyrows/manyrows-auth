package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

type ServerMagicLinkRequest struct {
	// RememberMe issues a longer-lived session when the link is consumed.
	RememberMe bool `json:"rememberMe"`
}

type ServerMagicLinkResponse struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// ServerCreateMagicLink generates a one-time, passwordless sign-in link for a
// member of this app and returns it for the caller's backend to deliver (e.g.
// in its own onboarding email). The link is consumed by the public
// GET /x/{ws}/apps/{appId}/auth/magic-link endpoint, so it requires the same
// preconditions that endpoint enforces — the app's primary auth method is
// Magic Link and an App URL is configured (checked by requireMagicLinkContext).
// Issuing a new link invalidates any previously issued unconsumed link for the
// same user, so a backend that issues links in parallel should treat only the
// latest as valid.
// POST /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/magic-link
func (handler *RequestHandler) ServerCreateMagicLink(w http.ResponseWriter, r *http.Request) {
	ws, app, ok := handler.requireMagicLinkContext(w, r)
	if !ok {
		return
	}

	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return
	}
	if !handler.requireAppMember(w, r, app.ID, userID) {
		return
	}

	user, err := handler.repo.GetUserByID(r.Context(), userID)
	if err != nil || user == nil {
		// requireAppMember already proved membership, so a miss here is a
		// race or internal error, not a normal 404.
		log.Err(err).Msg("ServerCreateMagicLink: GetUserByID failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Body is optional (defaults to rememberMe=false).
	var req ServerMagicLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	rawToken, tokenHash, err := handler.adminAuthService.NewMagicToken()
	if err != nil {
		log.Err(err).Msg("ServerCreateMagicLink: NewMagicToken failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	expiresAt := time.Now().UTC().Add(magicLinkTTL)
	if err := handler.repo.CreateMagicLink(r.Context(), repo.CreateMagicLinkParams{
		Purpose:   appLoginMagicPurpose(app.ID),
		Email:     user.Email,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	}); err != nil {
		log.Err(err).Msg("ServerCreateMagicLink: CreateMagicLink failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	url := buildMagicLinkConsumeURL(handler.AppBaseURL(app), ws.Slug, app.ID, rawToken, req.RememberMe)
	utils.WriteJson(w, ServerMagicLinkResponse{URL: url, ExpiresAt: expiresAt})
}
