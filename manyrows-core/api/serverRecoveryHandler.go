package api

import (
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

// resolveAppMember resolves the app from context and the {userId} from the URL,
// and confirms the user is a member of the app — the common preamble for
// member-scoped server handlers. On any failure it has already written the
// response and returns ok=false.
func (handler *RequestHandler) resolveAppMember(w http.ResponseWriter, r *http.Request) (*core.App, uuid.UUID, bool) {
	app, ok := core.AppFromContext(r.Context())
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return nil, uuid.Nil, false
	}
	userID, ok := handler.userIDFromURL(w, r)
	if !ok {
		return nil, uuid.Nil, false
	}
	if !handler.requireAppMember(w, r, app.ID, userID) {
		return nil, uuid.Nil, false
	}
	return app, userID, true
}

// ServerResetUserTOTP disables (clears) a member's TOTP/2FA — the recovery
// operation for a user who lost their authenticator. They can re-enroll via the
// normal flow afterward.
// DELETE /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/totp
func (handler *RequestHandler) ServerResetUserTOTP(w http.ResponseWriter, r *http.Request) {
	_, userID, ok := handler.resolveAppMember(w, r)
	if !ok {
		return
	}
	if err := handler.repo.DisableUserTOTP(r.Context(), userID); err != nil {
		log.Err(err).Msg("ServerResetUserTOTP: DisableUserTOTP failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ServerUnlockUser clears a failed-login lockout on a member, restoring sign-in
// immediately (the lockout is otherwise automatic and time-based).
// POST /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/unlock
func (handler *RequestHandler) ServerUnlockUser(w http.ResponseWriter, r *http.Request) {
	_, userID, ok := handler.resolveAppMember(w, r)
	if !ok {
		return
	}
	if err := handler.repo.ClearUserLockedUntil(r.Context(), userID); err != nil {
		log.Err(err).Msg("ServerUnlockUser: ClearUserLockedUntil failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type ServerIdentity struct {
	Provider        string    `json:"provider"`
	ProviderSubject string    `json:"providerSubject,omitempty"`
	ProviderEmail   string    `json:"providerEmail,omitempty"`
	CreatedAt       time.Time `json:"createdAt"`
	LastLoginAt     time.Time `json:"lastLoginAt"`
}

type ServerIdentitiesResponse struct {
	Identities []ServerIdentity `json:"identities"`
}

// ServerListUserIdentities lists a member's linked SSO/OAuth identities
// (Google, Apple, etc.). Identities are pool-level (shared across apps in the
// pool).
// GET /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/identities
func (handler *RequestHandler) ServerListUserIdentities(w http.ResponseWriter, r *http.Request) {
	_, userID, ok := handler.resolveAppMember(w, r)
	if !ok {
		return
	}
	identities, err := handler.repo.ListUserIdentities(r.Context(), userID)
	if err != nil {
		log.Err(err).Msg("ServerListUserIdentities: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	out := make([]ServerIdentity, 0, len(identities))
	for _, id := range identities {
		out = append(out, ServerIdentity{
			Provider:        string(id.Provider),
			ProviderSubject: id.ProviderSubject,
			ProviderEmail:   id.ProviderEmail,
			CreatedAt:       id.CreatedAt,
			LastLoginAt:     id.LastLoginAt,
		})
	}
	utils.WriteJson(w, ServerIdentitiesResponse{Identities: out})
}

// ServerDeleteUserIdentity unlinks a member's SSO/OAuth identity for a provider.
// Idempotent. Pool-level — the unlink applies across apps sharing the pool.
// DELETE /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/identities/{provider}
func (handler *RequestHandler) ServerDeleteUserIdentity(w http.ResponseWriter, r *http.Request) {
	_, userID, ok := handler.resolveAppMember(w, r)
	if !ok {
		return
	}
	provider := chi.URLParam(r, "provider")
	if err := handler.repo.DeleteUserIdentity(r.Context(), userID, core.UserSource(provider)); err != nil {
		log.Err(err).Msg("ServerDeleteUserIdentity: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type ServerPasskey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name,omitempty"`
	Transports []string   `json:"transports,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
}

type ServerPasskeysResponse struct {
	Passkeys []ServerPasskey `json:"passkeys"`
}

// ServerListUserPasskeys lists a member's registered passkeys (WebAuthn
// credentials) for this app.
// GET /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/passkeys
func (handler *RequestHandler) ServerListUserPasskeys(w http.ResponseWriter, r *http.Request) {
	app, userID, ok := handler.resolveAppMember(w, r)
	if !ok {
		return
	}
	passkeys, err := handler.repo.ListPasskeysByUser(r.Context(), app.ID, userID)
	if err != nil {
		log.Err(err).Msg("ServerListUserPasskeys: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	out := make([]ServerPasskey, 0, len(passkeys))
	for _, pk := range passkeys {
		name := ""
		if pk.Name != nil {
			name = *pk.Name
		}
		out = append(out, ServerPasskey{
			ID:         pk.ID.String(),
			Name:       name,
			Transports: pk.Transports,
			CreatedAt:  pk.CreatedAt,
			LastUsedAt: pk.LastUsedAt,
		})
	}
	utils.WriteJson(w, ServerPasskeysResponse{Passkeys: out})
}

// ServerDeleteUserPasskey removes one of a member's passkeys for this app.
// Idempotent; app-scoped so a credential from another app can't be touched.
// DELETE /x/{workspaceSlug}/api/v1/apps/{appId}/users/{userId}/passkeys/{passkeyId}
func (handler *RequestHandler) ServerDeleteUserPasskey(w http.ResponseWriter, r *http.Request) {
	app, userID, ok := handler.resolveAppMember(w, r)
	if !ok {
		return
	}
	passkeyID, err := uuid.FromString(chi.URLParam(r, "passkeyId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if err := handler.repo.DeletePasskey(r.Context(), app.ID, userID, passkeyID); err != nil && !errors.Is(err, repo.ErrNotFound) {
		log.Err(err).Msg("ServerDeleteUserPasskey: failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
