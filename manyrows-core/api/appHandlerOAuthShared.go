package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/crypto"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// Shared building blocks for the per-provider OAuth config update handlers
// (appHandlerGithub/Naver/Kakao/Google/Apple/Microsoft.go). Each provider's
// handler still owns its own request struct, enable-validation rules, and
// repo update call — only the byte-identical preamble and the credential-merge
// boilerplate live here.

// oauthConfigUpdate carries the context resolved by beginOAuthConfigUpdate:
// the authenticated owner, the workspace, the path IDs, and the current app.
type oauthConfigUpdate struct {
	acc       *core.Account
	ws        *core.Workspace
	projectID uuid.UUID
	appID     uuid.UUID
	curApp    core.App
}

// beginOAuthConfigUpdate runs the preamble common to every provider config
// handler: admin+owner auth, path-ID resolution, body decode into req, and
// loading the current app row. On any failure it writes the response and
// returns ok=false. provider is used only for the load-failure log message.
func (handler *RequestHandler) beginOAuthConfigUpdate(w http.ResponseWriter, r *http.Request, provider string, req any) (oauthConfigUpdate, bool) {
	var c oauthConfigUpdate
	var ok bool
	c.acc, c.ws, ok = handler.adminAndWorkspace(w, r)
	if !ok {
		return c, false
	}
	if !handler.requireOwner(w, r) {
		return c, false
	}
	c.projectID, c.appID, ok = handler.resolvePathIDs(w, r)
	if !ok {
		return c, false
	}

	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		log.Err(err).Msg("failed to decode json")
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return c, false
	}

	curApp, err := handler.repo.GetAppByIDForProject(r.Context(), c.ws.ID, c.projectID, c.appID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			WriteError(w, r, "error.appNotFound", http.StatusNotFound)
			return c, false
		}
		log.Err(err).Msgf("failed to load app for %s-config update", provider)
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return c, false
	}
	c.curApp = curApp
	return c, true
}

// mergeOptionalString applies an optional inbound string field onto the stored
// value: a nil pointer keeps the current value, a blank string clears it (nil),
// and any other value is trimmed and set.
func mergeOptionalString(in *string, current *string) *string {
	if in == nil {
		return current
	}
	trimmed := strings.TrimSpace(*in)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

// encryptOptionalSecret resolves an optional inbound secret against the
// currently-stored ciphertext for an apps column. The returned value is what
// to persist (nil = keep existing via COALESCE, empty-but-non-nil = clear,
// ciphertext = set) and postSaveHas reports whether a secret will exist after
// the write. On encryption failure it writes the error response and returns
// ok=false.
func (handler *RequestHandler) encryptOptionalSecret(
	w http.ResponseWriter, r *http.Request,
	in *string, currentEncrypted []byte, aadColumn string, appID uuid.UUID,
) (encrypted []byte, postSaveHas bool, ok bool) {
	if in == nil {
		return nil, len(currentEncrypted) > 0, true
	}
	trimmed := strings.TrimSpace(*in)
	if trimmed == "" {
		return []byte{}, false, true
	}
	enc, err := handler.encryptor.EncryptToBytesWithAAD([]byte(trimmed), crypto.AAD("apps", aadColumn, appID))
	if err != nil {
		log.Err(err).Msgf("failed to encrypt %s", aadColumn)
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return nil, false, false
	}
	return enc, true, true
}
