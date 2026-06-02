package api

// JWT signing-key rotation surface. Three endpoints, all super-admin
// only:
//
//   GET    /admin/security/signing-keys
//   POST   /admin/security/signing-keys/rotate
//   POST   /admin/security/signing-keys/retire-previous
//
// Rotation is purely operator-driven — there's no scheduled rotation,
// no env-var trigger that could fire twice on a re-deploy. The admin
// hits the rotate endpoint when they decide to rotate, then hits the
// retire endpoint after enough time has elapsed for in-flight tokens
// to expire (≥ longest live refresh-token TTL — default 7d, up to 30d
// with remember-me, or per-app override).

import (
	"net/http"

	"github.com/rs/zerolog/log"

	"manyrows-core/utils"
)

// requireSuperAdmin returns the current account when they're logged
// in AND the super-admin, otherwise writes a 401/403 and returns
// nil. Use at the top of any handler scoped to install-wide
// configuration (signing keys, etc.).
func (handler *RequestHandler) requireSuperAdmin(w http.ResponseWriter, r *http.Request) bool {
	acc, _, err := handler.adminAuthService.GetLoggedInAccount(r)
	if err != nil {
		log.Err(err).Msg("requireSuperAdmin: GetLoggedInAccount failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return false
	}
	if acc == nil {
		WriteError(w, r, "error.notLoggedIn", http.StatusUnauthorized)
		return false
	}
	if !acc.IsSuper() {
		WriteError(w, r, "error.forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// GetSigningKeys returns the live signing keyset's current + optional
// previous kid. Private material is never exposed.
func (handler *RequestHandler) GetSigningKeys(w http.ResponseWriter, r *http.Request) {
	if !handler.requireSuperAdmin(w, r) {
		return
	}
	utils.WriteJson(w, handler.clientAuthService.GetSigningKeyStatus())
}

// PostRotateSigningKey rotates the JWT signing key — generates a new
// current key, moves the prior current into the previous slot, and
// publishes both at /.well-known/jwks.json. In-flight JWTs continue
// to verify until they reach natural expiry; after that, the operator
// should call PostRetirePreviousSigningKey.
//
// Multi-instance caveat: only the replica that handles the request
// reloads its in-memory keyset. Other replicas continue issuing under
// the old kid until they restart. Cross-replica verification still
// works because both keys are published in JWKS.
func (handler *RequestHandler) PostRotateSigningKey(w http.ResponseWriter, r *http.Request) {
	if !handler.requireSuperAdmin(w, r) {
		return
	}
	status, err := handler.clientAuthService.RotateSigningKey(r.Context())
	if err != nil {
		log.Err(err).Msg("rotate signing key failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, status)
}

// PostRetirePreviousSigningKey drops the previous-key slot, ending
// the rotation overlap window. Tokens signed with the previous key
// will fail verification after this call returns. Only call once
// every token signed with the previous key has expired — typically
// 7 days after PostRotateSigningKey (or up to 30 days with
// remember-me, or whatever the app's RememberMeTTL override is).
func (handler *RequestHandler) PostRetirePreviousSigningKey(w http.ResponseWriter, r *http.Request) {
	if !handler.requireSuperAdmin(w, r) {
		return
	}
	status, err := handler.clientAuthService.RetirePreviousSigningKey(r.Context())
	if err != nil {
		log.Err(err).Msg("retire previous signing key failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, status)
}
