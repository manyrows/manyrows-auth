package api

import (
	"net/http"

	"manyrows-core/auth"
	"manyrows-core/auth/client"
	"manyrows-core/auth/dpop"
	"manyrows-core/config"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/crypto"
	"manyrows-core/email"
	"manyrows-core/webhook"

	"github.com/rs/zerolog/log"
)

type RequestHandler struct {
	repo              *repo.Repo
	adminAuthService  *auth.Service
	clientAuthService *client.AuthService
	emailService      *email.Service
	config            *config.Config
	encryptor         crypto.SecretEncryptor
	// secureSecrets is the system_secrets-writing surface that
	// transparently encrypts sensitive rows at rest (SMTP password
	// mirror, future bootstrap material). Routes the same encryption
	// pipeline the email service uses for reads, so writes round-trip
	// cleanly.
	secureSecrets     *crypto.EncryptingSystemSecretsStore
	webhookDispatcher *webhook.Dispatcher
	// totpKey is the HMAC key for short-lived signed tokens — TOTP challenges
	// AND OAuth state, despite the name. Derived (DeriveTokenSigningKey) from
	// SESSION_AUTH_KEY so it doesn't share raw bytes with the cookie store.
	totpKey          []byte
	previousTOTPKeys [][]byte
	dpopVerifier     *dpop.Verifier
}

func NewRequestHandler(repo *repo.Repo, adminAuthService *auth.Service, clientAuthService *client.AuthService, emailService *email.Service, config *config.Config, encryptor crypto.SecretEncryptor, secureSecrets *crypto.EncryptingSystemSecretsStore) *RequestHandler {
	var totpKey []byte
	var previousTOTPKeys [][]byte
	if config != nil {
		if key, err := config.GetSessionAuthKey(); err == nil {
			// Domain-separate the token-signing key from the cookie-store auth
			// key. Both root in SESSION_AUTH_KEY, but the gorilla securecookie
			// store and our raw-HMAC token signers must not share key bytes
			// across two different crypto constructions. See DeriveTokenSigningKey.
			totpKey = auth.DeriveTokenSigningKey([]byte(key))
		}
		if prev, err := config.GetSessionAuthKeyPrevious(); err == nil {
			for _, p := range prev {
				previousTOTPKeys = append(previousTOTPKeys, auth.DeriveTokenSigningKey([]byte(p)))
			}
		} else {
			log.Warn().Err(err).Msg("ignoring MANYROWS_SESSION_AUTH_KEY_PREVIOUS: invalid entry — token rotation grace window inactive")
		}
	}
	// Tests pass nil for the encryptor when they only exercise endpoints
	// that don't touch encrypted columns. Endpoints that DO encrypt
	// (TOTP setup, OAuth secret store, SMTP password mirror) would NPE
	// on the nil receiver, so default-construct one from cfg when
	// possible. Production callers always pass a real encryptor.
	if encryptor == nil && config != nil {
		if _, err := config.GetEncryptionKey(); err == nil {
			encryptor = crypto.NewMySecretEncryptor(config)
		}
	}
	if secureSecrets == nil {
		// Tests that don't care about the encrypted mirror can pass nil
		// and fall back to a wrapper rooted at the raw repo. Production
		// callers (app.go) pass the same wrapper they handed to the
		// email service so writes round-trip with reads.
		secureSecrets = crypto.NewEncryptingSystemSecretsStore(repo, encryptor)
	}
	return &RequestHandler{
		repo:              repo,
		adminAuthService:  adminAuthService,
		clientAuthService: clientAuthService,
		emailService:      emailService,
		config:            config,
		encryptor:         encryptor,
		secureSecrets:     secureSecrets,
		totpKey:           totpKey,
		previousTOTPKeys:  previousTOTPKeys,
		dpopVerifier:      dpop.NewVerifier(repo),
	}
}

// tokenVerifyKeys returns the verification key list: current first, then
// previous keys during a rotation grace window. Signing uses totpKey only.
func (handler *RequestHandler) tokenVerifyKeys() [][]byte {
	return append([][]byte{handler.totpKey}, handler.previousTOTPKeys...)
}

// requireOwner checks that the current admin has the "owner" role for this workspace.
// Returns false and writes a 403 response if the role is not "owner".
func (handler *RequestHandler) requireOwner(w http.ResponseWriter, r *http.Request) bool {
	role, ok := core.WorkspaceRoleFromContext(r.Context())
	if !ok || role != "owner" {
		WriteError(w, r, "error.forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func (handler *RequestHandler) SetWebhookDispatcher(d *webhook.Dispatcher) {
	handler.webhookDispatcher = d
}
