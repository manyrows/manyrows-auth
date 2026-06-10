package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/utils"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const (
	webauthnChallengeTTL = 5 * time.Minute
	webauthnRPDisplay    = "ManyRows"

	attemptPurposeWorkspacePasskeyLogin    = "workspace_login_passkey"
	attemptPurposeWorkspacePasskeyRegister = "workspace_register_passkey"

	// maxPasskeysPerUser caps total passkeys per (app, user). The
	// per-subject rate limit above (10 attempts / 10 min) bounds the
	// burst rate but lets a long-running attacker keep adding entries
	// indefinitely. Realistic legitimate usage is ~6 (phone + laptop +
	// hardware key per device family), so 20 leaves headroom without
	// becoming a DoS vector against the credential-list lookup on
	// every login.
	maxPasskeysPerUser = 20
)

// buildWebAuthnForApp constructs a *webauthn.WebAuthn instance for an app.
// RPID comes from the app's webauthn_rpid column; RPOrigins comes from the
// app's CORS origins (already validated to be under the RPID at config time).
func (handler *RequestHandler) buildWebAuthnForApp(ctx context.Context, app *core.App) (*webauthn.WebAuthn, string, error) {
	rpidPtr, err := handler.repo.GetAppWebAuthnRPID(ctx, app.ID)
	if err != nil {
		return nil, "", err
	}
	if rpidPtr == nil || *rpidPtr == "" {
		return nil, "", errors.New("passkeys not enabled for this app")
	}
	rpid := *rpidPtr

	originsRaw, err := handler.repo.GetCorsOrigins(ctx, app.ID)
	if err != nil {
		return nil, "", fmt.Errorf("load cors origins: %w", err)
	}
	origins := make([]string, 0, len(originsRaw))
	for _, o := range originsRaw {
		if o.Origin != "" {
			origins = append(origins, o.Origin)
		}
	}
	if len(origins) == 0 {
		return nil, "", errors.New("app has no CORS origins configured for passkeys")
	}

	displayName := strings.TrimSpace(app.DisplayName())
	if displayName == "" {
		displayName = webauthnRPDisplay
	}

	w, err := webauthn.New(&webauthn.Config{
		RPID:          rpid,
		RPDisplayName: displayName,
		RPOrigins:     origins,
	})
	if err != nil {
		return nil, "", fmt.Errorf("webauthn.New: %w", err)
	}
	return w, rpid, nil
}

// =====================
// User adapter
// =====================

type passkeyUser struct {
	user        *core.User
	credentials []webauthn.Credential
}

func newPasskeyUser(u *core.User, passkeys []core.UserPasskey) *passkeyUser {
	creds := make([]webauthn.Credential, 0, len(passkeys))
	for _, p := range passkeys {
		creds = append(creds, toWebAuthnCredential(p))
	}
	return &passkeyUser{user: u, credentials: creds}
}

func (p *passkeyUser) WebAuthnID() []byte {
	id := p.user.ID
	return id.Bytes()
}

func (p *passkeyUser) WebAuthnName() string                       { return p.user.Email }
func (p *passkeyUser) WebAuthnDisplayName() string                { return p.user.Email }
func (p *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return p.credentials }

func toWebAuthnCredential(p core.UserPasskey) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(p.Transports))
	for _, t := range p.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}
	var aaguid []byte
	if p.AAGUID != nil {
		b := p.AAGUID.Bytes()
		aaguid = b
	}
	return webauthn.Credential{
		ID:        p.CredentialID,
		PublicKey: p.PublicKey,
		Transport: transports,
		Flags: webauthn.CredentialFlags{
			BackupEligible: p.BackupEligible,
			BackupState:    p.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:    aaguid,
			SignCount: p.SignCount,
		},
	}
}

// =====================
// RPID validation
// =====================

// validateRPIDAgainstOrigins enforces that:
//   - the RPID is a valid registrable domain (eTLD+1 or a subdomain of one)
//   - every origin's hostname is == RPID or a subdomain of RPID
//
// localhost gets a special pass for development; the WebAuthn spec also
// treats localhost specially. Unicode IDN inputs are normalized to
// punycode so customers can enter "bücher.example" directly.
func validateRPIDAgainstOrigins(rpid string, origins []string) error {
	rpid = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(rpid, ".")))
	if rpid == "" {
		return errors.New("rpid is required")
	}
	if rpid == "localhost" {
		return nil
	}

	asciiRPID, err := idna.Lookup.ToASCII(rpid)
	if err != nil {
		return fmt.Errorf("rpid %q is not a valid domain: %w", rpid, err)
	}
	rpid = asciiRPID

	eTLD1, err := publicsuffix.EffectiveTLDPlusOne(rpid)
	if err != nil {
		return fmt.Errorf("rpid %q is not a valid registrable domain: %w", rpid, err)
	}
	if rpid != eTLD1 && !strings.HasSuffix(rpid, "."+eTLD1) {
		return fmt.Errorf("rpid %q does not match its registrable suffix %q", rpid, eTLD1)
	}

	for _, raw := range origins {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return fmt.Errorf("invalid CORS origin %q", raw)
		}
		host := strings.ToLower(u.Hostname())
		if host == "localhost" {
			continue
		}
		// Normalize the origin host to punycode too so "bücher.example"
		// inside an origin matches a punycode-stored RPID.
		if asciiHost, err := idna.Lookup.ToASCII(host); err == nil {
			host = asciiHost
		}
		if host != rpid && !strings.HasSuffix(host, "."+rpid) {
			return fmt.Errorf("CORS origin %q is not under RPID %q — passkeys would not work for this origin", raw, rpid)
		}
	}
	return nil
}

// ensureCorsChangeKeepsPasskeysValid enforces that, if passkeys are enabled
// for the app (RPID is set), a proposed CORS-origin change leaves the
// invariant intact: every origin still under the registrable suffix of the
// RPID. Returns nil when passkeys aren't configured (no invariant to keep).
//
// For POST (create), pass replacingID=nil. For PATCH (update), pass the id
// of the existing origin being replaced — the helper excludes it from the
// "current" list before adding the new value back in. The library still
// rejects mismatched origins per-ceremony, but checking at write time means
// admins get an immediate error with a clear message rather than a silent
// breakage they discover via a failing passkey login.
func (handler *RequestHandler) ensureCorsChangeKeepsPasskeysValid(ctx context.Context, appID uuid.UUID, newOrigin string, replacingID *uuid.UUID) error {
	rpidPtr, err := handler.repo.GetAppWebAuthnRPID(ctx, appID)
	if err != nil {
		return err
	}
	if rpidPtr == nil || *rpidPtr == "" {
		return nil
	}

	existing, err := handler.repo.GetCorsOrigins(ctx, appID)
	if err != nil {
		return err
	}
	proposed := make([]string, 0, len(existing)+1)
	for _, o := range existing {
		if replacingID != nil && o.ID == *replacingID {
			continue
		}
		proposed = append(proposed, o.Origin)
	}
	proposed = append(proposed, newOrigin)
	return validateRPIDAgainstOrigins(*rpidPtr, proposed)
}

// =====================
// Admin: configure RPID
// =====================

type SetWebAuthnRPIDRequest struct {
	RPID *string `json:"rpid"`
}

// HandleSetAppWebAuthnRPID configures (or clears) the per-app WebAuthn RPID.
// PUT /admin/workspace/{workspaceId}/projects/{projectId}/apps/{appId}/webauthn-rpid
func (handler *RequestHandler) HandleSetAppWebAuthnRPID(w http.ResponseWriter, r *http.Request) {
	_, _, appID, ok := handler.parseAppContext(w, r)
	if !ok {
		return
	}

	var req SetWebAuthnRPIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}

	var rpid *string
	if req.RPID != nil {
		trimmed := strings.ToLower(strings.TrimSpace(*req.RPID))
		if trimmed != "" {
			origins, err := handler.repo.GetCorsOrigins(r.Context(), appID)
			if err != nil {
				log.Err(err).Msg("Could not load CORS origins for RPID validation")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
			originStrs := make([]string, 0, len(origins))
			for _, o := range origins {
				originStrs = append(originStrs, o.Origin)
			}
			if err := validateRPIDAgainstOrigins(trimmed, originStrs); err != nil {
				WriteErrorf(w, r, "error.invalidRPID", http.StatusBadRequest, err.Error())
				return
			}
			rpid = &trimmed
		}
	}

	if err := handler.repo.SetAppWebAuthnRPID(r.Context(), appID, rpid); err != nil {
		log.Err(err).Msg("Could not save app WebAuthn RPID")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{"rpid": rpid})
}

// HandleGetAppWebAuthnRPID returns the configured RPID (admin view).
// GET /admin/workspace/{workspaceId}/projects/{projectId}/apps/{appId}/webauthn-rpid
func (handler *RequestHandler) HandleGetAppWebAuthnRPID(w http.ResponseWriter, r *http.Request) {
	_, _, appID, ok := handler.parseAppContext(w, r)
	if !ok {
		return
	}
	rpid, err := handler.repo.GetAppWebAuthnRPID(r.Context(), appID)
	if err != nil {
		log.Err(err).Msg("Could not load app WebAuthn RPID")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, map[string]any{"rpid": rpid})
}

// =====================
// End-user: registration ceremony (auth required)
// =====================

// WorkspacePasskeyRegisterBegin starts the registration ceremony.
// POST /x/{slug}/apps/{appId}/a/passkey/register/begin
func (handler *RequestHandler) WorkspacePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	user, _, app, ok := handler.requireAuthedAppUser(w, r)
	if !ok {
		return
	}

	// Per-user rate limit so a compromised session can't spam the
	// webauthn_challenges table. The endpoint is JWT-authed, so user.ID is
	// the right subject; IP is also recorded for cross-account attacker
	// fingerprinting.
	ip := auth.ClientIP(r)
	since := time.Now().UTC().Add(-workspacePasswordAuthWindow)
	subject := user.ID.String()
	subjectCount, err := handler.repo.CountAttemptsBySubject(r.Context(), attemptPurposeWorkspacePasskeyRegister, subject, since)
	if err != nil {
		log.Err(err).Msg("failed to count attempts for passkey register-begin")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if subjectCount >= maxAttemptsPerSubject10Min {
		WriteRateLimitError(w, r, 600)
		return
	}
	_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeWorkspacePasskeyRegister, subject, ip)

	wa, _, err := handler.buildWebAuthnForApp(r.Context(), app)
	if err != nil {
		WriteError(w, r, "error.passkeysDisabled", http.StatusBadRequest)
		return
	}

	existing, err := handler.repo.ListPasskeysByUser(r.Context(), app.ID, user.ID)
	if err != nil {
		log.Err(err).Msg("Could not list passkeys for register-begin")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	// Cap the total number of passkeys per user per app. The 10-attempts-
	// per-10-min subject rate limit above bounds the burst rate, but
	// successful registrations accumulate forever — over weeks an
	// attacker holding a compromised session could mint hundreds of
	// passkeys, bloating the credential list, slowing every login lookup,
	// and burying the user's legitimate keys. 20 is well above any
	// realistic legitimate count (phone + laptop + hardware key × a few
	// devices = ~6); operators who want a different cap can change the
	// constant.
	if len(existing) >= maxPasskeysPerUser {
		WriteError(w, r, "error.passkeyLimitReached", http.StatusConflict)
		return
	}
	pkUser := newPasskeyUser(user, existing)

	// Exclude already-registered credentials so the same authenticator
	// can't enroll twice — the browser surfaces InvalidStateError, which
	// the SDK maps to a friendly "already registered" error.
	creds := pkUser.WebAuthnCredentials()
	exclusions := make([]protocol.CredentialDescriptor, 0, len(creds))
	for i := range creds {
		exclusions = append(exclusions, creds[i].Descriptor())
	}

	// Require user verification (PIN, biometric, etc) so a credential
	// without UV — e.g. a hardware key configured without a PIN — can't
	// be registered. Combined with the matching policy on login, this
	// keeps passkeys as a true two-factor (something you have + something
	// you are/know).
	opts := []webauthn.RegistrationOption{
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		}),
	}
	if len(exclusions) > 0 {
		opts = append(opts, webauthn.WithExclusions(exclusions))
	}
	creation, sessionData, err := wa.BeginRegistration(pkUser, opts...)
	if err != nil {
		log.Err(err).Msg("BeginRegistration failed")
		WriteError(w, r, "error.passkeyBeginFailed", http.StatusBadRequest)
		return
	}

	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		log.Err(err).Msg("Could not marshal webauthn session data")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	uid := user.ID
	stored, err := handler.repo.InsertWebAuthnChallenge(r.Context(), core.WebAuthnChallenge{
		AppID:       app.ID,
		UserID:      &uid,
		Purpose:     core.WebAuthnChallengePurposeRegister,
		Challenge:   []byte(sessionData.Challenge),
		SessionData: sessionJSON,
		ExpiresAt:   time.Now().UTC().Add(webauthnChallengeTTL),
	})
	if err != nil {
		log.Err(err).Msg("Could not persist webauthn register challenge")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{
		"challengeId":      stored.ID,
		"publicKeyOptions": creation,
	})
}

type WorkspacePasskeyRegisterFinishRequest struct {
	ChallengeID uuid.UUID       `json:"challengeId"`
	Name        *string         `json:"name,omitempty"`
	Response    json.RawMessage `json:"response"`
}

// WorkspacePasskeyRegisterFinish verifies the attestation and persists the
// new credential.
// POST /x/{slug}/apps/{appId}/a/passkey/register/finish
func (handler *RequestHandler) WorkspacePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	user, _, app, ok := handler.requireAuthedAppUser(w, r)
	if !ok {
		return
	}
	wa, _, err := handler.buildWebAuthnForApp(r.Context(), app)
	if err != nil {
		WriteError(w, r, "error.passkeysDisabled", http.StatusBadRequest)
		return
	}

	var req WorkspacePasskeyRegisterFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if req.ChallengeID == uuid.Nil || len(req.Response) == 0 {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	ch, found, err := handler.repo.ConsumeWebAuthnChallenge(r.Context(), req.ChallengeID)
	if err != nil {
		log.Err(err).Msg("Could not consume webauthn register challenge")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !found || ch.AppID != app.ID || ch.Purpose != core.WebAuthnChallengePurposeRegister || ch.UserID == nil || *ch.UserID != user.ID {
		WriteError(w, r, "error.passkeyChallengeInvalid", http.StatusBadRequest)
		return
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(ch.SessionData, &sessionData); err != nil {
		log.Err(err).Msg("Could not unmarshal webauthn session data")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(req.Response)
	if err != nil {
		log.Err(err).Msg("Could not parse credential creation response")
		WriteError(w, r, "error.passkeyResponseInvalid", http.StatusBadRequest)
		return
	}

	existing, err := handler.repo.ListPasskeysByUser(r.Context(), app.ID, user.ID)
	if err != nil {
		log.Err(err).Msg("Could not load existing passkeys for finish-register")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	pkUser := newPasskeyUser(user, existing)

	cred, err := wa.CreateCredential(pkUser, sessionData, parsed)
	if err != nil {
		log.Err(err).Msg("CreateCredential failed")
		WriteError(w, r, "error.passkeyVerifyFailed", http.StatusBadRequest)
		return
	}

	// Defense-in-depth: the library should already enforce UV because we
	// set UserVerification: required on the session. Re-check here so a
	// future library refactor or a misconfigured option can't slip a
	// non-UV credential into the database.
	if !cred.Flags.UserVerified {
		log.Warn().Msg("Refusing passkey registration: authenticator did not perform user verification")
		WriteError(w, r, "error.passkeyUVRequired", http.StatusBadRequest)
		return
	}

	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	var aaguid *uuid.UUID
	if len(cred.Authenticator.AAGUID) == 16 {
		var u uuid.UUID
		copy(u[:], cred.Authenticator.AAGUID)
		aaguid = &u
	}

	saved, err := handler.repo.InsertPasskey(r.Context(), core.UserPasskey{
		AppID:          app.ID,
		UserID:         user.ID,
		CredentialID:   cred.ID,
		PublicKey:      cred.PublicKey,
		SignCount:      cred.Authenticator.SignCount,
		Transports:     transports,
		AAGUID:         aaguid,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
		Name:           req.Name,
	})
	if err != nil {
		log.Err(err).Msg("Could not persist new passkey")
		WriteError(w, r, "error.passkeyAlreadyRegistered", http.StatusConflict)
		return
	}

	handler.dispatchWebhook(app.ID, "user.passkey_register", map[string]any{
		"userId":    user.ID,
		"passkeyId": saved.ID,
		"appId":     app.ID,
	})

	if ws, ok := core.WorkspaceFromContext(r.Context()); ok && ws != nil {
		userID := user.ID
		var passkeyLabel string
		if saved.Name != nil {
			passkeyLabel = *saved.Name
		}
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:   ws.ID,
			AppID:         &app.ID,
			Event:         core.AuthEventPasskeyRegistered,
			Method:        core.AuthMethodPasskey,
			Outcome:       core.AuthOutcomeSuccess,
			SubjectUserID: &userID,
			ActorType:     core.AuthActorSelf,
			ActorLabel:    user.Email,
			Metadata:      core.PasskeyMetadata{PasskeyID: saved.ID, PasskeyLabel: passkeyLabel},
		})
	}

	utils.WriteJson(w, map[string]any{"passkey": toPasskeyResource(saved)})
}

// =====================
// End-user: login ceremony (public, then session created)
// =====================

// WorkspacePasskeyLoginBegin starts a discoverable-credential login.
// POST /x/{slug}/apps/{appId}/auth/passkey/login/begin
func (handler *RequestHandler) WorkspacePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	app, ok := core.AppFromContext(r.Context())
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}
	wa, _, err := handler.buildWebAuthnForApp(r.Context(), app)
	if err != nil {
		WriteError(w, r, "error.passkeysDisabled", http.StatusBadRequest)
		return
	}

	ip := auth.ClientIP(r)
	if !handler.checkAttemptRateLimit(w, r, attemptPurposeWorkspacePasskeyLogin, ip, "", "passkey login", nil) {
		return
	}
	// Burn an attempt unconditionally so /begin spam can't fill webauthn_challenges
	// without ever paying the rate-limit budget. Each attempt counts toward the
	// IP cap; finish failures pile on top.
	_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeWorkspacePasskeyLogin, "", ip)

	assertion, sessionData, err := wa.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		log.Err(err).Msg("BeginDiscoverableLogin failed")
		WriteError(w, r, "error.passkeyBeginFailed", http.StatusBadRequest)
		return
	}

	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		log.Err(err).Msg("Could not marshal webauthn session data")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	stored, err := handler.repo.InsertWebAuthnChallenge(r.Context(), core.WebAuthnChallenge{
		AppID:       app.ID,
		UserID:      nil,
		Purpose:     core.WebAuthnChallengePurposeLogin,
		Challenge:   []byte(sessionData.Challenge),
		SessionData: sessionJSON,
		ExpiresAt:   time.Now().UTC().Add(webauthnChallengeTTL),
	})
	if err != nil {
		log.Err(err).Msg("Could not persist webauthn login challenge")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{
		"challengeId":      stored.ID,
		"publicKeyOptions": assertion,
	})
}

type WorkspacePasskeyLoginFinishRequest struct {
	ChallengeID uuid.UUID       `json:"challengeId"`
	RememberMe  bool            `json:"rememberMe,omitempty"`
	Response    json.RawMessage `json:"response"`
}

// WorkspacePasskeyLoginFinish verifies the assertion, looks up the user via
// the discoverable user-handle, and creates a client session.
// POST /x/{slug}/apps/{appId}/auth/passkey/login/finish
func (handler *RequestHandler) WorkspacePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	ws, ok := core.WorkspaceFromContext(r.Context())
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}
	app, ok := core.AppFromContext(r.Context())
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return
	}
	wa, _, err := handler.buildWebAuthnForApp(r.Context(), app)
	if err != nil {
		WriteError(w, r, "error.passkeysDisabled", http.StatusBadRequest)
		return
	}

	ip := auth.ClientIP(r)
	ua := strings.TrimSpace(r.UserAgent())

	// passkeyLoginFailed is the shared failure-write closure for this
	// handler. subjectID and email are nil/"" when the user isn't yet
	// resolved (discoverable-credential lookup hasn't returned yet);
	// pass them on the later branches once we know the user.
	passkeyLoginFailed := func(reason core.AuthLogFailureReason, subjectID *uuid.UUID, email string, passkeyID *uuid.UUID) {
		in := AuthLogInput{
			WorkspaceID:    ws.ID,
			AppID:          &app.ID,
			Event:          core.AuthEventLoginFailed,
			Method:         core.AuthMethodPasskey,
			Outcome:        core.AuthOutcomeFailed,
			FailureReason:  reason,
			SubjectUserID:  subjectID,
			EmailAttempted: email,
			ActorType:      core.AuthActorSelf,
		}
		if passkeyID != nil {
			in.Metadata = core.PasskeyMetadata{PasskeyID: *passkeyID}
		}
		handler.writeAuthLogFromRequest(r, in)
	}

	var req WorkspacePasskeyLoginFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if req.ChallengeID == uuid.Nil || len(req.Response) == 0 {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	ch, found, err := handler.repo.ConsumeWebAuthnChallenge(r.Context(), req.ChallengeID)
	if err != nil {
		log.Err(err).Msg("Could not consume webauthn login challenge")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !found || ch.AppID != app.ID || ch.Purpose != core.WebAuthnChallengePurposeLogin {
		_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeWorkspacePasskeyLogin, "", ip)
		passkeyLoginFailed(core.AuthFailInvalidState, nil, "", nil)
		WriteError(w, r, "error.passkeyChallengeInvalid", http.StatusBadRequest)
		return
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(ch.SessionData, &sessionData); err != nil {
		log.Err(err).Msg("Could not unmarshal webauthn session data")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(req.Response)
	if err != nil {
		_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeWorkspacePasskeyLogin, "", ip)
		log.Err(err).Msg("Could not parse credential request response")
		passkeyLoginFailed(core.AuthFailPasskeyInvalid, nil, "", nil)
		WriteError(w, r, "error.passkeyResponseInvalid", http.StatusBadRequest)
		return
	}

	var resolvedUser *core.User
	var matchedPasskey core.UserPasskey
	resolver := func(rawID, userHandle []byte) (webauthn.User, error) {
		if len(userHandle) == 0 {
			return nil, errors.New("missing user handle")
		}
		uid, err := uuid.FromBytes(userHandle)
		if err != nil {
			return nil, fmt.Errorf("invalid user handle: %w", err)
		}
		u, err := handler.repo.GetUserByID(r.Context(), uid)
		if err != nil {
			return nil, fmt.Errorf("user not found: %w", err)
		}
		passkeys, err := handler.repo.ListPasskeysByUser(r.Context(), app.ID, u.ID)
		if err != nil {
			return nil, fmt.Errorf("load passkeys: %w", err)
		}
		for _, p := range passkeys {
			if string(p.CredentialID) == string(rawID) {
				matchedPasskey = p
				break
			}
		}
		if matchedPasskey.ID == uuid.Nil {
			return nil, errors.New("credential not registered for this app/user")
		}
		resolvedUser = u
		return newPasskeyUser(u, passkeys), nil
	}

	_, cred, err := wa.ValidatePasskeyLogin(resolver, sessionData, parsed)
	if err != nil || resolvedUser == nil {
		_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeWorkspacePasskeyLogin, "", ip)
		log.Err(err).Msg("ValidatePasskeyLogin failed")
		passkeyLoginFailed(core.AuthFailPasskeyInvalid, nil, "", nil)
		WriteError(w, r, "error.passkeyVerifyFailed", http.StatusUnauthorized)
		return
	}

	user := resolvedUser
	userID := user.ID
	passkeyID := matchedPasskey.ID

	// Defense-in-depth: enforce UV at the application layer too. The lib
	// should already enforce it because we set UserVerification: required
	// on the session, but a re-check is cheap insurance.
	if !cred.Flags.UserVerified {
		log.Warn().Str("passkey_id", matchedPasskey.ID.String()).Msg("Refusing passkey login: authenticator did not perform user verification")
		passkeyLoginFailed(core.AuthFailPasskeyUVRequired, &userID, user.Email, &passkeyID)
		WriteError(w, r, "error.passkeyUVRequired", http.StatusUnauthorized)
		return
	}

	// Reject on possible clone — the library compares the assertion's
	// signCount against the stored value and raises CloneWarning when the
	// new counter doesn't strictly exceed the old (with the all-zero
	// special case). The DB UPDATE is defense-in-depth below.
	if cred.Authenticator.CloneWarning {
		log.Warn().Str("passkey_id", matchedPasskey.ID.String()).Msg("Refusing passkey login: clone warning from authenticator")
		passkeyLoginFailed(core.AuthFailPasskeyCloneSuspected, &userID, user.Email, &passkeyID)
		WriteError(w, r, "error.passkeyCloneSuspected", http.StatusUnauthorized)
		return
	}

	// Deliberate policy: passkey login does NOT enforce TOTP or
	// app.Require2FA, even when the user has TOTP enabled or the admin set
	// the flag. The reasoning:
	//
	//   - WebAuthn with UserVerification: required (which we enforce above)
	//     is itself "something you have + something you are/know" — a
	//     hardware-bound credential plus biometric/PIN. By spec it counts
	//     as multi-factor authentication.
	//   - Stacking TOTP on top is friction without a corresponding security
	//     gain in the realistic threat model.
	//   - This is what Apple, Google, GitHub and others do: passkey alone,
	//     no second factor.
	//
	// If a customer's compliance regime requires two distinct credentials
	// regardless, they should keep `Require2FA` set AND disable passkey
	// auth (no RPID configured) on that app. Don't paper over the question
	// here without flipping the policy explicitly.
	if user.IsDisabled() {
		passkeyLoginFailed(core.AuthFailAccountDisabled, &userID, user.Email, &passkeyID)
		WriteError(w, r, "error.accountDisabled", http.StatusForbidden)
		return
	}

	if err := handler.repo.UpdatePasskeyOnLogin(r.Context(), matchedPasskey.ID, cred.Authenticator.SignCount, cred.Flags.BackupState); err != nil {
		log.Err(err).Msg("Refusing passkey login: sign-counter regression")
		passkeyLoginFailed(core.AuthFailPasskeyCloneSuspected, &userID, user.Email, &passkeyID)
		WriteError(w, r, "error.passkeyCloneSuspected", http.StatusUnauthorized)
		return
	}

	ses, err := handler.clientAuthService.CreateSessionWithOptions(r.Context(), user.ID, app.ID, ua, ip, req.RememberMe, app.SessionTTL(), app.RememberMeTTL(), app.MaxSessions())
	if err != nil {
		log.Err(err).Msg("Could not create client session for passkey login")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	dpopJKT, dpopErr := handler.extractDPoPJKT(w, r)
	if dpopErr != nil {
		_ = handler.clientAuthService.DeleteSession(r.Context(), ses.ID)
		return
	}
	tokenPair, err := handler.clientAuthService.IssueTokenPair(r.Context(), ses, ua, ip, effectiveSessionTTL(app, req.RememberMe), app.AccessTokenTTL(), dpopJKT, handler.clientAuthService.IssuerForApp(app), "")
	if err != nil {
		log.Err(err).Msg("Could not issue token pair for passkey login")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	loginAt := time.Now().UTC()
	_ = handler.repo.UpdateUserLastLogin(r.Context(), user.ID, loginAt)
	_ = handler.repo.UpdateAppUserLastLogin(r.Context(), app.ID, user.ID, loginAt)
	sessionID := ses.ID
	handler.writeAuthLogFromRequest(r, AuthLogInput{
		WorkspaceID:   ws.ID,
		AppID:         &app.ID,
		Event:         core.AuthEventLoginSuccess,
		Method:        core.AuthMethodPasskey,
		Outcome:       core.AuthOutcomeSuccess,
		SubjectUserID: &userID,
		ActorType:     core.AuthActorSelf,
		ActorLabel:    user.Email,
		SessionID:     &sessionID,
		Metadata:      core.PasskeyMetadata{PasskeyID: passkeyID},
	})
	handler.writeAuthLogFromRequest(r, AuthLogInput{
		WorkspaceID:   ws.ID,
		AppID:         &app.ID,
		Event:         core.AuthEventPasskeyUsed,
		Method:        core.AuthMethodPasskey,
		Outcome:       core.AuthOutcomeSuccess,
		SubjectUserID: &userID,
		ActorType:     core.AuthActorSelf,
		ActorLabel:    user.Email,
		SessionID:     &sessionID,
		Metadata:      core.PasskeyMetadata{PasskeyID: passkeyID},
	})

	handler.dispatchWebhook(app.ID, "user.login", map[string]any{
		"userId": user.ID, "email": user.Email, "appId": app.ID, "method": "passkey",
	})

	handler.setSessionCookies(w, r, ws, app, tokenPair, effectiveSessionTTL(app, req.RememberMe))
	utils.WriteJson(w, map[string]any{
		"accessToken":  tokenPair.AccessToken,
		"refreshToken": tokenPair.RefreshToken,
		"expiresAt":    tokenPair.ExpiresAt.Format(time.RFC3339),
		"expiresIn":    int(time.Until(tokenPair.ExpiresAt).Seconds()),
		"session":      toClientSessionResource(ses),
	})
}

// =====================
// End-user: list / rename / delete own passkeys
// =====================

type PasskeyResource struct {
	ID                uuid.UUID  `json:"id"`
	Name              *string    `json:"name,omitempty"`
	Transports        []string   `json:"transports"`
	AAGUID            *uuid.UUID `json:"aaguid,omitempty"`
	AuthenticatorName string     `json:"authenticatorName,omitempty"`
	BackupEligible    bool       `json:"backupEligible"`
	BackupState       bool       `json:"backupState"`
	CreatedAt         time.Time  `json:"createdAt"`
	LastUsedAt        *time.Time `json:"lastUsedAt,omitempty"`
}

func toPasskeyResource(p core.UserPasskey) PasskeyResource {
	return PasskeyResource{
		ID:                p.ID,
		Name:              p.Name,
		Transports:        p.Transports,
		AAGUID:            p.AAGUID,
		AuthenticatorName: authenticatorNameForAAGUID(p.AAGUID),
		BackupEligible:    p.BackupEligible,
		BackupState:       p.BackupState,
		CreatedAt:         p.CreatedAt,
		LastUsedAt:        p.LastUsedAt,
	}
}

// WorkspaceListMyPasskeys returns the logged-in user's passkeys for this app.
// GET /x/{slug}/apps/{appId}/a/passkeys
func (handler *RequestHandler) WorkspaceListMyPasskeys(w http.ResponseWriter, r *http.Request) {
	user, _, app, ok := handler.requireAuthedAppUser(w, r)
	if !ok {
		return
	}
	passkeys, err := handler.repo.ListPasskeysByUser(r.Context(), app.ID, user.ID)
	if err != nil {
		log.Err(err).Msg("Could not list passkeys")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	out := make([]PasskeyResource, 0, len(passkeys))
	for _, p := range passkeys {
		out = append(out, toPasskeyResource(p))
	}
	utils.WriteJson(w, map[string]any{"passkeys": out})
}

type WorkspaceRenamePasskeyRequest struct {
	Name *string `json:"name"`
}

// WorkspaceRenamePasskey renames a passkey owned by the logged-in user.
// PATCH /x/{slug}/apps/{appId}/a/passkeys/{passkeyId}
func (handler *RequestHandler) WorkspaceRenamePasskey(w http.ResponseWriter, r *http.Request) {
	user, _, app, ok := handler.requireAuthedAppUser(w, r)
	if !ok {
		return
	}
	pid, err := uuid.FromString(chi.URLParam(r, "passkeyId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	var req WorkspaceRenamePasskeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	var name *string
	if req.Name != nil {
		trimmed := strings.TrimSpace(*req.Name)
		if len(trimmed) > 80 {
			trimmed = trimmed[:80]
		}
		if trimmed != "" {
			name = &trimmed
		}
	}
	if err := handler.repo.RenamePasskey(r.Context(), app.ID, user.ID, pid, name); err != nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	utils.WriteJson(w, map[string]any{"ok": true})
}

// WorkspaceDeletePasskey deletes a passkey owned by the logged-in user.
// DELETE /x/{slug}/apps/{appId}/a/passkeys/{passkeyId}
//
// Re-auth required: deletion is irreversible and a stolen access token
// could otherwise be used to wipe every passkey on an account,
// permanently locking the legitimate owner out. The request body
// carries the same EITHER-password-OR-emailed-code surface as TOTP
// disable. A DELETE with a body is unusual but explicit on the wire
// is preferable to changing the route shape just for the second
// factor.
func (handler *RequestHandler) WorkspaceDeletePasskey(w http.ResponseWriter, r *http.Request) {
	user, _, app, ok := handler.requireAuthedAppUser(w, r)
	if !ok {
		return
	}
	pid, err := uuid.FromString(chi.URLParam(r, "passkeyId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// DELETE bodies are unusual but allowed by RFC 9110. Read may fail
	// on an empty body (e.g. older clients that don't send one) — fall
	// through to the reauth helper with empty values, which returns
	// error.reauthRequired so the client knows to prompt for password.
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	if !handler.requireSensitivePasswordOrCodeReauth(w, r, user, app, req.Password, req.Code) {
		return
	}

	if err := handler.repo.DeletePasskey(r.Context(), app.ID, user.ID, pid); err != nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	handler.dispatchWebhook(app.ID, "user.passkey_delete", map[string]any{
		"userId": user.ID, "passkeyId": pid, "appId": app.ID,
	})
	if ws, ok := core.WorkspaceFromContext(r.Context()); ok && ws != nil {
		userID := user.ID
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:   ws.ID,
			AppID:         &app.ID,
			Event:         core.AuthEventPasskeyDeleted,
			Method:        core.AuthMethodPasskey,
			Outcome:       core.AuthOutcomeSuccess,
			SubjectUserID: &userID,
			ActorType:     core.AuthActorSelf,
			ActorLabel:    user.Email,
			Metadata:      core.PasskeyMetadata{PasskeyID: pid},
		})
	}
	utils.WriteJson(w, map[string]any{"ok": true})
}

// =====================
// Admin: list / revoke a user's passkeys
// =====================

// HandleAdminListUserPasskeys returns one user's passkeys for support workflows.
// GET /admin/workspace/{workspaceId}/projects/{projectId}/apps/{appId}/users/{userId}/passkeys
func (handler *RequestHandler) HandleAdminListUserPasskeys(w http.ResponseWriter, r *http.Request) {
	_, _, appID, ok := handler.parseAppContext(w, r)
	if !ok {
		return
	}
	user, ok := handler.loadUserScopedToApp(w, r, appID)
	if !ok {
		return
	}
	passkeys, err := handler.repo.ListPasskeysByUser(r.Context(), appID, user.ID)
	if err != nil {
		log.Err(err).Msg("Could not list user passkeys (admin)")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	out := make([]PasskeyResource, 0, len(passkeys))
	for _, p := range passkeys {
		out = append(out, toPasskeyResource(p))
	}
	utils.WriteJson(w, map[string]any{"passkeys": out})
}

// HandleAdminDeleteUserPasskey revokes a passkey for a user.
// DELETE /admin/workspace/{workspaceId}/projects/{projectId}/apps/{appId}/users/{userId}/passkeys/{passkeyId}
func (handler *RequestHandler) HandleAdminDeleteUserPasskey(w http.ResponseWriter, r *http.Request) {
	_, _, appID, ok := handler.parseAppContext(w, r)
	if !ok {
		return
	}
	user, ok := handler.loadUserScopedToApp(w, r, appID)
	if !ok {
		return
	}
	uid := user.ID
	pid, err := uuid.FromString(chi.URLParam(r, "passkeyId"))
	if err != nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if err := handler.repo.DeletePasskey(r.Context(), appID, uid, pid); err != nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if ws, ok := core.WorkspaceFromContext(r.Context()); ok && ws != nil {
		var actorAccountID *uuid.UUID
		var actorLabel string
		if acc, ok := core.AdminAccountFromContext(r.Context()); ok && acc != nil {
			id := acc.ID
			actorAccountID = &id
			actorLabel = acc.Email
		}
		handler.writeAuthLogFromRequest(r, AuthLogInput{
			WorkspaceID:    ws.ID,
			AppID:          &appID,
			Event:          core.AuthEventPasskeyAdminRevoked,
			Method:         core.AuthMethodPasskey,
			Outcome:        core.AuthOutcomeSuccess,
			SubjectUserID:  &uid,
			ActorType:      core.AuthActorAdmin,
			ActorAccountID: actorAccountID,
			ActorLabel:     actorLabel,
			Metadata:       core.PasskeyMetadata{PasskeyID: pid},
		})
	}
	utils.WriteJson(w, map[string]any{"ok": true})
}

// =====================
// Helper
// =====================

func (handler *RequestHandler) requireAuthedAppUser(w http.ResponseWriter, r *http.Request) (*core.User, *core.ClientSession, *core.App, bool) {
	ses, ok := core.ClientSessionFromContext(r.Context())
	if !ok || ses == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return nil, nil, nil, false
	}
	app, ok := core.AppFromContext(r.Context())
	if !ok || app == nil {
		WriteError(w, r, "error.appNotFound", http.StatusNotFound)
		return nil, nil, nil, false
	}
	user, err := handler.repo.GetUserByID(r.Context(), ses.UserID)
	if err != nil || user == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return nil, nil, nil, false
	}
	return user, ses, app, true
}
