package api

import (
	"net/http"
	"os"
	"strings"
	"time"

	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/core/validation"
	"manyrows-core/crypto/passwordhash"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

const (
	minAdminPasswordLen = 10

	// Rate limit windows (reuse the same shape as magic link)
	adminPasswordAuthWindow = 10 * time.Minute

	// Separate purposes so you can tune independently
	attemptPurposeAdminRegister = "admin_register_pw"
	attemptPurposeAdminLogin    = "admin_login_pw"
)

type AdminRegisterPasswordRequest struct {
	Email          string `json:"email"`
	Password       string `json:"password"`
	TurnstileToken string `json:"turnstileToken"`
}

type AdminLoginPasswordRequest struct {
	Email          string `json:"email"`
	Password       string `json:"password"`
	TurnstileToken string `json:"turnstileToken"`
}

func normLower(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}

// verifyTurnstile validates a Cloudflare Turnstile challenge token from an
// admin auth request. Returns true on success. On failure it writes the error
// response and returns false — caller should just return after the false.
//
// Fails closed on any error (network, empty token, bad response) so a flaky
// Cloudflare outage or a missing widget on the client can't become an auth
// bypass. Intentionally burns no DB rate-limit attempts on failure — bots
// that never even submit a token shouldn't affect a legit user's throttle.
func (handler *RequestHandler) verifyTurnstile(w http.ResponseWriter, r *http.Request, token string) bool {
	// Turnstile is opt-in. When the operator hasn't configured keys
	// (typical for self-hosted single-tenant installs), the widget
	// isn't rendered client-side and there's no token to validate —
	// pass through. Operators flip the integration on by setting
	// MANYROWS_TURNSTILE_SITE_KEY + _SECRET_KEY env vars.
	if !handler.config.IsTurnstileEnabled() {
		return true
	}
	secret := handler.config.GetTurnstileSecretKey()
	result, err := core.VerifyTurnstileToken(r.Context(), secret, token, auth.ClientIP(r))
	if err != nil {
		log.Warn().Err(err).Msg("turnstile verification error")
		WriteError(w, r, "error.captchaFailed", http.StatusForbidden)
		return false
	}
	if !result.Success {
		log.Warn().
			Strs("errorCodes", result.ErrorCodes).
			Str("hostname", result.Hostname).
			Str("challengeTs", result.ChallengeTS).
			Str("action", result.Action).
			Msg("turnstile verification failed")
		WriteError(w, r, "error.captchaFailed", http.StatusForbidden)
		return false
	}
	return true
}

func (handler *RequestHandler) AdminRegister(w http.ResponseWriter, r *http.Request) {
	// Self-registration policy:
	//   - Dev mode: always open (matches the existing local workflow).
	//   - Self-hosted, no super-admin email pinned: open until the
	//     first registrant claims, then closed.
	//   - Self-hosted, super-admin email pinned (env or prior boot's
	//     claim): open only for the pinned email until an account
	//     exists for it, then closed.
	//
	// The in-memory `superAdminEmail` is populated at boot from
	// system_secrets. In a multi-instance deployment a fresh replica
	// that hasn't seen a registration yet has an empty in-memory value
	// even though instance A has already claimed; fall through to a
	// live DB read so the gate is authoritative across replicas.
	pinnedEmail := core.GetSuperAdminEmail()
	if pinnedEmail == "" {
		v, err := handler.repo.GetSystemSecret(r.Context(), "super_admin_email")
		if err != nil {
			log.Err(err).Msg("admin register: live super-admin lookup failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if v != "" {
			core.SetSuperAdminEmail(v) // catch this replica's in-memory up
			pinnedEmail = v
		}
	}

	// "first-admin needed" splits two cases: no pin (legacy — anyone can
	// register first), or pin set but no account yet (only the pinned
	// email can complete the registration). The pin-but-no-account case
	// uses GetAccountByEmail because the pinned row can be written by
	// the boot-time MANYROWS_SUPER_ADMIN_EMAIL claim before any account
	// exists; without this check the gate would close prematurely.
	needsFirstAdmin := false
	if pinnedEmail == "" {
		needsFirstAdmin = true
	} else {
		existing, _, err := handler.repo.GetAccountByEmail(r.Context(), pinnedEmail)
		if err != nil {
			log.Err(err).Msg("admin register: account lookup for pinned super-admin failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if existing == nil {
			needsFirstAdmin = true
		}
	}
	if !handler.config.IsDevMode() && !needsFirstAdmin {
		WriteError(w, r, "error.registrationDisabled", http.StatusForbidden)
		return
	}

	// If already logged in, forbid
	acc, _, err := handler.adminAuthService.GetLoggedInAccount(r)
	if err != nil {
		log.Err(err).Msg("failed to get logged in account for admin register")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if acc != nil {
		WriteError(w, r, "error.alreadyLoggedIn", http.StatusForbidden)
		return
	}

	req := AdminRegisterPasswordRequest{}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	if !handler.verifyTurnstile(w, r, req.TurnstileToken) {
		return
	}

	email := normLower(req.Email)
	if email == "" {
		WriteValidationError(w, r, validation.NewIssue("email", "required", "email is required"))
		return
	}

	toEmail, vr := auth.ValidateEmail(email)
	if !vr.Ok() {
		WriteValidationError(w, r, vr)
		return
	}

	// If the operator pinned a super-admin email (env or prior boot)
	// and the slot is still unclaimed, only that exact email can
	// complete the first registration. Earlier than rate-limit /
	// password-hash to keep the rejection cheap.
	if needsFirstAdmin && pinnedEmail != "" && !strings.EqualFold(pinnedEmail, toEmail) {
		log.Warn().
			Str("attempted", toEmail).
			Str("pinned", pinnedEmail).
			Msg("admin register: email doesn't match pinned super-admin; rejecting")
		WriteError(w, r, "error.registrationDisabled", http.StatusForbidden)
		return
	}

	pw := strings.TrimSpace(req.Password)
	if len(pw) < minAdminPasswordLen {
		WriteValidationError(w, r, validation.NewIssue("password", "too_short", "password is too short"))
		return
	}
	if len(pw) > 128 {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Rate limit (SEND/CREATE)
	now := time.Now().UTC()
	ip := auth.ClientIP(r)
	subject := normLower(toEmail)

	if !handler.checkAttemptRateLimit(w, r, attemptPurposeAdminRegister, ip, subject, "admin register", nil) {
		return
	}

	// Ensure not already registered
	existing, vr2, err := handler.repo.GetAccountByEmail(r.Context(), toEmail)
	if err != nil {
		log.Err(err).Msg("Could not check existing admin account by email")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !vr2.Ok() {
		WriteValidationError(w, r, vr2)
		return
	}
	if existing != nil {
		// Burn attempt to discourage enumeration spam on /register.
		_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeAdminRegister, subject, ip)

		// Return the same success response to avoid leaking account existence.
		utils.WriteJson(w, map[string]any{"ok": true})
		return
	}

	// Hash password
	hash, err := passwordhash.Hash(pw)
	if err != nil {
		log.Err(err).Msg("Could not hash password")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	id, err := uuid.NewV4()
	if err != nil {
		log.Err(err).Msg("Could not generate uuid")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Minimal name default (you can improve later)
	name := toEmail
	if i := strings.Index(toEmail, "@"); i > 0 {
		name = toEmail[:i]
	}

	newAcc := &core.Account{
		ID:        id,
		Email:     toEmail,
		Name:      name,
		CreatedAt: now,
		// ValidatedAt should remain nil by default (unvalidated)
	}

	tx, err := handler.repo.DB().Pool().Begin(r.Context())
	if err != nil {
		log.Err(err).Msg("Could not begin tx")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(r.Context())

	vr3, err := handler.repo.InsertAccountWithPassword(r.Context(), tx, newAcc, hash, now)
	if err != nil {
		log.Err(err).Msg("Could not insert account with password")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !vr3.Ok() {
		// Burn attempt on "duplicate" etc. to slow spam.
		_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeAdminRegister, subject, ip)

		WriteValidationError(w, r, vr3)
		return
	}

	// First-admin claim happens INSIDE the registration tx so a lost
	// race against a concurrent first-registrant rolls the account
	// insert back via the deferred Rollback. Without this the loser's
	// account would be committed before the claim ran, leaving a
	// stray regular-admin row from someone who shouldn't have been
	// able to register at all.
	firstAdminClaimed := false
	if needsFirstAdmin {
		stored, claimErr := handler.repo.PutSystemSecretTx(r.Context(), tx, "super_admin_email", toEmail)
		if claimErr != nil {
			log.Err(claimErr).Msg("first-admin claim: PutSystemSecretTx failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if stored != toEmail {
			// Same-process race lost. The other registrant's tx has
			// already committed (otherwise our INSERT would have seen
			// no row and won). Reject this request; deferred Rollback
			// undoes our account insert.
			log.Warn().
				Str("attempted", toEmail).
				Str("winner", stored).
				Msg("first-admin race lost — rejecting registration")
			WriteError(w, r, "error.registrationDisabled", http.StatusForbidden)
			return
		}
		firstAdminClaimed = true
	}

	if err := tx.Commit(r.Context()); err != nil {
		log.Err(err).Msg("Could not commit tx")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Post-commit first-admin housekeeping (auto-validate, BASE_URL
	// pin, default workspace). Each one is its own short tx because
	// the operations are independent and failure of any of them
	// shouldn't roll back the now-committed account.
	if firstAdminClaimed {
		core.SetSuperAdminEmail(toEmail)
		log.Info().Str("email", toEmail).Msg("first-admin claimed super-admin role")

		// Auto-validate the first admin's email. There's nobody else
		// to verify against, and the operator may not have SMTP
		// configured yet — sending a verification email to the
		// console output and asking them to fish it out is pointless
		// friction. Best-effort: failure here just means the admin
		// walks through the normal validate flow.
		if vtx, err := handler.repo.DB().Pool().Begin(r.Context()); err == nil {
			if err := handler.repo.SetAccountValidatedAt(r.Context(), vtx, newAcc.ID, time.Now().UTC()); err != nil {
				log.Err(err).Msg("first-admin: auto-validate failed")
				_ = vtx.Rollback(r.Context())
			} else if err := vtx.Commit(r.Context()); err != nil {
				log.Err(err).Msg("first-admin: auto-validate commit failed")
			} else {
				t := time.Now().UTC()
				newAcc.ValidatedAt = &t
			}
		}

		// Same first-write-wins pattern for BASE_URL — pin it to
		// whichever host the operator hit /admin/register from.
		// Best-effort: if the request lacks a usable host (rare),
		// just skip and the operator can set MANYROWS_BASE_URL or
		// edit the DB row later.
		if base := requestBaseURL(r); base != "" && handler.config.GetBaseURL() == "" {
			if _, err := handler.repo.PutSystemSecret(r.Context(), "base_url", base); err != nil {
				log.Err(err).Msg("first-admin: persist base_url failed (non-fatal)")
			} else {
				_ = os.Setenv("MANYROWS_BASE_URL", base)
				log.Info().Str("baseUrl", base).Msg("first-admin pinned base_url")
			}
		}

		// The workspace abstraction is invisible in the self-hosted UI,
		// so spin one up for the first admin so they don't land on an
		// empty home.
		if err := handler.createDefaultWorkspaceForFirstAdmin(r.Context(), newAcc.ID); err != nil {
			log.Err(err).Msg("first-admin: default workspace creation failed (non-fatal)")
		}
	}

	// ✅ Only burn attempt AFTER we actually created the account.
	// This stops a bot from consuming quota without doing useful work.
	if err := handler.repo.InsertAttempt(r.Context(), attemptPurposeAdminRegister, subject, ip); err != nil {
		log.Err(err).Msg("Could not insert admin register attempt (post-create)")
	}

	// Log them in immediately
	if _, err := handler.adminAuthService.DoLogin(w, r, newAcc); err != nil {
		log.Err(err).Msg("Could not login after register")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{"ok": true})
}

func (handler *RequestHandler) AdminLogin(w http.ResponseWriter, r *http.Request) {
	// If already logged in, forbid (optional - you could also just return ok)
	acc, _, err := handler.adminAuthService.GetLoggedInAccount(r)
	if err != nil {
		log.Err(err).Msg("failed to get logged in account for admin login")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if acc != nil {
		WriteError(w, r, "error.alreadyLoggedIn", http.StatusForbidden)
		return
	}

	req := AdminLoginPasswordRequest{}
	if !utils.ReadJson(w, r, &req) {
		return
	}

	if !handler.verifyTurnstile(w, r, req.TurnstileToken) {
		return
	}

	email := normLower(req.Email)
	if email == "" {
		WriteValidationError(w, r, validation.NewIssue("email", "required", "email is required"))
		return
	}

	toEmail, vr := auth.ValidateEmail(email)
	if !vr.Ok() {
		WriteValidationError(w, r, vr)
		return
	}

	pw := strings.TrimSpace(req.Password)
	if pw == "" {
		WriteValidationError(w, r, validation.NewIssue("password", "required", "password is required"))
		return
	}
	if len(pw) > 128 {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}

	// Rate limit (LOGIN)
	ip := auth.ClientIP(r)
	subject := normLower(toEmail)

	if !handler.checkAttemptRateLimit(w, r, attemptPurposeAdminLogin, ip, subject, "admin login", nil) {
		return
	}

	acc2, passwordHash, vr2, err := handler.repo.GetAccountWithPasswordByEmail(r.Context(), toEmail)
	if err != nil {
		log.Err(err).Msg("Could not lookup account with password")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !vr2.Ok() {
		WriteValidationError(w, r, vr2)
		return
	}

	// Don't leak whether the account exists.
	// Also: burn attempt on failures to slow brute force.
	if acc2 == nil || passwordHash == "" {
		_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeAdminLogin, subject, ip)
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	// Check account lockout
	if handler.checkAccountLocked(w, r, acc2.LockedUntil) {
		return
	}

	ok, err := passwordhash.Verify(passwordHash, pw)
	if err != nil || !ok {
		_ = handler.repo.InsertAttempt(r.Context(), attemptPurposeAdminLogin, subject, ip)
		handler.maybeApplyAdminLockout(r.Context(), acc2.ID, attemptPurposeAdminLogin, subject)
		WriteError(w, r, "error.invalidCredentials", http.StatusUnauthorized)
		return
	}

	// Success: clear any lockout
	if acc2.LockedUntil != nil {
		_ = handler.repo.ClearAccountLockedUntil(r.Context(), acc2.ID)
	}

	// If TOTP is enabled, return a challenge token instead of logging in
	if acc2.HasTOTP() {
		token := auth.SignTOTPChallenge(handler.totpKey, acc2.ID, 5*time.Minute)
		utils.WriteJson(w, map[string]any{
			"totpRequired":   true,
			"challengeToken": token,
		})
		return
	}

	if _, err := handler.adminAuthService.DoLogin(w, r, acc2); err != nil {
		log.Err(err).Msg("Could not login admin")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	utils.WriteJson(w, map[string]any{"ok": true})
}
