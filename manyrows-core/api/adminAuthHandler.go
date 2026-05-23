package api

import (
	"context"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/core/validation"
	"manyrows-core/utils"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	attemptPurposeMagicLink = "magic_link"

	maxAttemptsPerIP10Min      = 30
	maxAttemptsPerSubject10Min = 10
	attemptWindow              = 10 * time.Minute

	// maxEmailSendsPerSubjectDay caps the total magic-link / OTP sends
	// to a single email address over a rolling 24h window. The 10/10min
	// per-subject cap bounds burst rate but lets a botnet rotating IPs
	// drip-flood a single inbox: 10 sends every 10 min = 1440 a day.
	// 30/day is comfortable headroom for a confused legitimate user
	// (multiple lost emails, password-reset retries) while killing the
	// flood-the-inbox attack.
	maxEmailSendsPerSubjectDay = 30
	emailSendDailyWindow       = 24 * time.Hour
)

type AuthRequest struct {
	Email string `json:"email"`
}

type AdminLoginRequest struct {
	Email string `json:"email"`
}

// AdminAuthConfig returns public config needed by the admin login/register/forgot
// pages — just the Turnstile site key today. Deliberately public (no auth) and
// minimal: only expose values safe to put in the client JS bundle.
//
// Cache-Control: no-store prevents CF (and browsers) from caching the site key,
// so when it's rotated in CF or env vars change, clients immediately see the new
// value instead of the widget rendering against a stale key and failing
// verification with "invalid-input-response".
func (handler *RequestHandler) AdminAuthConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	// needsFirstAdmin is true when no super-admin has been claimed
	// yet — neither the env var nor the system_secrets row is set.
	// Used by the register page to show "you'll become the super
	// admin" so the first operator knows what's happening. Cheap
	// check: in-memory + one DB read worst case.
	needsFirstAdmin := false
	if core.GetSuperAdminEmail() == "" {
		v, err := handler.repo.GetSystemSecret(r.Context(), "super_admin_email")
		if err == nil && v == "" {
			needsFirstAdmin = true
		}
	}

	utils.WriteJson(w, map[string]any{
		"turnstileSiteKey": handler.config.GetTurnstileSiteKey(),
		"needsFirstAdmin":  needsFirstAdmin,
		// version is the server build (config.BuildVersion). Surfaced
		// on the auth screens so operators can confirm at a glance
		// which release they're hitting. /health also exposes it but
		// isn't proxied by the vite dev server, so we piggy-back on
		// this already-proxied public endpoint.
		"version": handler.config.GetVersion(),
	})
}

func (handler *RequestHandler) AdminLogout(w http.ResponseWriter, r *http.Request) {
	err := handler.adminAuthService.DoLogout(w, r)
	if err != nil {
		log.Err(err).Msg("Could not logout admin")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
}

func (handler *RequestHandler) createMagicToken(ctx context.Context, purpose string, toEmail string) (string, error) {
	// Create magic link token (raw) + hash (stored)
	rawToken, tokenHash, err := handler.adminAuthService.NewMagicToken()
	if err != nil {
		log.Err(err).Msg("Could not generate magic token")
		return "", err
	}

	expiresAt := time.Now().Add(15 * time.Minute)

	if err := handler.repo.CreateMagicLink(ctx, repo.CreateMagicLinkParams{
		Purpose:   purpose,
		Email:     toEmail,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	}); err != nil {
		log.Err(err).Msg("Could not persist magic link")
		return "", err
	}
	return rawToken, nil
}

func (handler *RequestHandler) AdminProcessMagicLink(w http.ResponseWriter, r *http.Request) {
	acc, _, err := handler.adminAuthService.GetLoggedInAccount(r)
	if err != nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}
	if acc != nil {
		// already logged in - do nothing
		http.Redirect(w, r, handler.config.GetBaseURL()+"/app", http.StatusFound)
		return
	}

	ml, ok := handler.extractMagicLink(w, r)
	if !ok {
		return
	}

	switch ml.Purpose {
	case "admin_register":
		acc, vr, err := handler.adminAuthService.AdminRegister(r.Context(), ml.Email)
		if err != nil {
			log.Err(err).Msg("Could not register admin")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if !vr.Ok() {
			WriteValidationError(w, r, vr)
			return
		}
		if _, err := handler.adminAuthService.DoLogin(w, r, acc); err != nil {
			log.Err(err).Msg("Could not login admin")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
	case "admin_login":
		acc, vr, err := handler.repo.GetAccountByEmail(r.Context(), ml.Email)
		if err != nil {
			log.Err(err).Msg("Could not lookup admin by email")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if !vr.Ok() || acc == nil {
			WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
			return
		}
		if _, err := handler.adminAuthService.DoLogin(w, r, acc); err != nil {
			log.Err(err).Msg("Could not login admin")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
	case "team_invite":
		// Register account if new, or look up existing
		acc, vr, err := handler.repo.GetAccountByEmail(r.Context(), ml.Email)
		if err != nil {
			log.Err(err).Msg("Could not lookup account for team invite")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if !vr.Ok() {
			WriteValidationError(w, r, vr)
			return
		}
		if acc == nil {
			var regVR *validation.Result
			acc, regVR, err = handler.adminAuthService.AdminRegister(r.Context(), ml.Email)
			if err != nil || !regVR.Ok() {
				log.Err(err).Msg("Could not register account for team invite")
				WriteError(w, r, "error.internalError", http.StatusInternalServerError)
				return
			}
		}

		// Accept all pending invites for this email and add as workspace admin
		wsIDs, err := handler.repo.AcceptTeamInvites(r.Context(), ml.Email)
		if err != nil {
			log.Err(err).Msg("AcceptTeamInvites failed")
			// Non-fatal: account is created, continue to login
		}
		for _, wsID := range wsIDs {
			admin := core.WorkspaceAdmin{
				WorkspaceID: wsID,
				AccountID:   acc.ID,
				Role:        "admin",
			}
			if err := handler.repo.AddWorkspaceAdmin(r.Context(), admin); err != nil {
				log.Err(err).Str("workspaceId", wsID.String()).Msg("AddWorkspaceAdmin failed for invite")
			}
		}

		if _, err := handler.adminAuthService.DoLogin(w, r, acc); err != nil {
			log.Err(err).Msg("Could not login admin after team invite")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, handler.config.GetBaseURL()+"/app", http.StatusFound)
}

func (handler *RequestHandler) extractMagicLink(w http.ResponseWriter, r *http.Request) (*core.MagicLink, bool) {
	token := r.URL.Query().Get("token")
	if token == "" {
		WriteError(w, r, "error.invalidToken", http.StatusBadRequest)
		return nil, false
	}

	tokenHash := handler.adminAuthService.HashMagicToken(token)

	ml, ok, err := handler.repo.ConsumeMagicLink(r.Context(), tokenHash)
	if err != nil {
		log.Err(err).Msg("Could not consume magic link")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return nil, false
	}
	if !ok || ml == nil {
		WriteError(w, r, "error.invalidToken", http.StatusUnauthorized)
		return nil, false
	}
	return ml, true
}
