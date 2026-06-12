package api

import (
	"fmt"
	"net/http"
	"time"

	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/email"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

const (
	accountDeleteTTL = 15 * time.Minute

	attemptPurposeClientAccountDelete = "client_account_delete"
)

// RequestAccountDeletion sends a one-time deletion-confirmation code to a
// passwordless user's verified email. Password users are told to use the
// password flow instead.
// POST /x/{workspaceSlug}/apps/{appId}/a/me/request-delete
func (handler *RequestHandler) RequestAccountDeletion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ses, identity, ws, ok := handler.requireActiveClientSession(w, r)
	if !ok {
		return
	}

	if app, appOk := core.AppFromContext(ctx); appOk && app != nil && !app.AllowAccountDeletion {
		WriteError(w, r, "error.forbidden", http.StatusForbidden)
		return
	}

	// Password users don't need an emailed code.
	if identity.User.PasswordSetAt != nil {
		WriteErrorMsg(w, r, "This account has a password; confirm deletion with your password.", http.StatusBadRequest)
		return
	}

	if ses.AppID == nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	app, err := handler.repo.GetAppByID(ctx, *ses.AppID)
	if err != nil {
		log.Err(err).Msg("RequestAccountDeletion: get app failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	ip := auth.ClientIP(r)
	subject := identity.User.Email
	if !handler.checkAttemptRateLimit(w, r, attemptPurposeClientAccountDelete, ip, subject, "client account delete request", nil) {
		return
	}
	if !handler.checkEmailSendDailyQuota(w, r, attemptPurposeClientAccountDelete, subject, "client account delete request", nil) {
		return
	}

	pepper, err := handler.getOTPPepper()
	if err != nil {
		log.Err(err).Msg("RequestAccountDeletion: missing pepper")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	code, err := generateOTP6()
	if err != nil {
		log.Err(err).Msg("RequestAccountDeletion: gen otp failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	otpID := utils.NewUUID()
	codeHash, err := hashOTP(otpID, code, pepper)
	if err != nil {
		log.Err(err).Msg("RequestAccountDeletion: hash otp failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if err := handler.repo.UpsertAccountDeleteRequest(ctx, otpID, identity.User.ID, app.ID, codeHash, time.Now().UTC().Add(accountDeleteTTL)); err != nil {
		log.Err(err).Msg("RequestAccountDeletion: upsert failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	lang := "en"
	emailName := ws.Name
	if app.DisplayName() != "" {
		emailName = app.DisplayName()
	}
	if emailName == "" {
		emailName = "your app"
	}
	msg := &email.Email{
		To:      identity.User.Email,
		From:    email.WorkspaceFrom(emailName),
		Subject: fmt.Sprintf(email.T(lang, "workspace.account_delete.subject"), emailName),
		Body:    fmt.Sprintf(email.T(lang, "workspace.account_delete.body"), emailName, code),
	}
	if err := handler.sendWorkspaceEmail(ctx, ws.ID, msg); err != nil {
		log.Err(err).Msg("RequestAccountDeletion: send failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	_ = handler.repo.InsertAttempt(ctx, attemptPurposeClientAccountDelete, subject, ip)

	utils.WriteJson(w, map[string]any{"ok": true})
}
