package api

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/core/validation"
	"manyrows-core/crypto/passwordhash"
	"manyrows-core/email"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

const (
	clientEmailChangeTTL = 15 * time.Minute

	attemptPurposeClientEmailChange       = "client_email_change"
	attemptPurposeClientEmailChangeVerify = "client_email_change_verify"
)

// ClientRequestEmailChange initiates an email change for an app user.
// POST /x/{workspaceSlug}/apps/{appId}/a/me/request-email-change
//
// Gated by app.AllowEmailChange — when admins flip it off, this
// endpoint refuses regardless of UI state. AppKit also hides the
// change-email block when the flag is false; this is the
// defense-in-depth check.
func (handler *RequestHandler) ClientRequestEmailChange(w http.ResponseWriter, r *http.Request) {
	if app, appOk := core.AppFromContext(r.Context()); appOk && app != nil && !app.AllowEmailChange {
		WriteError(w, r, "error.forbidden", http.StatusForbidden)
		return
	}

	ctx := r.Context()

	ses, identity, ws, ok := handler.requireActiveClientSession(w, r)
	if !ok {
		return
	}

	var body struct {
		Password string `json:"password"`
		NewEmail string `json:"newEmail"`
	}
	if !utils.ReadJson(w, r, &body) {
		return
	}

	password := strings.TrimSpace(body.Password)
	if password == "" {
		WriteValidationError(w, r, validation.NewIssue("password", "required", "password is required"))
		return
	}

	newEmail := strings.TrimSpace(strings.ToLower(body.NewEmail))
	if newEmail == "" {
		WriteValidationError(w, r, validation.NewIssue("newEmail", "required", "new email is required"))
		return
	}

	// Validate email format
	toEmail, vr := auth.ValidateEmail(newEmail)
	if !vr.Ok() {
		WriteValidationError(w, r, vr)
		return
	}

	// Check new email is different from current
	if strings.EqualFold(toEmail, identity.User.Email) {
		WriteValidationError(w, r, validation.NewIssue("newEmail", "same_as_current", "new email must be different from current email"))
		return
	}

	// Rate limiting
	now := time.Now().UTC()
	ip := auth.ClientIP(r)
	subject := strings.TrimSpace(strings.ToLower(identity.User.Email))

	if !handler.checkAttemptRateLimit(w, r, attemptPurposeClientEmailChange, ip, subject, "client email change", nil) {
		return
	}
	if !handler.checkEmailSendDailyQuota(w, r, attemptPurposeClientEmailChange, subject, "client email change", nil) {
		return
	}

	// Verify password
	var passwordHash string
	err := handler.repo.DB().Pool().QueryRow(ctx,
		`SELECT COALESCE(password_hash, '') FROM users WHERE id = $1`, identity.User.ID,
	).Scan(&passwordHash)
	if err != nil {
		log.Err(err).Msg("ClientRequestEmailChange: failed to get password hash")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if passwordHash == "" {
		WriteErrorMsg(w, r, "No password set. Set a password first.", http.StatusBadRequest)
		return
	}

	ok, vErr := passwordhash.Verify(passwordHash, password)
	if vErr != nil || !ok {
		_ = handler.repo.InsertAttempt(ctx, attemptPurposeClientEmailChange, subject, ip)
		vr2 := validation.NewIssue("password", "incorrect", "incorrect password")
		vr2.Status = http.StatusUnauthorized
		WriteValidationError(w, r, vr2)
		return
	}

	if ses.AppID == nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	app, err := handler.repo.GetAppByID(ctx, *ses.AppID)
	if err != nil {
		log.Err(err).Msg("ClientRequestEmailChange: failed to get app")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Check new email is not already in use within the same app
	existingUser, err := handler.repo.GetUserByEmail(ctx, toEmail, &app)
	if err != nil {
		log.Err(err).Msg("ClientRequestEmailChange: failed to check email uniqueness")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if existingUser != nil {
		vr3 := validation.NewIssue("newEmail", "duplicate", "email is already in use")
		vr3.Status = http.StatusConflict
		WriteValidationError(w, r, vr3)
		return
	}

	// Generate OTP and hash
	pepper, err := handler.getOTPPepper()
	if err != nil {
		log.Err(err).Msg("Missing OTP pepper")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	code, err := generateOTP6()
	if err != nil {
		log.Err(err).Msg("Could not generate otp")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	otpID := utils.NewUUID()
	codeHash, err := hashOTP(otpID, code, pepper)
	if err != nil {
		log.Err(err).Msg("Could not hash otp")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Upsert email change request
	if err := handler.repo.UpsertEmailChangeRequest(ctx, otpID, identity.User.ID, app.ID, toEmail, codeHash, now.Add(clientEmailChangeTTL)); err != nil {
		log.Err(err).Msg("Could not upsert email change request")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Send OTP to the NEW email address
	lang := "en"
	emailName := ws.Name
	if app.DisplayName() != "" {
		emailName = app.DisplayName()
	}
	if emailName == "" {
		emailName = "your app"
	}
	changeEmail := &email.Email{
		To:      toEmail,
		From:    email.WorkspaceFrom(emailName),
		Subject: fmt.Sprintf(email.T(lang, "workspace.email_change.subject"), emailName),
		Body:    fmt.Sprintf(email.T(lang, "workspace.email_change.body"), emailName, code),
	}
	if err := handler.sendWorkspaceEmail(ctx, ws.ID, changeEmail); err != nil {
		log.Err(err).Msg("Could not send email change code")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Burn attempt after successful send
	_ = handler.repo.InsertAttempt(ctx, attemptPurposeClientEmailChange, subject, ip)

	userID := identity.User.ID
	sessionID := ses.ID
	handler.writeAuthLogFromRequest(r, AuthLogInput{
		WorkspaceID:    ws.ID,
		AppID:          &app.ID,
		Event:          core.AuthEventEmailChangeRequested,
		Outcome:        core.AuthOutcomeSuccess,
		SubjectUserID:  &userID,
		EmailAttempted: identity.User.Email,
		ActorType:      core.AuthActorSelf,
		ActorLabel:     identity.User.Email,
		SessionID:      &sessionID,
		Metadata: core.EmailChangeMetadata{
			OldEmail: identity.User.Email,
			NewEmail: toEmail,
		},
	})

	utils.WriteJson(w, map[string]any{"ok": true})
}

// ClientVerifyEmailChange verifies the OTP and completes the email change.
// POST /x/{workspaceSlug}/apps/{appId}/a/me/verify-email-change
//
// Gated by app.AllowEmailChange — see ClientRequestEmailChange.
func (handler *RequestHandler) ClientVerifyEmailChange(w http.ResponseWriter, r *http.Request) {
	if app, appOk := core.AppFromContext(r.Context()); appOk && app != nil && !app.AllowEmailChange {
		WriteError(w, r, "error.forbidden", http.StatusForbidden)
		return
	}

	ctx := r.Context()

	ses, identity, ws, ok := handler.requireActiveClientSession(w, r)
	if !ok {
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	if !utils.ReadJson(w, r, &body) {
		return
	}

	code := strings.TrimSpace(body.Code)
	if len(code) != 6 || !isDigits(code) {
		WriteError(w, r, "error.invalidCode", http.StatusBadRequest)
		return
	}

	// Rate limit verification attempts
	ip := auth.ClientIP(r)
	verifySubject := strings.TrimSpace(strings.ToLower(identity.User.Email))
	now := time.Now().UTC()

	if !handler.checkAttemptRateLimit(w, r, attemptPurposeClientEmailChangeVerify, ip, verifySubject, "client email change verify", nil) {
		return
	}
	_ = handler.repo.InsertAttempt(ctx, attemptPurposeClientEmailChangeVerify, verifySubject, ip)

	// Get pending request
	req, err := handler.repo.GetEmailChangeRequest(ctx, identity.User.ID)
	if err != nil {
		if errors.Is(err, repo.ErrEmailChangeRequestNotFound) {
			WriteErrorMsg(w, r, "No pending email change request", http.StatusBadRequest)
			return
		}
		log.Err(err).Msg("Could not get email change request")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Check expiry
	if !req.IsActive(now) {
		_ = handler.repo.DeleteEmailChangeRequest(ctx, identity.User.ID)
		WriteErrorMsg(w, r, "Email change request has expired", http.StatusBadRequest)
		return
	}

	// Per-request attempt cap. Belt-and-braces against the IP/subject
	// windows: a single code burns after otpMaxAttempts wrong guesses.
	// "Burn" here = delete the row (this table doesn't have used_at —
	// rows are deleted on success or cap-hit, regenerated on retry).
	if req.Attempts >= otpMaxAttempts {
		_ = handler.repo.DeleteEmailChangeRequest(ctx, identity.User.ID)
		WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
		return
	}

	// Verify code hash
	pepper, err := handler.getOTPPepper()
	if err != nil {
		log.Err(err).Msg("Missing OTP pepper")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// ClientRequestEmailChange hashes with the OTP row id (a fresh UUID
	// per request), so verify must use the same.
	expectedHash, err := hashOTP(req.ID, code, pepper)
	if err != nil {
		log.Err(err).Msg("Could not hash otp for verify")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	if subtle.ConstantTimeCompare([]byte(req.CodeHash), []byte(expectedHash)) != 1 {
		// Wrong code: bump the per-request counter and, if we just
		// hit the cap, delete the row so further attempts fall into
		// the "no pending request" branch.
		newAttempts, incErr := handler.repo.IncrementEmailChangeRequestAttempts(ctx, identity.User.ID)
		if incErr != nil && !errors.Is(incErr, repo.ErrEmailChangeRequestNotFound) {
			log.Err(incErr).Msg("Could not increment email change request attempts")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		if newAttempts >= otpMaxAttempts {
			_ = handler.repo.DeleteEmailChangeRequest(ctx, identity.User.ID)
		}
		WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
		return
	}

	// Atomically consume the email change request right after the hash
	// match — single-DELETE-by-id-and-user means a concurrent verify
	// (same OTP, same user) loses the race here and surfaces
	// invalidCode, instead of both reaching the UpdateUserEmail call
	// with the same intent. The previous code deferred the delete
	// until after the email update, leaving a window where the OTP
	// was "verified but not consumed" and could be re-played by
	// concurrent requests.
	consumed, err := handler.repo.ConsumeEmailChangeRequest(ctx, identity.User.ID, req.ID)
	if err != nil {
		log.Err(err).Msg("Could not consume email change request")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !consumed {
		// Lost the race to a concurrent verify (or the row expired
		// between the GetEmailChangeRequest read and now). Same
		// surface as a wrong code.
		WriteError(w, r, "error.invalidCode", http.StatusUnauthorized)
		return
	}

	// Re-check email uniqueness (race condition guard)
	if ses.AppID == nil {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	app, err := handler.repo.GetAppByID(ctx, *ses.AppID)
	if err != nil {
		log.Err(err).Msg("ClientVerifyEmailChange: failed to get app")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	existingUser, err := handler.repo.GetUserByEmail(ctx, req.NewEmail, &app)
	if err != nil {
		log.Err(err).Msg("ClientVerifyEmailChange: failed to re-check email uniqueness")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if existingUser != nil {
		vr := validation.NewIssue("newEmail", "duplicate", "email is already in use")
		vr.Status = http.StatusConflict
		WriteValidationError(w, r, vr)
		return
	}

	// Update user email. The email_change_requests row was already
	// consumed atomically above (right after the hash match) so no
	// follow-up delete is needed here.
	oldEmail := identity.User.Email
	if err := handler.repo.UpdateUserEmail(ctx, identity.User.ID, req.NewEmail); err != nil {
		log.Err(err).Msg("Could not update user email")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Notify the OLD address that the swap happened. An account-
	// takeover victim sees this in their inbox and can act on it
	// before the attacker pivots deeper. Best-effort: a transient
	// SMTP failure doesn't roll back the email change itself (the
	// swap is already committed) — just logs and moves on. The new
	// email isn't included to avoid helping the attacker confirm
	// where the account moved.
	emailNameNotice := ws.Name
	if app.DisplayName() != "" {
		emailNameNotice = app.DisplayName()
	}
	if emailNameNotice == "" {
		emailNameNotice = "your app"
	}
	noticeEmail := &email.Email{
		To:      oldEmail,
		From:    email.WorkspaceFrom(emailNameNotice),
		Subject: fmt.Sprintf(email.T("en", "workspace.email_change.notice.subject"), emailNameNotice),
		Body:    fmt.Sprintf(email.T("en", "workspace.email_change.notice.body"), emailNameNotice),
	}
	if err := handler.sendWorkspaceEmail(ctx, ws.ID, noticeEmail); err != nil {
		log.Err(err).Str("old_email", oldEmail).Msg("email-change notice to old address failed (non-fatal)")
	}

	// Invalidate all sessions except current
	_, _ = handler.repo.DeleteClientSessionsByUser(ctx, identity.User.ID, &ses.ID)

	// Fire webhook
	handler.dispatchWebhook(app.ID, "user.email_change", map[string]any{
		"userId":   identity.User.ID,
		"oldEmail": identity.User.Email,
		"newEmail": req.NewEmail,
		"appId":    app.ID,
	})

	userID := identity.User.ID
	sessionID := ses.ID
	handler.writeAuthLogFromRequest(r, AuthLogInput{
		WorkspaceID:    ws.ID,
		AppID:          &app.ID,
		Event:          core.AuthEventEmailChanged,
		Outcome:        core.AuthOutcomeSuccess,
		SubjectUserID:  &userID,
		EmailAttempted: req.NewEmail,
		ActorType:      core.AuthActorSelf,
		ActorLabel:     req.NewEmail,
		SessionID:      &sessionID,
		Metadata: core.EmailChangeMetadata{
			OldEmail: identity.User.Email,
			NewEmail: req.NewEmail,
		},
	})

	utils.WriteJson(w, map[string]any{"ok": true, "email": req.NewEmail})
}
