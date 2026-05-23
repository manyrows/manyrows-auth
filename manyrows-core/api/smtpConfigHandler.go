package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"manyrows-core/core"
	"manyrows-core/crypto"
	"manyrows-core/email"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// HandleGetSMTPConfig returns the workspace SMTP config (password omitted)
// alongside the active system-level transport so the admin UI can tell
// the operator whether outbound mail will work without any further
// configuration (i.e. an env-configured transport is already active).
func (handler *RequestHandler) HandleGetSMTPConfig(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}

	cfg, found, err := handler.repo.GetWorkspaceSMTPConfig(r.Context(), ws.ID)
	if err != nil {
		log.Err(err).Msg("GetWorkspaceSMTPConfig failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	systemProvider := ""
	systemFromEmail := ""
	if handler.emailService != nil {
		systemProvider = handler.emailService.ProviderName()
		systemFromEmail = handler.emailService.DefaultFromEmail()
	}

	resp := map[string]any{
		"configured":      found,
		"systemProvider":  systemProvider,
		"systemFromEmail": systemFromEmail,
	}
	if found {
		resp["enabled"] = cfg.Enabled
		resp["host"] = cfg.Host
		resp["port"] = cfg.Port
		resp["username"] = cfg.Username
		resp["hasPassword"] = len(cfg.PasswordEncrypted) > 0
		resp["fromEmail"] = cfg.FromEmail
		resp["fromName"] = cfg.FromName
	}

	utils.WriteJsonWithStatusCode(w, resp, http.StatusOK)
}

// HandleUpsertSMTPConfig creates or updates the workspace SMTP config.
func (handler *RequestHandler) HandleUpsertSMTPConfig(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	if !handler.requireOwner(w, r) {
		return
	}

	var req struct {
		Enabled   bool   `json:"enabled"`
		Host      string `json:"host"`
		Port      int    `json:"port"`
		Username  string `json:"username"`
		Password  string `json:"password"` // plaintext, empty = keep existing
		FromEmail string `json:"fromEmail"`
		FromName  string `json:"fromName"`
	}
	if ok := utils.ReadJson(w, r, &req); !ok {
		return
	}

	req.Host = strings.TrimSpace(req.Host)
	req.Username = strings.TrimSpace(req.Username)
	req.FromEmail = strings.TrimSpace(req.FromEmail)
	req.FromName = strings.TrimSpace(req.FromName)

	if req.Host == "" || req.FromEmail == "" {
		WriteError(w, r, "error.badRequest", http.StatusBadRequest)
		return
	}
	if req.Port <= 0 || req.Port > 65535 {
		req.Port = 587
	}

	cfg := core.WorkspaceSMTPConfig{
		WorkspaceID: ws.ID,
		Enabled:     req.Enabled,
		Host:        req.Host,
		Port:        req.Port,
		Username:    req.Username,
		FromEmail:   req.FromEmail,
		FromName:    req.FromName,
	}

	// Encrypt password if provided; nil means keep existing (COALESCE in SQL)
	if req.Password != "" {
		if handler.encryptor == nil {
			log.Error().Msg("encryptor not configured, cannot store SMTP password")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		encrypted, err := handler.encryptor.EncryptToBytesWithAAD(
			[]byte(req.Password),
			crypto.AAD("workspace_smtp_config", "password_encrypted", ws.ID),
		)
		if err != nil {
			log.Err(err).Msg("failed to encrypt SMTP password")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		cfg.PasswordEncrypted = encrypted
	}

	if err := handler.repo.UpsertWorkspaceSMTPConfig(r.Context(), cfg); err != nil {
		log.Err(err).Msg("UpsertWorkspaceSMTPConfig failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Self-hosted: there's exactly one workspace and one admin, so the
	// workspace-level SMTP config also drives the system-level email
	// transport (admin register / password-reset emails). Mirror the
	// non-secret fields to system_secrets and reload the email
	// service so the next admin email goes via the operator's SMTP
	// without a restart. Password is only mirrored when supplied
	// (req.Password != "") so the "keep existing" path doesn't wipe
	// the system row.
	if req.Enabled {
		ctx := r.Context()
		// Non-sensitive fields go to the raw store — they're public-ish
		// (host/port/username appear in mail headers anyway).
		mirror := map[string]string{
			"smtp_host":       req.Host,
			"smtp_port":       strconv.Itoa(req.Port),
			"smtp_username":   req.Username,
			"smtp_from_email": req.FromEmail,
			"smtp_from_name":  req.FromName,
		}
		for name, v := range mirror {
			if err := handler.repo.UpsertSystemSecret(ctx, name, v); err != nil {
				log.Err(err).Str("row", name).Msg("mirror smtp to system_secrets failed (non-fatal)")
			}
		}
		if req.Password != "" {
			// Encrypt at rest in system_secrets — the email service reads
			// through the matching encrypting wrapper and decrypts on
			// the read path. Without this, the password survives a DB
			// dump in plaintext (already encrypted in
			// workspace_smtp_config.password_encrypted, but the mirror
			// would otherwise leak it).
			if err := handler.secureSecrets.UpsertSystemSecret(ctx, "smtp_password", req.Password); err != nil {
				log.Err(err).Msg("mirror smtp password to system_secrets failed (non-fatal)")
			}
		}
		handler.emailService.Reload()
	}

	utils.WriteJson(w, map[string]any{"ok": true})
}

// HandleDeleteSMTPConfig removes the workspace SMTP config.
func (handler *RequestHandler) HandleDeleteSMTPConfig(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	if !handler.requireOwner(w, r) {
		return
	}

	if err := handler.repo.DeleteWorkspaceSMTPConfig(r.Context(), ws.ID); err != nil {
		log.Err(err).Msg("DeleteWorkspaceSMTPConfig failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Keep system_secrets aligned. Clearing the workspace SMTP config
	// in the only-workspace install means the operator is reverting to
	// console output; wipe the mirrored rows so admin emails follow
	// suit.
	ctx := r.Context()
	for _, name := range []string{"smtp_host", "smtp_port", "smtp_username", "smtp_password", "smtp_from_email", "smtp_from_name"} {
		if err := handler.repo.DeleteSystemSecret(ctx, name); err != nil {
			log.Err(err).Str("row", name).Msg("clear smtp row failed (non-fatal)")
		}
	}
	handler.emailService.Reload()

	utils.WriteJson(w, map[string]any{"ok": true})
}

// HandleTestSMTPConfig sends a test email to the current admin. Uses
// the workspace's saved SMTP credentials when present; falls back to
// the system-default transport (env-configured) so the operator can
// still verify delivery in the common "no workspace SMTP, deliver via
// the global transport" case.
func (handler *RequestHandler) HandleTestSMTPConfig(w http.ResponseWriter, r *http.Request) {
	acc, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	if !handler.requireOwner(w, r) {
		return
	}

	cfg, found, err := handler.repo.GetWorkspaceSMTPConfig(r.Context(), ws.ID)
	if err != nil {
		log.Err(err).Msg("GetWorkspaceSMTPConfig failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	subject := "Email Test — " + ws.Name
	body := "This is a test email.\n\nIf you received this, outbound delivery is working correctly."

	useWorkspaceSMTP := found && cfg.Host != ""

	var sendErr error
	if useWorkspaceSMTP {
		smtpCfg, err := handler.decryptSMTPConfig(cfg)
		if err != nil {
			log.Err(err).Msg("failed to decrypt SMTP config")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		testEmail := &email.Email{
			To:      acc.Email,
			From:    smtpCfg.FormatFrom(),
			Subject: subject,
			Body:    body,
		}
		sendErr = handler.emailService.SendWithCustomSMTP(testEmail, smtpCfg)
	} else {
		// System transport. Must set From explicitly: Service.Send
		// rejects an empty From before the provider is consulted, so
		// relying on a provider default would always fail in prod.
		testEmail := &email.Email{
			To:      acc.Email,
			From:    email.WorkspaceFrom(ws.Name),
			Subject: subject,
			Body:    body,
		}
		sendErr = handler.emailService.Send(testEmail)
	}

	if sendErr != nil {
		log.Err(sendErr).Msg("test email send failed")
		WriteErrorf(w, r, "error.smtpTestFailed", http.StatusBadGateway, sendErr.Error())
		return
	}

	// First successful test ticks the "Email delivery verified" item
	// on the first-boot setup checklist. coalesce-on-write keeps
	// repeated tests from re-stamping the timestamp.
	if err := handler.repo.MarkWorkspaceTestEmailSent(r.Context(), ws.ID); err != nil {
		log.Err(err).Msg("MarkWorkspaceTestEmailSent failed (non-fatal)")
	}

	utils.WriteJson(w, map[string]any{"ok": true, "sentTo": acc.Email})
}

// HandleDismissSetupChecklist marks the first-boot setup checklist as
// dismissed for this workspace. Idempotent.
func (handler *RequestHandler) HandleDismissSetupChecklist(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := handler.adminAndWorkspace(w, r)
	if !ok {
		return
	}
	if err := handler.repo.MarkWorkspaceSetupChecklistDismissed(r.Context(), ws.ID); err != nil {
		log.Err(err).Msg("MarkWorkspaceSetupChecklistDismissed failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, map[string]any{"ok": true})
}

// sendWorkspaceEmail sends an email using custom SMTP if configured for the workspace,
// otherwise falls back to the default email service.
func (handler *RequestHandler) sendWorkspaceEmail(ctx context.Context, workspaceID uuid.UUID, e *email.Email) error {
	cfg, found, err := handler.repo.GetWorkspaceSMTPConfig(ctx, workspaceID)
	if err != nil {
		log.Err(err).Str("ws", workspaceID.String()).Msg("failed to load SMTP config, falling back to default")
		appendManyRowsFooter(e)
		return handler.emailService.Send(e)
	}
	if !found || !cfg.Enabled || cfg.Host == "" {
		appendManyRowsFooter(e)
		return handler.emailService.Send(e)
	}

	smtpCfg, err := handler.decryptSMTPConfig(cfg)
	if err != nil {
		log.Err(err).Str("ws", workspaceID.String()).Msg("failed to decrypt SMTP config, falling back to default")
		appendManyRowsFooter(e)
		return handler.emailService.Send(e)
	}

	// Override the From address with the custom SMTP config
	e.From = smtpCfg.FormatFrom()

	return handler.emailService.SendWithCustomSMTP(e, smtpCfg)
}

// appendManyRowsFooter adds a branding footer to emails sent via the default (non-custom) SMTP.
func appendManyRowsFooter(e *email.Email) {
	e.Body += "\n\n---\nAuthentication powered by ManyRows.com"
}

// decryptSMTPConfig decrypts the stored password and returns an email.SMTPConfig.
func (handler *RequestHandler) decryptSMTPConfig(cfg *core.WorkspaceSMTPConfig) (*email.SMTPConfig, error) {
	password := ""
	if len(cfg.PasswordEncrypted) > 0 && handler.encryptor != nil {
		plain, err := handler.encryptor.DecryptFromBytesWithAAD(
			cfg.PasswordEncrypted,
			crypto.AAD("workspace_smtp_config", "password_encrypted", cfg.WorkspaceID),
		)
		if err != nil {
			return nil, err
		}
		password = string(plain)
	}
	return &email.SMTPConfig{
		Host:      cfg.Host,
		Port:      cfg.Port,
		Username:  cfg.Username,
		Password:  password,
		FromEmail: cfg.FromEmail,
		FromName:  cfg.FromName,
	}, nil
}
