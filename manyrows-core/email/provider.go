package email

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cloudmailin/cloudmailin-go"
	"github.com/rs/zerolog/log"
)

// Provider sends an Email. The system-level Service holds exactly
// one — picked at construction time based on env vars — and routes
// every Send through it. Self-hosters pick SMTP (any provider —
// Postmark, SES, Mailgun, etc.); dev / unconfigured installs pick
// console (logs the email body to stdout so flows are still
// testable end-to-end).
//
// Per-workspace custom SMTP (Service.SendWithCustomSMTP) bypasses
// this — that's a separate code path workspaces use to send their
// own app emails (verify, password reset, etc.) from their own
// domain.
type Provider interface {
	Send(email *Email) error
	Name() string
}

// =====================================================================
// console — logs the email to stdout. Default when nothing else is
// configured. Plenty of self-hosters never set up SMTP and just want
// the magic-link flow to be testable; this lets them copy the link
// from the server log into the browser instead of dropping a separate
// SMTP gateway.
// =====================================================================

type consoleProvider struct{}

func (consoleProvider) Name() string { return "console" }

func (consoleProvider) Send(e *Email) error {
	fmt.Println("--------------------------------------------------")
	fmt.Println("EMAIL")
	fmt.Println("--------------------------------------------------")
	fmt.Printf("To:      %s\n", e.To)
	fmt.Printf("From:    %s\n", e.From)
	fmt.Printf("Subject: %s\n", e.Subject)
	fmt.Println()
	fmt.Println(e.Body)
	fmt.Println("--------------------------------------------------")
	return nil
}

// =====================================================================
// smtp — dials a generic SMTP server with credentials from env. Works
// with any provider (Postmark, SES, Mailgun, Gmail SMTP, self-hosted
// Postfix). Reuses the existing sendCustomSMTP transport so the wire
// format stays in one place.
// =====================================================================

type smtpProvider struct {
	cfg *SMTPConfig
}

func (smtpProvider) Name() string { return "smtp" }

func (s smtpProvider) Send(e *Email) error {
	// Fill in From if the caller didn't set one.
	if e.From == "" {
		from := s.cfg.FormatFrom()
		if from == "" {
			from = defaultFromEmail()
		}
		e.From = from
	}
	return sendCustomSMTP(e, s.cfg)
}

// loadSystemSMTPConfig assembles an SMTPConfig from env vars + the
// optional store. Env wins on a per-field basis: each field falls
// back to the matching system_secrets row only when the env var is
// empty. Returns nil when neither source has a host (SMTP is opt-in).
//
// Store row names: smtp_host, smtp_port, smtp_username, smtp_password,
// smtp_from_email, smtp_from_name.
func loadSystemSMTPConfig(store SecretsStore) *SMTPConfig {
	get := func(envName, storeName string) string {
		if v := strings.TrimSpace(os.Getenv(envName)); v != "" {
			return v
		}
		if store == nil {
			return ""
		}
		v, _ := store.GetSystemSecret(context.Background(), storeName)
		return strings.TrimSpace(v)
	}

	host := get("MANYROWS_SMTP_HOST", "smtp_host")
	if host == "" {
		return nil
	}
	port := 587
	if v := get("MANYROWS_SMTP_PORT", "smtp_port"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			port = p
		}
	}
	from := get("MANYROWS_SMTP_FROM_EMAIL", "smtp_from_email")
	if from == "" {
		from = defaultFromEmail()
	}
	// Password is the one field we don't TrimSpace — leading/trailing
	// whitespace in passwords is unusual but legal, and silently
	// stripping it would make "why doesn't auth work" debugging
	// painful. Read raw for env; store-side we already trimmed via
	// the helper.
	password := os.Getenv("MANYROWS_SMTP_PASSWORD")
	if password == "" && store != nil {
		password, _ = store.GetSystemSecret(context.Background(), "smtp_password")
	}

	return &SMTPConfig{
		Host:      host,
		Port:      port,
		Username:  get("MANYROWS_SMTP_USERNAME", "smtp_username"),
		Password:  password,
		FromEmail: from,
		FromName:  get("MANYROWS_SMTP_FROM_NAME", "smtp_from_name"),
	}
}

// =====================================================================
// cloudmailin — wraps the cloudmailin client. Used when the
// CLOUDMAILIN_SMTP_URL env var is set.
// =====================================================================

type cloudmailinProvider struct {
	client cloudmailin.Client
}

func (cloudmailinProvider) Name() string { return "cloudmailin" }

func (c cloudmailinProvider) Send(e *Email) error {
	from := e.From
	if from == "" {
		from = defaultFromEmail()
	}
	_, err := c.client.SendMail(&cloudmailin.OutboundMail{
		From:    from,
		To:      []string{e.To},
		Subject: e.Subject,
		Plain:   e.Body,
	})
	return err
}

// pickProvider chooses the system-level email transport. Order:
//
//  1. dev / no-config: console (always usable, logs to stdout).
//  2. SMTP configured via env or store: SMTP (any provider).
//  3. CLOUDMAILIN_SMTP_URL set: cloudmailin client (internal path).
//  4. Otherwise: console with a warning (operator probably forgot
//     to configure email; emails still land in the log so flows
//     are testable, just won't actually leave the box).
func pickProvider(isDev bool, store SecretsStore) Provider {
	if isDev {
		return consoleProvider{}
	}
	if cfg := loadSystemSMTPConfig(store); cfg != nil {
		return smtpProvider{cfg: cfg}
	}
	if strings.TrimSpace(os.Getenv("CLOUDMAILIN_SMTP_URL")) != "" {
		client, err := cloudmailin.NewClient()
		if err != nil {
			log.Err(err).Msg("CLOUDMAILIN_SMTP_URL set but client init failed; falling back to console")
			return consoleProvider{}
		}
		return cloudmailinProvider{client: client}
	}
	log.Warn().Msg("no email provider configured — falling back to console output. Set MANYROWS_SMTP_* to actually deliver mail.")
	return consoleProvider{}
}
