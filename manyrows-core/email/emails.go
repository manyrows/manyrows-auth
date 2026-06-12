package email

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"manyrows-core/utils"
)

// SMTP network timeouts for the custom/system relay path. These sends run
// inline on request paths (register / password reset), so a hung or
// blackholed relay must never pin a goroutine: bound both the TCP connect
// and the whole SMTP conversation (STARTTLS + AUTH + DATA).
const (
	smtpDialTimeout      = 10 * time.Second
	smtpConversationTime = 30 * time.Second
)

// defaultFromEmail is the system-default sender address. Reads
// MANYROWS_FROM_EMAIL on each call so an operator can change it
// without restarting (the SMTP path also reads MANYROWS_SMTP_FROM_EMAIL
// — that wins when present, since it's the more specific override).
//
// Returns "" when nothing is configured. Callers that hit empty must
// log loudly and refuse to send — there is no safe fallback. Any
// hardcoded vendor address would be rejected by the operator's SMTP
// provider (DKIM/SPF won't match), so silently making one up is worse
// than failing loudly.
func defaultFromEmail() string {
	if v := strings.TrimSpace(os.Getenv("MANYROWS_FROM_EMAIL")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("MANYROWS_SMTP_FROM_EMAIL")); v != "" {
		return v
	}
	return ""
}

// defaultFromName is the optional display name used by WorkspaceFrom
// when the workspace itself doesn't override (it usually does).
func defaultFromName() string {
	return strings.TrimSpace(os.Getenv("MANYROWS_FROM_NAME"))
}

type Email struct {
	To      string
	From    string
	Subject string
	Body    string
}

// SecretsStore is the narrow surface the email package needs from the
// repo to read runtime-configured SMTP settings. Implemented by
// *repo.Repo; small enough to fake in tests.
type SecretsStore interface {
	GetSystemSecret(ctx context.Context, name string) (string, error)
}

// Service is the system-level email transport. Holds a Provider
// chosen at startup (console / SMTP / internal); admin endpoints
// can call Reload() after writing new SMTP settings to the store so
// the next email goes via the new transport without a restart.
type Service struct {
	IsDev bool
	store SecretsStore

	mu       sync.RWMutex
	provider Provider
}

// NewEmailService picks the right transport based on env vars + the
// optional store. isDev forces console output (used by tests + dev
// mode). For non-dev installs the provider chain is:
//
//  1. SMTP if MANYROWS_SMTP_HOST (env) or smtp_host (store) is set —
//     env wins on a per-field basis.
//  2. cloudmailin client if CLOUDMAILIN_SMTP_URL is set (internal path).
//  3. Console with a warning otherwise.
//
// Pass store=nil to skip the DB-backed override path (tests, dev).
func NewEmailService(isDev bool, store SecretsStore) *Service {
	s := &Service{IsDev: isDev, store: store}
	s.provider = pickProvider(isDev, store)
	log.Info().Str("provider", s.provider.Name()).Msg("email service initialised")
	return s
}

// Reload re-runs provider selection. Called after the super-admin
// updates SMTP config so the next email uses the new transport.
func (s *Service) Reload() {
	next := pickProvider(s.IsDev, s.store)
	s.mu.Lock()
	s.provider = next
	s.mu.Unlock()
	log.Info().Str("provider", next.Name()).Msg("email service reloaded")
}

// ProviderName returns the active transport's name. Surfaces in the
// admin UI so operators can see at a glance whether outbound mail
// is configured without having to read logs.
func (s *Service) ProviderName() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.provider.Name()
}

// DefaultFromEmail is the system-default sender address. Exposed so
// admin UIs can show the operator which "From" their outbound mail
// will use (mostly relevant when nothing's configured per-workspace).
func (s *Service) DefaultFromEmail() string {
	return defaultFromEmail()
}

// WorkspaceFrom returns a From address with the workspace name as
// display name. Example: `"My App" <no-reply@example.com>`. Returns
// "" if defaultFromEmail() returns "" (no MANYROWS_FROM_EMAIL set);
// callers must treat that as a config error and refuse to send.
func WorkspaceFrom(workspaceName string) string {
	addr := defaultFromEmail()
	name := strings.TrimSpace(workspaceName)
	if name == "" {
		name = defaultFromName()
	}
	if name == "" {
		return addr
	}
	return fmt.Sprintf("%q <%s>", name, addr)
}

func (s *Service) Send(email *Email) error {
	if email != nil && strings.TrimSpace(email.From) == "" && !s.IsDev {
		// Hard fail rather than punting it to the SMTP server (which
		// would reject and we'd find out via vague logs later). Most
		// likely cause: operator forgot to set MANYROWS_FROM_EMAIL.
		log.Error().
			Str("to", utils.MaskEmail(email.To)).
			Str("subject", email.Subject).
			Msg("email: refused to send — From is empty; set MANYROWS_FROM_EMAIL")
		return errors.New("email: From not configured; set MANYROWS_FROM_EMAIL")
	}
	s.mu.RLock()
	p := s.provider
	s.mu.RUnlock()
	return p.Send(email)
}

// sendDev is kept around for the per-workspace SMTP path, which logs
// the email when isDev is set instead of dialling the provided SMTP
// server. The system-level send path now goes through s.provider.
//
// Intentionally prints the full email body (including OTP/reset codes
// and magic links) to stdout — this is LOCAL DEV convenience only.
// sendDev is only ever reached when IsDev is true (see SendWithCustomSMTP).
// The production no-transport path uses failProvider, which never prints.
func (s *Service) sendDev(email *Email) error {
	return consoleProvider{}.Send(email)
}

// SMTPConfig holds custom SMTP credentials for per-workspace email sending.
type SMTPConfig struct {
	Host      string
	Port      int
	Username  string
	Password  string // plaintext (caller decrypts before passing)
	FromEmail string
	FromName  string
}

// FormatFrom returns a formatted From address using FromName if set.
func (c *SMTPConfig) FormatFrom() string {
	if c.FromName == "" {
		return c.FromEmail
	}
	return fmt.Sprintf("%q <%s>", c.FromName, c.FromEmail)
}

// SendWithCustomSMTP sends an email via a custom SMTP server.
// If cfg is nil, falls back to the system-default transport.
func (s *Service) SendWithCustomSMTP(email *Email, cfg *SMTPConfig) error {
	if cfg == nil {
		return s.Send(email)
	}
	if s.IsDev {
		fmt.Printf("[custom SMTP: %s:%d]\n", cfg.Host, cfg.Port)
		return s.sendDev(email)
	}
	return sendCustomSMTP(email, cfg)
}

func sendCustomSMTP(e *Email, cfg *SMTPConfig) error {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))

	// Connect
	conn, err := net.DialTimeout("tcp", addr, smtpDialTimeout)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	// Bound the rest of the conversation (STARTTLS / AUTH / DATA) so a relay
	// that accepts the connection but then stalls can't hang the goroutine.
	_ = conn.SetDeadline(time.Now().Add(smtpConversationTime))

	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Close()

	// STARTTLS if supported
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: cfg.Host}); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}

	// Auth if credentials provided
	if cfg.Username != "" && cfg.Password != "" {
		auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	from := e.From
	if from == "" {
		from = cfg.FromEmail
	}

	if err := c.Mail(cfg.FromEmail); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := c.Rcpt(e.To); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}

	// Strip CR/LF from header fields to prevent SMTP header injection
	// (e.g. a workspace name or subject containing "\r\nBcc: attacker@..." would
	// otherwise inject extra headers). Body is left alone since it's below the blank line.
	headerSafe := strings.NewReplacer("\r", "", "\n", "")
	msg := "From: " + headerSafe.Replace(from) + "\r\n" +
		"To: " + headerSafe.Replace(e.To) + "\r\n" +
		"Subject: " + headerSafe.Replace(e.Subject) + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		e.Body

	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}

	return c.Quit()
}

func (s *Service) SendAdminEmailValidationCode(toEmail string, code string, lang string) error {
	toEmail = strings.TrimSpace(toEmail)
	code = strings.TrimSpace(code)
	if toEmail == "" || code == "" {
		return errors.New("missing email or code")
	}

	subject := T(lang, "admin.validation.subject")
	body := fmt.Sprintf(T(lang, "admin.validation.body"), code)

	email := Email{
		To:      toEmail,
		From:    defaultFromEmail(),
		Subject: subject,
		Body:    body,
	}
	return s.Send(&email)
}

func (s *Service) SendAdminPasswordResetCode(toEmail string, code string, lang string) error {
	toEmail = strings.TrimSpace(toEmail)
	code = strings.TrimSpace(code)
	if toEmail == "" || code == "" {
		return errors.New("missing email or code")
	}

	subject := T(lang, "admin.password_reset.subject")
	body := fmt.Sprintf(T(lang, "admin.password_reset.body"), code)

	email := Email{
		To:      toEmail,
		From:    defaultFromEmail(),
		Subject: subject,
		Body:    body,
	}
	return s.Send(&email)
}

func (s *Service) SendEmailChangeCode(toEmail string, code string, lang string) error {
	toEmail = strings.TrimSpace(toEmail)
	code = strings.TrimSpace(code)
	if toEmail == "" || code == "" {
		return errors.New("missing email or code")
	}

	subject := T(lang, "email_change.subject")
	body := fmt.Sprintf(T(lang, "email_change.body"), code)

	email := Email{
		To:      toEmail,
		From:    defaultFromEmail(),
		Subject: subject,
		Body:    body,
	}
	return s.Send(&email)
}

// SendEmailChangeNotice sends a "your email address was changed"
// notification to the OLD email address after a successful swap.
// Lets an account-takeover victim notice the change in their inbox
// and act on it before the attacker pivots deeper. Doesn't include
// the new address — that would confirm to an attacker where the
// account moved.
func (s *Service) SendEmailChangeNotice(oldEmail string, lang string) error {
	oldEmail = strings.TrimSpace(oldEmail)
	if oldEmail == "" {
		return errors.New("missing old email")
	}
	subject := T(lang, "email_change.notice.subject")
	body := T(lang, "email_change.notice.body")
	email := Email{
		To:      oldEmail,
		From:    defaultFromEmail(),
		Subject: subject,
		Body:    body,
	}
	return s.Send(&email)
}

// buildNewDeviceAlertEmail composes the new-device security alert. Kept
// separate from SendNewDeviceAlert so the composition (recipient, subject,
// body substitutions) is unit-testable without a live transport.
func buildNewDeviceAlertEmail(toEmail, appName, userAgent, ip string, when time.Time, lang string) Email {
	subject := fmt.Sprintf(T(lang, "new_device.subject"), appName)
	body := fmt.Sprintf(T(lang, "new_device.body"),
		appName, userAgent, ip, when.UTC().Format("2006-01-02 15:04 MST"))
	return Email{
		To:      toEmail,
		From:    WorkspaceFrom(appName),
		Subject: subject,
		Body:    body,
	}
}

// SendNewDeviceAlert notifies an end user that their account was signed in to
// from a device that hasn't been seen before, so they can react if it wasn't
// them. Best-effort — callers invoke it off the login path.
func (s *Service) SendNewDeviceAlert(toEmail, appName, userAgent, ip string, when time.Time, lang string) error {
	toEmail = strings.TrimSpace(toEmail)
	if toEmail == "" {
		return errors.New("missing recipient email")
	}
	em := buildNewDeviceAlertEmail(toEmail, appName, userAgent, ip, when, lang)
	return s.Send(&em)
}

func (s *Service) SendTeamInviteEmail(toEmail string, inviterName string, workspaceName string, magicLink string, lang string) error {
	subject := fmt.Sprintf(T(lang, "team_invite.subject"), workspaceName)
	body := fmt.Sprintf(T(lang, "team_invite.body"), inviterName, workspaceName, magicLink)

	email := Email{
		To:      toEmail,
		From:    defaultFromEmail(),
		Subject: subject,
		Body:    body,
	}
	return s.Send(&email)
}

// BuildOrgInviteEmail composes the org-invite email (plain text). Unlike the
// admin-facing Send* methods, it only builds the message — it does NOT send.
// The caller (the create-invite handler) delivers it via sendWorkspaceEmail so
// it picks up per-workspace branding, and so the handler can roll back the
// invite if the send fails.
//
// Placeholder order mirrors the "org_invite.*" templates:
//   - subject: orgName
//   - body:    inviterLabel, orgName, acceptLink
func BuildOrgInviteEmail(lang, toEmail, fromName, inviterLabel, orgName, acceptLink string) *Email {
	subject := fmt.Sprintf(T(lang, "org_invite.subject"), orgName)
	body := fmt.Sprintf(T(lang, "org_invite.body"), inviterLabel, orgName, acceptLink)
	return &Email{
		To:      toEmail,
		From:    fromName,
		Subject: subject,
		Body:    body,
	}
}
