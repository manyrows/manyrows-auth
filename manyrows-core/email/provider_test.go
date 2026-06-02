package email

import (
	"context"
	"testing"
)

// resetEmailEnv unsets every env var pickProvider reads so tests
// don't pick up the developer's local config.
func resetEmailEnv(t *testing.T) {
	t.Helper()
	for _, n := range []string{
		"MANYROWS_SMTP_HOST",
		"MANYROWS_SMTP_PORT",
		"MANYROWS_SMTP_USERNAME",
		"MANYROWS_SMTP_PASSWORD",
		"MANYROWS_SMTP_FROM_EMAIL",
		"MANYROWS_SMTP_FROM_NAME",
		"MANYROWS_FROM_EMAIL",
		"MANYROWS_FROM_NAME",
		"CLOUDMAILIN_SMTP_URL",
	} {
		t.Setenv(n, "")
	}
}

func TestPickProvider_DevAlwaysConsole(t *testing.T) {
	resetEmailEnv(t)
	t.Setenv("MANYROWS_SMTP_HOST", "smtp.example.com")
	t.Setenv("CLOUDMAILIN_SMTP_URL", "smtp://user:pass@host:25/")
	if got := pickProvider(true, nil).Name(); got != "console" {
		t.Errorf("isDev=true should always pick console; got %q", got)
	}
}

func TestPickProvider_SMTPWinsWhenConfigured(t *testing.T) {
	resetEmailEnv(t)
	t.Setenv("MANYROWS_SMTP_HOST", "smtp.example.com")
	t.Setenv("CLOUDMAILIN_SMTP_URL", "smtp://user:pass@host:25/")
	if got := pickProvider(false, nil).Name(); got != "smtp" {
		t.Errorf("SMTP_HOST set should win; got %q", got)
	}
}

func TestPickProvider_CloudmailinWhenSMTPUnset(t *testing.T) {
	resetEmailEnv(t)
	t.Setenv("CLOUDMAILIN_SMTP_URL", "smtp://user:pass@host:25/")
	got := pickProvider(false, nil).Name()
	// Client init can fail in CI without a real URL — accept either
	// "cloudmailin" (success) or "console" (init-fail fallback) but
	// reject "smtp" since we never set SMTP_HOST.
	if got != "cloudmailin" && got != "console" {
		t.Errorf("expected cloudmailin (or console fallback); got %q", got)
	}
}

func TestPickProvider_NothingConfiguredFallsToConsole(t *testing.T) {
	resetEmailEnv(t)
	if got := pickProvider(false, nil).Name(); got != "console" {
		t.Errorf("nothing configured should fall back to console; got %q", got)
	}
}

func TestReadSystemSMTPFromEnv_Defaults(t *testing.T) {
	resetEmailEnv(t)
	t.Setenv("MANYROWS_SMTP_HOST", "smtp.example.com")
	cfg := loadSystemSMTPConfig(nil)
	if cfg == nil {
		t.Fatal("expected non-nil cfg with HOST set")
	}
	if cfg.Host != "smtp.example.com" {
		t.Errorf("Host = %q, want smtp.example.com", cfg.Host)
	}
	if cfg.Port != 587 {
		t.Errorf("Port default = %d, want 587", cfg.Port)
	}
	if cfg.FromEmail != "" {
		t.Errorf("FromEmail default = %q, want empty (no hardcoded vendor address)", cfg.FromEmail)
	}
}

func TestReadSystemSMTPFromEnv_NilWhenHostMissing(t *testing.T) {
	resetEmailEnv(t)
	if cfg := loadSystemSMTPConfig(nil); cfg != nil {
		t.Errorf("expected nil when HOST unset; got %+v", cfg)
	}
}

func TestReadSystemSMTPFromEnv_HonoursOverrides(t *testing.T) {
	resetEmailEnv(t)
	t.Setenv("MANYROWS_SMTP_HOST", "smtp.acme.com")
	t.Setenv("MANYROWS_SMTP_PORT", "465")
	t.Setenv("MANYROWS_SMTP_USERNAME", "apikey")
	t.Setenv("MANYROWS_SMTP_PASSWORD", "secret")
	t.Setenv("MANYROWS_SMTP_FROM_EMAIL", "noreply@acme.com")
	t.Setenv("MANYROWS_SMTP_FROM_NAME", "Acme Auth")
	cfg := loadSystemSMTPConfig(nil)
	if cfg.Port != 465 {
		t.Errorf("Port = %d, want 465", cfg.Port)
	}
	if cfg.Username != "apikey" || cfg.Password != "secret" {
		t.Errorf("creds not propagated: %q / %q", cfg.Username, cfg.Password)
	}
	if cfg.FromEmail != "noreply@acme.com" || cfg.FromName != "Acme Auth" {
		t.Errorf("from fields not propagated: %q <%s>", cfg.FromName, cfg.FromEmail)
	}
}

type fakeStore struct{ values map[string]string }

func (f *fakeStore) GetSystemSecret(_ context.Context, name string) (string, error) {
	return f.values[name], nil
}

func TestLoadSystemSMTPConfig_StoreUsedWhenEnvEmpty(t *testing.T) {
	resetEmailEnv(t)
	store := &fakeStore{values: map[string]string{
		"smtp_host":       "smtp.acme.com",
		"smtp_port":       "2525",
		"smtp_username":   "apikey",
		"smtp_password":   "supersecret",
		"smtp_from_email": "auth@acme.com",
		"smtp_from_name":  "Acme Auth",
	}}
	cfg := loadSystemSMTPConfig(store)
	if cfg == nil {
		t.Fatal("expected non-nil cfg from store")
	}
	if cfg.Host != "smtp.acme.com" || cfg.Port != 2525 {
		t.Errorf("host/port not loaded from store: %s:%d", cfg.Host, cfg.Port)
	}
	if cfg.Username != "apikey" || cfg.Password != "supersecret" {
		t.Errorf("creds not loaded from store: %q/%q", cfg.Username, cfg.Password)
	}
	if cfg.FromEmail != "auth@acme.com" || cfg.FromName != "Acme Auth" {
		t.Errorf("from fields not loaded from store: %q <%s>", cfg.FromName, cfg.FromEmail)
	}
}

func TestLoadSystemSMTPConfig_EnvWinsPerField(t *testing.T) {
	resetEmailEnv(t)
	t.Setenv("MANYROWS_SMTP_HOST", "env.host")
	t.Setenv("MANYROWS_SMTP_PASSWORD", "env-password")
	store := &fakeStore{values: map[string]string{
		"smtp_host":     "store.host",
		"smtp_port":     "1025",
		"smtp_password": "store-password",
	}}
	cfg := loadSystemSMTPConfig(store)
	if cfg == nil {
		t.Fatal("expected non-nil cfg")
	}
	if cfg.Host != "env.host" {
		t.Errorf("env host should win: got %q", cfg.Host)
	}
	if cfg.Port != 1025 {
		t.Errorf("store port should be used (env not set): got %d", cfg.Port)
	}
	if cfg.Password != "env-password" {
		t.Errorf("env password should win: got %q", cfg.Password)
	}
}

func TestLoadSystemSMTPConfig_NilWhenNeitherSourceHasHost(t *testing.T) {
	resetEmailEnv(t)
	store := &fakeStore{values: map[string]string{"smtp_port": "587"}} // no host
	if cfg := loadSystemSMTPConfig(store); cfg != nil {
		t.Errorf("expected nil with no host in either source; got %+v", cfg)
	}
}

func TestService_Reload_SwapsProvider(t *testing.T) {
	resetEmailEnv(t)
	store := &fakeStore{values: map[string]string{}}
	svc := NewEmailService(false, store)
	if svc.provider.Name() != "console" {
		t.Fatalf("expected console initially; got %s", svc.provider.Name())
	}
	store.values["smtp_host"] = "smtp.acme.com"
	svc.Reload()
	if svc.provider.Name() != "smtp" {
		t.Errorf("expected smtp after store update; got %s", svc.provider.Name())
	}
}

func TestConsoleProvider_DoesNotErrorOnSend(t *testing.T) {
	// Smoke test for the most-used path; the real assertion is "doesn't
	// panic, doesn't try to dial anything, returns nil."
	err := consoleProvider{}.Send(&Email{To: "a@b.com", Subject: "x", Body: "y"})
	if err != nil {
		t.Errorf("console.Send should not fail; got %v", err)
	}
}
