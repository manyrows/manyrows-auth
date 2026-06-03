package email

import (
	"strings"
	"testing"
	"time"
)

// TestBuildNewDeviceAlertEmail checks the new-device security alert surfaces
// the app, device, IP and time, addresses the right recipient, and uses real
// translations (not raw i18n keys).
func TestBuildNewDeviceAlertEmail(t *testing.T) {
	when := time.Date(2026, 6, 3, 5, 4, 0, 0, time.UTC)
	em := buildNewDeviceAlertEmail("user@example.com", "Acme App", "Chrome on macOS", "203.0.113.7", when, "en")

	if em.To != "user@example.com" {
		t.Errorf("To = %q, want user@example.com", em.To)
	}
	if em.From == "" {
		t.Error("From should be set")
	}
	if !strings.Contains(em.Subject, "Acme App") {
		t.Errorf("subject should mention the app: %q", em.Subject)
	}
	// Guard against shipping an untranslated key (T returns the key on miss).
	if strings.Contains(em.Subject, "new_device.") || strings.Contains(em.Body, "new_device.") {
		t.Errorf("email looks untranslated:\nsubject=%q\nbody=%q", em.Subject, em.Body)
	}
	for _, want := range []string{"Acme App", "Chrome on macOS", "203.0.113.7", "2026-06-03"} {
		if !strings.Contains(em.Body, want) {
			t.Errorf("body missing %q:\n%s", want, em.Body)
		}
	}
}
