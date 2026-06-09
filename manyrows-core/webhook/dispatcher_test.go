package webhook

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"testing"

	"manyrows-core/core"
	"manyrows-core/crypto"

	"github.com/gofrs/uuid/v5"
)

// fakeEncryptor is a deterministic stand-in for crypto.SecretEncryptor that
// "encrypts" by prefixing the AAD, so resolveSecret's AAD plumbing and
// error-propagation are exercised without real key material.
type fakeEncryptor struct{ failDecrypt bool }

func (f fakeEncryptor) EncryptToBytesWithAAD(pt, aad []byte) ([]byte, error) {
	return append(append([]byte{}, aad...), append([]byte("|"), pt...)...), nil
}
func (f fakeEncryptor) DecryptFromBytesWithAAD(ct, aad []byte) ([]byte, error) {
	if f.failDecrypt {
		return nil, errors.New("boom")
	}
	prefix := append(append([]byte{}, aad...), '|')
	if !bytes.HasPrefix(ct, prefix) {
		return nil, errors.New("aad mismatch")
	}
	return ct[len(prefix):], nil
}
func (f fakeEncryptor) IsCanonical([]byte) bool { return true }

// TestResolveSecret covers the at-rest secret resolution: the encrypted path,
// the legacy plaintext fallback, and every fail-closed branch (so deliver()
// never signs with an empty or wrong secret).
func TestResolveSecret(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	enc := fakeEncryptor{}
	aad := crypto.AAD("webhooks", "secret_encrypted", id)
	ct, _ := enc.EncryptToBytesWithAAD([]byte("s3cr3t"), aad)

	t.Run("encrypted", func(t *testing.T) {
		d := &Dispatcher{enc: enc}
		got, err := d.resolveSecret(core.Webhook{ID: id, SecretEncrypted: ct})
		if err != nil || got != "s3cr3t" {
			t.Fatalf("got (%q, %v), want (s3cr3t, nil)", got, err)
		}
	})

	t.Run("legacy plaintext fallback", func(t *testing.T) {
		d := &Dispatcher{enc: enc}
		got, err := d.resolveSecret(core.Webhook{ID: id, Secret: "legacy"})
		if err != nil || got != "legacy" {
			t.Fatalf("got (%q, %v), want (legacy, nil)", got, err)
		}
	})

	t.Run("encrypted preferred over legacy", func(t *testing.T) {
		d := &Dispatcher{enc: enc}
		got, err := d.resolveSecret(core.Webhook{ID: id, SecretEncrypted: ct, Secret: "stale"})
		if err != nil || got != "s3cr3t" {
			t.Fatalf("got (%q, %v), want (s3cr3t, nil)", got, err)
		}
	})

	t.Run("nil encryptor fails closed", func(t *testing.T) {
		d := &Dispatcher{enc: nil}
		if _, err := d.resolveSecret(core.Webhook{ID: id, SecretEncrypted: ct}); err == nil {
			t.Fatal("expected error when no encryptor is configured")
		}
	})

	t.Run("decrypt error fails closed", func(t *testing.T) {
		d := &Dispatcher{enc: fakeEncryptor{failDecrypt: true}}
		if _, err := d.resolveSecret(core.Webhook{ID: id, SecretEncrypted: ct}); err == nil {
			t.Fatal("expected error when decrypt fails")
		}
	})

	t.Run("no secret at all fails closed", func(t *testing.T) {
		d := &Dispatcher{enc: enc}
		if _, err := d.resolveSecret(core.Webhook{ID: id}); err == nil {
			t.Fatal("expected error when no secret is on record")
		}
	})
}

// TestIsBlockedDialIP pins the SSRF connect-time guard: the dialer must refuse
// every non-public address (loopback, RFC1918, link-local incl. the cloud
// metadata endpoint, ULA, unspecified, and IPv4-mapped forms of the above)
// while still allowing genuinely public addresses.
func TestIsBlockedDialIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", // loopback
		"10.0.0.1", "172.16.0.1", "192.168.1.1", // RFC1918
		"169.254.169.254", // link-local — cloud metadata
		"fe80::1",         // link-local v6
		"fc00::1",         // unique-local v6
		"0.0.0.0", "::",   // unspecified
		"::ffff:10.0.0.1", // IPv4-mapped private
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test fixture IP %q", s)
		}
		if !isBlockedDialIP(ip) {
			t.Errorf("isBlockedDialIP(%s) = false, want true — webhooks must not reach this", s)
		}
	}

	allowed := []string{
		"8.8.8.8", "1.1.1.1", // public v4
		"2606:4700:4700::1111", // public v6
	}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test fixture IP %q", s)
		}
		if isBlockedDialIP(ip) {
			t.Errorf("isBlockedDialIP(%s) = true, want false — public address", s)
		}
	}
}

// TestNewWebhookClientRefusesRedirects ensures the delivery client never
// follows a redirect (a validated public URL could otherwise 302 onto an
// internal target). The policy applies regardless of dev/prod mode.
func TestNewWebhookClientRefusesRedirects(t *testing.T) {
	for _, devMode := range []bool{true, false} {
		c := newWebhookClient(devMode)
		if c.CheckRedirect == nil {
			t.Fatalf("devMode=%v: CheckRedirect not set", devMode)
		}
		if err := c.CheckRedirect(&http.Request{}, nil); err != http.ErrUseLastResponse {
			t.Errorf("devMode=%v: CheckRedirect = %v, want http.ErrUseLastResponse", devMode, err)
		}
	}
}
