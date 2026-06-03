package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// NewDeviceEvent describes a login from a device the user hasn't been seen
// on before. It carries only what the alert needs; the notifier looks up the
// user's email and app details itself.
type NewDeviceEvent struct {
	UserID    uuid.UUID
	AppID     uuid.UUID
	IP        string
	UserAgent string
	At        time.Time
}

// NewDeviceNotifier reacts to a new-device login (in practice, sends the
// alert email). Invoked off the login path, so it must not assume the
// request context is still live.
type NewDeviceNotifier func(NewDeviceEvent)

// SetNewDeviceNotifier wires the new-device notifier. Setting a non-nil
// notifier also enables device tracking on every login.
func (a *AuthService) SetNewDeviceNotifier(n NewDeviceNotifier) {
	a.newDeviceNotifier = n
}

// trackDeviceAsync records the login's device and, if it's genuinely new to
// the account, fires the notifier. Runs entirely in the background on a
// detached context so it never adds latency to — or fails — a login; device
// memory and alerting are best-effort. No-op when the notifier isn't wired
// or the session isn't app-scoped.
func (a *AuthService) trackDeviceAsync(userID, appID uuid.UUID, userAgent, ip string) {
	if a.newDeviceNotifier == nil || appID == uuid.Nil {
		return
	}
	ua := strings.TrimSpace(userAgent)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		wasNew, priorCount, err := a.repo.UpsertKnownDevice(ctx, userID, appID, deviceFingerprint(ua), ua, ip)
		if err != nil {
			log.Warn().Err(err).Str("user_id", userID.String()).Msg("new-device tracking: upsert failed")
			return
		}
		if shouldAlertNewDevice(wasNew, priorCount, ua) {
			a.newDeviceNotifier(NewDeviceEvent{
				UserID:    userID,
				AppID:     appID,
				IP:        ip,
				UserAgent: ua,
				At:        time.Now(),
			})
		}
	}()
}

// deviceFingerprint derives a stable per-device identifier from the
// user-agent string. We hash the (trimmed) UA so the stored fingerprint is
// fixed-width and the raw header isn't duplicated into yet another index.
// IP is deliberately excluded — it churns constantly (mobile, DHCP, NAT) and
// would make every login look like a new device. "Device" here means the
// browser/client, matching the user-facing "previously unseen device".
func deviceFingerprint(userAgent string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(userAgent)))
	return hex.EncodeToString(sum[:])
}

// shouldAlertNewDevice decides whether a login warrants a new-device alert.
// It fires only when the device is genuinely new to the account AND the
// account already had at least one known device (so a user's first-ever
// login — or the first login after this feature ships — never alerts). An
// empty user agent can't be meaningfully identified, so it never alerts.
func shouldAlertNewDevice(wasNew bool, priorDeviceCount int, userAgent string) bool {
	if strings.TrimSpace(userAgent) == "" {
		return false
	}
	return wasNew && priorDeviceCount > 0
}
