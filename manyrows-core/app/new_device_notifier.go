package app

import (
	"context"
	"strings"
	"time"

	"manyrows-core/auth/client"
	"manyrows-core/core/repo"
	"manyrows-core/email"

	"github.com/rs/zerolog/log"
)

// newDeviceAlertNotifier builds the callback the client auth service invokes
// when a login arrives from a device the user hasn't been seen on before. It
// resolves the app + user, honours the per-app toggle, and sends the alert.
// Best-effort — it already runs on a detached background goroutine, so any
// failure is logged and dropped rather than affecting the login.
func newDeviceAlertNotifier(r *repo.Repo, emailSvc *email.Service) client.NewDeviceNotifier {
	return func(ev client.NewDeviceEvent) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		appRow, err := r.GetAppByID(ctx, ev.AppID)
		if err != nil {
			log.Warn().Err(err).Str("app_id", ev.AppID.String()).Msg("new-device alert: load app failed")
			return
		}
		// The toggle gates only the email — devices are always tracked — so
		// flipping it on later won't false-alarm on already-known devices.
		if !appRow.NewDeviceAlertsEnabled {
			return
		}

		user, err := r.GetUserByID(ctx, ev.UserID)
		if err != nil {
			log.Warn().Err(err).Str("user_id", ev.UserID.String()).Msg("new-device alert: load user failed")
			return
		}
		if user == nil || strings.TrimSpace(user.Email) == "" {
			return
		}

		if err := emailSvc.SendNewDeviceAlert(user.Email, appRow.DisplayName(), ev.UserAgent, ev.IP, ev.At, "en"); err != nil {
			log.Warn().Err(err).Str("user_id", ev.UserID.String()).Msg("new-device alert: send failed")
		}
	}
}
