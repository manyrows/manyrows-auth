package app

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"

	"manyrows-core/core"
)

// clientAuthAccessLog emits one structured stdout line per client end-user
// auth request and seeds a request-scoped logger (request_id/app_id/
// workspace_id) so the auth handlers' own logs correlate. No DB write —
// auth_logs is reserved for authentication EVENTS; this is access logging,
// parity with serverAccessLogMiddleware. app/workspace are already resolved
// by upstream middleware on /apps/{appId}, so they're read from context.
//
// The user_id is carried back up through the auth-log holder: context flows
// DOWN the chain, so the handler can't write a value this outer frame reads
// from its own request context after the fact. Instead the middleware seeds a
// holder pointer (WithAuthLogHolder) that the handler writes through via
// core.SetAuthLogUser when it resolves an authenticated subject.
func clientAuthAccessLog() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			rid := middleware.GetReqID(r.Context())

			var appID, wsID string
			if a, ok := core.AppFromContext(r.Context()); ok && a != nil {
				appID = a.ID.String()
			}
			if ws, ok := core.WorkspaceFromContext(r.Context()); ok && ws != nil {
				wsID = ws.ID.String()
			}

			lg := log.With().
				Str("request_id", rid).
				Str("app_id", appID).
				Str("workspace_id", wsID).
				Logger()
			ctx, holder := core.WithAuthLogHolder(lg.WithContext(r.Context()))
			r = r.WithContext(ctx)

			next.ServeHTTP(ww, r)

			evt := log.Info().
				Str("component", "client_auth").
				Str("method", r.Method).
				Int("status", ww.Status()).
				Dur("duration", time.Since(start)).
				Str("ip", getClientIP(r))
			if rid != "" {
				evt = evt.Str("request_id", rid)
			}
			if rc := chi.RouteContext(r.Context()); rc != nil && rc.RoutePattern() != "" {
				evt = evt.Str("route", rc.RoutePattern())
			}
			if appID != "" {
				evt = evt.Str("app_id", appID)
			}
			if wsID != "" {
				evt = evt.Str("workspace_id", wsID)
			}
			if uid := holder.UserID(); uid != "" {
				evt = evt.Str("user_id", uid)
			}
			evt.Msg("client auth request")
		})
	}
}
