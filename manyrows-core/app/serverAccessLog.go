package app

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"
)

// serverAccessLogFields holds the identity of a server-to-server request for
// the access log. It's a mutable holder seeded into the request context by
// serverAccessLogMiddleware and filled in by the auth/app middlewares as they
// resolve each value.
//
// A holder is required because context flows DOWN the middleware chain, not
// back up: each inner middleware attaches its value to a child request via
// r.WithContext, so the outer access-log frame can't see those values by
// reading its own request context after the fact — but it can read a pointer
// it seeded earlier and the inner middlewares wrote through.
type serverAccessLogFields struct {
	apiKeyID    string
	apiKeyName  string
	workspaceID string
	appID       string
}

type serverAccessLogCtxKey struct{}

// withServerAccessLogFields seeds an empty holder and returns the augmented
// context plus the holder pointer to read once the request completes.
func withServerAccessLogFields(ctx context.Context) (context.Context, *serverAccessLogFields) {
	f := &serverAccessLogFields{}
	return context.WithValue(ctx, serverAccessLogCtxKey{}, f), f
}

// serverAccessLogFieldsFrom returns the holder if one was seeded, else nil.
// Middlewares populate it nil-safely so they stay usable on routers that
// don't run the access log.
func serverAccessLogFieldsFrom(ctx context.Context) *serverAccessLogFields {
	f, _ := ctx.Value(serverAccessLogCtxKey{}).(*serverAccessLogFields)
	return f
}

// serverAccessLogMiddleware emits one structured audit line per
// server-to-server API request: which API key (and what it was querying),
// against which workspace/app, the outcome, and timing.
//
// It runs as the OUTERMOST middleware on the server router so it also
// captures requests that never reach a handler — a missing/invalid key
// (no api_key_id in the line) or a throttled request (status 429) are
// exactly the rows an operator reviewing access most wants to see.
//
// There is intentionally no DB write: auth_logs is reserved for
// authentication events (its own contract forbids non-auth activity), and
// a row per read would be high-volume. Structured stdout logging lets
// operators ship these to whatever log pipeline they already run, with no
// schema or retention cost.
//
// The API key travels in a header, never the query string, so logging the
// raw query (email / id / accountId / permission being looked up) records
// the "what" of each access without leaking the credential.
func serverAccessLogMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			ctx, fields := withServerAccessLogFields(r.Context())
			r = r.WithContext(ctx)

			next.ServeHTTP(ww, r)

			evt := log.Info().
				Str("component", "server_api").
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", ww.Status()).
				Dur("duration", time.Since(start)).
				Str("ip", getClientIP(r))

			if rid := middleware.GetReqID(ctx); rid != "" {
				evt = evt.Str("request_id", rid)
			}
			if rc := chi.RouteContext(ctx); rc != nil && rc.RoutePattern() != "" {
				evt = evt.Str("route", rc.RoutePattern())
			}
			if q := r.URL.RawQuery; q != "" {
				evt = evt.Str("query", q)
			}
			if fields.apiKeyID != "" {
				evt = evt.Str("api_key_id", fields.apiKeyID).Str("api_key_name", fields.apiKeyName)
			}
			if fields.workspaceID != "" {
				evt = evt.Str("workspace_id", fields.workspaceID)
			}
			if fields.appID != "" {
				evt = evt.Str("app_id", fields.appID)
			}

			evt.Msg("server API request")
		})
	}
}
