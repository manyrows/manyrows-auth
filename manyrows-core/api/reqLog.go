package api

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// reqLog returns the request-scoped logger seeded by the client-auth
// access-log middleware (request_id/app_id/workspace_id), or the global
// logger when none was seeded (DefaultContextLogger fallback). Drop-in for
// the package-global log on request-handling paths.
func reqLog(ctx context.Context) *zerolog.Logger {
	return log.Ctx(ctx)
}
