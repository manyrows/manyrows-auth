package api

import (
	"context"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
)

// ResolveActiveRolesAndPermissionsForTest exposes resolveActiveRolesAndPermissions
// to the external api_test package. Test-only (lives in a _test.go file).
func (handler *RequestHandler) ResolveActiveRolesAndPermissionsForTest(
	ctx context.Context, app *core.App, projectID, userID uuid.UUID, ses *core.ClientSession,
) ([]string, []string, *core.OrganizationMember, error) {
	return handler.resolveActiveRolesAndPermissions(ctx, app, projectID, userID, ses)
}
