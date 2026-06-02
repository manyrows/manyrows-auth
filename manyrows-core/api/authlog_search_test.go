package api_test

import (
	"context"
	"testing"

	"manyrows-core/core/repo"
)

// TestListAuthLogs_EmailFilterEscapesWildcards is a smoke test for the auth-log
// email filter's ILIKE ... ESCAPE '\' clause: a search term containing the SQL
// wildcard chars (% _ \) must produce a valid query that runs without error.
// (Catches a malformed ESCAPE clause; the substantive behavior — literal '%'
// matches exactly rather than expanding — is provided by emailILIKEArg, which
// the user-search paths already exercise.)
func TestListAuthLogs_EmailFilterEscapesWildcards(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "authlog-"+GenerateUniqueSlug("t")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "AuthLog WS", GenerateUniqueSlug("ws"))

	if _, _, err := testEnv.Repo.ListAuthLogs(ctx, repo.ListAuthLogsParams{
		WorkspaceID:        ws.ID,
		EmailAttemptedLike: `a%b_c\d@example.com`,
	}); err != nil {
		t.Fatalf("ListAuthLogs with wildcard email filter errored (bad ESCAPE clause?): %v", err)
	}
}
