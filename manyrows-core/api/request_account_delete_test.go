package api_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/core"
)

func requestDeletePath(ws *core.Workspace, app *core.App) string {
	return "/x/" + ws.Slug + "/apps/" + app.ID.String() + "/a/me/request-delete"
}

func TestRequestAccountDeletion_Passwordless_CreatesRequest(t *testing.T) {
	r, ws, app, _, user, token := passwordlessDeleteSetup(t)
	ctx := context.Background()

	req := httptest.NewRequest(http.MethodPost, requestDeletePath(ws, app), bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if _, err := testEnv.Repo.GetAccountDeleteRequest(ctx, user.ID); err != nil {
		t.Fatalf("expected a pending request to be created: %v", err)
	}
}

func TestRequestAccountDeletion_PasswordUser_Rejected(t *testing.T) {
	r, ws, app, _, _, token := passwordDeleteSetup(t)
	req := httptest.NewRequest(http.MethodPost, requestDeletePath(ws, app), bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 (use password flow), got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestRequestAccountDeletion_DeletionDisabled(t *testing.T) {
	r, ws, app, _, _, token := passwordlessDeleteSetup(t)
	ctx := context.Background()

	// Flip the app's allow_account_deletion flag off.
	if _, err := testEnv.DB.Pool().Exec(ctx,
		"UPDATE apps SET allow_account_deletion = false WHERE id = $1", app.ID,
	); err != nil {
		t.Fatalf("disable deletion flag: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, requestDeletePath(ws, app), bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}
