package api_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"manyrows-core/core"

	"github.com/go-chi/chi/v5"
)

// setupAdminUnlockRouter registers the user-unlock endpoint under the standard
// admin/workspace scaffold (mirrors setupAdminUserOrgsRouter).
func setupAdminUnlockRouter(t *testing.T) *chi.Mux {
	t.Helper()
	svc := NewTestServices(t)
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)
	wsRouter.Route("/projects/{projectId}/apps/{appId}", func(r chi.Router) {
		r.Post("/users/{userId}/unlock", svc.Handler.HandleAdminUnlockUser)
	})
	return r
}

// TestAdminUnlock_PurgesAttemptCounter is the regression test for the bug where
// unlock cleared the lock flag but left the failed-login attempt rows in place,
// so the next failure immediately re-locked the user. The unlock must purge the
// counter as well.
func TestAdminUnlock_PurgesAttemptCounter(t *testing.T) {
	ctx := context.Background()
	router := setupAdminUnlockRouter(t)

	acc := testEnv.CreateTestAccount(t, "aun-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	// End user with a normalized login email (GetOrCreateUser lowercases/trims,
	// exactly as the password-login path normalizes the attempts subject).
	loginEmail := "locked-" + GenerateUniqueSlug("u") + "@example.com"
	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, loginEmail, app, core.UserSourceRegistered)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}
	// The subject stored at lock time matches user.Email (already normalized).
	subject := user.Email
	defer testEnv.DB.Pool().Exec(ctx, "DELETE FROM attempts WHERE subject = $1", subject)

	// 1. Insert >= threshold (10) failed-login attempts for this subject.
	const failedAttempts = 12
	for i := 0; i < failedAttempts; i++ {
		if err := testEnv.Repo.InsertAttempt(ctx, "workspace_login_pw", subject, "127.0.0.1"); err != nil {
			t.Fatalf("InsertAttempt %d: %v", i, err)
		}
	}

	// 2. Lock the user.
	if err := testEnv.Repo.SetUserLockedUntil(ctx, user.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SetUserLockedUntil: %v", err)
	}

	// 3. Admin unlock.
	url := fmt.Sprintf("/admin/workspace/%s/projects/%s/apps/%s/users/%s/unlock",
		ws.ID, app.ProjectID, app.ID, user.ID)
	req := httptest.NewRequest(http.MethodPost, url, nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// 4. The lock flag must be cleared.
	reloaded, err := testEnv.Repo.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if reloaded.LockedUntil != nil {
		t.Errorf("LockedUntil should be nil after unlock, got %v", *reloaded.LockedUntil)
	}

	// 5. THE TEETH: the failed-login counter must be purged, so a subsequent
	// failure does not re-lock the user.
	count, err := testEnv.Repo.CountAttemptsBySubject(ctx, "workspace_login_pw", subject, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("CountAttemptsBySubject: %v", err)
	}
	if count != 0 {
		t.Errorf("attempt counter should be 0 after unlock, got %d (stale failures re-lock the user)", count)
	}
}
