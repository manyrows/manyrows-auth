package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"manyrows-core/core"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// setupAdminBulkUserRouter registers the bulk user-action endpoint under the
// standard admin/workspace scaffold (mirrors setupAdminUnlockRouter).
func setupAdminBulkUserRouter(t *testing.T, svc *TestServices) *chi.Mux {
	t.Helper()
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)
	wsRouter.Route("/projects/{projectId}/apps/{appId}", func(r chi.Router) {
		r.Post("/users:bulk", svc.Handler.HandleAdminBulkUserAction)
	})
	return r
}

type bulkResp struct {
	Results []struct {
		UserID string `json:"userId"`
		OK     bool   `json:"ok"`
		Error  string `json:"error,omitempty"`
	} `json:"results"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
}

func TestBulkUserActions(t *testing.T) {
	ctx := context.Background()
	svc := NewTestServices(t)
	router := setupAdminBulkUserRouter(t, svc)

	acc := testEnv.CreateTestAccount(t, "abu-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	// Three end users in the app's user pool.
	mkUser := func(prefix string) *core.User {
		email := prefix + "-" + GenerateUniqueSlug("u") + "@example.com"
		u, _, err := testEnv.Repo.GetOrCreateUser(ctx, email, app, core.UserSourceRegistered)
		if err != nil {
			t.Fatalf("GetOrCreateUser(%s): %v", prefix, err)
		}
		t.Cleanup(func() {
			_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM client_sessions WHERE user_id = $1", u.ID)
			_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM attempts WHERE subject = $1", u.Email)
			_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", u.ID)
		})
		return u
	}
	u1 := mkUser("u1")
	u2 := mkUser("u2")
	u3 := mkUser("u3")

	bulkURL := fmt.Sprintf("/admin/workspace/%s/projects/%s/apps/%s/users:bulk",
		ws.ID, app.ProjectID, app.ID)

	post := func(t *testing.T, payload map[string]any) (*httptest.ResponseRecorder, bulkResp) {
		t.Helper()
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, bulkURL, bytes.NewReader(body))
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		var out bulkResp
		if rr.Code == http.StatusOK {
			if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
				t.Fatalf("decode response: %v (body=%s)", err, rr.Body.String())
			}
		}
		return rr, out
	}

	// (a) unlock: lock u1,u2 (SetUserLockedUntil + >=10 failed attempts each).
	const failedAttempts = 12
	for _, u := range []*core.User{u1, u2} {
		for i := 0; i < failedAttempts; i++ {
			if err := testEnv.Repo.InsertAttempt(ctx, "workspace_login_pw", u.Email, "127.0.0.1"); err != nil {
				t.Fatalf("InsertAttempt: %v", err)
			}
		}
		if err := testEnv.Repo.SetUserLockedUntil(ctx, u.ID, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("SetUserLockedUntil: %v", err)
		}
	}
	rr, out := post(t, map[string]any{
		"action":  "unlock",
		"userIds": []string{u1.ID.String(), u2.ID.String(), u3.ID.String()},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("(a) expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if out.Succeeded != 3 || out.Failed != 0 {
		t.Fatalf("(a) expected succeeded=3 failed=0, got %d/%d", out.Succeeded, out.Failed)
	}
	for _, u := range []*core.User{u1, u2} {
		reloaded, err := testEnv.Repo.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("(a) GetUserByID: %v", err)
		}
		if reloaded.LockedUntil != nil {
			t.Errorf("(a) %s LockedUntil should be nil, got %v", u.ID, *reloaded.LockedUntil)
		}
		cnt, err := testEnv.Repo.CountAttemptsBySubject(ctx, "workspace_login_pw", u.Email, time.Now().Add(-time.Hour))
		if err != nil {
			t.Fatalf("(a) CountAttemptsBySubject: %v", err)
		}
		if cnt != 0 {
			t.Errorf("(a) %s attempt counter should be 0 after unlock, got %d", u.ID, cnt)
		}
	}

	// (b) resetTotp: seed TOTP on u1, then bulk-reset.
	if err := testEnv.Repo.EnableUserTOTP(ctx, u1.ID, time.Now(), []byte("backupcodes")); err != nil {
		t.Fatalf("(b) EnableUserTOTP: %v", err)
	}
	rr, out = post(t, map[string]any{
		"action":  "resetTotp",
		"userIds": []string{u1.ID.String()},
	})
	if rr.Code != http.StatusOK || out.Succeeded != 1 {
		t.Fatalf("(b) expected 200 succeeded=1, got %d succeeded=%d: %s", rr.Code, out.Succeeded, rr.Body.String())
	}
	totpUser, err := testEnv.Repo.GetUserByIDWithTOTP(ctx, u1.ID)
	if err != nil {
		t.Fatalf("(b) GetUserByIDWithTOTP: %v", err)
	}
	if totpUser.HasTOTP() {
		t.Errorf("(b) u1 TOTP should be disabled after reset")
	}

	// (c) clearPassword: give u1 a password + a live session, then bulk-clear.
	if err := testEnv.Repo.UpdateUserPassword(ctx, u1.ID, "$2a$10$abcdefghijklmnopqrstuv", time.Now()); err != nil {
		t.Fatalf("(c) UpdateUserPassword: %v", err)
	}
	now := time.Now().UTC()
	aID := app.ID
	sessID := uuid.Must(uuid.NewV4())
	if err := testEnv.Repo.InsertClientSession(ctx, &core.ClientSession{
		ID: sessID, UserID: u1.ID, AppID: &aID, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("(c) InsertClientSession: %v", err)
	}
	rr, out = post(t, map[string]any{
		"action":  "clearPassword",
		"userIds": []string{u1.ID.String()},
	})
	if rr.Code != http.StatusOK || out.Succeeded != 1 {
		t.Fatalf("(c) expected 200 succeeded=1, got %d succeeded=%d: %s", rr.Code, out.Succeeded, rr.Body.String())
	}
	pwUser, err := testEnv.Repo.GetUserByIDWithTOTP(ctx, u1.ID)
	if err != nil {
		t.Fatalf("(c) reload: %v", err)
	}
	if pwUser.HasPassword() {
		t.Errorf("(c) u1 password should be cleared")
	}
	var sessCount int
	if err := testEnv.DB.Pool().QueryRow(ctx, "SELECT count(*) FROM client_sessions WHERE id = $1", sessID).Scan(&sessCount); err != nil {
		t.Fatalf("(c) count sessions: %v", err)
	}
	if sessCount != 0 {
		t.Errorf("(c) u1 session should be revoked, found %d", sessCount)
	}

	// (d) setStatus disable.
	rr, out = post(t, map[string]any{
		"action":  "setStatus",
		"userIds": []string{u1.ID.String()},
		"enabled": false,
	})
	if rr.Code != http.StatusOK || out.Succeeded != 1 {
		t.Fatalf("(d) expected 200 succeeded=1, got %d succeeded=%d: %s", rr.Code, out.Succeeded, rr.Body.String())
	}
	statUser, err := testEnv.Repo.GetUserByID(ctx, u1.ID)
	if err != nil {
		t.Fatalf("(d) reload: %v", err)
	}
	if statUser.Enabled {
		t.Errorf("(d) u1 should be disabled")
	}

	// (e) unknown action -> 400.
	rr, _ = post(t, map[string]any{
		"action":  "frobnicate",
		"userIds": []string{u1.ID.String()},
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("(e) expected 400, got %d", rr.Code)
	}

	// (f) over cap -> 400.
	tooMany := make([]string, 0, maxBatchUsersTestCap()+1)
	for i := 0; i < maxBatchUsersTestCap()+1; i++ {
		tooMany = append(tooMany, uuid.Must(uuid.NewV4()).String())
	}
	rr, _ = post(t, map[string]any{
		"action":  "unlock",
		"userIds": tooMany,
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("(f) expected 400, got %d", rr.Code)
	}

	// (g) foreign/unknown id -> partial success.
	rr, out = post(t, map[string]any{
		"action":  "unlock",
		"userIds": []string{u2.ID.String(), uuid.Must(uuid.NewV4()).String()},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("(g) expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if out.Succeeded != 1 || out.Failed != 1 {
		t.Fatalf("(g) expected succeeded=1 failed=1, got %d/%d", out.Succeeded, out.Failed)
	}
	foundForeignFail := false
	for _, res := range out.Results {
		if res.UserID != u2.ID.String() && !res.OK {
			foundForeignFail = true
		}
	}
	if !foundForeignFail {
		t.Errorf("(g) expected the foreign id result to have ok:false")
	}
}

// maxBatchUsersTestCap mirrors the api.maxBatchUsers cap (unexported) so the
// over-cap case can build a payload of cap+1 without importing the const.
func maxBatchUsersTestCap() int { return 100 }
