package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/core"
	"manyrows-core/utils"
)

func TestServerRemoveUser_AnonymizesAuthLogs(t *testing.T) {
	router := setupServerAPIRouter(t)
	ctx := context.Background()

	emailAddr := "srv-" + GenerateUniqueSlug("t") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "SRV WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() { _, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID) })

	// Seed an auth_log with the user's IP so we can prove anonymization.
	_, _ = testEnv.DB.Pool().Exec(ctx, `
		INSERT INTO auth_logs (id, workspace_id, app_id, event, outcome, actor_type, subject_user_id, email_attempted, ip, user_agent)
		VALUES ($1,$2,$3,'login.password','success','self',$4,$5,'203.0.113.4'::inet,'srv-agent')`,
		utils.NewUUID(), ws.ID, app.ID, user.ID, emailAddr)

	path := "/x/" + ws.Slug + "/api/v1/apps/" + app.ID.String() + "/users/" + user.ID.String()
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// User gone AND its auth_log row anonymized (ip nulled).
	var cnt int
	_ = testEnv.DB.Pool().QueryRow(ctx, "SELECT count(*) FROM users WHERE id = $1", user.ID).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("user not removed")
	}
	var ipNonNull int
	_ = testEnv.DB.Pool().QueryRow(ctx,
		"SELECT count(*) FROM auth_logs WHERE workspace_id = $1 AND lower(email_attempted) = lower($2) AND ip IS NOT NULL",
		ws.ID, emailAddr).Scan(&ipNonNull)
	if ipNonNull != 0 {
		t.Fatalf("auth_log not anonymized after server remove")
	}
}
