package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"manyrows-core/api"
	"manyrows-core/auth"
	"manyrows-core/auth/client"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/email"
	"manyrows-core/utils"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// setupMemberRolesRouter creates a router for member roles tests
func setupMemberRolesRouter(t *testing.T) *chi.Mux {
	t.Helper()

	cfg := GetTestConfig()
	adminAuthService, err := auth.NewAuthService(cfg, testEnv.Repo)
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}

	clientAuthService, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("failed to create client auth service: %v", err)
	}

	emailService := email.NewEmailService(true, nil)

	requestHandler := api.NewRequestHandler(
		testEnv.Repo,
		adminAuthService,
		clientAuthService,
		emailService,
		cfg,
		nil,
		nil,
	)

	r := chi.NewRouter()

	adminRouter := chi.NewRouter()
	adminRouter.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			acc, _, err := adminAuthService.GetLoggedInAccount(r)
			if err != nil || acc == nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			ctx := core.WithAdminAccount(r.Context(), acc)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	adminWorkspaceRouter := chi.NewRouter()
	adminWorkspaceRouter.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			acc, ok := core.AdminAccountFromContext(ctx)
			if !ok || acc == nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			wsIDStr := chi.URLParam(r, "workspaceId")
			wsID, err := uuid.FromString(wsIDStr)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
			ok, err = testEnv.Repo.IsWorkspaceOwner(ctx, wsID, acc.ID)
			if err != nil || !ok {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			ws, ok, err := testEnv.Repo.GetWorkspaceByID(ctx, wsID)
			if err != nil || !ok {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}
			ctx = core.WithWorkspace(ctx, ws)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	adminWorkspaceRouter.Get("/projects/{projectId}/memberRoles", requestHandler.HandleGetMemberRoles)
	adminWorkspaceRouter.Put("/projects/{projectId}/memberRoles/{userId}", requestHandler.HandlerUpdateMemberRoles)
	adminWorkspaceRouter.Get("/projects/{projectId}/members", requestHandler.HandleGetProjectMembers)
	adminWorkspaceRouter.Delete("/projects/{projectId}/members/{userId}", requestHandler.HandleRemoveProjectMember)

	adminRouter.Mount("/workspace/{workspaceId}", adminWorkspaceRouter)
	r.Mount("/admin", adminRouter)

	return r
}

// createTestRole creates a role for testing
func createTestRole(t *testing.T, projectID uuid.UUID) *core.Role {
	t.Helper()
	ctx := context.Background()

	slug := GenerateUniqueSlug("role")
	params := repo.CreateRoleParams{
		ProjectID: projectID,
		Name:      "test-role-" + slug,
		Slug:      slug,
		Now:       time.Now().UTC(),
	}

	role, err := testEnv.Repo.CreateRole(ctx, params)
	if err != nil {
		t.Fatalf("failed to create role: %v", err)
	}

	return &role
}

// TestGetMemberRoles_Success tests getting member roles for a project
func TestGetMemberRoles_Success(t *testing.T) {
	router := setupMemberRolesRouter(t)

	email := "member-roles-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/memberRoles", nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
}

// TestGetMemberRoles_Unauthenticated tests without auth
func TestGetMemberRoles_Unauthenticated(t *testing.T) {
	router := setupMemberRolesRouter(t)

	email := "member-roles-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/memberRoles", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// TestGetMemberRoles_NotFound tests getting member roles for non-existent project
func TestGetMemberRoles_NotFound(t *testing.T) {
	router := setupMemberRolesRouter(t)

	email := "member-roles-nf-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	fakeProjectID := uuid.Must(uuid.NewV4())
	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+fakeProjectID.String()+"/memberRoles", nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound && rr.Code != http.StatusForbidden {
		t.Errorf("expected status %d or %d, got %d: %s", http.StatusNotFound, http.StatusForbidden, rr.Code, rr.Body.String())
	}
}

// TestUpdateMemberRoles_Success tests updating member roles
func TestUpdateMemberRoles_Success(t *testing.T) {
	router := setupMemberRolesRouter(t)

	ownerEmail := "member-roles-owner-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, owner, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, owner)

	// Create an app so we can create a user with the new model
	appID := utils.NewUUID()
	ctx := context.Background()
	userPool, err := testEnv.Repo.CreateUserPool(ctx, ws.ID, "Pool "+GenerateUniqueSlug("p"))
	if err != nil {
		t.Fatalf("failed to create user pool: %v", err)
	}
	pool := testEnv.DB.Pool()
	_, err = pool.Exec(ctx, `
		INSERT INTO apps (id, workspace_id, project_id, user_pool_id, type, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'dev', true, NOW(), NOW())
	`, appID, ws.ID, project.ID, userPool.ID)
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	// Create a user (client app user) to update roles for
	memberEmail := "member-target-" + GenerateUniqueSlug("test") + "@example.com"
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, memberEmail, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	role := createTestRole(t, project.ID)

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM user_roles WHERE user_id = $1", user.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM roles WHERE id = $1", role.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM users WHERE id = $1", user.ID)
	}()

	body := map[string]any{
		// Handler requires appId in the body now ("env-scoped, no 'all envs'").
		"appId":   appID.String(),
		"roleIds": []string{role.ID.String()},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/memberRoles/"+user.ID.String(), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK && rr.Code != http.StatusNoContent {
		t.Errorf("expected status %d or %d, got %d: %s", http.StatusOK, http.StatusNoContent, rr.Code, rr.Body.String())
	}
}

// TestGetProjectMembers_Success tests getting project members
func TestGetProjectMembers_Success(t *testing.T) {
	router := setupMemberRolesRouter(t)

	email := "proj-members-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	appID := createTestApp(t, ws.ID, project.ID, uuid.Nil, "Members Test App")
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		_, _ = testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM apps WHERE id = $1", appID)
	}()

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/members?appId="+appID.String(), nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["members"] == nil {
		t.Error("expected members in response")
	}
}

// TestGetProjectMembers_Unauthenticated tests without auth
func TestGetProjectMembers_Unauthenticated(t *testing.T) {
	router := setupMemberRolesRouter(t)

	email := "proj-members-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/members", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// TestGetProjectMembers_NoAppId_AppScope tests that app-scoped projects require appId
func TestGetProjectMembers_NoAppId_AppScope(t *testing.T) {
	router := setupMemberRolesRouter(t)

	email := "proj-members-noapp-app-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	// No appId — app scope should reject
	req := httptest.NewRequest(http.MethodGet,
		"/admin/workspace/"+ws.ID.String()+"/projects/"+project.ID.String()+"/members",
		nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

// TestGetProjectMembers_NoAppId_ProjectScope tests that project-scoped projects
// can list members without appId (for autocomplete across all apps).

// removeMemberFixture builds ws+project+pool+app and a user that is a
// member of the app, with one role assigned and one active client
// session. Returns the ids + cleanup.
func removeMemberFixture(t *testing.T, emailPrefix string) (claims core.TokenClaims, wsID, projectID, appID, userID, roleID uuid.UUID, cleanup func()) {
	t.Helper()
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, emailPrefix+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "P", GenerateUniqueSlug("p"))
	_, claims = testEnv.CreateTestSession(t, acc)

	userPool, err := testEnv.Repo.CreateUserPool(ctx, ws.ID, "Pool "+GenerateUniqueSlug("p"))
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	appID = utils.NewUUID()
	db := testEnv.DB.Pool()
	if _, err := db.Exec(ctx, `
		INSERT INTO apps (id, workspace_id, project_id, user_pool_id, type, enabled, created_at, updated_at)
		VALUES ($1,$2,$3,$4,'dev',true,NOW(),NOW())`, appID, ws.ID, project.ID, userPool.ID); err != nil {
		t.Fatalf("create app: %v", err)
	}
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, acc.Email+".m", &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create member: %v", err)
	}
	role := createTestRole(t, project.ID)
	if err := testEnv.Repo.ReplaceUserRoles(ctx, repo.ReplaceUserRolesParams{
		ProjectID: project.ID, AppID: appID, UserID: user.ID,
		RoleIDs: []uuid.UUID{role.ID}, Now: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	now := time.Now().UTC()
	if err := testEnv.Repo.InsertClientSession(ctx, &core.ClientSession{
		ID: utils.NewUUID(), UserID: user.ID, AppID: &appID,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour),
		UserAgent: "test", IP: "127.0.0.1",
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	cleanup = func() {
		c := context.Background()
		_, _ = db.Exec(c, "DELETE FROM client_sessions WHERE user_id = $1", user.ID)
		_, _ = db.Exec(c, "DELETE FROM apps WHERE id = $1", appID)
		_, _ = db.Exec(c, "DELETE FROM users WHERE user_pool_id = $1", userPool.ID)
		_, _ = db.Exec(c, "DELETE FROM user_pools WHERE id = $1", userPool.ID)
		testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}})
	}
	return claims, ws.ID, project.ID, appID, user.ID, role.ID, cleanup
}

func countRows(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := testEnv.DB.Pool().QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("count (%s): %v", q, err)
	}
	return n
}

func TestRemoveProjectMember_Success(t *testing.T) {
	router := setupMemberRolesRouter(t)
	claims, wsID, projectID, appID, userID, _, cleanup := removeMemberFixture(t, "rpm-ok-")
	defer cleanup()

	req := httptest.NewRequest(http.MethodDelete,
		"/admin/workspace/"+wsID.String()+"/projects/"+projectID.String()+"/members/"+userID.String()+"?appId="+appID.String(), nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if n := countRows(t, "SELECT count(*) FROM app_users WHERE app_id=$1 AND user_id=$2", appID, userID); n != 0 {
		t.Errorf("membership should be gone, count=%d", n)
	}
	if n := countRows(t, "SELECT count(*) FROM user_roles WHERE app_id=$1 AND user_id=$2", appID, userID); n != 0 {
		t.Errorf("roles should be cleared, count=%d", n)
	}
	if n := countRows(t, "SELECT count(*) FROM client_sessions WHERE user_id=$1 AND app_id=$2", userID, appID); n != 0 {
		t.Errorf("sessions should be revoked, count=%d", n)
	}
	if n := countRows(t, "SELECT count(*) FROM users WHERE id=$1", userID); n != 0 {
		t.Errorf("orphaned pool account must be pruned when in no other app, count=%d", n)
	}
}

// TestRemoveProjectMember_PrunesOrphanReportsIt confirms the response signals
// that the pool identity was deleted, mirroring the server API.
func TestRemoveProjectMember_PrunesOrphanReportsIt(t *testing.T) {
	router := setupMemberRolesRouter(t)
	claims, wsID, projectID, appID, userID, _, cleanup := removeMemberFixture(t, "rpm-prune-")
	defer cleanup()

	req := httptest.NewRequest(http.MethodDelete,
		"/admin/workspace/"+wsID.String()+"/projects/"+projectID.String()+"/members/"+userID.String()+"?appId="+appID.String(), nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Removed         bool `json:"removed"`
		IdentityDeleted bool `json:"identityDeleted"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Removed {
		t.Errorf("expected removed=true")
	}
	if !resp.IdentityDeleted {
		t.Errorf("expected identityDeleted=true when user is in no other app")
	}
}

// TestRemoveProjectMember_KeepsIdentityWhenInOtherApp verifies the orphan
// prune does NOT fire when the user still belongs to another app sharing the
// pool: the per-app membership is dropped but the pool identity survives.
func TestRemoveProjectMember_KeepsIdentityWhenInOtherApp(t *testing.T) {
	router := setupMemberRolesRouter(t)
	claims, wsID, projectID, appID, userID, _, cleanup := removeMemberFixture(t, "rpm-multi-")
	defer cleanup()
	ctx := context.Background()

	// Add a second app in the same pool and make the user a member of it too.
	var poolID uuid.UUID
	if err := testEnv.DB.Pool().QueryRow(ctx, `SELECT user_pool_id FROM users WHERE id=$1`, userID).Scan(&poolID); err != nil {
		t.Fatalf("read pool: %v", err)
	}
	// 'staging' (the fixture app is 'dev') — apps are unique per (project, type).
	app2ID := utils.NewUUID()
	if _, err := testEnv.DB.Pool().Exec(ctx, `
		INSERT INTO apps (id, workspace_id, project_id, user_pool_id, type, enabled, created_at, updated_at)
		VALUES ($1,$2,$3,$4,'staging',true,NOW(),NOW())`, app2ID, wsID, projectID, poolID); err != nil {
		t.Fatalf("create app2: %v", err)
	}
	defer func() {
		c := context.Background()
		_, _ = testEnv.DB.Pool().Exec(c, "DELETE FROM app_users WHERE app_id=$1", app2ID)
		_, _ = testEnv.DB.Pool().Exec(c, "DELETE FROM apps WHERE id=$1", app2ID)
	}()
	if _, _, err := testEnv.Repo.EnsureAppMember(ctx, app2ID, userID, core.UserSourceInvited); err != nil {
		t.Fatalf("add to app2: %v", err)
	}

	// Remove from the first app only.
	req := httptest.NewRequest(http.MethodDelete,
		"/admin/workspace/"+wsID.String()+"/projects/"+projectID.String()+"/members/"+userID.String()+"?appId="+appID.String(), nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if n := countRows(t, "SELECT count(*) FROM app_users WHERE app_id=$1 AND user_id=$2", appID, userID); n != 0 {
		t.Errorf("membership in removed app should be gone, count=%d", n)
	}
	if n := countRows(t, "SELECT count(*) FROM app_users WHERE app_id=$1 AND user_id=$2", app2ID, userID); n != 1 {
		t.Errorf("membership in the other app must remain, count=%d", n)
	}
	if n := countRows(t, "SELECT count(*) FROM users WHERE id=$1", userID); n != 1 {
		t.Errorf("pool identity must be preserved while still in another app, count=%d", n)
	}
}

func TestRemoveProjectMember_Idempotent(t *testing.T) {
	router := setupMemberRolesRouter(t)
	claims, wsID, projectID, appID, userID, _, cleanup := removeMemberFixture(t, "rpm-idem-")
	defer cleanup()

	path := "/admin/workspace/" + wsID.String() + "/projects/" + projectID.String() + "/members/" + userID.String() + "?appId=" + appID.String()
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodDelete, path, nil)
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("call %d: expected 200 (idempotent), got %d: %s", i, rr.Code, rr.Body.String())
		}
	}
}

func TestRemoveProjectMember_MissingAppId(t *testing.T) {
	router := setupMemberRolesRouter(t)
	claims, wsID, projectID, _, userID, _, cleanup := removeMemberFixture(t, "rpm-noapp-")
	defer cleanup()

	req := httptest.NewRequest(http.MethodDelete,
		"/admin/workspace/"+wsID.String()+"/projects/"+projectID.String()+"/members/"+userID.String(), nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without appId, got %d: %s", rr.Code, rr.Body.String())
	}
}
