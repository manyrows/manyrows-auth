package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

/*
Tests for the pool-admin surface:

  - Repo: ListUserPoolsByWorkspaceWithStats, RenameUserPool,
    DeleteUserPool (with in-use refusal), CountAppsByUserPool,
    CountAppMembers, UpdateAppUserPool.

  - HTTP: create / list / rename / delete / repoint, plus the
    cross-workspace + in-use edges that the audit pass tightened.
*/

// ---- Repo-level ----

func TestPoolStats_CountsAppsAndUsers(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "ps-stats-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	// Seed one user in the app's pool with membership.
	email := "stats-" + GenerateUniqueSlug("u") + "@example.com"
	if _, _, err := testEnv.GetOrCreateUserWithMembership(ctx, email, app, core.UserSourceInvited); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	pools, err := testEnv.Repo.ListUserPoolsByWorkspaceWithStats(ctx, ws.ID)
	if err != nil {
		t.Fatalf("ListUserPoolsByWorkspaceWithStats: %v", err)
	}
	// Find this app's pool in the workspace list.
	var found *repo.UserPoolWithStats
	for i := range pools {
		if pools[i].ID == app.UserPoolID {
			found = &pools[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected pool %s in workspace list; got %d pools", app.UserPoolID, len(pools))
	}
	if found.AppCount != 1 {
		t.Errorf("expected appCount=1, got %d", found.AppCount)
	}
	if found.UserCount != 1 {
		t.Errorf("expected userCount=1, got %d", found.UserCount)
	}
}

func TestRenameUserPool_HappyPathAndCollision(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "ps-ren-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	a, err := testEnv.Repo.CreateUserPool(ctx, ws.ID, "alpha-"+GenerateUniqueSlug("p"))
	if err != nil {
		t.Fatalf("create a: %v", err)
	}
	b, err := testEnv.Repo.CreateUserPool(ctx, ws.ID, "beta-"+GenerateUniqueSlug("p"))
	if err != nil {
		t.Fatalf("create b: %v", err)
	}

	newName := "alpha-renamed-" + GenerateUniqueSlug("p")
	if _, err := testEnv.Repo.RenameUserPool(ctx, ws.ID, a.ID, newName); err != nil {
		t.Fatalf("rename a: %v", err)
	}

	// Renaming b to a's new name collides (workspace_id, name unique).
	_, err = testEnv.Repo.RenameUserPool(ctx, ws.ID, b.ID, newName)
	if err == nil || !repo.IsUniqueViolation(err) {
		t.Fatalf("expected unique-violation on collision; got %v", err)
	}

	// Renaming a pool that doesn't exist for this workspace returns ErrNotFound.
	_, err = testEnv.Repo.RenameUserPool(ctx, ws.ID, utils.NewUUID(), "anything")
	if !errors.Is(err, repo.ErrNotFound) {
		t.Errorf("expected ErrNotFound for unknown id; got %v", err)
	}
}

func TestDeleteUserPool_RefusesWhenInUse(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "ps-del-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc) // auto-creates a pool for the app
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	// The pool the app points at can't be deleted while the app exists.
	err := testEnv.Repo.DeleteUserPool(ctx, ws.ID, app.UserPoolID)
	if !errors.Is(err, repo.ErrPoolInUse) {
		t.Fatalf("expected ErrPoolInUse, got %v", err)
	}

	// An empty pool deletes cleanly.
	empty, err := testEnv.Repo.CreateUserPool(ctx, ws.ID, "empty-"+GenerateUniqueSlug("p"))
	if err != nil {
		t.Fatalf("create empty: %v", err)
	}
	if err := testEnv.Repo.DeleteUserPool(ctx, ws.ID, empty.ID); err != nil {
		t.Fatalf("delete empty pool: %v", err)
	}
	if _, err := testEnv.Repo.GetUserPoolByID(ctx, empty.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Errorf("expected ErrNotFound for deleted pool; got %v", err)
	}
}

func TestCountAppMembers_TracksMembership(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "ps-cnt-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	if n, err := testEnv.Repo.CountAppMembers(ctx, app.ID); err != nil || n != 0 {
		t.Fatalf("expected 0 members, got n=%d err=%v", n, err)
	}
	if _, _, err := testEnv.GetOrCreateUserWithMembership(ctx,
		"m1-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited); err != nil {
		t.Fatalf("seed m1: %v", err)
	}
	if _, _, err := testEnv.GetOrCreateUserWithMembership(ctx,
		"m2-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited); err != nil {
		t.Fatalf("seed m2: %v", err)
	}
	if n, err := testEnv.Repo.CountAppMembers(ctx, app.ID); err != nil || n != 2 {
		t.Errorf("expected 2 members, got n=%d err=%v", n, err)
	}
}

func TestUpdateAppUserPool_ChangesScope(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "ps-upd-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	newPool, err := testEnv.Repo.CreateUserPool(ctx, ws.ID, "target-"+GenerateUniqueSlug("p"))
	if err != nil {
		t.Fatalf("create target pool: %v", err)
	}
	if err := testEnv.Repo.UpdateAppUserPool(ctx, ws.ID, app.ID, newPool.ID); err != nil {
		t.Fatalf("UpdateAppUserPool: %v", err)
	}
	reloaded, err := testEnv.Repo.GetAppByID(ctx, app.ID)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}
	if reloaded.UserPoolID != newPool.ID {
		t.Errorf("expected pool %s, got %s", newPool.ID, reloaded.UserPoolID)
	}

	// Foreign workspace can't move it.
	otherAcc := testEnv.CreateTestAccount(t, "ps-other-"+GenerateUniqueSlug("u")+"@example.com")
	otherWs := testEnv.CreateTestWorkspace(t, otherAcc, "OtherWS", GenerateUniqueSlug("ws"))
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: otherAcc, Workspace: otherWs})
	err = testEnv.Repo.UpdateAppUserPool(ctx, otherWs.ID, app.ID, newPool.ID)
	if !errors.Is(err, repo.ErrNotFound) {
		t.Errorf("expected ErrNotFound for cross-workspace repoint, got %v", err)
	}
}

// ---- HTTP-level ----

func setupUserPoolsRouter(t *testing.T) *chi.Mux {
	t.Helper()
	svc := NewTestServices(t)
	r, ws := NewAdminWorkspaceRouter(t, svc)

	ws.Get("/userPools", svc.Handler.HandleListUserPools)
	ws.Post("/userPools", svc.Handler.HandleCreateUserPool)
	ws.Patch("/userPools/{poolId}", svc.Handler.HandleUpdateUserPool)
	ws.Delete("/userPools/{poolId}", svc.Handler.HandleDeleteUserPool)
	ws.Delete("/userPools/{poolId}/orphan-users", svc.Handler.HandleDeletePoolOrphanUsers)
	ws.Delete("/userPools/{poolId}/users/{userId}", svc.Handler.HandleDeletePoolUser)

	// Repoint lives under /projects/{projectId}/apps/{appId}/userPool
	ws.Post("/projects/{projectId}/apps/{appId}/userPool", svc.Handler.HandleRepointAppUserPool)
	return r
}

func adminGet(t *testing.T, router *chi.Mux, path string, claims core.TokenClaims) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func adminJSON(t *testing.T, router *chi.Mux, method, path string, body any, claims core.TokenClaims) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader([]byte{})
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func TestHandleCreateAndListUserPools(t *testing.T) {
	router := setupUserPoolsRouter(t)

	acc := testEnv.CreateTestAccount(t, "ph-list-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	_, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	name := "ph-pool-" + GenerateUniqueSlug("p")
	rr := adminJSON(t, router, http.MethodPost,
		"/admin/workspace/"+ws.ID.String()+"/userPools",
		map[string]any{"name": name}, claims)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = adminGet(t, router, "/admin/workspace/"+ws.ID.String()+"/userPools", claims)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var list struct {
		Pools []repo.UserPoolWithStats `json:"pools"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	found := false
	for _, p := range list.Pools {
		if p.Name == name {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("created pool %q not in list response", name)
	}
}

func TestHandleCreateUserPool_DuplicateReturns409(t *testing.T) {
	router := setupUserPoolsRouter(t)

	acc := testEnv.CreateTestAccount(t, "ph-dup-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	_, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	name := "dup-pool-" + GenerateUniqueSlug("p")
	if rr := adminJSON(t, router, http.MethodPost,
		"/admin/workspace/"+ws.ID.String()+"/userPools",
		map[string]any{"name": name}, claims); rr.Code != http.StatusCreated {
		t.Fatalf("first create failed: %d %s", rr.Code, rr.Body.String())
	}
	rr := adminJSON(t, router, http.MethodPost,
		"/admin/workspace/"+ws.ID.String()+"/userPools",
		map[string]any{"name": name}, claims)
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409 on duplicate, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleDeleteUserPool_RefusesWhenInUse(t *testing.T) {
	router := setupUserPoolsRouter(t)

	acc := testEnv.CreateTestAccount(t, "ph-deluse-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	_, claims := testEnv.CreateTestSession(t, acc)
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	rr := adminJSON(t, router, http.MethodDelete,
		"/admin/workspace/"+ws.ID.String()+"/userPools/"+app.UserPoolID.String(),
		nil, claims)
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409 deleting in-use pool, got %d: %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["code"] != "poolInUse" {
		t.Errorf("expected code=poolInUse in response, got %v", body)
	}
}

func TestHandleDeleteUserPool_CrossWorkspaceForbidden(t *testing.T) {
	router := setupUserPoolsRouter(t)

	owner := testEnv.CreateTestAccount(t, "ph-xws-own-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, owner, "Owner", GenerateUniqueSlug("ws"))
	_ = testEnv.CreateTestApp(t, ws, owner) // pool exists in ws

	attacker := testEnv.CreateTestAccount(t, "ph-xws-att-"+GenerateUniqueSlug("u")+"@example.com")
	otherWs := testEnv.CreateTestWorkspace(t, attacker, "Attacker", GenerateUniqueSlug("ws"))
	_, attackerClaims := testEnv.CreateTestSession(t, attacker)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: owner, Workspace: ws})
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: attacker, Workspace: otherWs})

	// List ws's pools (using owner) to grab the id; we deliberately
	// don't expose ws's session to the attacker.
	pools, err := testEnv.Repo.ListUserPoolsByWorkspaceWithStats(context.Background(), ws.ID)
	if err != nil || len(pools) == 0 {
		t.Fatalf("seed pool fetch failed: %v / %d", err, len(pools))
	}
	target := pools[0].ID

	// Attacker tries to delete owner's pool through their own workspace
	// path. The route is workspace-scoped, so the pool isn't visible
	// inside attacker's workspace; expect 404, not 200/409.
	rr := adminJSON(t, router, http.MethodDelete,
		"/admin/workspace/"+otherWs.ID.String()+"/userPools/"+target.String(),
		nil, attackerClaims)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 cross-workspace delete, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRepointAppUserPool_BlocksWhenAppHasMembers(t *testing.T) {
	router := setupUserPoolsRouter(t)

	acc := testEnv.CreateTestAccount(t, "ph-rep-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	_, claims := testEnv.CreateTestSession(t, acc)
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	// Seed one member so the app is non-empty.
	if _, _, err := testEnv.GetOrCreateUserWithMembership(context.Background(),
		"r-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited); err != nil {
		t.Fatalf("seed member: %v", err)
	}

	target, err := testEnv.Repo.CreateUserPool(context.Background(), ws.ID, "target-"+GenerateUniqueSlug("p"))
	if err != nil {
		t.Fatalf("create target pool: %v", err)
	}

	rr := adminJSON(t, router, http.MethodPost,
		"/admin/workspace/"+ws.ID.String()+"/projects/"+app.ProjectID.String()+"/apps/"+app.ID.String()+"/userPool",
		map[string]any{"userPoolId": target.ID.String()}, claims)
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409 (app has members), got %d: %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["code"] != "appHasMembers" {
		t.Errorf("expected code=appHasMembers, got %v", body)
	}
}

func TestHandleRepointAppUserPool_SucceedsWhenEmpty(t *testing.T) {
	router := setupUserPoolsRouter(t)

	acc := testEnv.CreateTestAccount(t, "ph-repok-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	_, claims := testEnv.CreateTestSession(t, acc)
	app := testEnv.CreateTestApp(t, ws, acc) // no members
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	target, err := testEnv.Repo.CreateUserPool(context.Background(), ws.ID, "target-"+GenerateUniqueSlug("p"))
	if err != nil {
		t.Fatalf("create target pool: %v", err)
	}

	rr := adminJSON(t, router, http.MethodPost,
		"/admin/workspace/"+ws.ID.String()+"/projects/"+app.ProjectID.String()+"/apps/"+app.ID.String()+"/userPool",
		map[string]any{"userPoolId": target.ID.String()}, claims)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on empty-app repoint, got %d: %s", rr.Code, rr.Body.String())
	}

	reloaded, err := testEnv.Repo.GetAppByID(context.Background(), app.ID)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}
	if reloaded.UserPoolID != target.ID {
		t.Errorf("expected pool %s after repoint, got %s", target.ID, reloaded.UserPoolID)
	}
}

func TestHandleRepointAppUserPool_TargetPoolCrossWorkspaceReturns404(t *testing.T) {
	router := setupUserPoolsRouter(t)

	// Caller workspace.
	acc := testEnv.CreateTestAccount(t, "ph-rep-xws-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	_, claims := testEnv.CreateTestSession(t, acc)
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	// A pool that lives in someone else's workspace.
	other := testEnv.CreateTestAccount(t, "ph-rep-other-"+GenerateUniqueSlug("u")+"@example.com")
	otherWs := testEnv.CreateTestWorkspace(t, other, "OtherWS", GenerateUniqueSlug("ws"))
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: other, Workspace: otherWs})

	foreign, err := testEnv.Repo.CreateUserPool(context.Background(), otherWs.ID, "foreign-"+GenerateUniqueSlug("p"))
	if err != nil {
		t.Fatalf("create foreign pool: %v", err)
	}

	rr := adminJSON(t, router, http.MethodPost,
		"/admin/workspace/"+ws.ID.String()+"/projects/"+app.ProjectID.String()+"/apps/"+app.ID.String()+"/userPool",
		map[string]any{"userPoolId": foreign.ID.String()}, claims)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for foreign target pool, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRepointAppUserPool_ForeignAppDoesntLeakMemberCount(t *testing.T) {
	// Audit regression: the handler used to count members by app id
	// without scoping to the workspace, so a 409 response would expose
	// the foreign app's memberCount. With adminAndProject +
	// GetAppByIDForProject the foreign id 404s before we read counts.
	router := setupUserPoolsRouter(t)

	owner := testEnv.CreateTestAccount(t, "ph-leak-own-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, owner, "Owner", GenerateUniqueSlug("ws"))
	ownerApp := testEnv.CreateTestApp(t, ws, owner)
	if _, _, err := testEnv.GetOrCreateUserWithMembership(context.Background(),
		"leak-"+GenerateUniqueSlug("u")+"@example.com", ownerApp, core.UserSourceInvited); err != nil {
		t.Fatalf("seed owner member: %v", err)
	}
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: owner, Workspace: ws})

	attacker := testEnv.CreateTestAccount(t, "ph-leak-att-"+GenerateUniqueSlug("u")+"@example.com")
	otherWs := testEnv.CreateTestWorkspace(t, attacker, "Attacker", GenerateUniqueSlug("ws"))
	_, attackerClaims := testEnv.CreateTestSession(t, attacker)
	// Give the attacker a real project so the URL parses, but the
	// ownerApp id below doesn't belong to it.
	otherProject := testEnv.CreateTestProject(t, otherWs, attacker, "AttProj", GenerateUniqueSlug("proj"))
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: attacker, Workspace: otherWs})

	target, err := testEnv.Repo.CreateUserPool(context.Background(), otherWs.ID, "att-target-"+GenerateUniqueSlug("p"))
	if err != nil {
		t.Fatalf("create attacker pool: %v", err)
	}

	rr := adminJSON(t, router, http.MethodPost,
		"/admin/workspace/"+otherWs.ID.String()+"/projects/"+otherProject.ID.String()+"/apps/"+ownerApp.ID.String()+"/userPool",
		map[string]any{"userPoolId": target.ID.String()}, attackerClaims)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for foreign app id, got %d: %s", rr.Code, rr.Body.String())
	}
	if bytes.Contains(rr.Body.Bytes(), []byte("memberCount")) {
		t.Errorf("response must not include memberCount for a foreign app id: %s", rr.Body.String())
	}
}

// poolUserFixture spins up ws+project+pool+app and a user. When
// withApp is false the membership is removed so the user is a pool
// orphan (the deletable case). Returns ids + a cleanup func.
func poolUserFixture(t *testing.T, email string, withApp bool) (claims core.TokenClaims, wsID, poolID, appID, userID uuid.UUID, cleanup func()) {
	t.Helper()
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, email)
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
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, email, &core.App{ID: appID}, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if !withApp {
		if err := testEnv.Repo.DeleteAppMember(ctx, appID, user.ID); err != nil {
			t.Fatalf("detach membership: %v", err)
		}
	}
	cleanup = func() {
		c := context.Background()
		_, _ = db.Exec(c, "DELETE FROM apps WHERE id = $1", appID)
		_, _ = db.Exec(c, "DELETE FROM users WHERE user_pool_id = $1", userPool.ID)
		_, _ = db.Exec(c, "DELETE FROM user_pools WHERE id = $1", userPool.ID)
		testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}})
	}
	return claims, ws.ID, userPool.ID, appID, user.ID, cleanup
}

func userRowCount(t *testing.T, userID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testEnv.DB.Pool().QueryRow(context.Background(), "SELECT count(*) FROM users WHERE id = $1", userID).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	return n
}

func TestDeletePoolUser_Success(t *testing.T) {
	router := setupUserPoolsRouter(t)
	claims, wsID, poolID, _, userID, cleanup := poolUserFixture(t, "pu-del-"+GenerateUniqueSlug("u")+"@example.com", false)
	defer cleanup()

	rr := adminJSON(t, router, http.MethodDelete,
		"/admin/workspace/"+wsID.String()+"/userPools/"+poolID.String()+"/users/"+userID.String(), nil, claims)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := userRowCount(t, userID); got != 0 {
		t.Errorf("user row should be gone, found %d", got)
	}
}

func TestDeletePoolUser_BlockedWhenInApp(t *testing.T) {
	router := setupUserPoolsRouter(t)
	claims, wsID, poolID, _, userID, cleanup := poolUserFixture(t, "pu-blk-"+GenerateUniqueSlug("u")+"@example.com", true)
	defer cleanup()

	rr := adminJSON(t, router, http.MethodDelete,
		"/admin/workspace/"+wsID.String()+"/userPools/"+poolID.String()+"/users/"+userID.String(), nil, claims)
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("userInApps")) {
		t.Errorf("expected userInApps code, got: %s", rr.Body.String())
	}
	if got := userRowCount(t, userID); got != 1 {
		t.Errorf("user must survive a blocked delete, count=%d", got)
	}
}

func TestDeletePoolUser_WrongPoolScope(t *testing.T) {
	router := setupUserPoolsRouter(t)
	claims, wsID, _, _, userID, cleanup := poolUserFixture(t, "pu-scope-"+GenerateUniqueSlug("u")+"@example.com", false)
	defer cleanup()

	// Real-looking but unrelated pool id → user.user_pool_id mismatch / pool not in ws.
	otherPool := uuid.Must(uuid.NewV4())
	rr := adminJSON(t, router, http.MethodDelete,
		"/admin/workspace/"+wsID.String()+"/userPools/"+otherPool.String()+"/users/"+userID.String(), nil, claims)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for wrong pool, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := userRowCount(t, userID); got != 1 {
		t.Errorf("user must not be deleted via a foreign pool id, count=%d", got)
	}
}

// Covers the user.UserPoolID != poolID branch with a REAL second pool
// in the SAME workspace (the random-uuid test above only exercises the
// GetUserPoolByID-not-found branch). This guard is what stops an admin
// deleting any user in their workspace by passing a pool id they own.
func TestDeletePoolUser_ForeignPoolSameWorkspace(t *testing.T) {
	router := setupUserPoolsRouter(t)
	claims, wsID, _, _, userID, cleanup := poolUserFixture(t, "pu-fpool-"+GenerateUniqueSlug("u")+"@example.com", false)
	defer cleanup()

	// A second, real pool in the same workspace (passes the
	// pool∈workspace check) — but the user does not live in it.
	poolB, err := testEnv.Repo.CreateUserPool(context.Background(), wsID, "Pool B "+GenerateUniqueSlug("p"))
	if err != nil {
		t.Fatalf("create pool B: %v", err)
	}
	defer func() {
		_, _ = testEnv.DB.Pool().Exec(context.Background(), "DELETE FROM user_pools WHERE id = $1", poolB.ID)
	}()

	rr := adminJSON(t, router, http.MethodDelete,
		"/admin/workspace/"+wsID.String()+"/userPools/"+poolB.ID.String()+"/users/"+userID.String(), nil, claims)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 (user not in pool B), got %d: %s", rr.Code, rr.Body.String())
	}
	if got := userRowCount(t, userID); got != 1 {
		t.Errorf("user must not be deleted via a foreign (same-ws) pool id, count=%d", got)
	}
}

func TestDeletePoolOrphanUsers_Success(t *testing.T) {
	router := setupUserPoolsRouter(t)
	ctx := context.Background()

	// Fixture gives us a pool + app + one MEMBER user (withApp=true).
	claims, wsID, poolID, appID, memberID, cleanup := poolUserFixture(t, "po-mem-"+GenerateUniqueSlug("u")+"@example.com", true)
	defer cleanup()

	// Add two more users to the same app, then detach → orphans.
	var orphanIDs []uuid.UUID
	for i := 0; i < 2; i++ {
		em := "po-orph-" + GenerateUniqueSlug("u") + "@example.com"
		u, _, err := testEnv.GetOrCreateUserWithMembership(ctx, em, &core.App{ID: appID}, core.UserSourceInvited)
		if err != nil {
			t.Fatalf("create orphan: %v", err)
		}
		if err := testEnv.Repo.DeleteAppMember(ctx, appID, u.ID); err != nil {
			t.Fatalf("detach orphan: %v", err)
		}
		orphanIDs = append(orphanIDs, u.ID)
	}

	rr := adminJSON(t, router, http.MethodDelete,
		"/admin/workspace/"+wsID.String()+"/userPools/"+poolID.String()+"/orphan-users", nil, claims)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Deleted int `json:"deleted"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Deleted != 2 {
		t.Errorf("expected deleted=2, got %d (%s)", resp.Deleted, rr.Body.String())
	}
	for _, id := range orphanIDs {
		if got := userRowCount(t, id); got != 0 {
			t.Errorf("orphan %s should be gone, count=%d", id, got)
		}
	}
	if got := userRowCount(t, memberID); got != 1 {
		t.Errorf("app member must NOT be purged, count=%d", got)
	}
}
