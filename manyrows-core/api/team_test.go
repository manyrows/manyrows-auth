package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"manyrows-core/api"
	"manyrows-core/auth"
	"manyrows-core/auth/client"
	"manyrows-core/core"
	"manyrows-core/email"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// setupTeamRouter creates a router for team endpoint tests.
// Uses GetWorkspaceAdminRole + WithWorkspaceRole so that requireOwner works.
func setupTeamRouter(t *testing.T) *chi.Mux {
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
			role, found, err := testEnv.Repo.GetWorkspaceAdminRole(ctx, wsID, acc.ID)
			if err != nil || !found {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			ws, ok, err := testEnv.Repo.GetWorkspaceByID(ctx, wsID)
			if err != nil || !ok {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}
			ctx = core.WithWorkspace(ctx, ws)
			ctx = core.WithWorkspaceRole(ctx, role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	adminWorkspaceRouter.Get("/team", requestHandler.HandleListTeamMembers)
	adminWorkspaceRouter.Post("/team", requestHandler.HandleAddTeamMember)
	adminWorkspaceRouter.Delete("/team/{accountId}", requestHandler.HandleRemoveTeamMember)
	adminWorkspaceRouter.Get("/team/invites", requestHandler.HandleListTeamInvites)
	adminWorkspaceRouter.Delete("/team/invites/{inviteId}", requestHandler.HandleCancelTeamInvite)

	adminRouter.Mount("/workspace/{workspaceId}", adminWorkspaceRouter)
	r.Mount("/admin", adminRouter)

	return r
}

// teamCleanup helper to remove workspace_admins and team_invites rows added during tests
func teamCleanup(t *testing.T, wsID uuid.UUID, extraAccountIDs ...uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	pool := testEnv.DB.Pool()
	for _, accID := range extraAccountIDs {
		_, _ = pool.Exec(ctx, "DELETE FROM workspace_admins WHERE workspace_id = $1 AND account_id = $2", wsID, accID)
	}
	_, _ = pool.Exec(ctx, "DELETE FROM team_invites WHERE workspace_id = $1", wsID)
}

// --- List team members ---

func TestListTeamMembers_OwnerSuccess(t *testing.T) {
	router := setupTeamRouter(t)

	ownerEmail := "team-list-owner-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, owner)

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/team", nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	members, ok := resp["members"].([]any)
	if !ok {
		t.Fatalf("expected members array, got %T", resp["members"])
	}
	if len(members) != 1 {
		t.Errorf("expected 1 member (owner), got %d", len(members))
	}

	callerRole, _ := resp["callerRole"].(string)
	if callerRole != "owner" {
		t.Errorf("expected callerRole 'owner', got %q", callerRole)
	}
}

func TestListTeamMembers_AdminSuccess(t *testing.T) {
	router := setupTeamRouter(t)

	ownerEmail := "team-list-admin-owner-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))

	adminEmail := "team-list-admin-" + GenerateUniqueSlug("test") + "@example.com"
	adminAcc := testEnv.CreateTestAccount(t, adminEmail)
	adminSess, adminClaims := testEnv.CreateTestSession(t, adminAcc)

	// AddFieldIssue admin to workspace
	err := testEnv.Repo.AddWorkspaceAdmin(context.Background(), core.WorkspaceAdmin{
		WorkspaceID: ws.ID,
		AccountID:   adminAcc.ID,
		Role:        "admin",
		AddedBy:     &owner.ID,
	})
	if err != nil {
		t.Fatalf("failed to add admin: %v", err)
	}

	fixtures := &TestFixtures{Account: owner, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		teamCleanup(t, ws.ID, adminAcc.ID)
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", adminSess.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", adminAcc.ID)
	}()

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/team", nil)
	testEnv.SetSessionCookie(t, req, adminClaims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	members, ok := resp["members"].([]any)
	if !ok {
		t.Fatalf("expected members array")
	}
	if len(members) != 2 {
		t.Errorf("expected 2 members (owner + admin), got %d", len(members))
	}

	callerRole, _ := resp["callerRole"].(string)
	if callerRole != "admin" {
		t.Errorf("expected callerRole 'admin', got %q", callerRole)
	}
}

// --- AddFieldIssue team member ---

func TestAddTeamMember_OwnerSuccess(t *testing.T) {
	router := setupTeamRouter(t)

	ownerEmail := "team-add-owner-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, owner)

	targetEmail := "team-add-target-" + GenerateUniqueSlug("test") + "@example.com"
	targetAcc := testEnv.CreateTestAccount(t, targetEmail)

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		teamCleanup(t, ws.ID, targetAcc.ID)
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", targetAcc.ID)
	}()

	body, _ := json.Marshal(map[string]any{"email": targetEmail})
	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/team", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	// Existing account — should be added directly, not invited
	if resp["invited"] == true {
		t.Error("expected invited to be absent/false for existing account")
	}

	// Verify the member was added
	role, found, err := testEnv.Repo.GetWorkspaceAdminRole(context.Background(), ws.ID, targetAcc.ID)
	if err != nil {
		t.Fatalf("failed to check role: %v", err)
	}
	if !found {
		t.Fatal("expected target to be a workspace admin")
	}
	if role != "admin" {
		t.Errorf("expected role 'admin', got %q", role)
	}
}

func TestAddTeamMember_ForbiddenForAdmin(t *testing.T) {
	router := setupTeamRouter(t)

	ownerEmail := "team-add-forbid-owner-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))

	adminEmail := "team-add-forbid-admin-" + GenerateUniqueSlug("test") + "@example.com"
	adminAcc := testEnv.CreateTestAccount(t, adminEmail)
	adminSess, adminClaims := testEnv.CreateTestSession(t, adminAcc)

	err := testEnv.Repo.AddWorkspaceAdmin(context.Background(), core.WorkspaceAdmin{
		WorkspaceID: ws.ID,
		AccountID:   adminAcc.ID,
		Role:        "admin",
		AddedBy:     &owner.ID,
	})
	if err != nil {
		t.Fatalf("failed to add admin: %v", err)
	}

	fixtures := &TestFixtures{Account: owner, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		teamCleanup(t, ws.ID, adminAcc.ID)
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", adminSess.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", adminAcc.ID)
	}()

	body, _ := json.Marshal(map[string]any{"email": "anyone@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/team", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, adminClaims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAddTeamMember_InviteWhenNoAccount(t *testing.T) {
	router := setupTeamRouter(t)

	ownerEmail := "team-invite-owner-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, owner)

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	inviteEmail := "nonexistent-" + GenerateUniqueSlug("test") + "@example.com"
	body, _ := json.Marshal(map[string]any{"email": inviteEmail})
	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/team", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["invited"] != true {
		t.Errorf("expected invited=true, got %v", resp["invited"])
	}

	// Verify a pending invite was created
	has, err := testEnv.Repo.HasPendingInvite(context.Background(), ws.ID, inviteEmail)
	if err != nil {
		t.Fatalf("HasPendingInvite failed: %v", err)
	}
	if !has {
		t.Error("expected a pending invite to exist")
	}
}

func TestAddTeamMember_AlreadyInvited(t *testing.T) {
	router := setupTeamRouter(t)

	ownerEmail := "team-dup-invite-owner-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, owner)

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	inviteEmail := "dup-invite-" + GenerateUniqueSlug("test") + "@example.com"

	// First invite — should succeed
	body, _ := json.Marshal(map[string]any{"email": inviteEmail})
	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/team", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("first invite: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Second invite — should return 409 conflict
	body2, _ := json.Marshal(map[string]any{"email": inviteEmail})
	req2 := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/team", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req2, claims)

	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusConflict {
		t.Errorf("second invite: expected 409, got %d: %s", rr2.Code, rr2.Body.String())
	}
}

func TestAddTeamMember_EmptyEmail(t *testing.T) {
	router := setupTeamRouter(t)

	ownerEmail := "team-add-empty-owner-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, owner)

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	body, _ := json.Marshal(map[string]any{"email": ""})
	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/team", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --- List team invites ---

func TestListTeamInvites_Empty(t *testing.T) {
	router := setupTeamRouter(t)

	ownerEmail := "team-inv-list-empty-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, owner)

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/team/invites", nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	// invites should be null or empty array
	invites, _ := resp["invites"].([]any)
	if len(invites) != 0 {
		t.Errorf("expected 0 invites, got %d", len(invites))
	}
}

func TestListTeamInvites_WithPending(t *testing.T) {
	router := setupTeamRouter(t)

	ownerEmail := "team-inv-list-pending-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, owner)

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	// Create an invite via the API
	inviteEmail := "pending-inv-" + GenerateUniqueSlug("test") + "@example.com"
	body, _ := json.Marshal(map[string]any{"email": inviteEmail})
	addReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/team", bytes.NewReader(body))
	addReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, addReq, claims)
	addRR := httptest.NewRecorder()
	router.ServeHTTP(addRR, addReq)
	if addRR.Code != http.StatusOK {
		t.Fatalf("setup: expected 200 for invite, got %d: %s", addRR.Code, addRR.Body.String())
	}

	// Now list invites
	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/team/invites", nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	invites, ok := resp["invites"].([]any)
	if !ok {
		t.Fatalf("expected invites array, got %T", resp["invites"])
	}
	if len(invites) != 1 {
		t.Fatalf("expected 1 invite, got %d", len(invites))
	}

	inv := invites[0].(map[string]any)
	if inv["email"] != inviteEmail {
		t.Errorf("expected email %q, got %q", inviteEmail, inv["email"])
	}
	if inv["status"] != "pending" {
		t.Errorf("expected status 'pending', got %q", inv["status"])
	}
}

// --- Cancel team invite ---

func TestCancelTeamInvite_OwnerSuccess(t *testing.T) {
	router := setupTeamRouter(t)

	ownerEmail := "team-inv-cancel-owner-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, owner)

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	// Create an invite
	inviteEmail := "cancel-inv-" + GenerateUniqueSlug("test") + "@example.com"
	body, _ := json.Marshal(map[string]any{"email": inviteEmail})
	addReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/team", bytes.NewReader(body))
	addReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, addReq, claims)
	addRR := httptest.NewRecorder()
	router.ServeHTTP(addRR, addReq)
	if addRR.Code != http.StatusOK {
		t.Fatalf("setup: expected 200 for invite, got %d: %s", addRR.Code, addRR.Body.String())
	}

	// Get the invite ID from list
	listReq := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/team/invites", nil)
	testEnv.SetSessionCookie(t, listReq, claims)
	listRR := httptest.NewRecorder()
	router.ServeHTTP(listRR, listReq)

	var listResp map[string]any
	if err := json.Unmarshal(listRR.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to parse list response: %v", err)
	}
	invites := listResp["invites"].([]any)
	if len(invites) == 0 {
		t.Fatal("expected at least 1 invite")
	}
	inviteID := invites[0].(map[string]any)["id"].(string)

	// Cancel the invite
	cancelReq := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/team/invites/"+inviteID, nil)
	testEnv.SetSessionCookie(t, cancelReq, claims)

	cancelRR := httptest.NewRecorder()
	router.ServeHTTP(cancelRR, cancelReq)

	if cancelRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", cancelRR.Code, cancelRR.Body.String())
	}

	// Verify invite is gone
	has, err := testEnv.Repo.HasPendingInvite(context.Background(), ws.ID, inviteEmail)
	if err != nil {
		t.Fatalf("HasPendingInvite failed: %v", err)
	}
	if has {
		t.Error("expected invite to be cancelled")
	}
}

func TestCancelTeamInvite_ForbiddenForAdmin(t *testing.T) {
	router := setupTeamRouter(t)

	ownerEmail := "team-inv-cancel-forbid-owner-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))
	sess, ownerClaims := testEnv.CreateTestSession(t, owner)

	adminEmail := "team-inv-cancel-forbid-admin-" + GenerateUniqueSlug("test") + "@example.com"
	adminAcc := testEnv.CreateTestAccount(t, adminEmail)
	adminSess, adminClaims := testEnv.CreateTestSession(t, adminAcc)

	err := testEnv.Repo.AddWorkspaceAdmin(context.Background(), core.WorkspaceAdmin{
		WorkspaceID: ws.ID,
		AccountID:   adminAcc.ID,
		Role:        "admin",
		AddedBy:     &owner.ID,
	})
	if err != nil {
		t.Fatalf("failed to add admin: %v", err)
	}

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		teamCleanup(t, ws.ID, adminAcc.ID)
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", adminSess.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", adminAcc.ID)
	}()

	// Owner creates an invite
	inviteEmail := "cancel-forbid-inv-" + GenerateUniqueSlug("test") + "@example.com"
	body, _ := json.Marshal(map[string]any{"email": inviteEmail})
	addReq := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/team", bytes.NewReader(body))
	addReq.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, addReq, ownerClaims)
	addRR := httptest.NewRecorder()
	router.ServeHTTP(addRR, addReq)
	if addRR.Code != http.StatusOK {
		t.Fatalf("setup: expected 200 for invite, got %d: %s", addRR.Code, addRR.Body.String())
	}

	// Get invite ID
	listReq := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/team/invites", nil)
	testEnv.SetSessionCookie(t, listReq, ownerClaims)
	listRR := httptest.NewRecorder()
	router.ServeHTTP(listRR, listReq)

	var listResp map[string]any
	json.Unmarshal(listRR.Body.Bytes(), &listResp)
	invites := listResp["invites"].([]any)
	inviteID := invites[0].(map[string]any)["id"].(string)

	// Admin tries to cancel — should fail
	cancelReq := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/team/invites/"+inviteID, nil)
	testEnv.SetSessionCookie(t, cancelReq, adminClaims)

	cancelRR := httptest.NewRecorder()
	router.ServeHTTP(cancelRR, cancelReq)

	if cancelRR.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", cancelRR.Code, cancelRR.Body.String())
	}
}

// --- Remove team member ---

func TestRemoveTeamMember_OwnerSuccess(t *testing.T) {
	router := setupTeamRouter(t)

	ownerEmail := "team-rm-owner-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, owner)

	adminEmail := "team-rm-target-" + GenerateUniqueSlug("test") + "@example.com"
	adminAcc := testEnv.CreateTestAccount(t, adminEmail)

	err := testEnv.Repo.AddWorkspaceAdmin(context.Background(), core.WorkspaceAdmin{
		WorkspaceID: ws.ID,
		AccountID:   adminAcc.ID,
		Role:        "admin",
		AddedBy:     &owner.ID,
	})
	if err != nil {
		t.Fatalf("failed to add admin: %v", err)
	}

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		teamCleanup(t, ws.ID, adminAcc.ID)
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", adminAcc.ID)
	}()

	req := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/team/"+adminAcc.ID.String(), nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify the member was removed
	_, found, err := testEnv.Repo.GetWorkspaceAdminRole(context.Background(), ws.ID, adminAcc.ID)
	if err != nil {
		t.Fatalf("failed to check role: %v", err)
	}
	if found {
		t.Error("expected target to no longer be a workspace admin")
	}
}

func TestRemoveTeamMember_ForbiddenForAdmin(t *testing.T) {
	router := setupTeamRouter(t)

	ownerEmail := "team-rm-forbid-owner-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))

	adminEmail := "team-rm-forbid-admin-" + GenerateUniqueSlug("test") + "@example.com"
	adminAcc := testEnv.CreateTestAccount(t, adminEmail)
	adminSess, adminClaims := testEnv.CreateTestSession(t, adminAcc)

	err := testEnv.Repo.AddWorkspaceAdmin(context.Background(), core.WorkspaceAdmin{
		WorkspaceID: ws.ID,
		AccountID:   adminAcc.ID,
		Role:        "admin",
		AddedBy:     &owner.ID,
	})
	if err != nil {
		t.Fatalf("failed to add admin: %v", err)
	}

	fixtures := &TestFixtures{Account: owner, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		teamCleanup(t, ws.ID, adminAcc.ID)
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", adminSess.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", adminAcc.ID)
	}()

	// Admin tries to remove the owner
	req := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/team/"+owner.ID.String(), nil)
	testEnv.SetSessionCookie(t, req, adminClaims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestRemoveTeamMember_CannotRemoveSelf(t *testing.T) {
	router := setupTeamRouter(t)

	ownerEmail := "team-rm-self-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, owner)

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/team/"+owner.ID.String(), nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestRemoveTeamMember_CannotRemoveLastOwner(t *testing.T) {
	router := setupTeamRouter(t)

	owner1Email := "team-rm-lastowner1-" + GenerateUniqueSlug("test") + "@example.com"
	owner1 := testEnv.CreateTestAccount(t, owner1Email)
	ws := testEnv.CreateTestWorkspace(t, owner1, "Team WS", GenerateUniqueSlug("ws"))

	// AddFieldIssue a second owner
	owner2Email := "team-rm-lastowner2-" + GenerateUniqueSlug("test") + "@example.com"
	owner2 := testEnv.CreateTestAccount(t, owner2Email)
	owner2Sess, owner2Claims := testEnv.CreateTestSession(t, owner2)

	err := testEnv.Repo.AddWorkspaceAdmin(context.Background(), core.WorkspaceAdmin{
		WorkspaceID: ws.ID,
		AccountID:   owner2.ID,
		Role:        "owner",
		AddedBy:     &owner1.ID,
	})
	if err != nil {
		t.Fatalf("failed to add owner2: %v", err)
	}

	fixtures := &TestFixtures{Account: owner1, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		teamCleanup(t, ws.ID, owner2.ID)
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", owner2Sess.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", owner2.ID)
	}()

	// owner2 removes owner1 — should succeed since there are 2 owners
	req := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/team/"+owner1.ID.String(), nil)
	testEnv.SetSessionCookie(t, req, owner2Claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 (2 owners, removing one is ok), got %d: %s", rr.Code, rr.Body.String())
	}

	// Now owner2 is the only owner. Try to remove themselves — should fail with 400 (cannot remove self)
	req2 := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/team/"+owner2.ID.String(), nil)
	testEnv.SetSessionCookie(t, req2, owner2Claims)

	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusBadRequest {
		t.Errorf("expected 400 (cannot remove self / last owner), got %d: %s", rr2.Code, rr2.Body.String())
	}
}

func TestRemoveTeamMember_NotFound(t *testing.T) {
	router := setupTeamRouter(t)

	ownerEmail := "team-rm-notfound-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, owner)

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	fakeID := uuid.Must(uuid.NewV4())
	req := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/team/"+fakeID.String(), nil)
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --- Authorization ---

func TestTeam_Unauthenticated(t *testing.T) {
	router := setupTeamRouter(t)

	ownerEmail := "team-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))

	fixtures := &TestFixtures{Account: owner, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/team", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestTeam_NotAMember(t *testing.T) {
	router := setupTeamRouter(t)

	ownerEmail := "team-notmember-owner-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))

	otherEmail := "team-notmember-other-" + GenerateUniqueSlug("test") + "@example.com"
	other := testEnv.CreateTestAccount(t, otherEmail)
	otherSess, otherClaims := testEnv.CreateTestSession(t, other)

	fixtures := &TestFixtures{Account: owner, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", otherSess.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", other.ID)
	}()

	req := httptest.NewRequest(http.MethodGet, "/admin/workspace/"+ws.ID.String()+"/team", nil)
	testEnv.SetSessionCookie(t, req, otherClaims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

// --- Accept invite (repo-level test) ---

func TestAcceptTeamInvites_AddsToWorkspace(t *testing.T) {
	ctx := context.Background()

	ownerEmail := "team-accept-owner-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))

	fixtures := &TestFixtures{Account: owner, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	inviteEmail := "accept-inv-" + GenerateUniqueSlug("test") + "@example.com"

	// Create a pending invite directly via repo
	invite := core.TeamInvite{
		ID:          uuid.Must(uuid.NewV4()),
		WorkspaceID: ws.ID,
		Email:       inviteEmail,
		InvitedBy:   owner.ID,
		Status:      "pending",
	}
	if err := testEnv.Repo.CreateTeamInvite(ctx, invite); err != nil {
		t.Fatalf("CreateTeamInvite failed: %v", err)
	}

	// Verify it exists
	has, err := testEnv.Repo.HasPendingInvite(ctx, ws.ID, inviteEmail)
	if err != nil {
		t.Fatalf("HasPendingInvite failed: %v", err)
	}
	if !has {
		t.Fatal("expected pending invite to exist")
	}

	// Accept invites
	wsIDs, err := testEnv.Repo.AcceptTeamInvites(ctx, inviteEmail)
	if err != nil {
		t.Fatalf("AcceptTeamInvites failed: %v", err)
	}
	if len(wsIDs) != 1 {
		t.Fatalf("expected 1 workspace ID, got %d", len(wsIDs))
	}
	if wsIDs[0] != ws.ID {
		t.Errorf("expected workspace ID %s, got %s", ws.ID, wsIDs[0])
	}

	// Verify invite is no longer pending
	has, err = testEnv.Repo.HasPendingInvite(ctx, ws.ID, inviteEmail)
	if err != nil {
		t.Fatalf("HasPendingInvite after accept failed: %v", err)
	}
	if has {
		t.Error("expected no pending invite after acceptance")
	}
}

func TestCreateTeamInvite_DuplicateIgnored(t *testing.T) {
	ctx := context.Background()

	ownerEmail := "team-dup-repo-owner-" + GenerateUniqueSlug("test") + "@example.com"
	owner := testEnv.CreateTestAccount(t, ownerEmail)
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))

	fixtures := &TestFixtures{Account: owner, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	inviteEmail := "dup-repo-inv-" + GenerateUniqueSlug("test") + "@example.com"

	invite1 := core.TeamInvite{
		ID:          uuid.Must(uuid.NewV4()),
		WorkspaceID: ws.ID,
		Email:       inviteEmail,
		InvitedBy:   owner.ID,
		Status:      "pending",
	}
	if err := testEnv.Repo.CreateTeamInvite(ctx, invite1); err != nil {
		t.Fatalf("first CreateTeamInvite failed: %v", err)
	}

	// Second insert with same email should not error (ON CONFLICT DO NOTHING)
	invite2 := core.TeamInvite{
		ID:          uuid.Must(uuid.NewV4()),
		WorkspaceID: ws.ID,
		Email:       inviteEmail,
		InvitedBy:   owner.ID,
		Status:      "pending",
	}
	if err := testEnv.Repo.CreateTeamInvite(ctx, invite2); err != nil {
		t.Fatalf("second CreateTeamInvite should not error: %v", err)
	}

	// Should still only have one pending invite
	invites, err := testEnv.Repo.GetPendingInvitesByWorkspace(ctx, ws.ID)
	if err != nil {
		t.Fatalf("GetPendingInvitesByWorkspace failed: %v", err)
	}
	if len(invites) != 1 {
		t.Errorf("expected 1 pending invite, got %d", len(invites))
	}
}
