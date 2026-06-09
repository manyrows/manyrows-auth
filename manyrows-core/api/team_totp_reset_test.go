package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
)

// enableAccountTOTP marks an admin account as having TOTP enabled so the
// reset path has something to clear. HasTOTP() keys off totp_enabled_at.
func enableAccountTOTP(t *testing.T, accountID uuid.UUID) {
	t.Helper()
	_, err := testEnv.DB.Pool().Exec(context.Background(),
		`UPDATE accounts SET totp_enabled_at = now(), totp_secret_encrypted = $2, totp_backup_codes_encrypted = $2 WHERE id = $1`,
		accountID, []byte("dummy-encrypted"))
	if err != nil {
		t.Fatalf("enable TOTP: %v", err)
	}
}

// accountTOTPEnabled reports whether the account's totp_enabled_at is set.
func accountTOTPEnabled(t *testing.T, accountID uuid.UUID) bool {
	t.Helper()
	var enabledAt *time.Time
	if err := testEnv.DB.Pool().QueryRow(context.Background(),
		`SELECT totp_enabled_at FROM accounts WHERE id = $1`, accountID).Scan(&enabledAt); err != nil {
		t.Fatalf("read totp_enabled_at: %v", err)
	}
	return enabledAt != nil
}

// TestResetTeamMemberTOTP_OwnerSuccess: an owner can reset a locked-out
// team member's 2FA, clearing their TOTP enrolment.
func TestResetTeamMemberTOTP_OwnerSuccess(t *testing.T) {
	router := setupTeamRouter(t)

	owner := testEnv.CreateTestAccount(t, "team-totp-owner-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, owner)

	member := testEnv.CreateTestAccount(t, "team-totp-member-"+GenerateUniqueSlug("test")+"@example.com")
	if err := testEnv.Repo.AddWorkspaceAdmin(context.Background(), core.WorkspaceAdmin{
		WorkspaceID: ws.ID,
		AccountID:   member.ID,
		Role:        "admin",
		AddedBy:     &owner.ID,
	}); err != nil {
		t.Fatalf("add admin: %v", err)
	}
	enableAccountTOTP(t, member.ID)

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		teamCleanup(t, ws.ID, member.ID)
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", member.ID)
	}()

	if !accountTOTPEnabled(t, member.ID) {
		t.Fatal("precondition: member should have TOTP enabled")
	}

	req := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/team/"+member.ID.String()+"/totp", nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if accountTOTPEnabled(t, member.ID) {
		t.Error("expected member TOTP to be disabled after reset")
	}
}

// TestResetTeamMemberTOTP_ForbiddenForAdmin: a non-owner admin cannot
// reset anyone's 2FA (owner-only, mirroring remove-member).
func TestResetTeamMemberTOTP_ForbiddenForAdmin(t *testing.T) {
	router := setupTeamRouter(t)

	owner := testEnv.CreateTestAccount(t, "team-totp-fb-owner-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))

	adminAcc := testEnv.CreateTestAccount(t, "team-totp-fb-admin-"+GenerateUniqueSlug("test")+"@example.com")
	adminSess, adminClaims := testEnv.CreateTestSession(t, adminAcc)
	if err := testEnv.Repo.AddWorkspaceAdmin(context.Background(), core.WorkspaceAdmin{
		WorkspaceID: ws.ID,
		AccountID:   adminAcc.ID,
		Role:        "admin",
		AddedBy:     &owner.ID,
	}); err != nil {
		t.Fatalf("add admin: %v", err)
	}
	enableAccountTOTP(t, owner.ID)

	fixtures := &TestFixtures{Account: owner, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		teamCleanup(t, ws.ID, adminAcc.ID)
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM sessions WHERE id = $1", adminSess.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", adminAcc.ID)
	}()

	// Admin tries to reset the owner's TOTP — should be forbidden.
	req := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/team/"+owner.ID.String()+"/totp", nil)
	testEnv.SetSessionCookie(t, req, adminClaims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
	// The owner's TOTP must be untouched.
	if !accountTOTPEnabled(t, owner.ID) {
		t.Error("owner TOTP should remain enabled after forbidden reset")
	}
}

// TestResetTeamMemberTOTP_NotAMember: an owner cannot reset the 2FA of
// an account that is not a member of their workspace (scoping guard
// against cross-workspace tampering).
func TestResetTeamMemberTOTP_NotAMember(t *testing.T) {
	router := setupTeamRouter(t)

	owner := testEnv.CreateTestAccount(t, "team-totp-nm-owner-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, owner, "Team WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, owner)

	// An account that exists but is NOT an admin of this workspace.
	outsider := testEnv.CreateTestAccount(t, "team-totp-nm-outsider-"+GenerateUniqueSlug("test")+"@example.com")
	enableAccountTOTP(t, outsider.ID)

	fixtures := &TestFixtures{Account: owner, Workspace: ws, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", outsider.ID)
	}()

	req := httptest.NewRequest(http.MethodDelete, "/admin/workspace/"+ws.ID.String()+"/team/"+outsider.ID.String()+"/totp", nil)
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for non-member, got %d: %s", rr.Code, rr.Body.String())
	}
	if !accountTOTPEnabled(t, outsider.ID) {
		t.Error("non-member account TOTP must not be touched")
	}
}
