package api_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"manyrows-core/core"
	"manyrows-core/crypto/passwordhash"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
)

// testHashOTP replicates the server-side hashOTP function (HMAC-SHA256)
// so tests can produce a known code hash for verification.
func testHashOTP(otpID uuid.UUID, code string, pepper string) string {
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte(otpID.String() + ":" + code))
	return hex.EncodeToString(mac.Sum(nil))
}

const testOTPPepper = "test-otp-pepper-value-here"

// emailChangeTestSetup creates workspace, app, user with password and a client session.
// Returns everything needed for email-change endpoint tests.
func emailChangeTestSetup(t *testing.T) (
	router http.Handler,
	ws *core.Workspace,
	app *core.App,
	acc *core.Account,
	userID uuid.UUID,
	accessToken string,
	cleanup func(),
) {
	t.Helper()

	r := setupClientAPIRouter(t)

	emailAddr := "ec-" + GenerateUniqueSlug("test") + "@example.com"
	acc = testEnv.CreateTestAccount(t, emailAddr)
	ws = testEnv.CreateTestWorkspace(t, acc, "EC WS", GenerateUniqueSlug("ws"))
	app = testEnv.CreateTestApp(t, ws, acc)

	ctx := context.Background()

	// Email-change handlers reject up front when app.allow_email_change
	// is false (it defaults to false on app creation). Flip it on so
	// the request-email-change / verify-email-change paths are reachable.
	if _, err := testEnv.DB.Pool().Exec(ctx,
		"UPDATE apps SET allow_email_change = true WHERE id = $1", app.ID,
	); err != nil {
		t.Fatalf("enable allow_email_change: %v", err)
	}
	app.AllowEmailChange = true

	// Create user for the app
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Set a known password
	hash, err := passwordhash.Hash("correct-password")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	if err := testEnv.Repo.UpdateUserPassword(ctx, user.ID, hash, time.Now().UTC()); err != nil {
		t.Fatalf("failed to set user password: %v", err)
	}

	_, accessToken = createTestClientSessionForApp(t, ws, acc, app)
	userID = user.ID

	cleanup = func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM email_change_requests WHERE user_id = $1", user.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM client_refresh_tokens WHERE session_id IN (SELECT id FROM client_sessions WHERE workspace_id = $1)", ws.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
		testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})
	}

	return r, ws, app, acc, userID, accessToken, cleanup
}

// requestEmailChangePath returns the URL path for the request-email-change endpoint.
func requestEmailChangePath(ws *core.Workspace, app *core.App) string {
	return "/x/" + ws.Slug + "/apps/" + app.ID.String() + "/a/me/request-email-change"
}

// verifyEmailChangePath returns the URL path for the verify-email-change endpoint.
func verifyEmailChangePath(ws *core.Workspace, app *core.App) string {
	return "/x/" + ws.Slug + "/apps/" + app.ID.String() + "/a/me/verify-email-change"
}

// =====================
// Request Email Change Tests
// =====================

func TestClientRequestEmailChange_Success(t *testing.T) {
	router, ws, app, _, _, accessToken, cleanup := emailChangeTestSetup(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"password": "correct-password",
		"newEmail": "new-" + GenerateUniqueSlug("ec") + "@example.com",
	})
	req := httptest.NewRequest(http.MethodPost, requestEmailChangePath(ws, app), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["ok"] != true {
		t.Errorf("expected ok=true, got %v", resp["ok"])
	}
}

func TestClientRequestEmailChange_WrongPassword(t *testing.T) {
	router, ws, app, _, _, accessToken, cleanup := emailChangeTestSetup(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"password": "wrong-password",
		"newEmail": "new-" + GenerateUniqueSlug("ec") + "@example.com",
	})
	req := httptest.NewRequest(http.MethodPost, requestEmailChangePath(ws, app), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestClientRequestEmailChange_InvalidEmail(t *testing.T) {
	router, ws, app, _, _, accessToken, cleanup := emailChangeTestSetup(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"password": "correct-password",
		"newEmail": "not-an-email",
	})
	req := httptest.NewRequest(http.MethodPost, requestEmailChangePath(ws, app), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestClientRequestEmailChange_NoPassword(t *testing.T) {
	router, ws, app, _, _, accessToken, cleanup := emailChangeTestSetup(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"newEmail": "new-" + GenerateUniqueSlug("ec") + "@example.com",
	})
	req := httptest.NewRequest(http.MethodPost, requestEmailChangePath(ws, app), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestClientRequestEmailChange_Unauthenticated(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "ec-unauth-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "EC WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	body, _ := json.Marshal(map[string]string{
		"password": "any-password",
		"newEmail": "new@example.com",
	})
	req := httptest.NewRequest(http.MethodPost, requestEmailChangePath(ws, app), bytes.NewReader(body))
	// No Authorization header
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =====================
// Verify Email Change Tests
// =====================

func TestClientVerifyEmailChange_Success(t *testing.T) {
	router, ws, app, _, userID, accessToken, cleanup := emailChangeTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	newEmail := "verified-" + GenerateUniqueSlug("ec") + "@example.com"
	knownCode := "123456"
	otpID := utils.NewUUID()
	codeHash := testHashOTP(otpID, knownCode, testOTPPepper)

	// Insert an email change request directly via the repo
	err := testEnv.Repo.UpsertEmailChangeRequest(
		ctx,
		otpID,
		userID,
		app.ID,
		newEmail,
		codeHash,
		time.Now().UTC().Add(15*time.Minute),
	)
	if err != nil {
		t.Fatalf("failed to insert email change request: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"code": knownCode})
	req := httptest.NewRequest(http.MethodPost, verifyEmailChangePath(ws, app), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["ok"] != true {
		t.Errorf("expected ok=true, got %v", resp["ok"])
	}
	if resp["email"] != newEmail {
		t.Errorf("expected email=%q, got %q", newEmail, resp["email"])
	}

	// Verify the user's email was actually updated in the database
	var dbEmail string
	err = testEnv.DB.Pool().QueryRow(ctx, "SELECT email FROM users WHERE id = $1", userID).Scan(&dbEmail)
	if err != nil {
		t.Fatalf("failed to query user email: %v", err)
	}
	if dbEmail != newEmail {
		t.Errorf("expected DB email=%q, got %q", newEmail, dbEmail)
	}
}

func TestClientVerifyEmailChange_WrongCode(t *testing.T) {
	router, ws, app, _, userID, accessToken, cleanup := emailChangeTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	newEmail := "wrong-code-" + GenerateUniqueSlug("ec") + "@example.com"
	correctCode := "123456"
	otpID := utils.NewUUID()
	codeHash := testHashOTP(otpID, correctCode, testOTPPepper)

	err := testEnv.Repo.UpsertEmailChangeRequest(
		ctx,
		otpID,
		userID,
		app.ID,
		newEmail,
		codeHash,
		time.Now().UTC().Add(15*time.Minute),
	)
	if err != nil {
		t.Fatalf("failed to insert email change request: %v", err)
	}

	// Send wrong code
	body, _ := json.Marshal(map[string]string{"code": "999999"})
	req := httptest.NewRequest(http.MethodPost, verifyEmailChangePath(ws, app), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestClientVerifyEmailChange_NoPendingRequest(t *testing.T) {
	router, ws, app, _, _, accessToken, cleanup := emailChangeTestSetup(t)
	defer cleanup()

	// No email change request inserted -- go straight to verify
	body, _ := json.Marshal(map[string]string{"code": "123456"})
	req := httptest.NewRequest(http.MethodPost, verifyEmailChangePath(ws, app), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestEmailChange_HashSymmetry pins the contract that the request and
// verify handlers hash the OTP with the same identifier. Previously the
// request side hashed with otpID (the new email_change_requests row id)
// while the verify side hashed with req.AppID — so the compare always
// failed and the entire feature was broken end-to-end. This test
// reproduces request-side hashing, persists the row, reads it back via
// GetEmailChangeRequest (the same path verify uses), and recomputes the
// hash from the loaded row's fields. The stored hash must match the
// hash derived from req.ID, not req.AppID.
func TestEmailChange_HashSymmetry(t *testing.T) {
	_, _, app, _, userID, _, cleanup := emailChangeTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	otpID := utils.NewUUID()
	code := "424242"
	requestHash := testHashOTP(otpID, code, testOTPPepper)

	if err := testEnv.Repo.UpsertEmailChangeRequest(ctx, otpID, userID, app.ID,
		"sym-"+GenerateUniqueSlug("ec")+"@example.com", requestHash,
		time.Now().UTC().Add(15*time.Minute),
	); err != nil {
		t.Fatalf("UpsertEmailChangeRequest: %v", err)
	}

	row, err := testEnv.Repo.GetEmailChangeRequest(ctx, userID)
	if err != nil {
		t.Fatalf("GetEmailChangeRequest: %v", err)
	}

	verifyHash := testHashOTP(row.ID, code, testOTPPepper)
	if verifyHash != row.CodeHash {
		t.Errorf("hash from row.ID does not match stored CodeHash — verify side would reject")
	}
	// And the inverse: hashing with AppID (the pre-fix mistake) must NOT match.
	if mistakenHash := testHashOTP(row.AppID, code, testOTPPepper); mistakenHash == row.CodeHash {
		t.Errorf("hash from row.AppID coincidentally matched — symmetry test useless")
	}
}

// TestGetEmailChangeRequest_PopulatesAllFields pins the repo's row-scan
// order field-by-field. Previously the Scan landed both the `id` and
// `app_id` columns into &req.AppID, so req.ID was always uuid.Nil and
// callers using req.ID for hashing / consumption silently broke.
func TestGetEmailChangeRequest_PopulatesAllFields(t *testing.T) {
	_, _, app, _, userID, _, cleanup := emailChangeTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	otpID := utils.NewUUID()
	newEmail := "scan-check-" + GenerateUniqueSlug("ec") + "@example.com"
	codeHash := testHashOTP(otpID, "123456", testOTPPepper)
	expiresAt := time.Now().UTC().Add(15 * time.Minute).Truncate(time.Microsecond)

	if err := testEnv.Repo.UpsertEmailChangeRequest(ctx, otpID, userID, app.ID, newEmail, codeHash, expiresAt); err != nil {
		t.Fatalf("UpsertEmailChangeRequest: %v", err)
	}

	got, err := testEnv.Repo.GetEmailChangeRequest(ctx, userID)
	if err != nil {
		t.Fatalf("GetEmailChangeRequest: %v", err)
	}
	if got.ID != otpID {
		t.Errorf("ID = %s, want %s", got.ID, otpID)
	}
	if got.UserID != userID {
		t.Errorf("UserID = %s, want %s", got.UserID, userID)
	}
	if got.AppID != app.ID {
		t.Errorf("AppID = %s, want %s", got.AppID, app.ID)
	}
	if got.NewEmail != newEmail {
		t.Errorf("NewEmail = %q, want %q", got.NewEmail, newEmail)
	}
	if got.CodeHash != codeHash {
		t.Errorf("CodeHash = %q, want %q", got.CodeHash, codeHash)
	}
	if !got.ExpiresAt.Equal(expiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, expiresAt)
	}
}
