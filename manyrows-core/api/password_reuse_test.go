package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"manyrows-core/crypto/passwordhash"

	"github.com/gofrs/uuid/v5"
)

// setAppReusePrevention enables or disables the password-reuse-prevention
// toggle for the given app directly in the DB.
func setAppReusePrevention(t *testing.T, appID uuid.UUID, on bool) {
	t.Helper()
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`UPDATE apps SET password_reuse_prevention = $2 WHERE id = $1`, appID, on); err != nil {
		t.Fatalf("set reuse prevention: %v", err)
	}
}

// doSetPassword is a helper to hit POST /x/{slug}/apps/{appID}/a/set-password.
// Returns the recorded response.
func doSetPassword(t *testing.T, router http.Handler, wsSlug, appID, accessToken, currentPW, newPW string) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{
		"password":        newPW,
		"currentPassword": currentPW,
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/x/"+wsSlug+"/apps/"+appID+"/a/set-password", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// TestSetPassword_ReuseBlocked verifies that reusing the current password is
// rejected when password_reuse_prevention is enabled.
func TestSetPassword_ReuseBlocked(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "reuse-blocked-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	clientSes, accessToken := createTestClientSessionForApp(t, ws, acc, app)

	// Seed password A directly (no history recording — mirrors mirrored test).
	pwA := "OldPassword!2026a"
	hashA, err := passwordhash.Hash(pwA)
	if err != nil {
		t.Fatalf("hash password A: %v", err)
	}
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		"UPDATE users SET password_hash = $1 WHERE id = $2", hashA, clientSes.UserID,
	); err != nil {
		t.Fatalf("seed password_hash: %v", err)
	}

	setAppReusePrevention(t, app.ID, true)

	// Attempt to set the same password A → must be blocked.
	// The safety-net check against the live users.password_hash catches this
	// even without a history row.
	rr := doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwA, pwA)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "passwordRecentlyUsed") {
		t.Errorf("expected error.passwordRecentlyUsed in body, got: %s", rr.Body.String())
	}
}

// TestSetPassword_ReuseOfOlderBlocked_ThenRotatesOut verifies:
//   - A password in the rolling window is rejected.
//   - A password that has been evicted from the window (older than newest 5) is accepted.
//
// Password sequence:
//
//	Fixture seeds P0 (no history).
//	API: P0→A  (history: [A])          — step 1
//	API: A→B   (history: [B, A])       — step 2
//	API: B→A   → 400 (A is in history) — step 3 (blocked)
//	API: B→C   (history: [C, B, A])    — step 4
//	API: C→D   (history: [D, C, B, A]) — step 5
//	API: D→E   (history: [E, D, C, B, A]) — step 6, window full (5 entries)
//	API: E→F   (history: [F, E, D, C, B], A evicted) — step 7
//	API: F→A   → 200 (A has rotated out) — step 8 (allowed)
func TestSetPassword_ReuseOfOlderBlocked_ThenRotatesOut(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "reuse-rotate-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	clientSes, accessToken := createTestClientSessionForApp(t, ws, acc, app)

	// Seed fixture password P0 directly — no history row created.
	pwP0 := "OldPassword!2026a" // reused as P0 seed; A will be the same value after step 1
	// Use a distinct P0 so A enters history through the API.
	pwP0 = "OldPassword!2026a-seed"
	hashP0, err := passwordhash.Hash(pwP0)
	if err != nil {
		t.Fatalf("hash P0: %v", err)
	}
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		"UPDATE users SET password_hash = $1 WHERE id = $2", hashP0, clientSes.UserID,
	); err != nil {
		t.Fatalf("seed password_hash: %v", err)
	}

	setAppReusePrevention(t, app.ID, true)

	pwA := "OldPassword!2026a"
	pwB := "NewPassword!2026b"
	pwC := "ThirdPassword!2026c"
	pwD := "FourthPassword!2026d"
	pwE := "FifthPassword!2026e"
	pwF := "SixthPassword!2026f"

	// Step 1: P0→A  (records A in history)
	rr := doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwP0, pwA)
	if rr.Code != http.StatusOK {
		t.Fatalf("step 1 P0→A: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Step 2: A→B  (records B; history [B, A])
	rr = doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwA, pwB)
	if rr.Code != http.StatusOK {
		t.Fatalf("step 2 A→B: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Step 3: B→A  → blocked (A is in history)
	rr = doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwB, pwA)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("step 3 B→A: expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "passwordRecentlyUsed") {
		t.Errorf("step 3: expected error.passwordRecentlyUsed in body, got: %s", rr.Body.String())
	}

	// Step 4: B→C  (records C; history [C, B, A])
	rr = doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwB, pwC)
	if rr.Code != http.StatusOK {
		t.Fatalf("step 4 B→C: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Step 5: C→D  (records D; history [D, C, B, A])
	rr = doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwC, pwD)
	if rr.Code != http.StatusOK {
		t.Fatalf("step 5 C→D: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Step 6: D→E  (records E; history [E, D, C, B, A] — window full at 5)
	rr = doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwD, pwE)
	if rr.Code != http.StatusOK {
		t.Fatalf("step 6 D→E: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Step 7: E→F  (records F; history [F, E, D, C, B] — A evicted)
	rr = doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwE, pwF)
	if rr.Code != http.StatusOK {
		t.Fatalf("step 7 E→F: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Step 8: F→A  → allowed (A has rotated out of the newest-5 window)
	rr = doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwF, pwA)
	if rr.Code != http.StatusOK {
		t.Fatalf("step 8 F→A: expected 200 (A rotated out), got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestSetPassword_ReuseAllowedWhenToggleOff verifies that when reuse
// prevention is disabled (the default), reusing a recent password is
// permitted.
func TestSetPassword_ReuseAllowedWhenToggleOff(t *testing.T) {
	router := setupClientAPIRouter(t)

	emailAddr := "reuse-off-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws}
	defer testEnv.CleanupTestData(t, fixtures)

	clientSes, accessToken := createTestClientSessionForApp(t, ws, acc, app)

	// Seed password A directly.
	pwA := "OldPassword!2026a"
	hashA, err := passwordhash.Hash(pwA)
	if err != nil {
		t.Fatalf("hash password A: %v", err)
	}
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		"UPDATE users SET password_hash = $1 WHERE id = $2", hashA, clientSes.UserID,
	); err != nil {
		t.Fatalf("seed password_hash: %v", err)
	}

	// Explicitly disable (default, set for clarity).
	setAppReusePrevention(t, app.ID, false)

	pwB := "NewPassword!2026b"

	// A→B: must succeed.
	rr := doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwA, pwB)
	if rr.Code != http.StatusOK {
		t.Fatalf("A→B: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// B→A: must succeed (reuse prevention is off).
	rr = doSetPassword(t, router, ws.Slug, app.ID.String(), accessToken, pwB, pwA)
	if rr.Code != http.StatusOK {
		t.Fatalf("B→A: expected 200 (toggle off), got %d: %s", rr.Code, rr.Body.String())
	}
}
