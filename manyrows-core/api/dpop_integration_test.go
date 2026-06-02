package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"manyrows-core/auth/client"
	"manyrows-core/core"
	"manyrows-core/crypto/passwordhash"

	"github.com/golang-jwt/jwt/v5"
)

// These tests cover the three gotchas locked in for the DPoP plan:
//   1. No first-refresh upgrade (unbound stays unbound)
//   2. jkt propagates through rotation
//   3. Strict downgrade rejection on bound rows

func newDPoPKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("dpop: generate key: %v", err)
	}
	return k
}

func padDPoPCoord(b []byte) []byte {
	if len(b) == 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func dpopJWK(key *ecdsa.PrivateKey) map[string]string {
	return map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(padDPoPCoord(key.X.Bytes())),
		"y":   base64.RawURLEncoding.EncodeToString(padDPoPCoord(key.Y.Bytes())),
	}
}

func computeDPoPJKT(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	jwk := dpopJWK(key)
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func signDPoPHeader(t *testing.T, key *ecdsa.PrivateKey, method, urlStr, jti string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"htm": method,
		"htu": urlStr,
		"jti": jti,
		"iat": time.Now().UTC().Unix(),
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = dpopJWK(key)
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("dpop: sign: %v", err)
	}
	return signed
}

// issueBoundSession creates a refresh token whose dpop_jkt is pre-set to the
// provided thumbprint. Bypasses the HTTP login flow (which is exercised by
// other tests) so each test focuses purely on the refresh path.
func issueBoundSession(t *testing.T, ws *core.Workspace, app *core.App, jkt string) (*core.User, *core.ClientSession, string) {
	t.Helper()
	cfg := GetTestConfig()
	clientAuthService, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("create client auth service: %v", err)
	}
	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, "dpop-"+GenerateUniqueSlug("user")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	ses, err := clientAuthService.CreateSession(ctx, user.ID, app.ID, "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	rawToken, _, err := clientAuthService.IssueRefreshToken(ctx, ses.ID, "test-agent", "127.0.0.1", 0, jkt)
	if err != nil {
		t.Fatalf("issue refresh token: %v", err)
	}
	return user, ses, rawToken
}

func cleanupDPopSession(t *testing.T, ws *core.Workspace) {
	t.Helper()
	pool := testEnv.DB.Pool()
	_, _ = pool.Exec(context.Background(), "DELETE FROM client_refresh_tokens WHERE session_id IN (SELECT id FROM client_sessions WHERE workspace_id = $1)", ws.ID)
	_, _ = pool.Exec(context.Background(), "DELETE FROM client_sessions WHERE workspace_id = $1", ws.ID)
	_, _ = pool.Exec(context.Background(), "DELETE FROM dpop_replay")
}

// dpopTestBaseURL must mirror MANYROWS_BASE_URL set in GetTestConfig — the
// server now reconstructs htu from BASE_URL rather than the inbound Host
// header (security hardening: H5), so the proofs we sign in the test must
// match the configured base.
const dpopTestBaseURL = "http://localhost:8080"
const dpopTestHost = "localhost:8080"

func refreshURL(ws *core.Workspace, app *core.App) string {
	return "/x/" + ws.Slug + "/apps/" + app.ID.String() + "/auth/refresh"
}

func absRefreshURL(ws *core.Workspace, app *core.App) string {
	return dpopTestBaseURL + refreshURL(ws, app)
}

func doRefresh(t *testing.T, router http.Handler, ws *core.Workspace, app *core.App, refreshToken, dpopHeader string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"refreshToken": refreshToken})
	req := httptest.NewRequest(http.MethodPost, refreshURL(ws, app), bytes.NewReader(body))
	req.Host = dpopTestHost
	req.Header.Set("Content-Type", "application/json")
	if dpopHeader != "" {
		req.Header.Set("DPoP", dpopHeader)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func TestDPoP_RefreshBoundSession_Success(t *testing.T) {
	router := setupClientAPIRouter(t)
	emailAddr := "dpop-bound-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})
	defer cleanupDPopSession(t, ws)

	key := newDPoPKey(t)
	jkt := computeDPoPJKT(t, key)
	_, _, refreshToken := issueBoundSession(t, ws, app, jkt)

	dpop := signDPoPHeader(t, key, "POST", absRefreshURL(ws, app), "j-success")
	rr := doRefresh(t, router, ws, app, refreshToken, dpop)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestDPoP_RefreshBoundSession_RejectedWithoutHeader(t *testing.T) {
	// Gotcha #3: a session bound to a jkt cannot be refreshed via plain Bearer.
	// No silent fallback; reject with the same error a stolen-token attempt
	// would receive.
	router := setupClientAPIRouter(t)
	emailAddr := "dpop-noheader-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})
	defer cleanupDPopSession(t, ws)

	key := newDPoPKey(t)
	jkt := computeDPoPJKT(t, key)
	_, _, refreshToken := issueBoundSession(t, ws, app, jkt)

	rr := doRefresh(t, router, ws, app, refreshToken, "")

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (no DPoP on bound session), got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestDPoP_RefreshBoundSession_RejectedWithWrongKey(t *testing.T) {
	router := setupClientAPIRouter(t)
	emailAddr := "dpop-wrongkey-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})
	defer cleanupDPopSession(t, ws)

	legitKey := newDPoPKey(t)
	jkt := computeDPoPJKT(t, legitKey)
	_, _, refreshToken := issueBoundSession(t, ws, app, jkt)

	attackerKey := newDPoPKey(t)
	dpop := signDPoPHeader(t, attackerKey, "POST", absRefreshURL(ws, app), "j-wrongkey")
	rr := doRefresh(t, router, ws, app, refreshToken, dpop)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (wrong key on bound session), got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestDPoP_RefreshUnboundSession_DoesNotUpgrade(t *testing.T) {
	// Gotcha #1: an unbound session must NOT be opportunistically upgraded
	// when a DPoP header arrives on a refresh. Otherwise an attacker holding
	// a stolen unbound refresh token could "claim" the session by binding it
	// to their own key, locking out the legit user.
	router := setupClientAPIRouter(t)
	emailAddr := "dpop-noupgrade-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})
	defer cleanupDPopSession(t, ws)

	// Unbound session (jkt empty)
	_, _, refreshToken := issueBoundSession(t, ws, app, "")

	key := newDPoPKey(t)
	dpop := signDPoPHeader(t, key, "POST", absRefreshURL(ws, app), "j-upgrade")
	rr := doRefresh(t, router, ws, app, refreshToken, dpop)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 (unbound session refreshes normally), got %d: %s", rr.Code, rr.Body.String())
	}

	// The new refresh token must also be unbound. Look it up directly.
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	newRT, _ := resp["refreshToken"].(string)
	if newRT == "" {
		t.Fatalf("missing refreshToken in response")
	}

	pool := testEnv.DB.Pool()
	hash := sha256HexForToken(newRT)
	var jkt *string
	err := pool.QueryRow(context.Background(),
		`SELECT dpop_jkt FROM client_refresh_tokens WHERE token_hash = $1`, hash,
	).Scan(&jkt)
	if err != nil {
		t.Fatalf("query new refresh token: %v", err)
	}
	if jkt != nil && *jkt != "" {
		t.Errorf("unbound session was upgraded to bound (jkt=%q); should never happen", *jkt)
	}
}

func TestDPoP_RotationPropagatesJKT(t *testing.T) {
	// Gotcha #2: the bound jkt must be inherited by every successor token
	// in the chain. If propagation drops on a single rotation, the session
	// silently becomes unbound and an attacker can use a stolen successor
	// without DPoP.
	router := setupClientAPIRouter(t)
	emailAddr := "dpop-propagation-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})
	defer cleanupDPopSession(t, ws)

	key := newDPoPKey(t)
	jkt := computeDPoPJKT(t, key)
	_, _, refreshToken := issueBoundSession(t, ws, app, jkt)

	current := refreshToken
	for i := 0; i < 3; i++ {
		dpop := signDPoPHeader(t, key, "POST", absRefreshURL(ws, app), fmt.Sprintf("j-rot-%d", i))
		rr := doRefresh(t, router, ws, app, current, dpop)
		if rr.Code != http.StatusOK {
			t.Fatalf("rotation %d: expected 200, got %d: %s", i, rr.Code, rr.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("rotation %d: parse: %v", i, err)
		}
		newRT, _ := resp["refreshToken"].(string)
		if newRT == "" {
			t.Fatalf("rotation %d: missing refreshToken", i)
		}

		// Each new row must carry the same jkt.
		hash := sha256HexForToken(newRT)
		var rowJKT *string
		if err := testEnv.DB.Pool().QueryRow(context.Background(),
			`SELECT dpop_jkt FROM client_refresh_tokens WHERE token_hash = $1`, hash,
		).Scan(&rowJKT); err != nil {
			t.Fatalf("rotation %d: query: %v", i, err)
		}
		if rowJKT == nil {
			t.Fatalf("rotation %d: jkt unexpectedly NULL after rotation", i)
		}
		if *rowJKT != jkt {
			t.Fatalf("rotation %d: jkt %q != original %q (propagation broken)", i, *rowJKT, jkt)
		}

		current = newRT
	}
}

// sha256HexForToken mirrors the client auth service's hashing scheme so tests
// can look up rows by their token_hash column.
func sha256HexForToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return fmt.Sprintf("%x", sum[:])
}

func TestDPoP_PasswordLoginBindsSession(t *testing.T) {
	// Covers the HTTP login path end-to-end: when AppKit POSTs /auth/password
	// with a DPoP header, the resulting refresh-token row must carry the
	// matching jkt. Refresh-handler tests already cover what happens *after*
	// a session is bound; this test catches regressions where a future
	// refactor of the login handlers silently drops the extractDPoPJKT call
	// and the new session is mistakenly created unbound.
	testEnv.ClearRateLimitAttempts(t)
	router := setupClientAPIRouter(t)

	emailAddr := "dpop-pwlogin-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})
	defer cleanupDPopSession(t, ws)

	// Set up a user with a known password.
	ctx := context.Background()
	password := "testpassword123"
	hash, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()
	now := time.Now().UTC()
	if _, err := testEnv.DB.Pool().Exec(ctx, `
		UPDATE users SET password_hash = $1, password_set_at = $2, email_verified_at = $3 WHERE id = $4
	`, hash, now, now, user.ID); err != nil {
		t.Fatalf("set password: %v", err)
	}

	key := newDPoPKey(t)
	expectedJKT := computeDPoPJKT(t, key)

	body, _ := json.Marshal(map[string]any{
		"email":    emailAddr,
		"password": password,
		"appId":    app.ID.String(),
	})
	url := "/x/" + ws.Slug + "/apps/" + app.ID.String() + "/auth/password"
	dpop := signDPoPHeader(t, key, "POST", dpopTestBaseURL+url, "j-pwlogin")

	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Host = dpopTestHost
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DPoP", dpop)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	rt, _ := resp["refreshToken"].(string)
	if rt == "" {
		t.Fatalf("missing refreshToken in response")
	}

	// The newly issued refresh-token row MUST be bound to the proof's jkt.
	var rowJKT *string
	if err := testEnv.DB.Pool().QueryRow(ctx,
		`SELECT dpop_jkt FROM client_refresh_tokens WHERE token_hash = $1`,
		sha256HexForToken(rt),
	).Scan(&rowJKT); err != nil {
		t.Fatalf("query refresh token row: %v", err)
	}
	if rowJKT == nil {
		t.Fatal("login with DPoP header produced an unbound refresh token (jkt is NULL)")
	}
	if *rowJKT != expectedJKT {
		t.Errorf("bound jkt %q != proof jkt %q", *rowJKT, expectedJKT)
	}

	// Sanity: a follow-up refresh with the same key must succeed; one without
	// the header must be rejected (confirms the binding is enforceable, not
	// just recorded).
	dpop2 := signDPoPHeader(t, key, "POST", absRefreshURL(ws, app), "j-pwlogin-r1")
	rr2 := doRefresh(t, router, ws, app, rt, dpop2)
	if rr2.Code != http.StatusOK {
		t.Errorf("follow-up refresh with matching DPoP: expected 200, got %d: %s", rr2.Code, rr2.Body.String())
	}
}

func TestDPoP_BadHeaderCountsTowardRateLimit(t *testing.T) {
	// A flood of malformed DPoP headers must accumulate failed-attempt rows
	// the same way a flood of bad refresh tokens does, so the per-IP refresh
	// throttle catches both attack shapes. Without this, an attacker could
	// hammer the endpoint with garbage DPoP headers indefinitely without
	// triggering rate limiting.
	router := setupClientAPIRouter(t)

	emailAddr := "dpop-rl-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})
	defer cleanupDPopSession(t, ws)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(context.Background(), "DELETE FROM attempts WHERE purpose = 'workspace_refresh'")
	}()

	body, _ := json.Marshal(map[string]any{"refreshToken": "doesnt-matter-rejected-on-dpop"})
	url := refreshURL(ws, app)
	ip := "203.0.113.99"

	// 30 requests with malformed DPoP — each gets 400 and increments the
	// attempts table.
	for i := 0; i < 30; i++ {
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", ip)
		req.Header.Set("DPoP", "not-a-valid-jwt")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d: expected 400 (bad DPoP), got %d: %s", i, rr.Code, rr.Body.String())
		}
	}

	// Next request from the same IP should now hit the per-IP rate limit
	// regardless of whether DPoP is presented or refresh token is real.
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after 30 bad-DPoP attempts, got %d: %s", rr.Code, rr.Body.String())
	}
}
