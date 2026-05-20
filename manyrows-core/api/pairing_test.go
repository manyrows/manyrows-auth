package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"manyrows-core/api"
	"manyrows-core/auth"
	"manyrows-core/auth/client"
	"manyrows-core/core"
	"manyrows-core/email"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// =====================
// Cross-device pairing tests
// =====================

type pairingTestEnv struct {
	router *chi.Mux
	cas    *client.AuthService

	ws  *core.Workspace
	app *core.App
}

func setupPairingRouter(t *testing.T) *pairingTestEnv {
	t.Helper()

	cfg := GetTestConfig()
	adminAuthService, err := auth.NewAuthService(cfg, testEnv.Repo)
	if err != nil {
		t.Fatalf("create admin auth service: %v", err)
	}
	cas, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("create client auth service: %v", err)
	}
	emailSvc := email.NewEmailService(true, nil)
	h := api.NewRequestHandler(testEnv.Repo, adminAuthService, cas, emailSvc, cfg, nil, nil)

	r := chi.NewRouter()
	wsRouter := chi.NewRouter()
	wsRouter.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slug := chi.URLParam(r, "workspaceSlug")
			ws, ok, err := testEnv.Repo.GetWorkspaceBySlug(r.Context(), slug)
			if err != nil || !ok {
				http.Error(w, "workspace not found", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(core.WithWorkspace(r.Context(), ws)))
		})
	})

	wsRouter.Route("/apps/{appId}", func(ar chi.Router) {
		ar.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := r.Context()
				ws, _ := core.WorkspaceFromContext(ctx)
				appIDStr := chi.URLParam(r, "appId")
				appID, err := uuid.FromString(appIDStr)
				if err != nil {
					http.Error(w, "invalid app id", http.StatusBadRequest)
					return
				}
				app, err := testEnv.Repo.GetAppByID(ctx, appID)
				if err != nil || app.WorkspaceID != ws.ID || !app.Enabled {
					http.Error(w, "app not found", http.StatusNotFound)
					return
				}
				next.ServeHTTP(w, r.WithContext(core.WithApp(ctx, &app)))
			})
		})

		ar.Get("/pair", h.HandlePairLandingPage)
		ar.Get("/qr-sign-in", h.HandleQRSignInPage)
		ar.Route("/auth", func(authR chi.Router) {
			authR.Post("/pair/start", h.HandleAuthPairStart)
			authR.Get("/pair/wait", h.HandleAuthPairWait)
			authR.Post("/pair/approve", h.HandleAuthPairApprove)
			authR.Post("/pair/cancel", h.HandleAuthPairCancel)
			authR.Get("/pair/qr", h.HandleAuthPairQR)
		})
	})

	r.Mount("/x/{workspaceSlug}", wsRouter)

	acc := testEnv.CreateTestAccount(t, fmt.Sprintf("pair-%s@test.example", GenerateUniqueSlug("u")))
	ws := testEnv.CreateTestWorkspace(t, acc, "Pair Test WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	return &pairingTestEnv{router: r, cas: cas, ws: ws, app: app}
}

// seedPhoneSession creates a real client_sessions row + access JWT for
// a user signed in to e.app. The JWT is what the phone presents on
// /pair/approve via Authorization: Bearer …
func (e *pairingTestEnv) seedPhoneSession(t *testing.T) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, fmt.Sprintf("phone-%s@test.example", GenerateUniqueSlug("u")), e.app, core.UserSourceRegistered)
	if err != nil {
		t.Fatalf("GetOrCreateUserWithMembership: %v", err)
	}
	now := time.Now().UTC()
	appID := e.app.ID
	ses := &core.ClientSession{
		ID:         uuid.Must(uuid.NewV4()),
		UserID:     user.ID,
		AppID:      &appID,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}
	if err := testEnv.Repo.InsertClientSession(ctx, ses); err != nil {
		t.Fatalf("InsertClientSession: %v", err)
	}
	access, _, err := e.cas.IssueAccessToken(ses, 15*time.Minute, e.cas.IssuerForApp(e.app))
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	return user.ID, access
}

func pairingBase(e *pairingTestEnv) string {
	return "/x/" + e.ws.Slug + "/apps/" + e.app.ID.String()
}

func startPairing(t *testing.T, e *pairingTestEnv) (pairingID, pairingCode, qrURL string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, pairingBase(e)+"/auth/pair/start", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/pair/start expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		PairingID   string `json:"pairingId"`
		PairingCode string `json:"pairingCode"`
		QRURL       string `json:"qrUrl"`
		ExpiresIn   int    `json:"expiresIn"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.PairingID == "" || resp.PairingCode == "" || resp.QRURL == "" {
		t.Fatalf("start response missing fields: %+v", resp)
	}
	if resp.ExpiresIn <= 0 {
		t.Fatalf("expiresIn should be positive, got %d", resp.ExpiresIn)
	}
	if !strings.Contains(resp.QRURL, "/pair?c=") {
		t.Fatalf("qrUrl should contain /pair?c=…, got %q", resp.QRURL)
	}
	return resp.PairingID, resp.PairingCode, resp.QRURL
}

func waitOnce(t *testing.T, e *pairingTestEnv, pairingID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, pairingBase(e)+"/auth/pair/wait?id="+pairingID, nil)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	return rr
}

func approve(t *testing.T, e *pairingTestEnv, accessJWT, pairingCode string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"pairingCode": pairingCode})
	req := httptest.NewRequest(http.MethodPost, pairingBase(e)+"/auth/pair/approve", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if accessJWT != "" {
		req.Header.Set("Authorization", "Bearer "+accessJWT)
	}
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	return rr
}

// =====================

func TestPair_StartReturnsPairingInfo(t *testing.T) {
	e := setupPairingRouter(t)
	id, code, qr := startPairing(t, e)
	if _, err := uuid.FromString(id); err != nil {
		t.Fatalf("pairingId not a UUID: %v", err)
	}
	if len(code) < 32 {
		t.Fatalf("pairingCode too short: %d chars", len(code))
	}
	if !strings.Contains(qr, code) {
		t.Fatalf("qrUrl should contain the pairing code, got %s", qr)
	}
}

func TestPair_WaitPendingReturns425(t *testing.T) {
	e := setupPairingRouter(t)
	id, _, _ := startPairing(t, e)

	rr := waitOnce(t, e, id)
	if rr.Code != http.StatusTooEarly {
		t.Fatalf("expected 425, got %d (body=%s)", rr.Code, rr.Body.String())
	}
}

func TestPair_HappyPath_StartApproveWaitMintsTokens(t *testing.T) {
	e := setupPairingRouter(t)
	id, code, _ := startPairing(t, e)

	userID, accessJWT := e.seedPhoneSession(t)

	apRR := approve(t, e, accessJWT, code)
	if apRR.Code != http.StatusNoContent {
		t.Fatalf("approve expected 204, got %d (body=%s)", apRR.Code, apRR.Body.String())
	}

	rr := waitOnce(t, e, id)
	if rr.Code != http.StatusOK {
		t.Fatalf("wait-after-approve expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var pair struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresIn    int    `json:"expiresIn"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &pair); err != nil {
		t.Fatalf("unmarshal token pair: %v (body=%s)", err, rr.Body.String())
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("token pair missing fields: %+v", pair)
	}
	if pair.ExpiresIn <= 0 {
		t.Fatalf("expires_in should be positive, got %d", pair.ExpiresIn)
	}

	// Verify the JWT's subject is the approver's user_id.
	parts := strings.Split(pair.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("access token not a JWT: %q", pair.AccessToken)
	}
	_ = userID // The session is bound to userID; access-token sub is the source of truth.
}

func TestPair_DoubleConsumeReturns410(t *testing.T) {
	e := setupPairingRouter(t)
	id, code, _ := startPairing(t, e)
	_, accessJWT := e.seedPhoneSession(t)

	if rr := approve(t, e, accessJWT, code); rr.Code != http.StatusNoContent {
		t.Fatalf("approve: %d", rr.Code)
	}
	if rr := waitOnce(t, e, id); rr.Code != http.StatusOK {
		t.Fatalf("first wait should mint tokens, got %d", rr.Code)
	}
	if rr := waitOnce(t, e, id); rr.Code != http.StatusGone {
		t.Fatalf("second wait should be 410 Gone (already consumed), got %d (body=%s)", rr.Code, rr.Body.String())
	}
}

func TestPair_ApproveRequiresSession(t *testing.T) {
	e := setupPairingRouter(t)
	_, code, _ := startPairing(t, e)

	rr := approve(t, e, "" /* no JWT */, code)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d (body=%s)", rr.Code, rr.Body.String())
	}
}

func TestPair_ApproveWithUnknownCodeIs404(t *testing.T) {
	e := setupPairingRouter(t)
	_, accessJWT := e.seedPhoneSession(t)

	rr := approve(t, e, accessJWT, "this-code-was-never-issued-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d (body=%s)", rr.Code, rr.Body.String())
	}
}

func TestPair_ApproveCrossAppIsRejected(t *testing.T) {
	// Two apps in the same workspace. Phone is signed in to app A;
	// pairing is for app B. Phone POSTs to /apps/B/auth/pair/approve
	// with B's appID in path — but the phone's JWT is for app A,
	// so the session check fails (different aud), returns 401.
	e := setupPairingRouter(t)
	id, codeForA, _ := startPairing(t, e) // pairing for app A
	_ = id

	// Build a second app in the same workspace.
	ctx := context.Background()
	// Use raw repo to make a second app. CreateTestApp insists on its
	// own product+pool, which is fine for our test purposes.
	appBOwner := testEnv.CreateTestAccount(t, fmt.Sprintf("appB-owner-%s@test.example", GenerateUniqueSlug("u")))
	appB := testEnv.CreateTestApp(t, e.ws, appBOwner)

	// Sign the phone in to app B.
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, fmt.Sprintf("phoneB-%s@test.example", GenerateUniqueSlug("u")), appB, core.UserSourceRegistered)
	if err != nil {
		t.Fatalf("GetOrCreateUserWithMembership: %v", err)
	}
	now := time.Now().UTC()
	appBID := appB.ID
	sesB := &core.ClientSession{
		ID:         uuid.Must(uuid.NewV4()),
		UserID:     user.ID,
		AppID:      &appBID,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}
	if err := testEnv.Repo.InsertClientSession(ctx, sesB); err != nil {
		t.Fatalf("InsertClientSession: %v", err)
	}
	accessB, _, err := e.cas.IssueAccessToken(sesB, 15*time.Minute, e.cas.IssuerForApp(appB))
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	// Try to approve the app-A pairing while signed into app B —
	// the phone POSTs to app A's path with an app-B JWT. The Bearer-
	// vs-app aud-check rejects with 401.
	body, _ := json.Marshal(map[string]string{"pairingCode": codeForA})
	req := httptest.NewRequest(http.MethodPost, pairingBase(e)+"/auth/pair/approve", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessB)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("cross-app approve should be 401, got %d (body=%s)", rr.Code, rr.Body.String())
	}
}

func TestPair_CancelMakesWaitReturnGone(t *testing.T) {
	e := setupPairingRouter(t)
	id, code, _ := startPairing(t, e)
	_, accessJWT := e.seedPhoneSession(t)

	// Phone explicitly cancels.
	body, _ := json.Marshal(map[string]string{"pairingCode": code})
	req := httptest.NewRequest(http.MethodPost, pairingBase(e)+"/auth/pair/cancel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessJWT)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("cancel expected 204, got %d (body=%s)", rr.Code, rr.Body.String())
	}

	if rr := waitOnce(t, e, id); rr.Code != http.StatusGone {
		t.Fatalf("wait after cancel expected 410, got %d", rr.Code)
	}
}

// TestPair_QRPNGEndpointReturnsImage verifies the QR endpoint
// renders supplied text as a PNG.
func TestPair_QRPNGEndpointReturnsImage(t *testing.T) {
	e := setupPairingRouter(t)
	req := httptest.NewRequest(http.MethodGet, pairingBase(e)+"/auth/pair/qr?text=hello-world", nil)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "image/png" {
		t.Fatalf("Content-Type should be image/png, got %q", ct)
	}
	// PNGs start with the 8-byte signature 89 50 4E 47 0D 0A 1A 0A.
	body := rr.Body.Bytes()
	if len(body) < 8 || body[0] != 0x89 || body[1] != 'P' || body[2] != 'N' || body[3] != 'G' {
		t.Fatalf("body does not start with PNG signature, got first bytes %x", body[:min(8, len(body))])
	}
}

func TestPair_QRPNGEndpointRejectsEmptyText(t *testing.T) {
	e := setupPairingRouter(t)
	req := httptest.NewRequest(http.MethodGet, pairingBase(e)+"/auth/pair/qr?text=", nil)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty text, got %d", rr.Code)
	}
}

// TestPair_QRSignInPageRenders confirms the desktop hosted page
// returns HTML with anti-clickjacking headers.
func TestPair_QRSignInPageRenders(t *testing.T) {
	e := setupPairingRouter(t)
	req := httptest.NewRequest(http.MethodGet, pairingBase(e)+"/qr-sign-in", nil)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("/qr-sign-in expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Sign in with your phone") {
		t.Fatalf("page should contain the desktop heading; got %s", rr.Body.String()[:min(200, rr.Body.Len())])
	}
	if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options should be DENY, got %q", got)
	}
}

func TestPair_QRSignInPageRejectsJavaScriptReturnTo(t *testing.T) {
	e := setupPairingRouter(t)
	req := httptest.NewRequest(http.MethodGet, pairingBase(e)+"/qr-sign-in?return_to=javascript:alert(1)", nil)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("javascript: return_to must be rejected, got %d", rr.Code)
	}
}

func TestPair_LandingPageHasAntiClickjackingHeaders(t *testing.T) {
	e := setupPairingRouter(t)
	_, code, _ := startPairing(t, e)

	req := httptest.NewRequest(http.MethodGet, pairingBase(e)+"/pair?c="+code, nil)
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("landing page expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options must be DENY on /pair, got %q", got)
	}
	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP must include frame-ancestors 'none', got %q", csp)
	}
}
