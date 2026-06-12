package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"manyrows-core/core"
	"manyrows-core/utils"
)

func TestApp_ConsentColumnsRoundTrip(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "consent-"+GenerateUniqueSlug("t")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Consent WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	// Defaults: empty/false.
	got, err := testEnv.Repo.GetAppByID(ctx, app.ID)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}
	if got.RequireConsent || got.ConsentVersion != "" || got.TermsURL != "" || got.PrivacyURL != "" {
		t.Fatalf("expected empty consent defaults, got %+v", got)
	}

	// Set via raw SQL, re-read through the scanner.
	if _, err := testEnv.DB.Pool().Exec(ctx,
		`UPDATE apps SET terms_url=$2, privacy_url=$3, consent_version=$4, require_consent=true WHERE id=$1`,
		app.ID, "https://t", "https://p", "v1"); err != nil {
		t.Fatalf("update: %v", err)
	}
	got2, _ := testEnv.Repo.GetAppByID(ctx, app.ID)
	if !got2.RequireConsent || got2.ConsentVersion != "v1" || got2.TermsURL != "https://t" || got2.PrivacyURL != "https://p" {
		t.Fatalf("consent columns not scanned: %+v", got2)
	}
}

func TestUserConsentRepo_InsertAndGet(t *testing.T) {
	ctx := context.Background()
	emailAddr := "uc-" + GenerateUniqueSlug("t") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "UC WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() { _, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id=$1", user.ID) })

	if err := testEnv.Repo.InsertUserConsent(ctx, utils.NewUUID(), user.ID, app.ID, "terms", "v1", "203.0.113.5", "test-agent"); err != nil {
		t.Fatalf("InsertUserConsent: %v", err)
	}
	got, err := testEnv.Repo.GetLatestUserConsent(ctx, user.ID, app.ID, "terms")
	if err != nil {
		t.Fatalf("GetLatestUserConsent: %v", err)
	}
	if got == nil || got.Version != "v1" || got.Kind != "terms" {
		t.Fatalf("unexpected consent: %+v", got)
	}
}

// consentSignupSetup builds an app with require_consent and a seeded register OTP.
// It returns the router, ws, app, the email, and the known code.
func consentSignupSetup(t *testing.T, requireConsent bool, version string) (router http.Handler, ws *core.Workspace, app *core.App, emailAddr, code string) {
	t.Helper()
	router = setupClientAPIRouter(t)
	ctx := context.Background()
	emailAddr = "signup-" + GenerateUniqueSlug("t") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws = testEnv.CreateTestWorkspace(t, acc, "Signup WS", GenerateUniqueSlug("ws"))
	app = testEnv.CreateTestApp(t, ws, acc)
	if _, err := testEnv.DB.Pool().Exec(ctx,
		`UPDATE apps SET allow_registration=true, require_consent=$2, consent_version=$3 WHERE id=$1`,
		app.ID, requireConsent, version); err != nil {
		t.Fatalf("config app: %v", err)
	}
	// Seed a register OTP for emailAddr.
	code = "654321"
	otpID := utils.NewUUID()
	codeHash := testHashOTP(otpID, code, testOTPPepper)
	if err := testEnv.Repo.InsertClientOTP(ctx, core.ClientOTPCode{
		ID:        otpID,
		AppID:     app.ID,
		EmailNorm: emailAddr,
		CodeHash:  codeHash,
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("seed otp: %v", err)
	}
	t.Cleanup(func() { _, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE email=$1", emailAddr) })
	return
}

func consentVerifyPath(ws *core.Workspace, app *core.App) string {
	return "/x/" + ws.Slug + "/apps/" + app.ID.String() + "/auth/verify"
}

func TestSignup_ConsentRequired_Rejected(t *testing.T) {
	router, ws, app, emailAddr, code := consentSignupSetup(t, true, "v1")
	body, _ := json.Marshal(map[string]any{"email": emailAddr, "code": code, "appId": app.ID})
	req := httptest.NewRequest(http.MethodPost, consentVerifyPath(ws, app), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rr.Code, rr.Body.String())
	}
	var cnt int
	_ = testEnv.DB.Pool().QueryRow(context.Background(), "SELECT count(*) FROM users WHERE email=$1", emailAddr).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("user created despite missing consent")
	}
}

func TestSignup_ConsentAccepted_CreatesUserAndRecords(t *testing.T) {
	router, ws, app, emailAddr, code := consentSignupSetup(t, true, "v1")
	body, _ := json.Marshal(map[string]any{"email": emailAddr, "code": code, "appId": app.ID, "consentAccepted": true, "consentVersion": "v1"})
	req := httptest.NewRequest(http.MethodPost, consentVerifyPath(ws, app), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var uid string
	if err := testEnv.DB.Pool().QueryRow(context.Background(), "SELECT id FROM users WHERE email=$1", emailAddr).Scan(&uid); err != nil {
		t.Fatalf("user not created: %v", err)
	}
	var n int
	_ = testEnv.DB.Pool().QueryRow(context.Background(),
		"SELECT count(*) FROM user_consents WHERE user_id=$1 AND app_id=$2 AND kind='terms' AND version='v1'", uid, app.ID).Scan(&n)
	if n != 1 {
		t.Fatalf("consent not recorded (n=%d)", n)
	}
}

func TestSignup_ConsentVersionMismatch_Rejected(t *testing.T) {
	router, ws, app, emailAddr, code := consentSignupSetup(t, true, "v1")
	body, _ := json.Marshal(map[string]any{"email": emailAddr, "code": code, "appId": app.ID, "consentAccepted": true, "consentVersion": "v0"})
	req := httptest.NewRequest(http.MethodPost, consentVerifyPath(ws, app), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rr.Code, rr.Body.String())
	}
	var cnt int
	_ = testEnv.DB.Pool().QueryRow(context.Background(), "SELECT count(*) FROM users WHERE email=$1", emailAddr).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("user created despite version mismatch")
	}
}

func TestSignup_ConsentRequiredButVersionUnset_Blocks(t *testing.T) {
	router, ws, app, emailAddr, code := consentSignupSetup(t, true, "")
	body, _ := json.Marshal(map[string]any{"email": emailAddr, "code": code, "appId": app.ID, "consentAccepted": true})
	req := httptest.NewRequest(http.MethodPost, consentVerifyPath(ws, app), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rr.Code, rr.Body.String())
	}
	var cnt int
	_ = testEnv.DB.Pool().QueryRow(context.Background(), "SELECT count(*) FROM users WHERE email=$1", emailAddr).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("user created despite missing consent_version in app config")
	}
}

func TestSignup_ConsentNotRequired_NoEnforcement(t *testing.T) {
	router, ws, app, emailAddr, code := consentSignupSetup(t, false, "")
	body, _ := json.Marshal(map[string]any{"email": emailAddr, "code": code, "appId": app.ID})
	req := httptest.NewRequest(http.MethodPost, consentVerifyPath(ws, app), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCollectUserEmailHistory(t *testing.T) {
	ctx := context.Background()
	emailAddr := "hist-" + GenerateUniqueSlug("t") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Hist WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() { _, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id=$1", user.ID) })

	// Seed an email-change history row in auth_logs metadata.
	oldEmail := "old-" + GenerateUniqueSlug("t") + "@example.com"
	_, _ = testEnv.DB.Pool().Exec(ctx, `
		INSERT INTO auth_logs (id, workspace_id, app_id, event, outcome, actor_type, subject_user_id, metadata)
		VALUES ($1,$2,$3,'email.changed','success','self',$4, jsonb_build_object('old_email',$5::text,'new_email',$6::text))`,
		utils.NewUUID(), ws.ID, app.ID, user.ID, oldEmail, emailAddr)

	got, err := testEnv.Repo.CollectUserEmailHistory(ctx, user.ID, emailAddr)
	if err != nil {
		t.Fatalf("CollectUserEmailHistory: %v", err)
	}
	set := map[string]bool{}
	for _, e := range got {
		set[e] = true
	}
	if !set[strings.ToLower(emailAddr)] || !set[strings.ToLower(oldEmail)] {
		t.Fatalf("expected current+old email, got %v", got)
	}
}

func TestBootstrap_ExposesConsentConfig(t *testing.T) {
	// setupClientAPIRouter mounts GET /x/{slug}/apps/{appId} -> HandleGetAppForAppKit
	router := setupClientAPIRouter(t)
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "boot-"+GenerateUniqueSlug("t")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Boot WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	_, _ = testEnv.DB.Pool().Exec(ctx,
		`UPDATE apps SET require_consent=true, consent_version='v2', terms_url='https://t', privacy_url='https://p' WHERE id=$1`, app.ID)

	req := httptest.NewRequest(http.MethodGet, "/x/"+ws.Slug+"/apps/"+app.ID.String(), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["requireConsent"] != true || out["consentVersion"] != "v2" || out["termsUrl"] != "https://t" || out["privacyUrl"] != "https://p" {
		t.Fatalf("bootstrap missing consent config: %v", out)
	}
}
