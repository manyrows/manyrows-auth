package api_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"manyrows-core/auth/client"
	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

// setupPasskeyRegisterRouter builds a minimal chi router that mirrors the
// production /x/{slug}/apps/{appId}/a/passkey/register/begin path, using
// the same session-based authentication middleware the real client router uses.
func setupPasskeyRegisterRouter(t *testing.T) (*chi.Mux, *client.AuthService) {
	t.Helper()
	svc := NewTestServices(t)

	clientAuth, err := client.NewAuthService(svc.Config, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("create client auth: %v", err)
	}

	r := chi.NewRouter()

	wsRouter := chi.NewRouter()
	wsRouter.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			workspaceSlug := chi.URLParam(r, "workspaceSlug")
			ws, ok, err := testEnv.Repo.GetWorkspaceBySlug(ctx, workspaceSlug)
			if err != nil || !ok {
				http.Error(w, "workspace not found", http.StatusNotFound)
				return
			}
			next.ServeHTTP(w, r.WithContext(core.WithWorkspace(ctx, ws)))
		})
	})

	wsRouter.Route("/apps/{appId}", func(ar chi.Router) {
		ar.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := r.Context()
				appID, err := uuid.FromString(chi.URLParam(r, "appId"))
				if err != nil {
					http.Error(w, "invalid app id", http.StatusBadRequest)
					return
				}
				app, err := testEnv.Repo.GetAppByID(ctx, appID)
				if err != nil {
					http.Error(w, "app not found", http.StatusNotFound)
					return
				}
				next.ServeHTTP(w, r.WithContext(core.WithApp(ctx, &app)))
			})
		})

		ar.Route("/a", func(authed chi.Router) {
			authed.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					app, _ := core.AppFromContext(r.Context())
					if app == nil {
						http.Error(w, "unauthorized", http.StatusUnauthorized)
						return
					}
					loggedIn, ses, err := clientAuth.IsLoggedIntoApp(r, app.ID)
					if err != nil || !loggedIn || ses == nil {
						http.Error(w, "unauthorized", http.StatusUnauthorized)
						return
					}
					next.ServeHTTP(w, r.WithContext(core.WithClientSessionContext(r.Context(), ses)))
				})
			})
			authed.Post("/passkey/register/begin", svc.Handler.WorkspacePasskeyRegisterBegin)
		})
	})

	r.Mount("/x/{workspaceSlug}", wsRouter)
	return r, clientAuth
}

// seedPasskeyFixture sets up: workspace, app (with WebAuthn enabled), user, and
// a client session. Returns everything the caller needs.
type passkeyFixture struct {
	ws          *core.Workspace
	app         *core.App
	user        *core.User
	accessToken string
}

func newPasskeyFixture(t *testing.T, clientAuth *client.AuthService) *passkeyFixture {
	t.Helper()
	ctx := context.Background()

	acc := testEnv.CreateTestAccount(t, "pk-excl-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "PK Exclusions WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)

	// Enable WebAuthn: set RPID to "localhost" (special-cased by the validator)
	// and add a matching CORS origin.
	rpid := "localhost"
	if err := testEnv.Repo.SetAppWebAuthnRPID(ctx, app.ID, &rpid); err != nil {
		t.Fatalf("set rpid: %v", err)
	}
	if err := testEnv.Repo.InsertCorsOrigin(ctx, core.CorsOrigin{
		ID:        uuid.Must(uuid.NewV4()),
		AppID:     app.ID,
		Origin:    "http://localhost:5173",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed cors origin: %v", err)
	}

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, "pk-u-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceRegistered)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	})

	ses, err := clientAuth.CreateSession(ctx, user.ID, app.ID, "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	tokens, err := clientAuth.IssueTokenPair(ctx, ses, "test-agent", "127.0.0.1", 0, 0, "", "", "")
	if err != nil {
		t.Fatalf("issue tokens: %v", err)
	}

	return &passkeyFixture{ws: ws, app: app, user: user, accessToken: tokens.AccessToken}
}

// postRegisterBegin issues a POST to the register/begin endpoint and returns
// the response recorder.
func postRegisterBegin(t *testing.T, router *chi.Mux, fx *passkeyFixture) *httptest.ResponseRecorder {
	t.Helper()
	url := "/x/" + fx.ws.Slug + "/apps/" + fx.app.ID.String() + "/a/passkey/register/begin"
	req := httptest.NewRequest(http.MethodPost, url, nil)
	req.Header.Set("Authorization", "Bearer "+fx.accessToken)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// TestPasskeyRegisterBegin_ExcludesExistingCredentials verifies that when the
// user already has a passkey, the BeginRegistration response includes an
// excludeCredentials list containing that credential's ID.
func TestPasskeyRegisterBegin_ExcludesExistingCredentials(t *testing.T) {
	ctx := context.Background()
	router, clientAuth := setupPasskeyRegisterRouter(t)
	testEnv.ClearRateLimitAttempts(t)

	fx := newPasskeyFixture(t, clientAuth)

	// Seed one passkey for the user. Use a deterministic credential ID so we
	// can look for it in the response.
	credID := uuid.Must(uuid.NewV4()).Bytes()
	_, err := testEnv.Repo.InsertPasskey(ctx, core.UserPasskey{
		AppID:        fx.app.ID,
		UserID:       fx.user.ID,
		CredentialID: credID,
		PublicKey:    utils.NewUUID().Bytes(), // arbitrary bytes for the key
		Transports:   []string{"internal"},
	})
	if err != nil {
		t.Fatalf("insert passkey: %v", err)
	}

	rr := postRegisterBegin(t, router, fx)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// The response is { challengeId, publicKeyOptions } where publicKeyOptions
	// is the go-webauthn creation options object (which itself wraps publicKey).
	var outer struct {
		ChallengeID      string          `json:"challengeId"`
		PublicKeyOptions json.RawMessage `json:"publicKeyOptions"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&outer); err != nil {
		t.Fatalf("decode outer: %v", err)
	}

	// go-webauthn serialises the creation options as { "publicKey": { ... } }
	var pkWrapper struct {
		PublicKey struct {
			ExcludeCredentials []struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"excludeCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(outer.PublicKeyOptions, &pkWrapper); err != nil {
		t.Fatalf("decode publicKeyOptions: %v", err)
	}

	excludes := pkWrapper.PublicKey.ExcludeCredentials
	if len(excludes) == 0 {
		t.Fatal("expected excludeCredentials to be non-empty, got empty")
	}

	// The credential ID is base64url-encoded in the JSON response.
	want := base64.RawURLEncoding.EncodeToString(credID)
	found := false
	for _, ex := range excludes {
		if ex.ID == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("seeded credential ID %q not found in excludeCredentials: %v", want, excludes)
	}
}

// TestPasskeyRegisterBegin_NoPasskeys_NoExclusions verifies that for a user
// with no passkeys, excludeCredentials is absent or empty.
func TestPasskeyRegisterBegin_NoPasskeys_NoExclusions(t *testing.T) {
	router, clientAuth := setupPasskeyRegisterRouter(t)
	testEnv.ClearRateLimitAttempts(t)

	fx := newPasskeyFixture(t, clientAuth)

	rr := postRegisterBegin(t, router, fx)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var outer struct {
		PublicKeyOptions json.RawMessage `json:"publicKeyOptions"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&outer); err != nil {
		t.Fatalf("decode outer: %v", err)
	}

	var pkWrapper struct {
		PublicKey struct {
			ExcludeCredentials []json.RawMessage `json:"excludeCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(outer.PublicKeyOptions, &pkWrapper); err != nil {
		t.Fatalf("decode publicKeyOptions: %v", err)
	}

	if len(pkWrapper.PublicKey.ExcludeCredentials) != 0 {
		t.Errorf("expected excludeCredentials to be empty for a fresh user, got %d entries", len(pkWrapper.PublicKey.ExcludeCredentials))
	}
}
