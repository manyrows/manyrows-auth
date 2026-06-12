package api_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"manyrows-core/api"
	"manyrows-core/auth"
	"manyrows-core/auth/client"
	"manyrows-core/config"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/crypto"
	"manyrows-core/db"
	"manyrows-core/email"
	"manyrows-core/utils"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/gorilla/sessions"
)

// TestEnv holds shared test infrastructure
type TestEnv struct {
	DB          *db.DB
	Repo        *repo.Repo
	CookieStore *sessions.CookieStore
}

var testEnv *TestEnv

func TestMain(m *testing.M) {
	var err error
	testEnv, err = setupTestEnv()
	if err != nil {
		panic("failed to setup test environment: " + err.Error())
	}
	// Trust every peer in the test process. httptest.NewRequest's
	// default RemoteAddr (192.0.2.1) isn't in the production "private"
	// allow-list, so without this any test that uses X-Forwarded-For
	// to control the perceived client IP would silently fall back to
	// the shared default and collide with other tests' rate-limit
	// state. Production installs configure MANYROWS_TRUSTED_PROXIES
	// explicitly; tests don't need that ceremony.
	if err := auth.SetTrustedProxiesFromEnv("*"); err != nil {
		panic("failed to set trusted proxies in test setup: " + err.Error())
	}
	// Reset bootstrapped system_secrets rows that the encrypting wrapper
	// would have migrated under whatever encryption_key the prior
	// process used. Without this, a stray `go run ./` against the test
	// DB leaves the JWT/session/otp rows encrypted under a key the test
	// process doesn't have, and every subsequent test that constructs
	// client.NewAuthService fails decrypt. encryption_key itself is
	// preserved so the test config's expectations don't drift.
	if _, err := testEnv.DB.Pool().Exec(context.Background(),
		`DELETE FROM system_secrets WHERE name IN ('jwt_signing_key_pem','jwt_signing_key_pem_previous','session_auth_key','session_secret_key','otp_pepper')`,
	); err != nil {
		panic("failed to reset bootstrap secrets in test setup: " + err.Error())
	}
	code := m.Run()
	testEnv.Cleanup()
	os.Exit(code)
}

func setupTestEnv() (*TestEnv, error) {
	// TEST_DATABASE_URL is REQUIRED. The previous behaviour fell back to
	// DATABASE_URL (the dev database) which silently dumped fixture rows
	// — workspaces, users, sessions, auth_scopes — into local dev
	// databases. Refuse to start tests without an explicit, separate
	// test database to make the footgun impossible.
	dbURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if dbURL == "" {
		return nil, errors.New("TEST_DATABASE_URL must be set to a dedicated test database — refusing to fall back to DATABASE_URL because tests insert fixtures destructively")
	}

	dbConf := db.Config{
		DatabaseURL: dbURL,
		MaxConns:    5,
	}

	dbInstance, err := db.New(dbConf)
	if err != nil {
		return nil, err
	}

	repoInstance := repo.NewRepo(dbInstance)

	// Create cookie store with test keys
	authKey := []byte("0123456789012345678901234567890123456789012345678901234567890123")
	encKey := []byte("01234567890123456789012345678901")
	cookieStore := sessions.NewCookieStore(authKey, encKey)
	cookieStore.Options.Secure = false
	cookieStore.Options.SameSite = http.SameSiteLaxMode

	return &TestEnv{
		DB:          dbInstance,
		Repo:        repoInstance,
		CookieStore: cookieStore,
	}, nil
}

func (e *TestEnv) Cleanup() {
	if e.DB != nil {
		e.DB.Shutdown()
	}
}

// cleanupUser deletes a test user by id. Best-effort.
func cleanupUser(t *testing.T, userID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
}

// TestFixtures holds created test data for a test run
type TestFixtures struct {
	Account    *core.Account
	Workspace  *core.Workspace
	Workspaces []*core.Workspace
	Projects   []core.Project
	Session    *core.Session
}

// CreateTestAccount creates a test account
func (e *TestEnv) CreateTestAccount(t *testing.T, email string) *core.Account {
	t.Helper()
	ctx := context.Background()

	acc := &core.Account{
		ID:        utils.NewUUID(),
		Email:     email,
		Name:      "Test User",
		CreatedAt: time.Now().UTC(),
	}

	tx, err := e.DB.Pool().Begin(ctx)
	if err != nil {
		t.Fatalf("failed to begin tx: %v", err)
	}
	defer tx.Rollback(ctx)

	vr, err := e.Repo.InsertAccount(ctx, tx, acc)
	if err != nil {
		t.Fatalf("failed to insert account: %v", err)
	}
	if !vr.Ok() {
		t.Fatalf("failed to insert account: %v", vr.Issues)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("failed to commit: %v", err)
	}

	t.Cleanup(func() {
		_, _ = e.DB.Pool().Exec(context.Background(), "DELETE FROM accounts WHERE id = $1", acc.ID)
	})

	return acc
}

// CreateTestWorkspace creates a test workspace and adds the account as owner
func (e *TestEnv) CreateTestWorkspace(t *testing.T, acc *core.Account, name, slug string) *core.Workspace {
	t.Helper()
	ctx := context.Background()

	ws := &core.Workspace{
		ID:        utils.NewUUID(),
		Name:      name,
		Slug:      slug,
		CreatedBy: &acc.ID,
	}

	tx, err := e.DB.Pool().Begin(ctx)
	if err != nil {
		t.Fatalf("failed to begin tx: %v", err)
	}
	defer tx.Rollback(ctx)

	if err := e.Repo.InsertWorkspace(ctx, ws, tx); err != nil {
		t.Fatalf("failed to insert workspace: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("failed to commit: %v", err)
	}

	// Insert workspace_admins row for the owner (after commit so FK is satisfied)
	admin := core.WorkspaceAdmin{
		WorkspaceID: ws.ID,
		AccountID:   acc.ID,
		Role:        "owner",
		AddedBy:     &acc.ID,
	}
	if err := e.Repo.AddWorkspaceAdmin(ctx, admin); err != nil {
		t.Fatalf("failed to add workspace admin: %v", err)
	}

	t.Cleanup(func() {
		_, _ = e.DB.Pool().Exec(context.Background(), "DELETE FROM workspaces WHERE id = $1", ws.ID)
	})

	return ws
}

// CreateTestProject creates a test project in a workspace.
// The slug param is retained for call-site backward compatibility but
// is otherwise ignored — projects no longer carry a slug post-c46.
func (e *TestEnv) CreateTestProject(t *testing.T, ws *core.Workspace, acc *core.Account, name, _ string) *core.Project {
	t.Helper()
	ctx := context.Background()

	p := core.Project{
		ID:          utils.NewUUID(),
		WorkspaceID: ws.ID,
		Name:        name,
		CreatedBy:   acc.ID,
	}

	if err := e.Repo.InsertProject(ctx, p); err != nil {
		t.Fatalf("failed to insert project: %v", err)
	}

	// Fetch the project to get timestamps
	project, err := e.Repo.GetProject(ctx, p.ID, ws.ID)
	if err != nil {
		t.Fatalf("failed to get project: %v", err)
	}

	t.Cleanup(func() {
		_, _ = e.DB.Pool().Exec(context.Background(), "DELETE FROM projects WHERE id = $1", p.ID)
	})

	return project
}

func (e *TestEnv) CreateTestApp(t *testing.T, ws *core.Workspace, acc *core.Account) *core.App {
	t.Helper()
	ctx := context.Background()

	proj := e.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))

	pool, err := e.Repo.CreateUserPool(ctx, ws.ID, "Test Pool "+GenerateUniqueSlug("pool"))
	if err != nil {
		t.Fatalf("failed to create user pool: %v", err)
	}

	app := core.App{
		ID:                   utils.NewUUID(),
		WorkspaceID:          ws.ID,
		ProjectID:            proj.ID,
		UserPoolID:           pool.ID,
		Type:                 "dev",
		Enabled:              true,
		PrimaryAuthMethod:    core.PrimaryAuthMethodPassword,
		AllowAccountDeletion: true, // mirror DB default (DEFAULT true)
	}
	app, err = e.Repo.InsertApp(ctx, app)
	if err != nil {
		t.Fatalf("failed to insert app: %v", err)
	}

	t.Cleanup(func() {
		// app first (user_pools.id ← apps.user_pool_id is ON DELETE
		// RESTRICT), then the pool. Workspace-level cascade also covers
		// these, but explicit cleanup keeps shared-workspace tests from
		// piling up apps and biting future migrations like 00004 did.
		_, _ = e.DB.Pool().Exec(context.Background(), "DELETE FROM apps WHERE id = $1", app.ID)
		_, _ = e.DB.Pool().Exec(context.Background(), "DELETE FROM user_pools WHERE id = $1", pool.ID)
	})

	return &app
}

// GetOrCreateUserWithMembership is the test-fixture wrapper around
// Repo.GetOrCreateUser. After the Position B refactor, end-user
// sign-in requires both a pool user AND an app_users membership row;
// tests that just want to seed "a user who can authenticate to this
// app" need both. Returns the same (user, created, err) shape as
// GetOrCreateUser so existing call sites can swap function name only.
//
// Tolerates a partial *core.App literal (just ID set, no UserPoolID).
// Many existing tests build a synthetic app by ID; we load the real
// row here so the GetOrCreateUser pool lookup has a non-nil pool id.
func (e *TestEnv) GetOrCreateUserWithMembership(
	ctx context.Context,
	email string,
	app *core.App,
	source core.UserSource,
) (*core.User, bool, error) {
	if app != nil && app.UserPoolID == uuid.Nil && app.ID != uuid.Nil {
		loaded, err := e.Repo.GetAppByID(ctx, app.ID)
		if err != nil {
			return nil, false, err
		}
		app = &loaded
	}
	user, created, err := e.Repo.GetOrCreateUser(ctx, email, app, source)
	if err != nil {
		return nil, false, err
	}
	if _, _, err := e.Repo.EnsureAppMember(ctx, app.ID, user.ID, source); err != nil {
		return nil, false, err
	}
	return user, created, nil
}

// CreateTestSession creates a test session for authentication
func (e *TestEnv) CreateTestSession(t *testing.T, acc *core.Account) (*core.Session, core.TokenClaims) {
	t.Helper()
	ctx := context.Background()

	// Generate token claims
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("failed to generate secret: %v", err)
	}

	tokenID := utils.NewUUID()
	sum := sha256.Sum256(secret)
	secretHash := sum[:]

	tokenPrefix := tokenID.String()
	if len(tokenPrefix) > 8 {
		tokenPrefix = tokenPrefix[:8]
	}

	now := time.Now().UTC()
	expiresAt := now.Add(24 * time.Hour)

	sess := &core.Session{
		ID:              utils.NewUUID(),
		AccountID:       acc.ID,
		CreatedAt:       now,
		LastSeenAt:      now,
		ExpiresAt:       expiresAt,
		TokenID:         tokenID,
		TokenSecretHash: secretHash,
		TokenPrefix:     tokenPrefix,
		UserAgent:       "test-agent",
		IP:              "127.0.0.1",
	}

	if err := e.Repo.InsertSession(ctx, sess); err != nil {
		t.Fatalf("failed to insert session: %v", err)
	}

	claims := core.TokenClaims{
		TokenID: tokenID,
		Secret:  secret,
	}

	return sess, claims
}

// SetSessionCookie adds the session cookie to a request
func (e *TestEnv) SetSessionCookie(t *testing.T, r *http.Request, claims core.TokenClaims) {
	t.Helper()

	// Create a temporary response writer to save the session
	w := httptest.NewRecorder()

	sess, err := e.CookieStore.Get(r, "MRSESSION")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}

	sess.Values["tid"] = claims.TokenID.String()
	sess.Values["ts"] = base64.RawURLEncoding.EncodeToString(claims.Secret)

	if err := sess.Save(r, w); err != nil {
		t.Fatalf("failed to save session: %v", err)
	}

	// Copy cookies from response to request
	for _, cookie := range w.Result().Cookies() {
		r.AddCookie(cookie)
	}
}

// CleanupTestData removes test data by unique identifiers
func (e *TestEnv) CleanupTestData(t *testing.T, fixtures *TestFixtures) {
	t.Helper()
	ctx := context.Background()
	pool := e.DB.Pool()

	// Delete in reverse order of dependencies
	for _, p := range fixtures.Projects {
		_, _ = pool.Exec(ctx, "DELETE FROM projects WHERE id = $1", p.ID)
	}

	if fixtures.Session != nil {
		_, _ = pool.Exec(ctx, "DELETE FROM sessions WHERE id = $1", fixtures.Session.ID)
	}

	if fixtures.Workspace != nil {
		_, _ = pool.Exec(ctx, "DELETE FROM workspace_accounts WHERE workspace_id = $1", fixtures.Workspace.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspace_admins WHERE workspace_id = $1", fixtures.Workspace.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspace_members WHERE workspace_id = $1", fixtures.Workspace.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspaces WHERE id = $1", fixtures.Workspace.ID)
	}

	for _, ws := range fixtures.Workspaces {
		_, _ = pool.Exec(ctx, "DELETE FROM workspace_accounts WHERE workspace_id = $1", ws.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspace_admins WHERE workspace_id = $1", ws.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspace_members WHERE workspace_id = $1", ws.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspaces WHERE id = $1", ws.ID)
	}

	if fixtures.Account != nil {
		_, _ = pool.Exec(ctx, "DELETE FROM accounts WHERE id = $1", fixtures.Account.ID)
	}
}

// ClearRateLimitAttempts clears all rate limit attempts from the database
// Call this at the start of tests that involve rate-limited endpoints
func (e *TestEnv) ClearRateLimitAttempts(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	_, err := e.DB.Pool().Exec(ctx, "DELETE FROM attempts")
	if err != nil {
		t.Fatalf("failed to clear rate limit attempts: %v", err)
	}
}

// SetWorkspacePlan is a no-op kept for compatibility with existing
// tests after the billing/plans rip-out. There is no plan concept in
// the self-hosted shape, so registration / API limits no longer
// depend on a per-workspace tier. Tests that previously relied on
// "promote this workspace to Pro for the test" now just inherit the
// always-unlimited behaviour.
func (e *TestEnv) SetWorkspacePlan(_ *testing.T, _ uuid.UUID, _ string) {}

// GetTestConfig returns a config suitable for testing
func GetTestConfig() *config.Config {
	// Set required environment variables for testing
	os.Setenv("MANYROWS_BASE_URL", "http://localhost:8080")
	os.Setenv("MANYROWS_SESSION_AUTH_KEY", "0123456789012345678901234567890123456789012345678901234567890123")
	os.Setenv("MANYROWS_SESSION_SECRET_KEY", "01234567890123456789012345678901")
	// Explicit prefix — preserves the legacy interpretation (base64
	// decode → 24 bytes / AES-192) without tripping the ambiguity
	// warning C3 added.
	os.Setenv("MANYROWS_ENCRYPTION_KEY", "base64:01234567890123456789012345678901")
	os.Setenv("MANYROWS_OTP_PEPPER", "test-otp-pepper-value-here")
	os.Setenv("MANYROWS_PROFILE", "dev")

	return config.NewConfig("MANYROWS_")
}

// GenerateUniqueSlug generates a unique slug for testing
func GenerateUniqueSlug(prefix string) string {
	return prefix + "-" + uuid.Must(uuid.NewV4()).String()[:8]
}

// ── Shared test router helpers ──────────────────────────────────────────

// TestServices bundles services needed by test routers.
type TestServices struct {
	Handler    *api.RequestHandler
	AdminAuth  *auth.Service
	ClientAuth *client.AuthService
	EmailSvc   *email.Service
	Config     *config.Config
}

// NewTestServices creates all shared services for a test.
func NewTestServices(t *testing.T) *TestServices {
	t.Helper()
	cfg := GetTestConfig()
	adminAuth, err := auth.NewAuthService(cfg, testEnv.Repo)
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}
	clientAuth, err := client.NewAuthService(cfg, testEnv.Repo, nil)
	if err != nil {
		t.Fatalf("failed to create client auth service: %v", err)
	}
	emailSvc := email.NewEmailService(true, nil)
	encryptor := crypto.NewMySecretEncryptor(cfg)
	handler := api.NewRequestHandler(testEnv.Repo, adminAuth, clientAuth, emailSvc, cfg, encryptor, nil)
	return &TestServices{Handler: handler, AdminAuth: adminAuth, ClientAuth: clientAuth, EmailSvc: emailSvc, Config: cfg}
}

// AdminAuthMiddleware returns middleware that authenticates an admin account from session cookies.
func AdminAuthMiddleware(adminAuth *auth.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			acc, _, err := adminAuth.GetLoggedInAccount(r)
			if err != nil || acc == nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			ctx := core.WithAdminAccount(r.Context(), acc)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// WorkspaceOwnerMiddleware returns middleware that validates workspace ownership and sets context.
func WorkspaceOwnerMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			acc, ok := core.AdminAccountFromContext(ctx)
			if !ok || acc == nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			wsID, err := uuid.FromString(chi.URLParam(r, "workspaceId"))
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
			ctx = core.WithWorkspaceRole(ctx, "owner")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// NewAdminWorkspaceRouter creates the standard admin + workspace router scaffold.
// Returns (outerRouter, workspaceRouter) so callers can register routes on the workspace router.
func NewAdminWorkspaceRouter(t *testing.T, svc *TestServices) (*chi.Mux, chi.Router) {
	t.Helper()
	r := chi.NewRouter()
	adminRouter := chi.NewRouter()
	adminRouter.Use(AdminAuthMiddleware(svc.AdminAuth))
	wsRouter := chi.NewRouter()
	wsRouter.Use(WorkspaceOwnerMiddleware())
	adminRouter.Mount("/workspace/{workspaceId}", wsRouter)
	r.Mount("/admin", adminRouter)
	return r, wsRouter
}
