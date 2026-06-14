package core

import (
	"context"
	"errors"
	"time"

	"github.com/gofrs/uuid/v5"
)

type SessionWorkspace struct {
	WorkspaceID uuid.UUID `db:"workspace_id"`
	CreatedAt   time.Time `db:"created_at"`
}

type Session struct {
	ID        uuid.UUID `db:"id"`
	AccountID uuid.UUID `db:"account_id"`

	CreatedAt  time.Time `db:"created_at"`
	ExpiresAt  time.Time `db:"expires_at"`
	LastSeenAt time.Time `db:"last_seen_at"`

	TokenID uuid.UUID `db:"token_id"`

	TokenSecretHash []byte `db:"token_secret_hash"`
	TokenPrefix     string `db:"token_prefix"`

	UserAgent string `db:"user_agent"`
	IP        string `db:"ip"`

	RememberMe bool `db:"remember_me"`
}

// TokenClaims is what we store in the encrypted cookie.
// Recommended: store TokenID + Secret in cookie, store hash(secret) in DB.
type TokenClaims struct {
	TokenID uuid.UUID
	Secret  []byte
}

func (t TokenClaims) IsZero() bool {
	return t.TokenID == uuid.Nil || len(t.Secret) == 0
}

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrSessionInvalid  = errors.New("session invalid")
)

// ---- context keys (unique, unexported, collision-proof) ----

type ctxKey struct{ name string }

var (
	workspaceKey     = &ctxKey{"workspace"}
	workspaceRoleKey = &ctxKey{"workspaceRole"}
	projectKey       = &ctxKey{"project"}
	appKey           = &ctxKey{"app"}
)

// WithWorkspace stores workspace in context.
func WithWorkspace(ctx context.Context, ws *Workspace) context.Context {
	return context.WithValue(ctx, workspaceKey, ws)
}

// WorkspaceFromContext retrieves workspace from context.
func WorkspaceFromContext(ctx context.Context) (*Workspace, bool) {
	v, ok := ctx.Value(workspaceKey).(*Workspace)
	return v, ok
}

// WithWorkspaceRole stores the admin's workspace role ("owner" or "admin") in context.
func WithWorkspaceRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, workspaceRoleKey, role)
}

// WorkspaceRoleFromContext retrieves the workspace role from context.
func WorkspaceRoleFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(workspaceRoleKey).(string)
	return v, ok
}

// WithProject stores project in context.
func WithProject(ctx context.Context, p *Project) context.Context {
	key := projectKey
	return context.WithValue(ctx, key, p)
}

// ProjectFromContext retrieves project from context.
func ProjectFromContext(ctx context.Context) (*Project, bool) {
	key := projectKey
	v, ok := ctx.Value(key).(*Project)
	return v, ok
}

// WithApp stores app in context.
func WithApp(ctx context.Context, a *App) context.Context {
	return context.WithValue(ctx, appKey, a)
}

// AppFromContext retrieves app from context.
func AppFromContext(ctx context.Context) (*App, bool) {
	v, ok := ctx.Value(appKey).(*App)
	return v, ok
}

// SessionResource is a safe/session-list friendly shape for frontend.
// IMPORTANT: do NOT include token_secret_hash (or raw secrets).
type SessionResource struct {
	ID         uuid.UUID `json:"id"`
	AccountID  uuid.UUID `json:"accountId"`
	CreatedAt  time.Time `json:"createdAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`

	UserAgent string `json:"userAgent"`
	IP        string `json:"ip"`

	Account AccountResource `json:"account"`
}
