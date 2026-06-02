package client

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

// =====================
// Session lifecycle (DB)
// =====================

// RememberMeTTL is the fallback refresh-token / session lifetime applied
// when the user opts in via the AppKit "Keep me signed in" checkbox and
// the app has no per-app remember-me override (App.RememberMeTTL()).
const RememberMeTTL = 30 * 24 * time.Hour

// defaultMaxSessionsPerUser is the fallback session cap applied when the
// app has no per-app override (App.MaxSessions()). Login beyond this
// prunes the oldest by last_seen_at.
const defaultMaxSessionsPerUser = 5

// CreateSession is a thin shim that defaults rememberMe to false and falls
// back to service-default TTLs (sessionTTL=0, rememberMeTTL=0). Preserved
// so non-login callers (tests, internal flows) compile unchanged. Login
// handlers should call CreateSessionWithOptions directly and pass the
// per-app SessionTTL/RememberMeTTL.
func (a *AuthService) CreateSession(
	ctx context.Context,
	userID uuid.UUID,
	appID uuid.UUID,
	userAgent string,
	ip string,
) (*core.ClientSession, error) {
	return a.CreateSessionWithOptions(ctx, userID, appID, userAgent, ip, false, 0, 0, 0)
}

// CreateSessionWithOptions inserts a new client_sessions row for the
// user+app, pruning the oldest active session if the per-app limit
// would be exceeded. It never reuses an existing session — every login
// gets its own row.
//
// sessionTTL is the per-app absolute session lifetime (App.SessionTTL()) —
// 0 falls back to the service default.
// rememberMeTTL is the per-app remember-me override (App.RememberMeTTL())
// — 0 falls back to the RememberMeTTL package constant when rememberMe
// is true. The two combine as `max(sessionTTL, rememberMeTTL)` when
// rememberMe is true, so an app with a long absolute TTL isn't silently
// shortened by a shorter remember-me override.
// maxSessions is the per-app cap on active sessions per user
// (App.MaxSessions()) — 0 falls back to the package default
// (defaultMaxSessionsPerUser).
func (a *AuthService) CreateSessionWithOptions(
	ctx context.Context,
	userID uuid.UUID,
	appID uuid.UUID,
	userAgent string,
	ip string,
	rememberMe bool,
	sessionTTL time.Duration,
	rememberMeTTL time.Duration,
	maxSessions int,
) (*core.ClientSession, error) {
	if userID == uuid.Nil {
		return nil, errors.New("missing userID")
	}
	if appID == uuid.Nil {
		return nil, errors.New("missing appID")
	}

	now := time.Now().UTC()

	// Keep at most maxSessions active sessions per user+app — prune
	// oldest by last_seen_at if over limit.
	if maxSessions <= 0 {
		maxSessions = defaultMaxSessionsPerUser
	}
	_ = a.repo.PruneOldestSessionsByUserAndApp(ctx, userID, appID, maxSessions-1)
	ttl := sessionTTL
	if ttl <= 0 {
		ttl = a.sessionTTL
	}
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	if rememberMe {
		rmTTL := rememberMeTTL
		if rmTTL <= 0 {
			rmTTL = RememberMeTTL
		}
		if ttl < rmTTL {
			ttl = rmTTL
		}
	}

	ses := core.ClientSession{
		ID:     utils.NewUUID(),
		UserID: userID,
		AppID:  &appID,

		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(ttl),

		UserAgent:  strings.TrimSpace(userAgent),
		IP:         strings.TrimSpace(ip),
		RememberMe: rememberMe,
	}

	if err := a.repo.InsertClientSession(ctx, &ses); err != nil {
		return nil, err
	}

	// Collapse to one session per device: drop any prior active session
	// from the same (ip, user_agent) for this user+app. Re-authenticating
	// from a browser you were already signed into replaces that session
	// instead of leaving a ghost that lingers until its TTL. Best-effort
	// — a failure here must not fail an otherwise-successful login, and
	// the new session is already persisted. Runs for every login method
	// (this is the single shared seam), not just OAuth.
	_ = a.repo.DeleteOtherSessionsBySameDevice(ctx, userID, appID, ses.IP, ses.UserAgent, ses.ID)

	return &ses, nil
}

// DeleteSession hard-deletes the DB session row (logout / revoke-by-delete).
// If it doesn't exist, treat as success.
func (a *AuthService) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	if sessionID == uuid.Nil {
		return errors.New("missing sessionID")
	}
	_, err := a.repo.DeleteClientSession(ctx, sessionID)
	return err
}

// =====================
// Bearer parsing + session resolution
// =====================

const (
	authHeader   = "Authorization"
	bearerPrefix = "Bearer "

	// Cookie-name prefixes. The full name is "<prefix>_<appID>" so two apps
	// on the same eTLD don't collide in the cookie jar — without this,
	// logging into one app overwrites the other's session cookie. The
	// trailing "_" before the UUID keeps the name unambiguous when the
	// prefix grows to include an env tag in the future.
	accessCookiePrefix  = "mr_at_"
	refreshCookiePrefix = "mr_rt_"
)

// AccessCookieName / RefreshCookieName return the per-app cookie name.
// All writers (setSessionCookies, clearSessionCookies) and readers
// (bearerTokenFromRequest, the /refresh handlers) agree on this name.
// manyrows-go duplicates the same scheme — keep them in sync.
func AccessCookieName(appID uuid.UUID) string  { return accessCookiePrefix + appID.String() }
func RefreshCookieName(appID uuid.UUID) string { return refreshCookiePrefix + appID.String() }

// GetSession resolves the current client session from Authorization: Bearer <jwt>.
// Returns (nil, nil) when not present/invalid/expired/notfound.
func (a *AuthService) GetSession(r *http.Request) (*core.ClientSession, error) {
	if r == nil {
		return nil, nil
	}

	raw := bearerTokenFromRequest(r)
	if raw == "" {
		return nil, nil
	}

	claims, ok := a.parseJWT(raw)
	if !ok {
		return nil, nil
	}

	sid, err := uuid.FromString(strings.TrimSpace(claims.SessionID))
	if err != nil {
		return nil, nil
	}

	ses, err := a.repo.GetClientSessionByID(r.Context(), sid)
	if err != nil {
		// Treat expired/notfound as "not logged in"
		if errors.Is(err, repo.ErrClientSessionNotFound) || errors.Is(err, repo.ErrClientSessionExpired) {
			return nil, nil
		}
		return nil, err
	}
	if ses == nil {
		return nil, nil
	}

	// Strict app check (defense in depth).
	appClaim := strings.TrimSpace(claims.AppID)
	if ses.AppID != nil && *ses.AppID != uuid.Nil {
		if appClaim == "" || ses.AppID.String() != appClaim {
			return nil, nil
		}
	}

	// Best-effort touch last_seen.
	if _, err := a.repo.TouchClientSessionLastSeen(r.Context(), ses.ID); err != nil {
		log.Err(err).Msgf(
			"Could not touch client session last seen (sid=%s)",
			ses.ID.String(),
		)
	}

	// Defensive: enforce expiry in code too.
	if !ses.IsActive(time.Now().UTC()) {
		return nil, nil
	}

	return ses, nil
}

// IsLoggedIntoApp is a convenience helper that checks if there's an active session for the given app.
func (a *AuthService) IsLoggedIntoApp(r *http.Request, appID uuid.UUID) (bool, *core.ClientSession, error) {
	ses, err := a.GetSession(r)
	if err != nil {
		return false, nil, err
	}
	if ses == nil {
		return false, nil, nil
	}
	if ses.AppID == nil || *ses.AppID != appID {
		return false, ses, nil
	}
	return ses.IsActive(time.Now().UTC()), ses, nil
}

func bearerTokenFromRequest(r *http.Request) string {
	// Authorization: Bearer ... wins (AppKit-direct + native clients
	// all use this). Fall back to the access-token cookie
	// (cookie mode — same domain or workspace-configured cookie
	// domain). Browsers send the cookie automatically on first-party
	// requests, so we read it as a second-class source.
	//
	// The cookie name is per-app (mr_at_<appID>) so two apps on the
	// same eTLD don't share a cookie slot — without that, logging
	// into one app overwrites the other. We pull the app from the
	// request context (the workspace router sets it before this
	// handler runs); no app context means no cookie fallback (the
	// caller is on an admin path that doesn't use these cookies).
	h := strings.TrimSpace(r.Header.Get(authHeader))
	if h != "" && strings.HasPrefix(h, bearerPrefix) {
		return strings.TrimSpace(strings.TrimPrefix(h, bearerPrefix))
	}
	if app, ok := core.AppFromContext(r.Context()); ok && app != nil && app.ID != uuid.Nil {
		if c, err := r.Cookie(AccessCookieName(app.ID)); err == nil && c != nil {
			return strings.TrimSpace(c.Value)
		}
	}
	return ""
}

func (a *AuthService) parseJWT(raw string) (*mrClientJWTClaims, bool) {
	parsed, err := jwt.ParseWithClaims(raw, &mrClientJWTClaims{}, func(token *jwt.Token) (any, error) {
		// Only allow ES256 (alg match). Resolves the public key by kid
		// header against the live keyset — during a rotation overlap
		// window this matches both current and previous keys, so
		// in-flight tokens signed before the rotation still verify.
		if token.Method == nil || token.Method.Alg() != jwt.SigningMethodES256.Alg() {
			return nil, errors.New("unexpected jwt signing method")
		}
		kid, _ := token.Header["kid"].(string)
		pub := a.jwtKeys.Load().PublicKeyByKID(kid)
		if pub == nil {
			return nil, errors.New("unknown kid")
		}
		return pub, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		// `iss` is intentionally NOT validated here. With per-app
		// AuthDomain it's no longer a single install-wide value — DK
		// apps mint iss="https://auth.drumkingdom.com", Jerry Lingo
		// mints "https://auth.jerrylingo.com", and the install URL
		// covers the rest. This verifier has no app context to pick
		// the right expected value, and we'd block a stale-but-valid
		// token surviving an AuthDomain change. The signature check
		// already proves the token came from this install (per-install
		// signing key); cross-deployment replay would also need the
		// signing key, so dropping the iss check doesn't open a hole.
		// `aud` is similarly NOT validated here — the downstream
		// "ses.AppID == claims.AppID" check (in GetSession +
		// workspaceAuthMiddleware) is the authoritative per-request
		// audience check, against the app the request actually
		// landed on.
	)
	if err != nil || parsed == nil || !parsed.Valid {
		return nil, false
	}

	c, ok := parsed.Claims.(*mrClientJWTClaims)
	if !ok || c == nil {
		return nil, false
	}
	if strings.TrimSpace(c.SessionID) == "" {
		return nil, false
	}
	return c, true
}
