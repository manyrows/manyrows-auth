package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"manyrows-core/config"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/core/validation"
	"manyrows-core/utils"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/gorilla/sessions"
	"github.com/rs/zerolog/log"
)

type Service struct {
	repo        *repo.Repo
	cookieStore *sessions.CookieStore
}

const sessionTTL = 30 * 24 * time.Hour
const CookieName = "MRSESSION"

// Store token claims as strings in the gorilla session map.
const (
	tokenIDKey     = "tid"
	tokenSecretKey = "ts"
)

func NewAuthService(c *config.Config, repo *repo.Repo) (*Service, error) {
	cookieStore, err := newCookieStore(c)
	if err != nil {
		return nil, err
	}
	return &Service{cookieStore: cookieStore, repo: repo}, nil
}

func newCookieStore(c *config.Config) (*sessions.CookieStore, error) {
	authKey, err := c.GetSessionAuthKey()
	if err != nil {
		return nil, err
	}
	encryptionKey, err := c.GetSessionSecretKey()
	if err != nil {
		return nil, err
	}
	store := sessions.NewCookieStore([]byte(authKey), []byte(encryptionKey))

	store.Options.HttpOnly = true
	store.Options.SameSite = http.SameSiteStrictMode

	if c.IsDevMode() {
		store.Options.Secure = false // dev runs on http
	} else {
		store.Options.Secure = true
		if domain := c.GetCookieDomain(); domain != "" {
			store.Options.Domain = domain
		}
	}

	return store, nil
}

// GetLoggedInAccount returns (account, ok, err).
// - ok=false means "not logged in" (no/invalid cookie, session missing/expired/revoked).
// - err is reserved for "real problems" (DB/crypto/etc).
func (a *Service) GetLoggedInAccount(r *http.Request) (*core.Account, *core.Session, error) {
	sess, err := a.GetSession(r)
	if err != nil {
		return nil, nil, err
	}
	if sess == nil {
		return nil, nil, nil
	}
	account, err := a.repo.GetAccountByID(r.Context(), sess.AccountID)
	if err != nil {
		return nil, nil, err
	}
	if account == nil {
		return nil, nil, errors.New("account not found")
	}
	return account, sess, nil
}

func (a *Service) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cookieStore.Options.Secure,
		SameSite: a.cookieStore.Options.SameSite,
		Domain:   a.cookieStore.Options.Domain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

func (a *Service) GetSession(r *http.Request) (*core.Session, error) {
	ok, claims, err := a.getTokenClaimsFromSession(r)
	if err != nil {
		log.Err(err).Msg("getTokenClaimsFromSession failed")
		return nil, err
	}
	if !ok || claims.IsZero() {
		return nil, nil
	}
	sess, err := a.repo.GetSessionByToken(r.Context(), claims)
	if err != nil {
		if errors.Is(err, core.ErrSessionNotFound) || errors.Is(err, core.ErrSessionExpired) || errors.Is(err, core.ErrSessionInvalid) {
			return nil, nil
		}
		return nil, err
	}
	if sess == nil {
		return nil, errors.New("session not found")
	}
	return sess, nil
}

func encodeClaims(t core.TokenClaims) (tokenID string, secretB64 string) {
	return t.TokenID.String(), base64.RawURLEncoding.EncodeToString(t.Secret)
}

func decodeClaims(tokenID string, secretB64 string) (core.TokenClaims, error) {
	id, err := uuid.FromString(tokenID)
	if err != nil {
		return core.TokenClaims{}, err
	}
	sec, err := base64.RawURLEncoding.DecodeString(secretB64)
	if err != nil {
		return core.TokenClaims{}, err
	}
	if len(sec) == 0 {
		return core.TokenClaims{}, errors.New("empty secret")
	}
	return core.TokenClaims{TokenID: id, Secret: sec}, nil
}

// getCookieSession returns the gorilla session for CookieName.
//
// sessions.CookieStore.Get only ever fails when securecookie can't
// authenticate/decrypt the incoming cookie: rotated keys, a cookie
// minted by a different install (the common case when this repo is
// copied and boots against a fresh DB with freshly generated session
// keys), an expired MAC, or tampering. In all of those cases Get
// still returns a fresh, usable, empty session — and the correct
// response is "treat the caller as logged out", not a hard 500. So we
// swallow the decode error (debug-logged) and hand back that empty
// session; downstream the missing token keys yield ok=false and the
// middleware clears the stale cookie and 401s cleanly.
func (a *Service) getCookieSession(r *http.Request) *sessions.Session {
	session, err := a.cookieStore.Get(r, CookieName)
	if err != nil {
		log.Debug().Err(err).Msg("ignoring undecodable session cookie (treating as logged out)")
	}
	return session
}

func (a *Service) getTokenClaimsFromSession(r *http.Request) (bool, core.TokenClaims, error) {
	session := a.getCookieSession(r)

	tidVal, ok := session.Values[tokenIDKey].(string)
	if !ok || tidVal == "" {
		return false, core.TokenClaims{}, nil
	}

	secVal, ok := session.Values[tokenSecretKey].(string)
	if !ok || secVal == "" {
		return false, core.TokenClaims{}, nil
	}

	claims, err := decodeClaims(tidVal, secVal)
	if err != nil {
		return false, core.TokenClaims{}, err
	}

	return true, claims, nil
}

// setTokenClaims stores TokenClaims into the encrypted cookie session and saves it.
// Use this on login / session creation.
func (a *Service) setTokenClaims(w http.ResponseWriter, r *http.Request, claims core.TokenClaims) error {
	// Tolerate an undecodable incoming cookie here too: a user arriving
	// with a stale/foreign cookie must still be able to log in. Get
	// returns a fresh empty session in that case, which we overwrite.
	session := a.getCookieSession(r)

	tid, sec := encodeClaims(claims)
	session.Values[tokenIDKey] = tid
	session.Values[tokenSecretKey] = sec

	return session.Save(r, w)
}

// clearTokenClaims removes token keys from the cookie and saves it.
func (a *Service) clearTokenClaims(w http.ResponseWriter, r *http.Request) error {
	// An undecodable cookie should still be clearable — proceed with the
	// fresh empty session Get hands back and expire it on the response.
	session := a.getCookieSession(r)

	delete(session.Values, tokenIDKey)
	delete(session.Values, tokenSecretKey)

	session.Options.MaxAge = -1

	return session.Save(r, w)
}

func (a *Service) AdminRegister(ctx context.Context, email string) (*core.Account, *validation.Result, error) {
	email, vr := ValidateEmail(email)
	if !vr.Ok() {
		return nil, vr, nil
	}

	acc := core.Account{
		ID:        utils.NewUUID(),
		Email:     email,
		Name:      email, // Default name to email, user can change later
		CreatedAt: time.Now().UTC(),
	}

	tx, err := a.repo.DB().Pool().Begin(ctx)
	if err != nil {
		return nil, &validation.Result{}, err
	}
	defer tx.Rollback(ctx)

	vr, err = a.repo.InsertAccount(ctx, tx, &acc)
	if err != nil {
		return nil, &validation.Result{}, err
	}
	if !vr.Ok() {
		return nil, vr, nil
	}

	err = tx.Commit(ctx)
	if err != nil {
		return nil, &validation.Result{}, err
	}

	return &acc, &validation.Result{}, nil
}

func (a *Service) DoLogout(w http.ResponseWriter, r *http.Request) error {
	// Best-effort: even if cookie is missing/corrupt, still clear it.
	ok, claims, err := a.getTokenClaimsFromSession(r)
	if err != nil {
		_ = a.clearTokenClaims(w, r)
		return err
	}

	// If we have a token, delete the DB session row.
	if ok && !claims.IsZero() {
		if err = a.repo.DeleteSessionByToken(r.Context(), claims.TokenID); err != nil {
			// Still clear cookie so user is logged out client-side even if DB delete fails.
			_ = a.clearTokenClaims(w, r)
			return err
		}
	}
	// Always clear cookie.
	return a.clearTokenClaims(w, r)
}

func (a *Service) DoLogin(w http.ResponseWriter, r *http.Request, ac *core.Account) (*core.Session, error) {
	// 1) Generate token claims (TokenID + secret)
	claims, secretHash, err := newTokenClaims()
	if err != nil {
		return nil, err
	}

	// 2) Insert session row in DB
	now := time.Now().UTC()
	expiresAt := now.Add(sessionTTL)

	userAgent := r.UserAgent()
	ip := ClientIP(r)

	tokenPrefix := claims.TokenID.String()
	if len(tokenPrefix) > 8 {
		tokenPrefix = tokenPrefix[:8]
	}

	ses := core.Session{}
	ses.AccountID = ac.ID
	ses.CreatedAt = now
	ses.LastSeenAt = now
	ses.ExpiresAt = expiresAt
	ses.TokenID = claims.TokenID
	ses.TokenSecretHash = secretHash
	ses.TokenPrefix = tokenPrefix
	ses.UserAgent = userAgent
	ses.IP = ip
	ses.ID = utils.NewUUID()

	err = a.repo.InsertSession(r.Context(), &ses)

	if err != nil {
		// don’t set cookie if we failed to create the DB session
		return nil, err
	}

	// 3) Store TokenID + secret into encrypted cookie
	if err := a.setTokenClaims(w, r, claims); err != nil {
		a.ClearSessionCookie(w)
		return nil, err
	}

	return &ses, nil
}

func newTokenClaims() (core.TokenClaims, []byte, error) {
	// Secret should be high entropy (32 bytes is plenty).
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return core.TokenClaims{}, nil, err
	}

	tokenID := utils.NewUUID()

	sum := sha256.Sum256(secret)
	secretHash := sum[:] // 32 bytes

	return core.TokenClaims{
		TokenID: tokenID,
		Secret:  secret,
	}, secretHash, nil
}

func ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}

	// Forwarding headers (CF-Connecting-IP, X-Forwarded-For, X-Real-IP)
	// are spoofable by anyone who can reach the listener directly. We
	// only consult them when the immediate peer (r.RemoteAddr) is in
	// the operator-configured trusted-proxies allow-list — see
	// MANYROWS_TRUSTED_PROXIES. Default is "private" (RFC1918 + loopback
	// + ULA), which covers the typical self-hosted-behind-platform-
	// router shape; public-edge deploys (Cloudflare, AWS ALB, …) must
	// enumerate the proxy CIDRs explicitly.
	peerTrusted := loadTrustedProxies().IsTrusted(r.RemoteAddr)
	if peerTrusted {
		// When traffic is proxied through Cloudflare, CF sets CF-Connecting-IP to the
		// authoritative client IP and strips any client-supplied value at the edge,
		// so it's safe to trust when present. Prefer it over XFF — when our
		// upstream router appends the observed source IP to XFF, that entry
		// becomes CF's edge IP once CF is in front, making rightmost-XFF point
		// at CF instead of the real client.
		if ip := normalizedIP(r.Header.Get("CF-Connecting-IP")); ip != "" {
			return ip
		}

		// Trusted reverse proxies (in our deploy: the platform router) append the
		// observed source IP to the right side of X-Forwarded-For. Use the rightmost
		// parseable IP as the canonical client address for rate limiting, audit
		// logs, and allowlists.
		if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				if ip := normalizedIP(parts[i]); ip != "" {
					return ip
				}
			}
		}

		// Check X-Real-IP header (set by some proxies like nginx).
		if ip := normalizedIP(r.Header.Get("X-Real-IP")); ip != "" {
			return ip
		}
	}

	// Untrusted peer (or no usable header value): the kernel-set
	// RemoteAddr is the ground truth — it can't be spoofed by the
	// request payload, only by network-level attacks the operator's
	// infra has to handle separately.
	if ip := normalizedIP(r.RemoteAddr); ip != "" {
		return ip
	}
	return sanitizeIPCandidate(r.RemoteAddr)
}

func normalizedIP(raw string) string {
	candidate := sanitizeIPCandidate(raw)
	if candidate == "" {
		return ""
	}

	if addr, err := netip.ParseAddr(candidate); err == nil {
		return addr.String()
	}
	if ip := net.ParseIP(candidate); ip != nil {
		return ip.String()
	}
	return ""
}

func sanitizeIPCandidate(raw string) string {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return ""
	}

	if host, _, err := net.SplitHostPort(candidate); err == nil && host != "" {
		candidate = host
	} else {
		candidate = strings.TrimPrefix(candidate, "[")
		candidate = strings.TrimSuffix(candidate, "]")
	}

	candidate = strings.TrimSpace(candidate)
	if i := strings.LastIndex(candidate, "%"); i > 0 {
		candidate = candidate[:i]
	}
	return strings.TrimSpace(candidate)
}
