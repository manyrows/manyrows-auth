package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
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
// Refresh Token Flow
// =====================

// IssueAccessToken creates a short-lived JWT for API access. ttl
// overrides AccessTokenTTL when > 0 — typically supplied via the
// per-app AccessTokenTTLMinutes knob; pass 0 to use the default.
// Expiry is also capped at the session's own ExpiresAt regardless.
func (a *AuthService) IssueAccessToken(s *core.ClientSession, ttl time.Duration, issuer string) (string, time.Time, error) {
	if s == nil || s.ID == uuid.Nil || s.UserID == uuid.Nil {
		return "", time.Time{}, errors.New("invalid client session")
	}

	// Caller-supplied issuer (per-app, derived from AuthDomain when set)
	// wins; fall back to the install-wide BASE_URL.
	iss := strings.TrimRight(strings.TrimSpace(issuer), "/")
	if iss == "" {
		iss = a.issuer()
	}
	if iss == "" {
		return "", time.Time{}, errors.New("cannot issue access token: MANYROWS_BASE_URL not configured (will be pinned after first /admin/register)")
	}

	if ttl <= 0 {
		ttl = AccessTokenTTL
	}
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)

	// Cap token expiry at session expiry
	if !s.ExpiresAt.IsZero() && expiresAt.After(s.ExpiresAt) {
		expiresAt = s.ExpiresAt
	}

	claims := mrClientJWTClaims{
		SessionID: s.ID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   s.UserID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	if s.AppID != nil && *s.AppID != uuid.Nil {
		claims.AppID = s.AppID.String()
		claims.Audience = jwt.ClaimStrings{s.AppID.String()}
	}

	current := a.jwtKeys.Load().Current
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = current.KID
	signed, err := tok.SignedString(current.Private)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}

// IssueRefreshToken creates a new refresh token for the session.
// sessionTTL overrides the default refresh token TTL if > 0.
// dpopJKT is the JWK SHA-256 thumbprint of the keypair binding this refresh
// token to a DPoP proof; empty for clients that didn't opt into DPoP.
// Returns the raw token (to send to client) and the stored record.
func (a *AuthService) IssueRefreshToken(
	ctx context.Context,
	sessionID uuid.UUID,
	userAgent string,
	ip string,
	sessionTTL time.Duration,
	dpopJKT string,
) (string, *core.ClientRefreshToken, error) {
	if sessionID == uuid.Nil {
		return "", nil, errors.New("missing sessionID")
	}

	rawToken, err := generateSecureToken(32)
	if err != nil {
		return "", nil, err
	}

	ttl := RefreshTokenTTL
	if sessionTTL > 0 {
		ttl = sessionTTL
	}

	now := time.Now().UTC()
	rt := &core.ClientRefreshToken{
		ID:        utils.NewUUID(),
		SessionID: sessionID,
		TokenHash: hashToken(rawToken),
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		UserAgent: strings.TrimSpace(userAgent),
		IP:        strings.TrimSpace(ip),
		DPopJKT:   strings.TrimSpace(dpopJKT),
	}

	if err := a.repo.InsertClientRefreshToken(ctx, rt); err != nil {
		return "", nil, err
	}

	return rawToken, rt, nil
}

// IssueTokenPair creates both an access token and refresh token for a session.
// sessionTTL overrides the default refresh-token TTL if > 0.
// accessTokenTTL overrides AccessTokenTTL if > 0 — supplied via the
// per-app AccessTokenTTLMinutes knob.
// dpopJKT is the verified JWK thumbprint from a DPoP proof on the inbound
// request, or empty when the client did not opt into DPoP at this issuance.
func (a *AuthService) IssueTokenPair(
	ctx context.Context,
	session *core.ClientSession,
	userAgent string,
	ip string,
	sessionTTL time.Duration,
	accessTokenTTL time.Duration,
	dpopJKT string,
	issuer string,
) (*TokenPair, error) {
	if session == nil {
		return nil, errors.New("missing session")
	}

	accessToken, expiresAt, err := a.IssueAccessToken(session, accessTokenTTL, issuer)
	if err != nil {
		return nil, err
	}

	refreshToken, rt, err := a.IssueRefreshToken(ctx, session.ID, userAgent, ip, sessionTTL, dpopJKT)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		ExpiresAt:        expiresAt,
		ExpiresIn:        int(time.Until(expiresAt).Seconds()),
		RefreshExpiresIn: int(time.Until(rt.ExpiresAt).Seconds()),
	}, nil
}

// RefreshTokenPair validates a refresh token, rotates it, and issues a new
// token pair.
//
// sessionTTL overrides the default refresh token TTL if > 0.
//
// presentedJKT is the JWK thumbprint extracted from a verified DPoP proof on
// the inbound request (empty if no proof was presented). DPoP enforcement
// follows the rules locked in on the project plan:
//
//   - If the existing refresh token has a bound jkt, the request MUST carry
//     a matching presentedJKT. Missing or mismatching → reject (no Bearer
//     downgrade, gotchas #1 and #3 in todo/TODO.md).
//   - If the existing refresh token is unbound (jkt == ""), presentedJKT is
//     IGNORED — an unbound session is never upgraded mid-flight (gotcha #1).
//   - The new refresh token inherits the existing token's jkt, so the
//     binding propagates through the entire rotation chain (gotcha #2).
func (a *AuthService) RefreshTokenPair(
	ctx context.Context,
	refreshToken string,
	appID uuid.UUID,
	userAgent string,
	ip string,
	sessionTTL time.Duration,
	accessTokenTTL time.Duration,
	idleTimeout time.Duration,
	rememberMeTTL time.Duration,
	presentedJKT string,
	issuer string,
) (*TokenPair, error) {
	if refreshToken == "" {
		return nil, ErrInvalidRefreshToken
	}

	tokenHash := hashToken(refreshToken)

	// Look up the refresh token
	rt, err := a.repo.GetClientRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, repo.ErrRefreshTokenNotFound) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, err
	}

	now := time.Now().UTC()

	// Concurrent-refresh grace window. Two browser tabs (or an SDK
	// retry firing before the first call returned) commonly hit
	// /refresh with the same token at near-identical times — both
	// pass the rotated-check, one wins the atomic UPDATE, the other
	// loses and returns an error to its caller. The losing client
	// then retries with the *same now-rotated* token, which would
	// trip true reuse detection and nuke the whole session.
	//
	// Within `refreshGraceWindow` of the rotation, treat the second
	// presentation as a duplicate concurrent request: skip the
	// rotation marker (already done by the first call) and mint a
	// sibling token pair from the still-active replacement chain.
	// Outside the window, or when the replacement isn't usable,
	// fall through to true reuse detection.
	concurrentRetry := false
	if rt.RotatedAt != nil && !rt.RotatedAt.IsZero() {
		// Grace eligibility is just "rotated within the last
		// refreshGraceWindow". An earlier version also required
		// ReplacedByID to be set + the replacement to be active, but
		// that's racey: MarkRefreshTokenRotated runs BEFORE the new
		// refresh token row exists, so a near-simultaneous retry
		// landing in that window would see ReplacedByID=nil and fall
		// through to "real reuse" — which is exactly the case we're
		// trying to catch.
		//
		// The session.IsActive() check further down still gates
		// revoked sessions, so dropping the replacement check here is
		// safe — a logged-out user can't get a sibling pair just by
		// presenting a recently-rotated token.
		if now.Sub(*rt.RotatedAt) <= refreshGraceWindow {
			log.Debug().
				Str("session_id", rt.SessionID.String()).
				Str("token_id", rt.ID.String()).
				Msg("refresh: concurrent retry within grace window — issuing sibling pair")
			concurrentRetry = true
		} else {
			// Outside the grace window: treat as real reuse, revoke.
			log.Warn().
				Str("session_id", rt.SessionID.String()).
				Str("token_id", rt.ID.String()).
				Msg("Refresh token reuse detected - revoking session")
			_ = a.repo.RevokeAllRefreshTokensForSession(ctx, rt.SessionID, now)
			return nil, ErrInvalidRefreshToken
		}
	}

	// Check if token is active. Skip when we're in the grace-window
	// path — IsActive() returns false for rotated tokens, but we've
	// already established the rotation was a legitimate concurrent
	// race we're servicing.
	if !concurrentRetry && !rt.IsActive(now) {
		return nil, ErrInvalidRefreshToken
	}

	// DPoP binding enforcement. Done BEFORE the rotation marker so a failed
	// DPoP check leaves the original token usable for a legitimate retry —
	// only successful refreshes consume the rotation slot. The legitimate
	// client will still need to mint a new proof on the retry because the
	// jti was already recorded in the replay cache by the verifier.
	boundJKT := strings.TrimSpace(rt.DPopJKT)
	if boundJKT != "" {
		if presentedJKT == "" {
			return nil, ErrDPoPRequired
		}
		if presentedJKT != boundJKT {
			return nil, ErrDPoPBindingMismatch
		}
	}

	// Load the session
	session, err := a.repo.GetClientSessionByID(ctx, rt.SessionID)
	if err != nil {
		if errors.Is(err, repo.ErrClientSessionNotFound) || errors.Is(err, repo.ErrClientSessionExpired) {
			return nil, ErrSessionExpired
		}
		return nil, err
	}

	// Verify app matches (for app-scoped sessions)
	if session.AppID != nil && *session.AppID != uuid.Nil && appID != uuid.Nil {
		if *session.AppID != appID {
			return nil, ErrInvalidRefreshToken
		}
	}

	// Check session is still active (absolute lifetime).
	if !session.IsActive(now) {
		return nil, ErrSessionExpired
	}

	// Idle-timeout enforcement. The app's IdleTimeoutMinutes is
	// supplied as `idleTimeout`; > 0 means "refuse refresh if the
	// session hasn't been touched within this duration." End-to-end
	// behaviour: the current access token finishes its lifetime
	// (AccessTokenTTL) and the next refresh returns ErrSessionExpired,
	// so the session dies naturally without forcing a stateful
	// per-request check on every JWT verify.
	if idleTimeout > 0 && !session.LastSeenAt.IsZero() && now.Sub(session.LastSeenAt) > idleTimeout {
		return nil, ErrSessionExpired
	}

	// Mark the old refresh token as rotated BEFORE issuing new tokens.
	// This closes the race window where two concurrent requests could both
	// pass the reuse check and get valid token pairs.
	//
	// Two race shapes to handle:
	//
	//  1. Both requests' GETs happened BEFORE either UPDATE — both see
	//     RotatedAt=nil at GET time, the rotated-check above doesn't
	//     fire for either, and both reach this MarkRefreshTokenRotated
	//     call. The atomic UPDATE serialises them: one wins
	//     (RowsAffected=1), the other gets RowsAffected=0 and
	//     "already rotated or revoked".
	//
	//  2. The losing request's GET happened AFTER the winner's UPDATE,
	//     so it saw RotatedAt set and was already routed to
	//     concurrentRetry above.
	//
	// Both shapes deserve grace-window handling. Distinguish them by
	// re-fetching the row after a failed UPDATE: if the rotation is
	// recent, treat the loser as a sibling (case 1); if not (or the
	// row was actually revoked), bail with 401.
	if !concurrentRetry {
		if err := a.repo.MarkRefreshTokenRotated(ctx, rt.ID, now); err != nil {
			fresh, refetchErr := a.repo.GetClientRefreshTokenByHash(ctx, tokenHash)
			if refetchErr == nil && fresh != nil &&
				fresh.RotatedAt != nil && !fresh.RotatedAt.IsZero() &&
				now.Sub(*fresh.RotatedAt) <= refreshGraceWindow {
				log.Debug().
					Str("session_id", rt.SessionID.String()).
					Str("token_id", rt.ID.String()).
					Msg("refresh: lost the rotation race within grace window — issuing sibling pair")
				concurrentRetry = true
			} else {
				log.Err(err).Str("token_id", rt.ID.String()).Msg("Failed to mark refresh token as rotated")
				return nil, ErrInvalidRefreshToken
			}
		}
	}

	// Issue new token pair
	newAccessToken, expiresAt, err := a.IssueAccessToken(session, accessTokenTTL, issuer)
	if err != nil {
		return nil, err
	}

	// Honor the original "remember me" decision recorded on the session row
	// — without this, every refresh would shrink the long TTL back to the
	// caller-supplied (app-default) value. Take the larger of (app default,
	// per-app remember-me override, package fallback) so an app configured
	// with a > 30d TTL isn't accidentally shortened, and so a per-app
	// remember-me override is actually applied at refresh time.
	effectiveTTL := sessionTTL
	if session.RememberMe {
		rmTTL := rememberMeTTL
		if rmTTL <= 0 {
			rmTTL = RememberMeTTL
		}
		if effectiveTTL < rmTTL {
			effectiveTTL = rmTTL
		}
	}

	// Propagate the existing jkt to the new token. This is the *bound* jkt
	// from the row we just rotated — never presentedJKT — so even a buggy
	// caller cannot accidentally upgrade or change the binding mid-chain.
	newRefreshToken, newRT, err := a.IssueRefreshToken(ctx, session.ID, userAgent, ip, effectiveTTL, boundJKT)
	if err != nil {
		return nil, err
	}

	// Update the rotation record with the actual new token ID
	_ = a.repo.UpdateRotatedRefreshTokenReplacement(ctx, rt.ID, newRT.ID)

	return &TokenPair{
		AccessToken:      newAccessToken,
		RefreshToken:     newRefreshToken,
		ExpiresAt:        expiresAt,
		ExpiresIn:        int(time.Until(expiresAt).Seconds()),
		RefreshExpiresIn: int(time.Until(newRT.ExpiresAt).Seconds()),
	}, nil
}

// RevokeRefreshToken revokes a specific refresh token.
func (a *AuthService) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return nil
	}
	return a.repo.RevokeClientRefreshToken(ctx, hashToken(refreshToken), time.Now().UTC())
}

// RevokeAllSessionTokens revokes all refresh tokens for a session.
func (a *AuthService) RevokeAllSessionTokens(ctx context.Context, sessionID uuid.UUID) error {
	return a.repo.RevokeAllRefreshTokensForSession(ctx, sessionID, time.Now().UTC())
}

// LogoutSessionByRefreshToken resolves the session that owns a given
// refresh token, revokes every refresh token in that session's family,
// and deletes the session row. Used by logout flows that have the
// refresh token but no bearer header / cookie. Returns the session's
// app_id (for audit logging) plus the user_id.
//
// Returns the empty struct + nil if the refresh token doesn't resolve
// to anything — same shape as the workspace logout's "session not
// found" path. Genuine I/O errors bubble up as the second return.
func (a *AuthService) LogoutSessionByRefreshToken(ctx context.Context, refreshToken string) (LogoutInfo, error) {
	if refreshToken == "" {
		return LogoutInfo{}, nil
	}
	rt, err := a.repo.GetClientRefreshTokenByHash(ctx, hashToken(refreshToken))
	if err != nil {
		// Unknown / never-existed token is a not-found, not a real
		// error. Surface as "not found" so the caller can treat
		// logout as idempotent.
		if errors.Is(err, repo.ErrRefreshTokenNotFound) {
			return LogoutInfo{}, nil
		}
		return LogoutInfo{}, err
	}
	if rt == nil {
		return LogoutInfo{}, nil
	}

	// Look up the session BEFORE deleting it so the caller has user_id +
	// app_id for the audit log.
	ses, err := a.repo.GetClientSessionByID(ctx, rt.SessionID)
	if err != nil {
		return LogoutInfo{}, err
	}
	if ses == nil {
		// Stale token — best-effort revoke and stop.
		_ = a.repo.RevokeAllRefreshTokensForSession(ctx, rt.SessionID, time.Now().UTC())
		return LogoutInfo{}, nil
	}

	if err := a.repo.RevokeAllRefreshTokensForSession(ctx, rt.SessionID, time.Now().UTC()); err != nil {
		return LogoutInfo{}, err
	}
	if err := a.DeleteSession(ctx, rt.SessionID); err != nil {
		return LogoutInfo{}, err
	}

	return LogoutInfo{
		SessionID: ses.ID,
		UserID:    ses.UserID,
		AppID:     ses.AppID,
		Found:     true,
	}, nil
}

// LogoutInfo describes the session that LogoutSessionByRefreshToken
// just terminated. Found is false when no session matched (the caller
// typically maps that to a 409 / "already logged out").
type LogoutInfo struct {
	SessionID uuid.UUID
	UserID    uuid.UUID
	AppID     *uuid.UUID
	Found     bool
}

// =====================
// Token helpers
// =====================

// generateSecureToken creates a cryptographically secure random token.
func generateSecureToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// hashToken creates a SHA256 hash of a token for storage.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
