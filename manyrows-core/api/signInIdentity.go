package api

import (
	"context"
	"errors"

	"manyrows-core/core"
	"manyrows-core/core/repo"
)

// Sentinel errors returned by ResolveSignInIdentity so callers can map
// them to the right HTTP response without re-checking app state.
//
// ErrRegistrationDisabled: the email-proof sign-in path tried to create
// either a new pool user or a new (app, user) membership row, but the
// app's AllowRegistration flag is false. Callers turn this into the
// same 401 shape as a bad code/token, no info leak about whether the
// user exists.
//
// ErrAppUserDisabled: the app_users membership row exists but its
// status is not 'active'. Admin disabled this member; sign-in is
// refused at every email-proof path the same way password sign-in is
// refused at the GetUserWithPasswordByEmailAndApp lookup.
//
// ErrIdentityConflict (OAuth-only): the email-fallback path resolved
// to a user already linked to a different provider account. Surfaces
// repo.ErrIdentitySubjectMismatch so the OAuth handler can respond
// with a 409 instead of silently swapping subjects.
var (
	ErrRegistrationDisabled = errors.New("registration disabled")
	ErrAppUserDisabled      = errors.New("app member disabled")
	ErrIdentityConflict     = errors.New("identity already linked to different provider account")
)

// ResolveSignInIdentity is the single gate for email-proof sign-in
// paths (OTP, magic link, OAuth callback). Possible outcomes:
//
//   - existing active member  -> (user, false, nil)
//   - existing pool user, no membership row:
//       AllowRegistration true  -> EnsureAppMember, return (user, false, nil)
//       AllowRegistration false -> (nil, false, ErrRegistrationDisabled)
//   - no pool user yet:
//       AllowRegistration true  -> create user + membership, return (user, true, nil)
//       AllowRegistration false -> (nil, false, ErrRegistrationDisabled)
//   - existing member, status != active -> (nil, false, ErrAppUserDisabled)
//
// userCreated is true only when a brand new pool user was inserted (for
// webhook dispatch + auth-log distinguishing first-ever sign-in from
// returning).
func (handler *RequestHandler) ResolveSignInIdentity(
	ctx context.Context,
	app *core.App,
	email string,
	source core.UserSource,
) (user *core.User, userCreated bool, err error) {
	user, err = handler.repo.GetUserByEmail(ctx, email, app)
	if err != nil {
		return nil, false, err
	}
	if user != nil {
		member, mErr := handler.repo.GetAppUser(ctx, app.ID, user.ID)
		if mErr != nil {
			return nil, false, mErr
		}
		if member != nil {
			if !member.IsActive() {
				return nil, false, ErrAppUserDisabled
			}
			return user, false, nil
		}
		if !app.AllowRegistration {
			return nil, false, ErrRegistrationDisabled
		}
		if _, _, err := handler.repo.EnsureAppMember(ctx, app.ID, user.ID, source); err != nil {
			return nil, false, err
		}
		return user, false, nil
	}
	if !app.AllowRegistration {
		return nil, false, ErrRegistrationDisabled
	}
	user, userCreated, err = handler.repo.GetOrCreateUser(ctx, email, app, source)
	if err != nil {
		return nil, false, err
	}
	if _, _, err := handler.repo.EnsureAppMember(ctx, app.ID, user.ID, source); err != nil {
		return nil, false, err
	}
	return user, userCreated, nil
}

// ResolveOAuthSignInIdentity is the OAuth-specific gate. It layers on
// top of ResolveSignInIdentity:
//
//  1. Look up the user by (provider, providerSubject). Subject is the
//     IdP's stable id, so this survives a provider-side email change.
//     If a row matches but the user has no app membership yet, gate on
//     AllowRegistration before creating one. The identity row's
//     provider_email is refreshed with the current value either way.
//
//  2. Fall back to ResolveSignInIdentity (matches by verified email or
//     creates a pool user + membership). Then upsert the identity so
//     subsequent logins take the fast path.
//
// providerSubject must be non-empty - the four provider call sites
// already validate the OAuth response before reaching here.
//
// providerKey is the user_identities.provider value used to match and
// write the identity link. It is decoupled from `source` (the coarse
// user.source / app_users.source) so generic external IdPs can use a
// per-IdP key ("idp:<slug>") while still recording a coarse origin
// (UserSourceExternalIDP). When providerKey is "" it defaults to
// string(source) — exactly the old behavior, so the bespoke Google /
// Apple / Microsoft / GitHub callers (which don't set it) are
// unchanged: provider stays "google", etc.
func (handler *RequestHandler) ResolveOAuthSignInIdentity(
	ctx context.Context,
	app *core.App,
	email string,
	source core.UserSource,
	providerKey string,
	providerSubject string,
) (user *core.User, userCreated bool, err error) {
	if providerKey == "" {
		providerKey = string(source)
	}
	identityProvider := core.UserSource(providerKey)
	if providerSubject != "" {
		user, err = handler.repo.FindUserByIdentity(ctx, app.UserPoolID, identityProvider, providerSubject)
		if err != nil {
			return nil, false, err
		}
		if user != nil {
			member, mErr := handler.repo.GetAppUser(ctx, app.ID, user.ID)
			if mErr != nil {
				return nil, false, mErr
			}
			if member != nil && !member.IsActive() {
				return nil, false, ErrAppUserDisabled
			}
			if member == nil {
				if !app.AllowRegistration {
					return nil, false, ErrRegistrationDisabled
				}
				if _, _, err := handler.repo.EnsureAppMember(ctx, app.ID, user.ID, source); err != nil {
					return nil, false, err
				}
			}
			if err := handler.repo.UpsertUserIdentity(
				ctx, user.ID, app.UserPoolID, identityProvider, providerSubject, email,
			); err != nil {
				if errors.Is(err, repo.ErrIdentitySubjectMismatch) {
					return nil, false, ErrIdentityConflict
				}
				return nil, false, err
			}
			return user, false, nil
		}
	}

	user, userCreated, err = handler.ResolveSignInIdentity(ctx, app, email, source)
	if err != nil {
		return nil, false, err
	}
	if providerSubject != "" {
		if err := handler.repo.UpsertUserIdentity(
			ctx, user.ID, app.UserPoolID, identityProvider, providerSubject, email,
		); err != nil {
			if errors.Is(err, repo.ErrIdentitySubjectMismatch) {
				return nil, false, ErrIdentityConflict
			}
			return nil, false, err
		}
	}
	return user, userCreated, nil
}
