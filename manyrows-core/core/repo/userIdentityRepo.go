package repo

import (
	"context"
	"errors"
	"strings"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

const userIdentityCols = `
  id, user_id, user_pool_id, provider, provider_subject, provider_email,
  created_at, last_login_at
`

func scanUserIdentity(scanner interface{ Scan(...any) error }) (*core.UserIdentity, error) {
	var i core.UserIdentity
	var provider string
	var providerEmail *string
	err := scanner.Scan(
		&i.ID, &i.UserID, &i.UserPoolID, &provider, &i.ProviderSubject, &providerEmail,
		&i.CreatedAt, &i.LastLoginAt,
	)
	if err != nil {
		return nil, err
	}
	i.Provider = core.UserSource(provider)
	if providerEmail != nil {
		i.ProviderEmail = *providerEmail
	}
	return &i, nil
}

// FindUserByIdentity returns the pool user linked to (provider, sub),
// or nil,nil if no identity row exists. Returned user is the joined
// users row, scanned with the standard userCols column set.
func (r *Repo) FindUserByIdentity(
	ctx context.Context,
	poolID uuid.UUID,
	provider core.UserSource,
	providerSubject string,
) (*core.User, error) {
	q := `SELECT` + userCols + `FROM users u
	        JOIN user_identities i ON i.user_id = u.id
	       WHERE i.user_pool_id = $1 AND i.provider = $2 AND i.provider_subject = $3
	       LIMIT 1`
	u, err := scanUser(r.db.Pool().QueryRow(ctx, q, poolID, string(provider), providerSubject))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return u, nil
}

// UpsertUserIdentity links a provider identity to a user, or refreshes
// the provider_email + last_login_at on an existing link. Refuses to
// silently rewrite the subject: if a row already exists for
// (user, provider) and its subject differs from providerSubject, returns
// ErrIdentitySubjectMismatch. With Google/Apple subs being stable per
// account, that condition means the email-fallback path resolved to a
// user already linked to a different provider account - the right move
// is to surface it and let the user resolve, not paper over it.
func (r *Repo) UpsertUserIdentity(
	ctx context.Context,
	userID uuid.UUID,
	poolID uuid.UUID,
	provider core.UserSource,
	providerSubject string,
	providerEmail string,
) error {
	if providerSubject == "" {
		return errors.New("provider_subject is required")
	}
	providerEmail = strings.TrimSpace(strings.ToLower(providerEmail))
	var emailArg any
	if providerEmail == "" {
		emailArg = nil
	} else {
		emailArg = providerEmail
	}

	var existing string
	err := r.db.Pool().QueryRow(ctx,
		`SELECT provider_subject FROM user_identities WHERE user_id = $1 AND provider = $2`,
		userID, string(provider),
	).Scan(&existing)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil {
		if existing != providerSubject {
			return ErrIdentitySubjectMismatch
		}
		_, err := r.db.Pool().Exec(ctx, `
UPDATE user_identities
   SET provider_email = $1, last_login_at = now()
 WHERE user_id = $2 AND provider = $3;
`, emailArg, userID, string(provider))
		return err
	}

	id := uuid.Must(uuid.NewV4())
	_, err = r.db.Pool().Exec(ctx, `
INSERT INTO user_identities
  (id, user_id, user_pool_id, provider, provider_subject, provider_email, created_at, last_login_at)
VALUES ($1, $2, $3, $4, $5, $6, now(), now());
`, id, userID, poolID, string(provider), providerSubject, emailArg)
	return err
}

// ListUserIdentities returns every identity linked to a user, newest
// last_login_at first. Empty slice (not nil error) when the user has
// no linked identities.
func (r *Repo) ListUserIdentities(
	ctx context.Context,
	userID uuid.UUID,
) ([]*core.UserIdentity, error) {
	q := `SELECT` + userIdentityCols + `FROM user_identities
	       WHERE user_id = $1
	       ORDER BY last_login_at DESC`
	rows, err := r.db.Pool().Query(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*core.UserIdentity, 0)
	for rows.Next() {
		i, err := scanUserIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// DeleteUserIdentity removes a single provider link from a user (for
// "disconnect Google" account-settings UX). No error when the row is
// already gone.
func (r *Repo) DeleteUserIdentity(
	ctx context.Context,
	userID uuid.UUID,
	provider core.UserSource,
) error {
	const q = `DELETE FROM user_identities WHERE user_id = $1 AND provider = $2;`
	_, err := r.db.Pool().Exec(ctx, q, userID, string(provider))
	return err
}
