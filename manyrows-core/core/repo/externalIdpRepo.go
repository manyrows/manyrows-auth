package repo

import (
	"context"
	"errors"
	"time"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// ErrExternalIDPNotFound is returned by the by-id / by-slug lookups and
// by Update/Delete when no matching row exists for the app.
var ErrExternalIDPNotFound = errors.New("external idp not found")

// externalIDPColumns is the shared SELECT list. Optional text columns
// are COALESCEd to "" so the model can use plain strings (empty =
// absent); writes convert "" back to NULL via extNullText so the
// per-mode CHECK constraint (which distinguishes NULL from ”) holds.
const externalIDPColumns = `
  id, app_id, slug, display_name, enabled, mode,
  coalesce(issuer_url, '')           as issuer_url,
  coalesce(authorize_url, '')        as authorize_url,
  coalesce(token_url, '')            as token_url,
  coalesce(userinfo_url, '')         as userinfo_url,
  coalesce(jwks_url, '')             as jwks_url,
  client_id, client_secret_encrypted, scopes,
  subject_field, email_field,
  coalesce(email_verified_field, '') as email_verified_field,
  coalesce(name_field, '')           as name_field,
  coalesce(button_icon, '')          as button_icon,
  trust_unverified_email,
  created_at, updated_at`

// extNullText maps "" to a SQL NULL. Optional URL/field columns stay
// NULL when unset so external_idps_endpoints_per_mode (NULL vs ”) works.
func extNullText(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func scanExternalIDP(row pgx.Row) (*core.ExternalIDP, error) {
	var e core.ExternalIDP
	var mode string // scan into plain string, convert (avoids named-type scan quirks)
	if err := row.Scan(
		&e.ID, &e.AppID, &e.Slug, &e.DisplayName, &e.Enabled, &mode,
		&e.IssuerURL, &e.AuthorizeURL, &e.TokenURL, &e.UserinfoURL, &e.JWKSURL,
		&e.ClientID, &e.ClientSecretEncrypted, &e.Scopes,
		&e.SubjectField, &e.EmailField, &e.EmailVerifiedField, &e.NameField,
		&e.ButtonIcon, &e.TrustUnverifiedEmail, &e.CreatedAt, &e.UpdatedAt,
	); err != nil {
		return nil, err
	}
	e.Mode = core.ExternalIDPMode(mode)
	return &e, nil
}

// applyExternalIDPDefaults fills the NOT-NULL mapping columns so a bare
// Create/Update can't blank out the standard claim names by passing "".
func applyExternalIDPDefaults(e *core.ExternalIDP) {
	if e.Mode == "" {
		e.Mode = core.ExternalIDPModeOIDC
	}
	if e.Scopes == "" {
		e.Scopes = "openid email profile"
	}
	if e.SubjectField == "" {
		e.SubjectField = "sub"
	}
	if e.EmailField == "" {
		e.EmailField = "email"
	}
}

// CreateExternalIDP inserts a new external IdP config. Generates the ID
// and timestamps if unset. The client secret must already be encrypted.
func (r *Repo) CreateExternalIDP(ctx context.Context, e *core.ExternalIDP) error {
	if e == nil {
		return errors.New("external idp is nil")
	}
	if e.AppID == uuid.Nil {
		return errors.New("app_id must be set")
	}
	if e.ID == uuid.Nil {
		id, err := uuid.NewV4()
		if err != nil {
			return err
		}
		e.ID = id
	}
	applyExternalIDPDefaults(e)
	now := time.Now().UTC()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	e.UpdatedAt = now

	const q = `
insert into external_idps (
  id, app_id, slug, display_name, enabled, mode,
  issuer_url, authorize_url, token_url, userinfo_url, jwks_url,
  client_id, client_secret_encrypted, scopes,
  subject_field, email_field, email_verified_field, name_field, button_icon,
  created_at, updated_at, trust_unverified_email
) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22);`

	_, err := r.db.Pool().Exec(ctx, q,
		e.ID, e.AppID, e.Slug, e.DisplayName, e.Enabled, string(e.Mode),
		extNullText(e.IssuerURL), extNullText(e.AuthorizeURL), extNullText(e.TokenURL), extNullText(e.UserinfoURL), extNullText(e.JWKSURL),
		e.ClientID, e.ClientSecretEncrypted, e.Scopes,
		e.SubjectField, e.EmailField, extNullText(e.EmailVerifiedField), extNullText(e.NameField), extNullText(e.ButtonIcon),
		e.CreatedAt, e.UpdatedAt, e.TrustUnverifiedEmail,
	)
	return err
}

// UpdateExternalIDP overwrites every mutable column for (app_id, id).
// Full overwrite: callers that don't change the secret must carry the
// existing ClientSecretEncrypted forward on the struct (the admin
// handler loads-then-merges). Returns ErrExternalIDPNotFound if no row.
func (r *Repo) UpdateExternalIDP(ctx context.Context, e *core.ExternalIDP) error {
	if e == nil {
		return errors.New("external idp is nil")
	}
	if e.AppID == uuid.Nil || e.ID == uuid.Nil {
		return errors.New("app_id and id must be set")
	}
	applyExternalIDPDefaults(e)
	e.UpdatedAt = time.Now().UTC()

	const q = `
update external_idps set
  slug=$3, display_name=$4, enabled=$5, mode=$6,
  issuer_url=$7, authorize_url=$8, token_url=$9, userinfo_url=$10, jwks_url=$11,
  client_id=$12, client_secret_encrypted=$13, scopes=$14,
  subject_field=$15, email_field=$16, email_verified_field=$17, name_field=$18, button_icon=$19,
  updated_at=$20, trust_unverified_email=$21
where app_id=$1 and id=$2;`

	tag, err := r.db.Pool().Exec(ctx, q,
		e.AppID, e.ID, e.Slug, e.DisplayName, e.Enabled, string(e.Mode),
		extNullText(e.IssuerURL), extNullText(e.AuthorizeURL), extNullText(e.TokenURL), extNullText(e.UserinfoURL), extNullText(e.JWKSURL),
		e.ClientID, e.ClientSecretEncrypted, e.Scopes,
		e.SubjectField, e.EmailField, extNullText(e.EmailVerifiedField), extNullText(e.NameField), extNullText(e.ButtonIcon),
		e.UpdatedAt, e.TrustUnverifiedEmail,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrExternalIDPNotFound
	}
	return nil
}

// DeleteExternalIDP removes (app_id, id). Reports whether a row went.
func (r *Repo) DeleteExternalIDP(ctx context.Context, appID, id uuid.UUID) (bool, error) {
	tag, err := r.db.Pool().Exec(ctx, `delete from external_idps where app_id=$1 and id=$2;`, appID, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// GetExternalIDPByID fetches one config, scoped to the app so a caller
// can't read another app's IdP by guessing its id.
func (r *Repo) GetExternalIDPByID(ctx context.Context, appID, id uuid.UUID) (*core.ExternalIDP, error) {
	q := `select` + externalIDPColumns + ` from external_idps where app_id=$1 and id=$2;`
	e, err := scanExternalIDP(r.db.Pool().QueryRow(ctx, q, appID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrExternalIDPNotFound
	}
	if err != nil {
		return nil, err
	}
	return e, nil
}

// GetExternalIDPByAppAndSlug resolves the provider the authorize/callback
// routes are scoped to.
func (r *Repo) GetExternalIDPByAppAndSlug(ctx context.Context, appID uuid.UUID, slug string) (*core.ExternalIDP, error) {
	q := `select` + externalIDPColumns + ` from external_idps where app_id=$1 and slug=$2;`
	e, err := scanExternalIDP(r.db.Pool().QueryRow(ctx, q, appID, slug))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrExternalIDPNotFound
	}
	if err != nil {
		return nil, err
	}
	return e, nil
}

// ListExternalIDPsByApp returns every configured IdP for an app (admin
// view), ordered by display name.
func (r *Repo) ListExternalIDPsByApp(ctx context.Context, appID uuid.UUID) ([]core.ExternalIDP, error) {
	return r.listExternalIDPs(ctx, `where app_id=$1 order by display_name asc`, appID)
}

// ListEnabledExternalIDPsByApp returns only the enabled IdPs — what
// AppKit needs to render its provider buttons.
func (r *Repo) ListEnabledExternalIDPsByApp(ctx context.Context, appID uuid.UUID) ([]core.ExternalIDP, error) {
	return r.listExternalIDPs(ctx, `where app_id=$1 and enabled=true order by display_name asc`, appID)
}

func (r *Repo) listExternalIDPs(ctx context.Context, whereClause string, args ...any) ([]core.ExternalIDP, error) {
	q := `select` + externalIDPColumns + ` from external_idps ` + whereClause + `;`
	rows, err := r.db.Pool().Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]core.ExternalIDP, 0)
	for rows.Next() {
		e, err := scanExternalIDP(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}
