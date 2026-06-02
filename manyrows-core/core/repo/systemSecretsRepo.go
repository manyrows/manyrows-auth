package repo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// GetSystemSecret returns the stored secret for `name` or ("", nil)
// when no row exists yet (the bootstrap path uses this to decide
// whether to generate one).
func (r *Repo) GetSystemSecret(ctx context.Context, name string) (string, error) {
	const q = `select value from system_secrets where name = $1`
	var v string
	err := r.db.Pool().QueryRow(ctx, q, name).Scan(&v)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return v, nil
}

// PutSystemSecret writes a secret if `name` doesn't already have a row.
// ON CONFLICT DO NOTHING means a concurrent boot that lost the race
// picks up the winner's value on its next read — neither boot blows
// the other away. Returns the value persisted (the input on a fresh
// insert; the existing value when a concurrent writer beat us).
//
// Use this for "first one wins" claims (super-admin email, base URL,
// generated keys). For values the operator can edit at runtime, use
// UpsertSystemSecret instead.
func (r *Repo) PutSystemSecret(ctx context.Context, name, value string) (string, error) {
	return putSystemSecret(ctx, r.db.Pool(), name, value)
}

// PutSystemSecretTx is the tx-bound variant used by callers that need
// the "first one wins" claim to be part of a larger transaction — most
// importantly AdminRegister, which has to roll the account-insert back
// when the super-admin race is lost.
func (r *Repo) PutSystemSecretTx(ctx context.Context, tx pgx.Tx, name, value string) (string, error) {
	return putSystemSecret(ctx, tx, name, value)
}

// pgxQuerier is the minimal interface satisfied by *pgxpool.Pool and pgx.Tx.
// Lets putSystemSecret run against either without duplicating the query.
type pgxQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func putSystemSecret(ctx context.Context, q pgxQuerier, name, value string) (string, error) {
	const sql = `
		insert into system_secrets (name, value, generated_at)
		values ($1, $2, now())
		on conflict (name) do nothing
		returning value
	`
	var stored string
	err := q.QueryRow(ctx, sql, name, value).Scan(&stored)
	if err == nil {
		return stored, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	// Race: another caller inserted first. Read what's there using the
	// same connection / tx so we see the committed value (in-tx readers
	// see uncommitted writes from the same tx, which is what we need
	// for "did our insert win" inside the registration tx).
	const sel = `select value from system_secrets where name = $1`
	if err := q.QueryRow(ctx, sel, name).Scan(&stored); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return stored, nil
}

// UpsertSystemSecret writes a secret unconditionally — caller wants
// the new value to win. Used by admin-editable settings (SMTP config,
// site URL override) where the super-admin's intent overrides any
// previously-stored value.
func (r *Repo) UpsertSystemSecret(ctx context.Context, name, value string) error {
	const q = `
		insert into system_secrets (name, value, generated_at)
		values ($1, $2, now())
		on conflict (name) do update set value = excluded.value, generated_at = now()
	`
	_, err := r.db.Pool().Exec(ctx, q, name, value)
	return err
}

// DeleteSystemSecret removes a row by name. Used by admin "reset to
// defaults" actions (e.g. clear SMTP config to fall back to env or
// console).
//
// CRITICAL: never call this for the auto-generated cryptographic
// secrets (session/JWT/encryption keys, OTP pepper) — every encrypted
// column in the rest of the schema is bound to those values.
func (r *Repo) DeleteSystemSecret(ctx context.Context, name string) error {
	const q = `delete from system_secrets where name = $1`
	_, err := r.db.Pool().Exec(ctx, q, name)
	return err
}
