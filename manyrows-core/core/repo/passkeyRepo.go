package repo

import (
	"context"
	"errors"
	"fmt"
	"manyrows-core/core"
	"manyrows-core/utils"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// =====================
// App-level RPID config
// =====================

// GetAppWebAuthnRPID returns the configured WebAuthn Relying Party ID for an
// app, or nil if passkeys are not enabled for that app. Stored on the apps
// table but exposed here (rather than via core.App) so the rest of the app
// code doesn't have to thread an unused field through every query.
func (r *Repo) GetAppWebAuthnRPID(ctx context.Context, appID uuid.UUID) (*string, error) {
	const q = `SELECT webauthn_rpid FROM apps WHERE id = $1`
	var rpid *string
	if err := r.db.Pool().QueryRow(ctx, q, appID).Scan(&rpid); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("GetAppWebAuthnRPID: %w", err)
	}
	return rpid, nil
}

// SetAppWebAuthnRPID writes (or clears, when rpid is nil) the WebAuthn RPID
// for an app. Caller is responsible for validating that the RPID is a
// registrable suffix of every CORS origin currently configured on the app —
// public-suffix logic doesn't belong in SQL.
func (r *Repo) SetAppWebAuthnRPID(ctx context.Context, appID uuid.UUID, rpid *string) error {
	const q = `UPDATE apps SET webauthn_rpid = $2, updated_at = now() WHERE id = $1`
	tag, err := r.db.Pool().Exec(ctx, q, appID, rpid)
	if err != nil {
		return fmt.Errorf("SetAppWebAuthnRPID: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// =====================
// Passkey CRUD
// =====================

// InsertPasskey persists a newly registered credential. Returns the inserted
// row's ID. Returns a unique-violation error if the credential is already
// registered for this app (which would indicate a buggy client or a replay
// attempt — the library should have prevented this).
func (r *Repo) InsertPasskey(ctx context.Context, p core.UserPasskey) (core.UserPasskey, error) {
	if p.ID == uuid.Nil {
		p.ID = utils.NewUUID()
	}
	if p.AppID == uuid.Nil || p.UserID == uuid.Nil || len(p.CredentialID) == 0 || len(p.PublicKey) == 0 {
		return core.UserPasskey{}, errors.New("InsertPasskey: missing required field")
	}
	if p.Transports == nil {
		p.Transports = []string{}
	}

	const q = `
		INSERT INTO user_passkeys (
			id, app_id, user_id, credential_id, public_key, sign_count,
			transports, aaguid, backup_eligible, backup_state, name, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())
		RETURNING id, created_at
	`
	if err := r.db.Pool().QueryRow(ctx, q,
		p.ID, p.AppID, p.UserID, p.CredentialID, p.PublicKey, int64(p.SignCount),
		p.Transports, p.AAGUID, p.BackupEligible, p.BackupState, p.Name,
	).Scan(&p.ID, &p.CreatedAt); err != nil {
		if IsUniqueViolation(err) {
			return core.UserPasskey{}, errors.New("passkey already registered")
		}
		return core.UserPasskey{}, fmt.Errorf("InsertPasskey: %w", err)
	}
	return p, nil
}

// ListPasskeysByUser returns all passkeys for a user in an app, newest first.
// Used by the AppKit profile page and the admin per-user passkey list.
func (r *Repo) ListPasskeysByUser(ctx context.Context, appID, userID uuid.UUID) ([]core.UserPasskey, error) {
	const q = `
		SELECT id, app_id, user_id, credential_id, public_key, sign_count,
		       transports, aaguid, backup_eligible, backup_state, name,
		       created_at, last_used_at
		FROM user_passkeys
		WHERE app_id = $1 AND user_id = $2
		ORDER BY created_at DESC
	`
	rows, err := r.db.Pool().Query(ctx, q, appID, userID)
	if err != nil {
		return nil, fmt.Errorf("ListPasskeysByUser: %w", err)
	}
	defer rows.Close()

	out := []core.UserPasskey{}
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPasskeyByCredentialID looks up a credential during the login-finish
// ceremony. The (app_id, credential_id) pair is unique by schema.
func (r *Repo) GetPasskeyByCredentialID(ctx context.Context, appID uuid.UUID, credentialID []byte) (core.UserPasskey, error) {
	const q = `
		SELECT id, app_id, user_id, credential_id, public_key, sign_count,
		       transports, aaguid, backup_eligible, backup_state, name,
		       created_at, last_used_at
		FROM user_passkeys
		WHERE app_id = $1 AND credential_id = $2
	`
	row := r.db.Pool().QueryRow(ctx, q, appID, credentialID)
	p, err := scanPasskey(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.UserPasskey{}, ErrNotFound
		}
		return core.UserPasskey{}, fmt.Errorf("GetPasskeyByCredentialID: %w", err)
	}
	return p, nil
}

// UpdatePasskeyOnLogin bumps the sign counter, records last_used_at = now(),
// and refreshes backup_state in one round-trip after a successful login.
//
// Sign-counter regression detection: per WebAuthn spec, both stored and new
// signCount of 0 indicates an authenticator that doesn't track the counter
// (and that's allowed — every login looks the same). Otherwise new MUST be
// strictly greater than stored; equal or lesser indicates a possible clone.
//
// The accept condition: (both are 0) OR (new > stored). Earlier this was
// (new = 0 OR new > stored), which incorrectly accepted new=0 against
// stored=5 — a clone could have rolled the counter back. The library's
// CloneWarning flag is the primary defense; this SQL is defense-in-depth.
func (r *Repo) UpdatePasskeyOnLogin(ctx context.Context, id uuid.UUID, newSignCount uint32, backupState bool) error {
	const q = `
		UPDATE user_passkeys
		SET sign_count = $2, backup_state = $3, last_used_at = now()
		WHERE id = $1
		  AND (($2 = 0 AND sign_count = 0) OR $2 > sign_count)
	`
	tag, err := r.db.Pool().Exec(ctx, q, id, int64(newSignCount), backupState)
	if err != nil {
		return fmt.Errorf("UpdatePasskeyOnLogin: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New("passkey sign counter regression — possible cloned credential")
	}
	return nil
}

// RenamePasskey updates the user-facing label. Empty name clears it.
func (r *Repo) RenamePasskey(ctx context.Context, appID, userID, id uuid.UUID, name *string) error {
	const q = `
		UPDATE user_passkeys
		SET name = $4
		WHERE id = $1 AND app_id = $2 AND user_id = $3
	`
	tag, err := r.db.Pool().Exec(ctx, q, id, appID, userID, name)
	if err != nil {
		return fmt.Errorf("RenamePasskey: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeletePasskey removes a credential. Scoped to (app, user) so a compromised
// or stolen ID can't be used to delete another user's passkey.
func (r *Repo) DeletePasskey(ctx context.Context, appID, userID, id uuid.UUID) error {
	const q = `DELETE FROM user_passkeys WHERE id = $1 AND app_id = $2 AND user_id = $3`
	tag, err := r.db.Pool().Exec(ctx, q, id, appID, userID)
	if err != nil {
		return fmt.Errorf("DeletePasskey: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// =====================
// Helpers
// =====================

// scanPasskey reads a passkey row using the package-shared rowScanner
// interface defined in workspaceRepo.go.
func scanPasskey(r rowScanner) (core.UserPasskey, error) {
	var p core.UserPasskey
	var signCount int64
	var lastUsedAt *time.Time
	if err := r.Scan(
		&p.ID, &p.AppID, &p.UserID, &p.CredentialID, &p.PublicKey, &signCount,
		&p.Transports, &p.AAGUID, &p.BackupEligible, &p.BackupState, &p.Name,
		&p.CreatedAt, &lastUsedAt,
	); err != nil {
		return core.UserPasskey{}, err
	}
	if signCount < 0 || signCount > 0xFFFFFFFF {
		return core.UserPasskey{}, fmt.Errorf("passkey sign_count out of uint32 range: %d", signCount)
	}
	p.SignCount = uint32(signCount)
	p.LastUsedAt = lastUsedAt
	return p, nil
}
