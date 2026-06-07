package repo

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// Repo-level sentinel errors (use these in handlers)
var (
	ErrNotFound   = errors.New("not found")
	ErrConflict   = errors.New("conflict")
	ErrBadRequest = errors.New("bad request")

	// ErrLastOwner is returned by the guarded org-member mutations when a
	// remove/demote would leave the organization with zero active owners.
	// Handlers map it to 409 Conflict.
	ErrLastOwner = errors.New("organization must retain at least one active owner")

	// ErrPoolInUse is returned by DeleteUserPool when one or more apps
	// still point at the pool. Handler maps to 409 Conflict so admins
	// see "this pool is in use" rather than a generic 500.
	ErrPoolInUse = errors.New("user pool in use")

	// ErrIdentitySubjectMismatch is returned by UpsertUserIdentity when
	// a user already has a row for the same provider but a different
	// provider_subject. We refuse rather than silently overwrite -
	// the OAuth handler turns this into a 409 so the user can intervene
	// (the typical case is "this Google account is linked to a different
	// pool user").
	ErrIdentitySubjectMismatch = errors.New("user identity subject mismatch")

	// ErrInvitePending means a pending invite already exists for this (org, email).
	ErrInvitePending = errors.New("a pending invite already exists for this email")

	// ErrInviteNotPending is returned by AcceptOrganizationInviteTx when the
	// invite has already been accepted/revoked/expired (status != pending).
	ErrInviteNotPending = errors.New("invite is not pending")

	// ErrInviteExpired is returned by AcceptOrganizationInviteTx when the
	// invite is still pending but past its expires_at.
	ErrInviteExpired = errors.New("invite has expired")
)

func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// 23505 = unique_violation
		return pgErr.Code == "23505"
	}
	return false
}

// IsForeignKeyViolation returns true for SQLSTATE 23503. Useful when
// a constraint protects against a race the application-level check
// can't fully close - e.g. DeleteUserPool's app-count check and the
// actual DELETE happen in two statements.
func IsForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23503"
	}
	return false
}
