package repo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// ErrQRSignInRequiresAppURL is returned by UpdateAppQRSignInConfig
// when an admin tries to enable QR sign-in on an app whose AppURL is
// empty. The QR flow's success path redirects the desktop browser to
// AppURL with tokens in the fragment; without it, there's nowhere
// safe to land. Same shape as OIDC's ErrOIDCRequiresCookieTransport.
var ErrQRSignInRequiresAppURL = errors.New("QR sign-in requires app_url to be set")

// UpdateAppQRSignInConfig flips the per-app QR-sign-in toggle.
// Enabling requires apps.app_url to be non-empty.
func (r *Repo) UpdateAppQRSignInConfig(ctx context.Context, workspaceID, projectID, appID uuid.UUID, enabled bool) (core.App, error) {
	if enabled {
		var appURL *string
		err := r.db.Pool().QueryRow(ctx, `select app_url from apps where id = $1 and workspace_id = $2 and project_id = $3`, appID, workspaceID, projectID).Scan(&appURL)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return core.App{}, ErrNotFound
			}
			return core.App{}, fmt.Errorf("UpdateAppQRSignInConfig: app_url lookup: %w", err)
		}
		if appURL == nil || strings.TrimSpace(*appURL) == "" {
			return core.App{}, ErrQRSignInRequiresAppURL
		}
	}

	q := `
		update apps
		set qr_sign_in_enabled = $4,
		    updated_at = now()
		where id = $1 and workspace_id = $2 and project_id = $3
		returning ` + appColumnsReturning

	var out core.App
	err := scanAppFull(r.db.Pool().QueryRow(ctx, q, appID, workspaceID, projectID, enabled), &out)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.App{}, ErrNotFound
		}
		return core.App{}, fmt.Errorf("UpdateAppQRSignInConfig: %w", err)
	}
	return out, nil
}

// Cross-device pairing repo. The /start handler creates a pending
// row with a hashed code and a desktop-side polling id. The /approve
// handler flips it to approved bound to the approver's user_id. The
// /wait handler atomically consumes the approved row to mint tokens.
//
// All three transitions are single-statement UPDATE ... WHERE ...
// RETURNING so concurrent callers race cleanly (one winner, others
// see no-rows and bail).
//
// TTL policy lives here, not in the schema, so it can move without
// a migration:
//   - CrossDevicePairingTTL: 90s. Enough for camera scan + sign-in +
//     approve on a slow connection; short enough to keep the attack
//     window tight.
//   - crossDevicePairingConsumedGrace: 1h. How long terminal (consumed
//     or denied) rows linger so a late /wait still gets a terminal
//     answer before the row truly disappears.
const (
	CrossDevicePairingTTL           = 90 * time.Second
	crossDevicePairingConsumedGrace = 1 * time.Hour
)

// CreateCrossDevicePairingParams is the input to CreateCrossDevicePairing.
// IP + UserAgent are the desktop's; they become the new session's
// IP/UA when the desktop's /wait poll mints tokens.
type CreateCrossDevicePairingParams struct {
	CodeHash           string
	AppID              uuid.UUID
	InitiatorIP        string
	InitiatorUserAgent string
}

// CreateCrossDevicePairing inserts a new pending pairing. ExpiresAt is
// set here so callers don't have to remember the policy.
func (r *Repo) CreateCrossDevicePairing(ctx context.Context, p CreateCrossDevicePairingParams) (uuid.UUID, error) {
	id := utils.NewUUID()
	_, err := r.db.Pool().Exec(ctx, `
		insert into cross_device_pairings (
			id, code_hash, app_id,
			initiator_ip, initiator_user_agent,
			expires_at
		)
		values ($1, $2, $3, $4, $5, $6)
	`, id, p.CodeHash, p.AppID, p.InitiatorIP, p.InitiatorUserAgent,
		time.Now().UTC().Add(CrossDevicePairingTTL))
	if err != nil {
		return uuid.Nil, fmt.Errorf("CreateCrossDevicePairing: %w", err)
	}
	return id, nil
}

// ApproveCrossDevicePairing atomically flips a pending pairing to
// approved, binding the approver's user_id. expectedAppID guards
// against approving a pairing for app B while the phone is signed
// into app A.
//
// Returns (nil, false, nil) when no pending pairing matches (unknown
// code, expired, already approved/denied, or app mismatch) — these
// are intentionally indistinguishable to the caller so /approve does
// not leak which kind of failure occurred.
func (r *Repo) ApproveCrossDevicePairing(
	ctx context.Context,
	codeHash string,
	approverUserID uuid.UUID,
	approverIP, approverUA string,
	expectedAppID uuid.UUID,
) (*core.CrossDevicePairing, bool, error) {
	const q = `
		update cross_device_pairings
		set status = 'approved',
		    approved_user_id = $2,
		    approver_ip = $3,
		    approver_user_agent = $4,
		    approved_at = now()
		where code_hash = $1
		  and status = 'pending'
		  and expires_at > now()
		  and app_id = $5
		returning
			id, code_hash, app_id,
			initiator_ip, initiator_user_agent,
			status, approved_user_id,
			approver_ip, approver_user_agent,
			created_at, expires_at, approved_at, consumed_at
	`
	var p core.CrossDevicePairing
	err := r.db.Pool().QueryRow(ctx, q, codeHash, approverUserID, approverIP, approverUA, expectedAppID).Scan(
		&p.ID, &p.CodeHash, &p.AppID,
		&p.InitiatorIP, &p.InitiatorUserAgent,
		&p.Status, &p.ApprovedUserID,
		&p.ApproverIP, &p.ApproverUserAgent,
		&p.CreatedAt, &p.ExpiresAt, &p.ApprovedAt, &p.ConsumedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("ApproveCrossDevicePairing: %w", err)
	}
	return &p, true, nil
}

// GetCrossDevicePairing reads a pairing by id (the desktop's
// polling token). Does NOT consume; the desktop uses this for the
// "is it ready yet?" poll. Returns (nil, nil) when not found.
func (r *Repo) GetCrossDevicePairing(ctx context.Context, id uuid.UUID) (*core.CrossDevicePairing, error) {
	const q = `
		select
			id, code_hash, app_id,
			initiator_ip, initiator_user_agent,
			status, approved_user_id,
			approver_ip, approver_user_agent,
			created_at, expires_at, approved_at, consumed_at
		from cross_device_pairings
		where id = $1
	`
	var p core.CrossDevicePairing
	err := r.db.Pool().QueryRow(ctx, q, id).Scan(
		&p.ID, &p.CodeHash, &p.AppID,
		&p.InitiatorIP, &p.InitiatorUserAgent,
		&p.Status, &p.ApprovedUserID,
		&p.ApproverIP, &p.ApproverUserAgent,
		&p.CreatedAt, &p.ExpiresAt, &p.ApprovedAt, &p.ConsumedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("GetCrossDevicePairing: %w", err)
	}
	return &p, nil
}

// ConsumeApprovedCrossDevicePairing atomically marks an approved
// pairing as consumed_at=now(). Caller mints tokens on success.
//
// Returns (nil, false, nil) when the pairing is no longer approved-
// and-unconsumed-and-unexpired. Lets two concurrent /wait polls
// resolve to one winner (gets tokens) and one loser (sees 410).
func (r *Repo) ConsumeApprovedCrossDevicePairing(ctx context.Context, id uuid.UUID) (*core.CrossDevicePairing, bool, error) {
	const q = `
		update cross_device_pairings
		set consumed_at = now()
		where id = $1
		  and status = 'approved'
		  and consumed_at is null
		  and expires_at > now()
		returning
			id, code_hash, app_id,
			initiator_ip, initiator_user_agent,
			status, approved_user_id,
			approver_ip, approver_user_agent,
			created_at, expires_at, approved_at, consumed_at
	`
	var p core.CrossDevicePairing
	err := r.db.Pool().QueryRow(ctx, q, id).Scan(
		&p.ID, &p.CodeHash, &p.AppID,
		&p.InitiatorIP, &p.InitiatorUserAgent,
		&p.Status, &p.ApprovedUserID,
		&p.ApproverIP, &p.ApproverUserAgent,
		&p.CreatedAt, &p.ExpiresAt, &p.ApprovedAt, &p.ConsumedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("ConsumeApprovedCrossDevicePairing: %w", err)
	}
	return &p, true, nil
}

// DenyCrossDevicePairing flips a pending pairing to denied. Used
// when the approver explicitly cancels on the phone; the desktop's
// next /wait poll sees the terminal status and bails.
func (r *Repo) DenyCrossDevicePairing(ctx context.Context, codeHash string) error {
	_, err := r.db.Pool().Exec(ctx, `
		update cross_device_pairings
		set status = 'denied'
		where code_hash = $1
		  and status = 'pending'
	`, codeHash)
	if err != nil {
		return fmt.Errorf("DenyCrossDevicePairing: %w", err)
	}
	return nil
}

// SweepExpiredCrossDevicePairings is the janitor counterpart. Deletes:
//   - rows past their expires_at (the dominant case)
//   - rows that were consumed long enough ago that late polls don't
//     matter (terminal grace)
//   - denied rows older than the same grace (same reasoning)
func (r *Repo) SweepExpiredCrossDevicePairings(ctx context.Context) (int64, error) {
	ct, err := r.db.Pool().Exec(ctx, `
		delete from cross_device_pairings
		where expires_at < now()
		   or (consumed_at is not null and consumed_at < now() - $1::interval)
		   or (status = 'denied' and created_at < now() - $1::interval)
	`, fmt.Sprintf("%d seconds", int(crossDevicePairingConsumedGrace.Seconds())))
	if err != nil {
		return 0, fmt.Errorf("SweepExpiredCrossDevicePairings: %w", err)
	}
	return ct.RowsAffected(), nil
}
