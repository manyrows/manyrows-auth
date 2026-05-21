package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

// =====================
// Cross-device sign-in (QR pairing)
// =====================
//
// The desktop initiates an anonymous pairing, polls on a generated id,
// and shows a QR code containing the pairing's secret. The user scans
// it on their phone, signs in (if not already), and approves. The
// desktop's next poll mints a fresh session tied to the approver's
// user_id with the desktop's IP/UA.

// CrossDevicePairing status values. The set is closed at the DB
// level via a CHECK constraint; keep these strings in sync with the
// migration.
const (
	CrossDevicePairingStatusPending  = "pending"
	CrossDevicePairingStatusApproved = "approved"
	CrossDevicePairingStatusDenied   = "denied"
)

// CrossDevicePairing models the pending → approved → consumed
// lifecycle of a QR cross-device sign-in attempt. CodeHash is the
// SHA-256 hex of the raw pairing code rendered into the QR; raw
// values never touch the DB.
type CrossDevicePairing struct {
	ID                 uuid.UUID
	CodeHash           string
	AppID              uuid.UUID
	InitiatorIP        string
	InitiatorUserAgent string
	Status             string
	ApprovedUserID     *uuid.UUID
	ApproverIP         string
	ApproverUserAgent  string
	CreatedAt          time.Time
	ExpiresAt          time.Time
	ApprovedAt         *time.Time
	ConsumedAt         *time.Time
}
