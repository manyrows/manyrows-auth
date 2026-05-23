package core

import (
	"encoding/json"
	"net/netip"
	"time"

	"github.com/gofrs/uuid/v5"
)

// AuthLog is a single row in the auth_logs table. Every authentication-
// related event (sign-in attempts, password changes, OAuth flows,
// admin-on-user actions, session revocations, lockouts, etc.) lands
// here. Non-auth activity does NOT belong in this table.
type AuthLog struct {
	ID uuid.UUID `json:"id"`

	WorkspaceID uuid.UUID  `json:"workspaceId"`
	AppID       *uuid.UUID `json:"appId,omitempty"` // null = workspace-admin auth event

	CreatedAt time.Time `json:"createdAt"`

	Event         AuthLogEvent         `json:"event"`
	Method        AuthLogMethod        `json:"method,omitempty"`
	Outcome       AuthLogOutcome       `json:"outcome"`
	FailureReason AuthLogFailureReason `json:"failureReason,omitempty"`

	SubjectUserID    *uuid.UUID `json:"subjectUserId,omitempty"`
	SubjectAccountID *uuid.UUID `json:"subjectAccountId,omitempty"`
	EmailAttempted   string     `json:"emailAttempted,omitempty"`

	ActorType      AuthLogActorType `json:"actorType"`
	ActorAccountID *uuid.UUID       `json:"actorAccountId,omitempty"`
	ActorAPIKeyID  *uuid.UUID       `json:"actorApiKeyId,omitempty"`
	ActorLabel     string           `json:"actorLabel,omitempty"`

	IP        *netip.Addr `json:"ip,omitempty"`
	UserAgent string      `json:"userAgent,omitempty"`
	SessionID *uuid.UUID  `json:"sessionId,omitempty"`
	RequestID string      `json:"requestId,omitempty"`

	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// AuthLogEvent enumerates the closed vocabulary of auth events. Adding
// a new event is a code change — there is no customer-extension surface.
// Event names are stable wire format (admin UI filters, exports, etc.)
// — do not rename without a migration plan for downstream consumers.
type AuthLogEvent string

const (
	AuthEventRegisterSuccess AuthLogEvent = "register.success"
	AuthEventRegisterFailed  AuthLogEvent = "register.failed"

	AuthEventLoginSuccess AuthLogEvent = "login.success"
	AuthEventLoginFailed  AuthLogEvent = "login.failed"

	AuthEventLogout AuthLogEvent = "logout"

	AuthEventSessionRevoked AuthLogEvent = "session.revoked"
	AuthEventSessionsPruned AuthLogEvent = "sessions.pruned"

	AuthEventPasswordSet            AuthLogEvent = "password.set"
	AuthEventPasswordChanged        AuthLogEvent = "password.changed"
	AuthEventPasswordCleared        AuthLogEvent = "password.cleared"
	AuthEventPasswordResetRequested AuthLogEvent = "password.reset_requested"
	AuthEventPasswordResetCompleted AuthLogEvent = "password.reset_completed"

	AuthEventEmailChangeRequested AuthLogEvent = "email.change_requested"
	AuthEventEmailChanged         AuthLogEvent = "email.changed"

	AuthEventTOTPEnabled  AuthLogEvent = "totp.enabled"
	AuthEventTOTPDisabled AuthLogEvent = "totp.disabled"
	AuthEventTOTPFailed   AuthLogEvent = "totp.failed"

	AuthEventPasskeyRegistered   AuthLogEvent = "passkey.registered"
	AuthEventPasskeyUsed         AuthLogEvent = "passkey.used"
	AuthEventPasskeyDeleted      AuthLogEvent = "passkey.deleted"
	AuthEventPasskeyAdminRevoked AuthLogEvent = "passkey.admin_revoked"

	AuthEventAccountLocked        AuthLogEvent = "account.locked"
	AuthEventAccountStatusChanged AuthLogEvent = "account.status_changed"
	AuthEventAccountDeleted       AuthLogEvent = "account.deleted"
)

// AuthLogMethod is the authentication mechanism in play for the event.
// Empty string is allowed for events where no method applies (e.g.
// session.revoked by admin, account.status_changed).
type AuthLogMethod string

const (
	AuthMethodPassword  AuthLogMethod = "password"
	AuthMethodGoogle    AuthLogMethod = "google"
	AuthMethodMicrosoft AuthLogMethod = "microsoft"
	AuthMethodApple     AuthLogMethod = "apple"
	AuthMethodGithub    AuthLogMethod = "github"
	AuthMethodKakao     AuthLogMethod = "kakao"
	AuthMethodPasskey   AuthLogMethod = "passkey"
	AuthMethodTOTP      AuthLogMethod = "totp"
	AuthMethodEmailOTP  AuthLogMethod = "email_otp"
	AuthMethodMagicLink AuthLogMethod = "magic_link"
	// AuthMethodExternalIDP tags sign-ins via a generic configured
	// external IdP (the per-IdP slug is recorded on the user_identities
	// row, not here — this stays a small coarse method set).
	AuthMethodExternalIDP AuthLogMethod = "external"
)

// AuthLogOutcome is the binary success/failure axis. Even events that
// "can't fail" in the application (e.g. logout, sessions.pruned) carry
// success here — the outcome column is non-null in the schema and the
// admin UI groups by it.
type AuthLogOutcome string

const (
	AuthOutcomeSuccess AuthLogOutcome = "success"
	AuthOutcomeFailed  AuthLogOutcome = "failed"
)

// AuthLogFailureReason is a short structured code, never free text.
// Empty when outcome is success. Add new codes here rather than passing
// arbitrary strings — the admin UI uses these as filterable values.
type AuthLogFailureReason string

const (
	AuthFailWrongPassword        AuthLogFailureReason = "wrong_password"
	AuthFailUnknownUser          AuthLogFailureReason = "unknown_user"
	AuthFailEmailNotVerified     AuthLogFailureReason = "email_not_verified"
	AuthFailEmailNotProvided     AuthLogFailureReason = "email_not_provided"
	AuthFailTOTPRequired         AuthLogFailureReason = "totp_required"
	AuthFailTOTPInvalid          AuthLogFailureReason = "totp_invalid"
	AuthFailAccountLocked        AuthLogFailureReason = "account_locked"
	AuthFailAccountDisabled      AuthLogFailureReason = "account_disabled"
	AuthFailInvalidState         AuthLogFailureReason = "invalid_state"
	AuthFailInvalidCode          AuthLogFailureReason = "invalid_code"
	AuthFailExpiredCode          AuthLogFailureReason = "expired_code"
	AuthFailRegistrationDisabled AuthLogFailureReason = "registration_disabled"
	AuthFailDomainNotAllowed     AuthLogFailureReason = "domain_not_allowed"
	AuthFailIdentityConflict     AuthLogFailureReason = "identity_conflict"
	AuthFailProviderExchangeFail AuthLogFailureReason = "provider_exchange_failed"
	AuthFailAudienceMismatch     AuthLogFailureReason = "audience_mismatch"
	AuthFailTenantMismatch       AuthLogFailureReason = "tenant_mismatch"
	AuthFailRateLimited          AuthLogFailureReason = "rate_limited"
	AuthFailInternalError        AuthLogFailureReason = "internal_error"

	// Passkey-specific verification failures. Generic
	// AuthFailInvalidCode is too vague for an admin trying to
	// distinguish a misbehaving authenticator from a typo'd OTP.
	AuthFailPasskeyInvalid        AuthLogFailureReason = "passkey_invalid"         // challenge/response invalid, sign-count regression
	AuthFailPasskeyUVRequired     AuthLogFailureReason = "passkey_uv_required"     // authenticator skipped user verification
	AuthFailPasskeyCloneSuspected AuthLogFailureReason = "passkey_clone_suspected" // CloneWarning from the WebAuthn library
)

// AuthLogActorType distinguishes who triggered the event from who it
// happened to (the subject_* fields). For most rows actor=subject and
// ActorTypeSelf is used; admin/system/api_key cover the rest.
//
// 'self' is explicit (not null) so we can spot missing instrumentation.
// A null actor_type would be ambiguous — was it self-service, or did
// we forget to populate it?
type AuthLogActorType string

const (
	AuthActorSelf   AuthLogActorType = "self"
	AuthActorAdmin  AuthLogActorType = "admin"
	AuthActorAPIKey AuthLogActorType = "api_key"
	AuthActorSystem AuthLogActorType = "system"
)

// AuthLogMetadata is a sealed marker interface — only the per-event
// metadata structs declared in this file may be passed as metadata.
// This keeps the jsonb column honest: no map[string]any sneaking in,
// no free-form notes, no duplicating columns into metadata. Adding a
// new event with new metadata is a typed code change.
//
// Events that need no metadata (login.*, logout, password.*, totp.*,
// account.locked) just leave the writer's Metadata field nil — there
// is no NoMetadata sentinel.
type AuthLogMetadata interface {
	isAuthLogMetadata()
}

// RegisterMetadata accompanies register.success / register.failed.
// Source distinguishes self-signup from invite acceptance from
// admin-bulk-add — useful for understanding registration funnels and
// for security review (admin-added accounts that immediately failed
// to log in are a different signal than self-signups that did).
type RegisterMetadata struct {
	Source RegisterSource `json:"source"`
}

func (RegisterMetadata) isAuthLogMetadata() {}

type RegisterSource string

const (
	RegisterSourceSelfSignup RegisterSource = "self_signup"
	RegisterSourceInvite     RegisterSource = "invite"
	RegisterSourceAdminAdded RegisterSource = "admin_added"
)

// SessionRevokedMetadata accompanies session.revoked. The session_id
// COLUMN holds the actor's current session (the one used to make the
// revoke request); TargetSessionID is the session being killed. They
// are usually different (admin or other-device revoke). On self-revoke
// from the same session they may be equal.
type SessionRevokedMetadata struct {
	TargetSessionID uuid.UUID `json:"target_session_id"`
}

func (SessionRevokedMetadata) isAuthLogMetadata() {}

// SessionsPrunedMetadata accompanies sessions.pruned (bulk cleanup of
// expired sessions, usually by a background job).
type SessionsPrunedMetadata struct {
	Count int `json:"count"`
}

func (SessionsPrunedMetadata) isAuthLogMetadata() {}

// EmailChangeMetadata accompanies email.change_requested and
// email.changed. Both old and new are kept on the change_requested row
// even though new is also derivable from the row's user, because the
// user might be re-edited again later — the metadata freezes the
// values at event time.
type EmailChangeMetadata struct {
	OldEmail string `json:"old_email"`
	NewEmail string `json:"new_email"`
}

func (EmailChangeMetadata) isAuthLogMetadata() {}

// PasskeyMetadata accompanies passkey.registered / passkey.used /
// passkey.deleted / passkey.admin_revoked. PasskeyLabel is the
// user-supplied nickname when present.
type PasskeyMetadata struct {
	PasskeyID    uuid.UUID `json:"passkey_id"`
	PasskeyLabel string    `json:"passkey_label,omitempty"`
}

func (PasskeyMetadata) isAuthLogMetadata() {}

// AccountStatusChangedMetadata accompanies account.status_changed when
// an admin enables or disables an account. Captures the transition for
// review without joining back to the account history.
type AccountStatusChangedMetadata struct {
	From string `json:"from_status"` // 'active' | 'disabled'
	To   string `json:"to_status"`
}

func (AccountStatusChangedMetadata) isAuthLogMetadata() {}
