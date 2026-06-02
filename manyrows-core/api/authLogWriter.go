package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"manyrows-core/core"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

// AuthLogInput is the writer's input — a subset of core.AuthLog with the
// fields a caller actually has to think about. ID and CreatedAt are
// server-generated. IP, UserAgent, RequestID, and the actor's account
// (when an admin is logged in) are auto-filled from the *http.Request
// the caller already has — pass them only to override.
//
// Validation rules: WorkspaceID, Event, Outcome, ActorType are required.
// FailureReason must be empty when Outcome=success and present when
// Outcome=failed (the writer enforces this). Metadata, when present,
// must be one of the typed structs in core/authLog.go (the AuthLogMetadata
// sealed interface enforces this at the type level).
type AuthLogInput struct {
	WorkspaceID uuid.UUID
	AppID       *uuid.UUID

	Event         core.AuthLogEvent
	Method        core.AuthLogMethod
	Outcome       core.AuthLogOutcome
	FailureReason core.AuthLogFailureReason

	SubjectUserID    *uuid.UUID
	SubjectAccountID *uuid.UUID
	EmailAttempted   string

	// ActorType defaults to AuthActorSelf when omitted on a row that has
	// a subject. Set explicitly to Admin/System/APIKey for non-self
	// actions. The writer does not infer admin actor from request
	// context — that would silently mis-attribute admin-on-user rows
	// any time an admin happened to be making the request. Be explicit.
	ActorType      core.AuthLogActorType
	ActorAccountID *uuid.UUID
	ActorAPIKeyID  *uuid.UUID
	ActorLabel     string

	// SessionID ties the event to a specific session. Login events
	// should set this to the newly-created session; in-session events
	// (password change, totp.enable) should set it to the current
	// session from ClientSessionFromContext.
	SessionID *uuid.UUID

	Metadata core.AuthLogMetadata
}

// writeAuthLogFromRequest is the standard call shape: takes an *http.Request
// to auto-fill IP/UA/RequestID, then writes the row best-effort. Never
// blocks the caller on log-write failures.
func (handler *RequestHandler) writeAuthLogFromRequest(r *http.Request, in AuthLogInput) {
	if in.WorkspaceID == uuid.Nil {
		log.Warn().Msg("writeAuthLogFromRequest: missing workspace_id")
		return
	}

	row := buildAuthLog(in)

	clientIP, ipAddr := auditRequestIP(r)
	_ = clientIP
	row.IP = ipAddr

	if ua := strings.TrimSpace(r.UserAgent()); ua != "" {
		row.UserAgent = ua
	}
	if rid := strings.TrimSpace(middleware.GetReqID(r.Context())); rid != "" {
		row.RequestID = rid
	}

	handler.persistAuthLog(r.Context(), row)
}

// buildAuthLog applies defaults and validates the input into a writeable
// core.AuthLog. Intentionally does not touch IP/UA/RequestID — those are
// the responsibility of the request-aware caller above.
func buildAuthLog(in AuthLogInput) core.AuthLog {
	if in.ActorType == "" {
		// Default: when the row has a subject we presume self-service.
		// Background-job writes (subjects nil) must set System explicitly.
		if in.SubjectUserID != nil || in.SubjectAccountID != nil {
			in.ActorType = core.AuthActorSelf
		} else {
			in.ActorType = core.AuthActorSystem
		}
	}

	// Outcome/FailureReason coherence — clear failure_reason on success
	// rows so the column meaning stays unambiguous.
	if in.Outcome == core.AuthOutcomeSuccess {
		in.FailureReason = ""
	}

	row := core.AuthLog{
		WorkspaceID:      in.WorkspaceID,
		AppID:            in.AppID,
		Event:            in.Event,
		Method:           in.Method,
		Outcome:          in.Outcome,
		FailureReason:    in.FailureReason,
		SubjectUserID:    in.SubjectUserID,
		SubjectAccountID: in.SubjectAccountID,
		EmailAttempted:   strings.TrimSpace(strings.ToLower(in.EmailAttempted)),
		ActorType:        in.ActorType,
		ActorAccountID:   in.ActorAccountID,
		ActorAPIKeyID:    in.ActorAPIKeyID,
		ActorLabel:       strings.TrimSpace(in.ActorLabel),
		SessionID:        in.SessionID,
	}

	if in.Metadata != nil {
		if b, err := json.Marshal(in.Metadata); err == nil && len(b) > 0 && string(b) != "null" {
			row.Metadata = b
		} else if err != nil {
			log.Err(err).Msg("auth log metadata marshal failed")
		}
	}

	return row
}

// authMethodFromLoginMethod bridges the legacy core.LoginMethod (a holdover
// from the pre-rebuild user_login_events.method enum) to the new
// AuthLogMethod constants. Most values share a wire format; magic_link
// becomes email_otp because the underlying flow has been email-OTP for a
// while now and "magic link" was a misnomer. core.LoginMethod is slated
// for deletion once every call site passes AuthLogMethod directly.
func authMethodFromLoginMethod(m core.LoginMethod) core.AuthLogMethod {
	switch m {
	case core.LoginMethodPassword:
		return core.AuthMethodPassword
	case core.LoginMethodGoogle:
		return core.AuthMethodGoogle
	case core.LoginMethodApple:
		return core.AuthMethodApple
	case core.LoginMethodMicrosoft:
		return core.AuthMethodMicrosoft
	case core.LoginMethodGithub:
		return core.AuthMethodGithub
	case core.LoginMethodTOTP:
		return core.AuthMethodTOTP
	case core.LoginMethodMagicLink:
		return core.AuthMethodEmailOTP
	case core.LoginMethodPasskey:
		return core.AuthMethodPasskey
	}
	return ""
}

// authFailFromLoginFailure bridges legacy core.LoginFailure* string codes
// (used by the old user_login_events.failure_reason column) to the typed
// AuthLogFailureReason constants. Slated for deletion once every call
// site passes AuthLogFailureReason directly.
func authFailFromLoginFailure(s string) core.AuthLogFailureReason {
	switch s {
	case core.LoginFailureNoUser:
		return core.AuthFailUnknownUser
	case core.LoginFailureWrongPass:
		return core.AuthFailWrongPassword
	case core.LoginFailureNotVerified:
		return core.AuthFailEmailNotVerified
	case core.LoginFailureLocked:
		return core.AuthFailAccountLocked
	case core.LoginFailureRateLimit:
		return core.AuthFailRateLimited
	case core.LoginFailureDisabled:
		return core.AuthFailAccountDisabled
	case core.LoginFailureTOTPRequired:
		return core.AuthFailTOTPRequired
	case core.LoginFailureTOTPInvalid:
		return core.AuthFailTOTPInvalid
	}
	return ""
}

// persistAuthLog calls the repo and logs (but does not propagate) errors.
// Auth-log writes are best-effort by design; a Postgres outage must not
// take down the auth flow itself.
func (handler *RequestHandler) persistAuthLog(ctx context.Context, row core.AuthLog) {
	if _, err := handler.repo.InsertAuthLog(ctx, row); err != nil {
		log.Err(err).Str("event", string(row.Event)).Msg("auth log insert failed")
	}
}
