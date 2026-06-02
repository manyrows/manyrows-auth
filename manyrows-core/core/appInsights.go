package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

// LoginMethod identifies which auth path produced a login event.
type LoginMethod string

const (
	LoginMethodPassword  LoginMethod = "password"
	LoginMethodGoogle    LoginMethod = "google"
	LoginMethodApple     LoginMethod = "apple"
	LoginMethodMicrosoft LoginMethod = "microsoft"
	LoginMethodGithub    LoginMethod = "github"
	LoginMethodTOTP      LoginMethod = "totp"
	LoginMethodMagicLink LoginMethod = "magic_link"
	LoginMethodPasskey   LoginMethod = "passkey"
	LoginMethodOther     LoginMethod = "other"
)

// LoginEventStatus is "success" or "failed".
type LoginEventStatus string

const (
	LoginEventSuccess LoginEventStatus = "success"
	LoginEventFailed  LoginEventStatus = "failed"
)

// LoginFailureReason categorizes why a login attempt failed. Free-form
// strings, but we use a small set of canonical values for charting.
const (
	LoginFailureNoUser       = "no_user"
	LoginFailureWrongPass    = "wrong_password"
	LoginFailureNotVerified  = "not_verified"
	LoginFailureLocked       = "locked"
	LoginFailureRateLimit    = "rate_limit"
	LoginFailureDisabled     = "disabled"
	LoginFailureTOTPRequired = "totp_required"
	LoginFailureTOTPInvalid  = "totp_invalid"
)

// UserLoginEvent is one row of the per-app login attempt log.
type UserLoginEvent struct {
	ID             uuid.UUID
	AppID          uuid.UUID
	UserID         *uuid.UUID
	Status         LoginEventStatus
	FailureReason  string
	Method         LoginMethod
	EmailAttempted string
	IP             string
	UserAgent      string
	CreatedAt      time.Time
}

// ===== Insights response types =====

// AppInsightsSummary backs the top stat-card row of the analytics dashboard.
// Counts are scoped to a single app and a chosen window (e.g. last 30 days),
// with a parallel "previous period" count for delta calculations.
type AppInsightsSummary struct {
	RangeDays         int `json:"rangeDays"`
	TotalUsers        int `json:"totalUsers"`
	NewUsers          int `json:"newUsers"`
	NewUsersPrev      int `json:"newUsersPrev"`
	ActiveUsers       int `json:"activeUsers"`
	ActiveUsersPrev   int `json:"activeUsersPrev"`
	LoginFailures     int `json:"loginFailures"`
	LoginFailuresPrev int `json:"loginFailuresPrev"`
}

// TimeseriesPoint is a single (date, count) pair for charts that show one
// line — signups, logins, login failures, cumulative users, etc.
type TimeseriesPoint struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// Timeseries is the response envelope for single-series charts.
type Timeseries struct {
	Metric string            `json:"metric"`
	Points []TimeseriesPoint `json:"points"`
}

// ActivityPoint is a single day's DAU/WAU/MAU sample.
type ActivityPoint struct {
	Date string `json:"date"`
	DAU  int    `json:"dau"`
	WAU  int    `json:"wau"`
	MAU  int    `json:"mau"`
}

// ActivityTimeseries powers the DAU/WAU/MAU triple-line chart.
type ActivityTimeseries struct {
	Points []ActivityPoint `json:"points"`
}

// SourceBreakdownItem is one slice of the "where did users come from" donut.
type SourceBreakdownItem struct {
	Source string `json:"source"`
	Count  int    `json:"count"`
}

// SourceBreakdown is the response envelope for the source donut chart.
type SourceBreakdown struct {
	Items []SourceBreakdownItem `json:"items"`
}

// ===== Per-user activity =====

// UserActivityEvent is one row in the recent-events list shown in the user
// activity drill-down. Mirrors UserLoginEvent but flattened to JSON-friendly
// shapes (no nullable UUIDs / timestamps).
type UserActivityEvent struct {
	Status        string `json:"status"`
	Method        string `json:"method"`
	FailureReason string `json:"failureReason,omitempty"`
	IP            string `json:"ip,omitempty"`
	UserAgent     string `json:"userAgent,omitempty"`
	CreatedAt     string `json:"createdAt"`
}

// UserActivitySummary backs the per-user drill-down — clicking a user in the
// list opens a dialog populated by this payload.
type UserActivitySummary struct {
	UserID          string              `json:"userId"`
	RangeDays       int                 `json:"rangeDays"`
	Logins          int                 `json:"logins"`
	LoginsPrev      int                 `json:"loginsPrev"`
	Failures        int                 `json:"failures"`
	FailuresPrev    int                 `json:"failuresPrev"`
	LastLoginAt     string              `json:"lastLoginAt,omitempty"`
	LastLoginIP     string              `json:"lastLoginIp,omitempty"`
	LastLoginUA     string              `json:"lastLoginUa,omitempty"`
	LastLoginMethod string              `json:"lastLoginMethod,omitempty"`
	ActiveSessions  int                 `json:"activeSessions"`
	Daily           []TimeseriesPoint   `json:"daily"`
	RecentEvents    []UserActivityEvent `json:"recentEvents"`
}
