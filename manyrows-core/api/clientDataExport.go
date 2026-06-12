package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/rs/zerolog/log"
)

const attemptPurposeClientDataExport = "client_data_export"

const dataExportAuthLogCap = 5000

type exportProfile struct {
	ID              string     `json:"id"`
	Email           string     `json:"email"`
	Enabled         bool       `json:"enabled"`
	Source          string     `json:"source"`
	EmailVerifiedAt *time.Time `json:"emailVerifiedAt,omitempty"`
	PasswordSetAt   *time.Time `json:"passwordSetAt,omitempty"`
	TOTPEnabled     bool       `json:"totpEnabled"`
	LastLoginAt     *time.Time `json:"lastLoginAt,omitempty"`
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`
}

type exportCustomField struct {
	Key        string          `json:"key"`
	Label      string          `json:"label"`
	Type       string          `json:"type"`
	Visibility string          `json:"visibility"`
	Value      json.RawMessage `json:"value,omitempty"`
}

type exportSession struct {
	IP         string    `json:"ip,omitempty"`
	UserAgent  string    `json:"userAgent,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

type exportAuthLog struct {
	Event          string          `json:"event"`
	Method         string          `json:"method,omitempty"`
	Outcome        string          `json:"outcome"`
	IP             string          `json:"ip,omitempty"`
	UserAgent      string          `json:"userAgent,omitempty"`
	EmailAttempted string          `json:"emailAttempted,omitempty"`
	RequestID      string          `json:"requestId,omitempty"`
	CreatedAt      time.Time       `json:"createdAt"`
	Metadata       json.RawMessage `json:"metadata,omitempty"`
}

type dataExport struct {
	ExportedAt        time.Time                         `json:"exportedAt"`
	SchemaVersion     int                               `json:"schemaVersion"`
	Profile           exportProfile                     `json:"profile"`
	CustomFields      []exportCustomField               `json:"customFields"`
	Identities        []*core.UserIdentityResource      `json:"identities"`
	Sessions          []exportSession                   `json:"sessions"`
	Passkeys          []PasskeyResource                 `json:"passkeys"`
	Organizations     []core.OrganizationMembershipView `json:"organizations"`
	AuthLogs          []exportAuthLog                   `json:"authLogs"`
	AuthLogsTruncated bool                              `json:"authLogsTruncated,omitempty"`
}

// GetMyDataExport returns the full set of personal data held about the caller
// as a downloadable JSON document (GDPR Art. 15 / 20).
// GET /x/{workspaceSlug}/apps/{appId}/a/me/export
func (handler *RequestHandler) GetMyDataExport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, identity, ws, app, _, ok := handler.requireActiveClientSessionApp(w, r)
	if !ok {
		return
	}

	// Rate-limit (a right, but guard against abuse / DB load).
	ip := auth.ClientIP(r)
	if !handler.checkAttemptRateLimit(w, r, attemptPurposeClientDataExport, ip, identity.User.Email, "client data export", nil) {
		return
	}
	_ = handler.repo.InsertAttempt(ctx, attemptPurposeClientDataExport, identity.User.Email, ip)

	u := identity.User
	out := dataExport{
		ExportedAt:    time.Now().UTC(),
		SchemaVersion: 1,
		Profile: exportProfile{
			ID:              u.ID.String(),
			Email:           u.Email,
			Enabled:         u.Enabled,
			Source:          string(u.Source),
			EmailVerifiedAt: u.EmailVerifiedAt,
			PasswordSetAt:   u.PasswordSetAt,
			TOTPEnabled:     u.HasTOTP(),
			LastLoginAt:     u.LastLoginAt,
			CreatedAt:       u.CreatedAt,
			UpdatedAt:       u.UpdatedAt,
		},
		CustomFields:  []exportCustomField{},
		Identities:    []*core.UserIdentityResource{},
		Sessions:      []exportSession{},
		Passkeys:      []PasskeyResource{},
		Organizations: []core.OrganizationMembershipView{},
		AuthLogs:      []exportAuthLog{},
	}

	// Custom fields — ALL values incl. server-visibility (subject is entitled).
	defs, err := handler.repo.GetUserFieldsByUserPoolID(ctx, u.UserPoolID)
	if err != nil {
		log.Err(err).Msg("GetMyDataExport: field defs failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	defByID := make(map[string]core.UserField, len(defs))
	for _, d := range defs {
		defByID[d.ID.String()] = d
	}
	vals, err := handler.repo.GetUserFieldValuesByUser(ctx, u.ID)
	if err != nil {
		log.Err(err).Msg("GetMyDataExport: field values failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	for _, v := range vals {
		d := defByID[v.UserFieldID.String()]
		out.CustomFields = append(out.CustomFields, exportCustomField{
			Key:        d.Key,
			Label:      d.Label,
			Type:       string(d.ValueType),
			Visibility: d.Visibility,
			Value:      v.ValueJSON,
		})
	}

	// Identities.
	ids, err := handler.repo.ListUserIdentities(ctx, u.ID)
	if err != nil {
		log.Err(err).Msg("GetMyDataExport: identities failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	for _, row := range ids {
		out.Identities = append(out.Identities, core.ToUserIdentityResource(row))
	}

	// Sessions.
	sessions, err := handler.repo.GetActiveClientSessionsByUserID(ctx, u.ID)
	if err != nil {
		log.Err(err).Msg("GetMyDataExport: sessions failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	for _, s := range sessions {
		out.Sessions = append(out.Sessions, exportSession{
			IP:         s.IP,
			UserAgent:  s.UserAgent,
			CreatedAt:  s.CreatedAt,
			LastSeenAt: s.LastSeenAt,
			ExpiresAt:  s.ExpiresAt,
		})
	}

	// Passkeys.
	passkeys, err := handler.repo.ListPasskeysByUser(ctx, app.ID, u.ID)
	if err != nil {
		log.Err(err).Msg("GetMyDataExport: passkeys failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	for _, p := range passkeys {
		out.Passkeys = append(out.Passkeys, toPasskeyResource(p))
	}

	// Organizations (only when the app has orgs enabled).
	if app.OrganizationsEnabled {
		orgs, err := handler.repo.ListOrganizationsForUserInApp(ctx, app.ID, u.ID)
		if err != nil {
			log.Err(err).Msg("GetMyDataExport: orgs failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		out.Organizations = append(out.Organizations, orgs...)
	}

	// Auth-log history — page through until exhausted or the safety cap.
	// OFFSET paging across round-trips can duplicate or skip a row if auth_logs change mid-export; acceptable for a point-in-time export.
	emailHistory, err := handler.repo.CollectUserEmailHistory(ctx, u.ID, u.Email)
	if err != nil {
		log.Err(err).Msg("GetMyDataExport: email history failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	const pageSize = 200
	for page := 0; len(out.AuthLogs) < dataExportAuthLogCap; page++ {
		userID := u.ID
		logs, _, err := handler.repo.ListAuthLogs(ctx, repo.ListAuthLogsParams{
			WorkspaceID:        ws.ID,
			SubjectUserID:      &userID,
			SubjectEmailsExact: emailHistory,
			Page:               page,
			PageSize:           pageSize,
		})
		if err != nil {
			log.Err(err).Msg("GetMyDataExport: auth logs failed")
			WriteError(w, r, "error.internalError", http.StatusInternalServerError)
			return
		}
		for _, l := range logs {
			el := exportAuthLog{
				Event:          string(l.Event),
				Method:         string(l.Method),
				Outcome:        string(l.Outcome),
				UserAgent:      l.UserAgent,
				EmailAttempted: l.EmailAttempted,
				RequestID:      l.RequestID,
				CreatedAt:      l.CreatedAt,
				Metadata:       l.Metadata,
			}
			if l.IP != nil {
				el.IP = l.IP.String()
			}
			out.AuthLogs = append(out.AuthLogs, el)
		}
		if len(logs) < pageSize {
			break
		}
	}
	if len(out.AuthLogs) >= dataExportAuthLogCap {
		out.AuthLogsTruncated = true
		log.Warn().Str("user_id", u.ID.String()).Msg("GetMyDataExport: auth log export hit cap; truncated")
	}

	filename := fmt.Sprintf("my-data-%s-%s.json", ws.Slug, time.Now().UTC().Format("2006-01-02"))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	utils.WriteJsonWithStatusCode(w, out, http.StatusOK)
}
