package repo

import (
	"context"
	"errors"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// =====================
// Create
// =====================

// InsertApp inserts an app and returns the persisted row.
func (r *Repo) InsertApp(ctx context.Context, a core.App) (core.App, error) {
	if a.ID == uuid.Nil {
		a.ID = utils.NewUUID()
	}
	if a.WorkspaceID == uuid.Nil || a.ProjectID == uuid.Nil {
		return core.App{}, errors.New("invalid app")
	}
	switch a.Type {
	case "prod", "staging", "dev":
		// valid env type
	default:
		return core.App{}, errors.New("invalid app type (must be prod, staging, or dev)")
	}

	if a.UserPoolID == uuid.Nil {
		return core.App{}, errors.New("user_pool_id is required")
	}

	const q = `
		INSERT INTO apps (id, workspace_id, project_id, type, enabled, allow_registration, allow_account_deletion, allow_email_change, default_role_id, allowed_email_domains, primary_auth_method, auth_method_google, require_2fa, google_oauth_client_id, description, app_url, user_pool_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		RETURNING ` + appColumnsReturning

	var out core.App
	err := scanAppFull(r.db.Pool().QueryRow(ctx, q,
		a.ID,
		a.WorkspaceID,
		a.ProjectID,
		a.Type,
		a.Enabled,
		a.AllowRegistration,
		a.AllowAccountDeletion,
		a.AllowEmailChange,
		a.DefaultRoleID,
		a.AllowedEmailDomains,
		a.PrimaryAuthMethod,
		a.AuthMethodGoogle,
		a.Require2FA,
		a.GoogleOAuthClientID,
		a.Description,
		a.AppURL,
		a.UserPoolID,
	), &out)
	if err != nil {
		return core.App{}, err
	}
	return out, nil
}

// =====================
// List (project)
// =====================

// Safer multi-tenant list (recommended to use in handlers)
func (r *Repo) GetAppsByWorkspaceAndProjectID(ctx context.Context, workspaceID, projectID uuid.UUID) ([]core.App, error) {
	const q = `
		select ` + appColumnsReturning + `
from apps
		where workspace_id = $1 and project_id = $2
		order by created_at desc
	`

	rows, err := r.db.Pool().Query(ctx, q, workspaceID, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.App
	for rows.Next() {
		var a core.App
		if err := scanAppFull(rows, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

// =====================
// Get (by id)
// =====================

func (r *Repo) GetAppByID(ctx context.Context, appID uuid.UUID) (core.App, error) {
	const q = `
		select ` + appColumnsReturning + `
from apps
		where id = $1
	`

	var a core.App
	err := scanAppFull(r.db.Pool().QueryRow(ctx, q, appID), &a)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.App{}, ErrNotFound
		}
		return core.App{}, err
	}

	return a, nil
}

func (r *Repo) GetAppByIDForProject(ctx context.Context, workspaceID, projectID, appID uuid.UUID) (core.App, error) {
	const q = `
		select ` + appColumnsReturning + `
from apps
		where id = $1 and workspace_id = $2 and project_id = $3
	`

	var a core.App
	err := scanAppFull(r.db.Pool().QueryRow(ctx, q, appID, workspaceID, projectID), &a)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.App{}, ErrNotFound
		}
		return core.App{}, err
	}

	return a, nil
}

// =====================
// Update (name + enabled)
// =====================

// AppCoreUpdate carries the optional-pointer fields the catch-all
// UpdateAppEnabled handler can write. Nil pointers mean "leave the
// current value" - every column uses COALESCE($n, current) so a nil
// bumps nothing. Apps no longer have a freeform name, so the only
// mandatory writable field is enabled.
type AppCoreUpdate struct {
	AppURL                *string
	AuthDomain            *string
	SessionTTLMinutes     *int
	IdleTimeoutMinutes    *int
	RememberMeTTLMinutes  *int
	AccessTokenTTLMinutes *int
	MaxSessionsPerUser    *int
	Description           *string
}

// UpdateAppEnabled writes the small set of mutable fields. Apps used
// to carry a renameable display name; that's gone now in favor of
// the computed project + env-type label.
func (r *Repo) UpdateAppEnabled(ctx context.Context, workspaceID, projectID, appID uuid.UUID, enabled bool, u AppCoreUpdate) (core.App, error) {
	const q = `
		update apps
		set enabled = $4,
		    app_url = $5,
		    auth_domain = $6,
		    session_ttl_minutes = $7,
		    idle_timeout_minutes = $8,
		    remember_me_ttl_minutes = $9,
		    access_token_ttl_minutes = $10,
		    max_sessions_per_user = $11,
		    description = $12,
		    updated_at = now()
		where id = $1 and workspace_id = $2 and project_id = $3
		returning ` + appColumnsReturning

	var out core.App
	err := scanAppFull(r.db.Pool().QueryRow(ctx, q, appID, workspaceID, projectID, enabled,
		u.AppURL, u.AuthDomain, u.SessionTTLMinutes, u.IdleTimeoutMinutes, u.RememberMeTTLMinutes, u.AccessTokenTTLMinutes, u.MaxSessionsPerUser, u.Description,
	), &out)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.App{}, ErrNotFound
		}
		return core.App{}, err
	}

	return out, nil
}

// scanAppFull reads a full apps-table row into a core.App. The column
// order here must match appColumnsReturning; every read/write that returns
// an apps row pairs the two so the 55-field list lives in exactly one place.
type appRowScanner interface {
	Scan(dest ...any) error
}

func scanAppFull(row appRowScanner, a *core.App) error {
	return row.Scan(
		&a.ID,
		&a.WorkspaceID,
		&a.ProjectID,
		&a.Type,
		&a.ProjectName,
		&a.Enabled,
		&a.AllowRegistration,
		&a.AllowAccountDeletion,
		&a.AllowEmailChange,
		&a.DefaultRoleID,
		&a.AllowedEmailDomains,
		&a.PrimaryAuthMethod,
		&a.AuthMethodGoogle,
		&a.Require2FA,
		&a.GoogleOAuthClientID,
		&a.GoogleOAuthClientSecretEncrypted,
		&a.AuthMethodApple,
		&a.AppleServicesID,
		&a.AppleTeamID,
		&a.AppleKeyID,
		&a.ApplePrivateKeyEncrypted,
		&a.AuthMethodMicrosoft,
		&a.MicrosoftClientID,
		&a.MicrosoftClientSecretEncrypted,
		&a.MicrosoftTenant,
		&a.AuthMethodGithub,
		&a.GithubClientID,
		&a.GithubClientSecretEncrypted,
		&a.AuthMethodKakao,
		&a.KakaoClientID,
		&a.KakaoClientSecretEncrypted,
		&a.AuthMethodNaver,
		&a.NaverClientID,
		&a.NaverClientSecretEncrypted,
		&a.NaverTrustUnverifiedEmail,
		&a.AppURL,
		&a.AuthDomain,
		&a.SessionTTLMinutes,
		&a.IdleTimeoutMinutes,
		&a.RememberMeTTLMinutes,
		&a.AccessTokenTTLMinutes,
		&a.MaxSessionsPerUser,
		&a.CreatedAt,
		&a.UpdatedAt,
		&a.Description,
		&a.PasswordMinLength,
		&a.PasswordMinZxcvbnScore,
		&a.CookieDomain,
		&a.TransportMode,
		&a.SessionCookieSameSite,
		&a.QRSignInEnabled,
		&a.NewDeviceAlertsEnabled,
		&a.BruteForceProtectionEnabled,
		&a.UserPoolID,
		&a.UserPoolName,
	)
}

const appColumnsReturning = `id, workspace_id, project_id, type, (select name from projects where id = apps.project_id) as project_name, enabled, allow_registration, allow_account_deletion, allow_email_change, default_role_id, allowed_email_domains, primary_auth_method, auth_method_google, require_2fa, google_oauth_client_id, google_oauth_client_secret_encrypted, auth_method_apple, apple_services_id, apple_team_id, apple_key_id, apple_private_key_encrypted, auth_method_microsoft, microsoft_client_id, microsoft_client_secret_encrypted, microsoft_tenant, auth_method_github, github_client_id, github_client_secret_encrypted, auth_method_kakao, kakao_client_id, kakao_client_secret_encrypted, auth_method_naver, naver_client_id, naver_client_secret_encrypted, naver_trust_unverified_email, app_url, auth_domain, session_ttl_minutes, idle_timeout_minutes, remember_me_ttl_minutes, access_token_ttl_minutes, max_sessions_per_user, created_at, updated_at, description, password_min_length, password_min_zxcvbn_score, cookie_domain, transport_mode, session_cookie_samesite, qr_sign_in_enabled, new_device_alerts_enabled, brute_force_protection_enabled, user_pool_id, (select name from user_pools where id = apps.user_pool_id) as user_pool_name`

// AppRegistrationUpdate carries self-registration settings + the
// require-2FA flag (a cross-cutting policy that applies to all sign-in
// methods, not a provider concern).
type AppRegistrationUpdate struct {
	AllowRegistration    bool
	AllowAccountDeletion bool
	AllowEmailChange     bool
	DefaultRoleID        *uuid.UUID
	AllowedEmailDomains  []string
	Require2FA           bool
}

// UpdateAppRegistration updates self-registration + 2FA-required settings.
// DefaultRoleID is optional: when registration is on without a default
// role, self-registered users land with zero roles and the customer
// backend decides what a roleless token can do.
func (r *Repo) UpdateAppRegistration(ctx context.Context, workspaceID, projectID, appID uuid.UUID, u AppRegistrationUpdate) (core.App, error) {
	q := `
		update apps
		set allow_registration = $4,
		    default_role_id = $5,
		    allowed_email_domains = $6,
		    require_2fa = $7,
		    allow_account_deletion = $8,
		    allow_email_change = $9,
		    updated_at = now()
		where id = $1 and workspace_id = $2 and project_id = $3
		returning ` + appColumnsReturning

	var out core.App
	err := scanAppFull(r.db.Pool().QueryRow(ctx, q,
		appID, workspaceID, projectID,
		u.AllowRegistration, u.DefaultRoleID, u.AllowedEmailDomains, u.Require2FA, u.AllowAccountDeletion, u.AllowEmailChange,
	), &out)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.App{}, ErrNotFound
		}
		return core.App{}, err
	}
	return out, nil
}

// UpdateAppPrimaryAuthMethod sets the email-form mode for the sign-in
// screen — one of core.PrimaryAuthMethod{Password,Code,None}. password
// and code are mutually exclusive; "none" hides the email form. Cross-
// method validation (must have a working sign-in path, code mode needs
// SMTP) happens at the API layer, not here.
func (r *Repo) UpdateAppPrimaryAuthMethod(ctx context.Context, workspaceID, projectID, appID uuid.UUID, primaryAuthMethod string) (core.App, error) {
	q := `
		update apps
		set primary_auth_method = $4,
		    updated_at = now()
		where id = $1 and workspace_id = $2 and project_id = $3
		returning ` + appColumnsReturning

	var out core.App
	err := scanAppFull(r.db.Pool().QueryRow(ctx, q,
		appID, workspaceID, projectID,
		primaryAuthMethod,
	), &out)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.App{}, ErrNotFound
		}
		return core.App{}, err
	}
	return out, nil
}

// UpdateAppCookieDomain sets the per-app override for the session
// cookie Domain attribute. Pass nil to clear (app then inherits the
// workspace-level setting). Public-suffix / format validation is the
// caller's job.
func (r *Repo) UpdateAppCookieDomain(ctx context.Context, workspaceID, projectID, appID uuid.UUID, cookieDomain *string) (core.App, error) {
	q := `
		update apps
		set cookie_domain = $4,
		    updated_at = now()
		where id = $1 and workspace_id = $2 and project_id = $3
		returning ` + appColumnsReturning

	var out core.App
	err := scanAppFull(r.db.Pool().QueryRow(ctx, q,
		appID, workspaceID, projectID,
		cookieDomain,
	), &out)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.App{}, ErrNotFound
		}
		return core.App{}, err
	}
	return out, nil
}

// UpdateAppTransportMode sets the explicit transport selector for how
// the session token is delivered (see core.TransportMode* constants).
// Caller validates the value is one of the allowed enum values; the DB
// CHECK constraint is the second line of defence.
func (r *Repo) UpdateAppTransportMode(ctx context.Context, workspaceID, projectID, appID uuid.UUID, mode string) (core.App, error) {
	q := `
		update apps
		set transport_mode = $4,
		    updated_at = now()
		where id = $1 and workspace_id = $2 and project_id = $3
		returning ` + appColumnsReturning

	var out core.App
	err := scanAppFull(r.db.Pool().QueryRow(ctx, q,
		appID, workspaceID, projectID,
		mode,
	), &out)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.App{}, ErrNotFound
		}
		return core.App{}, err
	}
	return out, nil
}

// UpdateAppSessionCookieSameSite sets the SameSite attribute used when
// issuing the session cookies. Caller validates the value is one of the
// allowed enum values; the DB CHECK constraint is the second line of
// defence. Caller is also responsible for the link-flow precondition
// check (Strict + magic links / OAuth = invalid).
func (r *Repo) UpdateAppSessionCookieSameSite(ctx context.Context, workspaceID, projectID, appID uuid.UUID, mode string) (core.App, error) {
	q := `
		update apps
		set session_cookie_samesite = $4,
		    updated_at = now()
		where id = $1 and workspace_id = $2 and project_id = $3
		returning ` + appColumnsReturning

	var out core.App
	err := scanAppFull(r.db.Pool().QueryRow(ctx, q,
		appID, workspaceID, projectID,
		mode,
	), &out)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.App{}, ErrNotFound
		}
		return core.App{}, err
	}
	return out, nil
}

// UpdateAppPasswordPolicy sets the per-app password-strength policy.
// minLength is enforced as a hard floor; minScore is the zxcvbn
// threshold (0..4). Both are CHECK-constrained at the DB layer; the
// API caller validates ranges before calling.
func (r *Repo) UpdateAppPasswordPolicy(ctx context.Context, workspaceID, projectID, appID uuid.UUID, minLength, minScore int) (core.App, error) {
	q := `
		update apps
		set password_min_length = $4,
		    password_min_zxcvbn_score = $5,
		    updated_at = now()
		where id = $1 and workspace_id = $2 and project_id = $3
		returning ` + appColumnsReturning

	var out core.App
	err := scanAppFull(r.db.Pool().QueryRow(ctx, q,
		appID, workspaceID, projectID,
		minLength, minScore,
	), &out)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.App{}, ErrNotFound
		}
		return core.App{}, err
	}
	return out, nil
}

// AppGoogleConfigUpdate carries the Google sign-in toggle + credentials.
// ClientSecretEncrypted: nil = keep current, []byte{} = clear, non-empty = set.
type AppGoogleConfigUpdate struct {
	AuthMethodGoogle      bool
	ClientID              *string
	ClientSecretEncrypted []byte
}

// UpdateAppGoogleConfig sets the Google toggle + client_id/secret atomically.
func (r *Repo) UpdateAppGoogleConfig(ctx context.Context, workspaceID, projectID, appID uuid.UUID, u AppGoogleConfigUpdate) (core.App, error) {
	q := `
		update apps
		set auth_method_google = $4,
		    google_oauth_client_id = $5,
		    google_oauth_client_secret_encrypted = COALESCE($6, google_oauth_client_secret_encrypted),
		    updated_at = now()
		where id = $1 and workspace_id = $2 and project_id = $3
		returning ` + appColumnsReturning

	var out core.App
	err := scanAppFull(r.db.Pool().QueryRow(ctx, q,
		appID, workspaceID, projectID,
		u.AuthMethodGoogle, u.ClientID, u.ClientSecretEncrypted,
	), &out)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.App{}, ErrNotFound
		}
		return core.App{}, err
	}
	return out, nil
}

// AppAppleConfigUpdate carries the Apple sign-in toggle + credentials.
// PrivateKeyEncrypted: nil = keep current, []byte{} = clear, non-empty = set.
type AppAppleConfigUpdate struct {
	AuthMethodApple     bool
	ServicesID          *string
	TeamID              *string
	KeyID               *string
	PrivateKeyEncrypted []byte
}

// UpdateAppAppleConfig sets the Apple toggle + credentials atomically.
func (r *Repo) UpdateAppAppleConfig(ctx context.Context, workspaceID, projectID, appID uuid.UUID, u AppAppleConfigUpdate) (core.App, error) {
	q := `
		update apps
		set auth_method_apple = $4,
		    apple_services_id = $5,
		    apple_team_id = $6,
		    apple_key_id = $7,
		    apple_private_key_encrypted = COALESCE($8, apple_private_key_encrypted),
		    updated_at = now()
		where id = $1 and workspace_id = $2 and project_id = $3
		returning ` + appColumnsReturning

	var out core.App
	err := scanAppFull(r.db.Pool().QueryRow(ctx, q,
		appID, workspaceID, projectID,
		u.AuthMethodApple, u.ServicesID, u.TeamID, u.KeyID, u.PrivateKeyEncrypted,
	), &out)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.App{}, ErrNotFound
		}
		return core.App{}, err
	}
	return out, nil
}

// AppMicrosoftConfigUpdate carries the Microsoft sign-in toggle, client
// credentials, and tenant scope. ClientSecretEncrypted: nil = keep
// current, []byte{} = clear, non-empty = set.
type AppMicrosoftConfigUpdate struct {
	AuthMethodMicrosoft   bool
	ClientID              *string
	ClientSecretEncrypted []byte
	Tenant                string // 'common' | 'organizations' | 'consumers' | UUID
}

// UpdateAppMicrosoftConfig sets the Microsoft toggle + credentials +
// tenant scope atomically. Tenant validation (one of the four allowed
// values) lives at the API layer.
func (r *Repo) UpdateAppMicrosoftConfig(ctx context.Context, workspaceID, projectID, appID uuid.UUID, u AppMicrosoftConfigUpdate) (core.App, error) {
	q := `
		update apps
		set auth_method_microsoft = $4,
		    microsoft_client_id = $5,
		    microsoft_client_secret_encrypted = COALESCE($6, microsoft_client_secret_encrypted),
		    microsoft_tenant = $7,
		    updated_at = now()
		where id = $1 and workspace_id = $2 and project_id = $3
		returning ` + appColumnsReturning

	var out core.App
	err := scanAppFull(r.db.Pool().QueryRow(ctx, q,
		appID, workspaceID, projectID,
		u.AuthMethodMicrosoft, u.ClientID, u.ClientSecretEncrypted, u.Tenant,
	), &out)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.App{}, ErrNotFound
		}
		return core.App{}, err
	}
	return out, nil
}

// AppGithubConfigUpdate carries the GitHub sign-in toggle + OAuth
// credentials. ClientSecretEncrypted: nil = keep current,
// []byte{} = clear, non-empty = set.
type AppGithubConfigUpdate struct {
	AuthMethodGithub      bool
	ClientID              *string
	ClientSecretEncrypted []byte
}

// UpdateAppGithubConfig sets the GitHub toggle + client_id/secret
// atomically.
func (r *Repo) UpdateAppGithubConfig(ctx context.Context, workspaceID, projectID, appID uuid.UUID, u AppGithubConfigUpdate) (core.App, error) {
	q := `
		update apps
		set auth_method_github = $4,
		    github_client_id = $5,
		    github_client_secret_encrypted = COALESCE($6, github_client_secret_encrypted),
		    updated_at = now()
		where id = $1 and workspace_id = $2 and project_id = $3
		returning ` + appColumnsReturning

	var out core.App
	err := scanAppFull(r.db.Pool().QueryRow(ctx, q,
		appID, workspaceID, projectID,
		u.AuthMethodGithub, u.ClientID, u.ClientSecretEncrypted,
	), &out)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.App{}, ErrNotFound
		}
		return core.App{}, err
	}
	return out, nil
}

// AppKakaoConfigUpdate carries the Kakao sign-in toggle + OAuth
// credentials (client_id is the app's REST API key).
// ClientSecretEncrypted: nil = keep current, []byte{} = clear,
// non-empty = set.
type AppKakaoConfigUpdate struct {
	AuthMethodKakao       bool
	ClientID              *string
	ClientSecretEncrypted []byte
}

// UpdateAppKakaoConfig sets the Kakao toggle + client_id/secret atomically.
func (r *Repo) UpdateAppKakaoConfig(ctx context.Context, workspaceID, projectID, appID uuid.UUID, u AppKakaoConfigUpdate) (core.App, error) {
	q := `
		update apps
		set auth_method_kakao = $4,
		    kakao_client_id = $5,
		    kakao_client_secret_encrypted = COALESCE($6, kakao_client_secret_encrypted),
		    updated_at = now()
		where id = $1 and workspace_id = $2 and project_id = $3
		returning ` + appColumnsReturning

	var out core.App
	err := scanAppFull(r.db.Pool().QueryRow(ctx, q,
		appID, workspaceID, projectID,
		u.AuthMethodKakao, u.ClientID, u.ClientSecretEncrypted,
	), &out)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.App{}, ErrNotFound
		}
		return core.App{}, err
	}
	return out, nil
}

// AppNaverConfigUpdate carries the Naver sign-in toggle + OAuth credentials.
// ClientSecretEncrypted: nil = keep current, []byte{} = clear,
// non-empty = set.
type AppNaverConfigUpdate struct {
	AuthMethodNaver       bool
	ClientID              *string
	ClientSecretEncrypted []byte
	TrustUnverifiedEmail  bool
}

// UpdateAppNaverConfig sets the Naver toggle + client_id/secret atomically.
func (r *Repo) UpdateAppNaverConfig(ctx context.Context, workspaceID, projectID, appID uuid.UUID, u AppNaverConfigUpdate) (core.App, error) {
	q := `
		update apps
		set auth_method_naver = $4,
		    naver_client_id = $5,
		    naver_client_secret_encrypted = COALESCE($6, naver_client_secret_encrypted),
		    naver_trust_unverified_email = $7,
		    updated_at = now()
		where id = $1 and workspace_id = $2 and project_id = $3
		returning ` + appColumnsReturning

	var out core.App
	err := scanAppFull(r.db.Pool().QueryRow(ctx, q,
		appID, workspaceID, projectID,
		u.AuthMethodNaver, u.ClientID, u.ClientSecretEncrypted, u.TrustUnverifiedEmail,
	), &out)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.App{}, ErrNotFound
		}
		return core.App{}, err
	}
	return out, nil
}

// =====================
// Delete
// =====================

func (r *Repo) DeleteAppByID(ctx context.Context, workspaceID, projectID, appID uuid.UUID) error {
	const q = `
		delete from apps
		where id = $1 and workspace_id = $2 and project_id = $3
	`

	return r.execAffectingOne(ctx, ErrNotFound, q, appID, workspaceID, projectID)
}

// CountAppsByProjectID returns the number of apps in a project. Used
// for the project-level "Apps" usage counter
func (r *Repo) CountAppsByProjectID(ctx context.Context, projectID uuid.UUID) (int, error) {
	const q = `select count(*) from apps where project_id = $1`
	return r.scalarCount(ctx, q, projectID)
}

// CountAppsByWorkspaceID returns the number of apps in a workspace,
// across all projects. Used to enforce the per-workspace app cap.
func (r *Repo) CountAppsByWorkspaceID(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	const q = `select count(*) from apps where workspace_id = $1`
	return r.scalarCount(ctx, q, workspaceID)
}
