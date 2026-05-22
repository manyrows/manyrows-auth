// Package manyrows is a typed client for the ManyRows server-to-server API.
//
// Use it from your backend to manage and authorize users. Every call is scoped
// to one app and authenticated with a workspace API key.
//
//	client, err := manyrows.New(manyrows.Options{
//		BaseURL:   "https://auth.example.com",
//		Workspace: "acme",
//		AppID:     "3f2a…",
//		APIKey:    os.Getenv("MANYROWS_API_KEY"),
//	})
//	if err != nil { /* ... */ }
//	res, err := client.CheckPermission(ctx, userID, "posts:read")
package manyrows

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Options configures a Client.
type Options struct {
	// BaseURL of your ManyRows host, e.g. "https://auth.example.com".
	BaseURL string
	// Workspace slug.
	Workspace string
	// AppID (uuid).
	AppID string
	// APIKey is a server API key ("mr_<prefix>_<secret>").
	APIKey string
	// HTTPClient is optional; defaults to a client with a 30s timeout.
	HTTPClient *http.Client
}

// Client talks to one app's server-to-server API.
type Client struct {
	base   string
	apiKey string
	http   *http.Client
}

// New validates opts and returns a Client.
func New(opts Options) (*Client, error) {
	switch {
	case opts.BaseURL == "":
		return nil, fmt.Errorf("manyrows: BaseURL is required")
	case opts.Workspace == "":
		return nil, fmt.Errorf("manyrows: Workspace is required")
	case opts.AppID == "":
		return nil, fmt.Errorf("manyrows: AppID is required")
	case opts.APIKey == "":
		return nil, fmt.Errorf("manyrows: APIKey is required")
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	root := strings.TrimRight(opts.BaseURL, "/")
	base := fmt.Sprintf("%s/x/%s/api/v1/apps/%s", root, url.PathEscape(opts.Workspace), url.PathEscape(opts.AppID))
	return &Client{base: base, apiKey: opts.APIKey, http: httpClient}, nil
}

// Error is returned for any non-2xx response; it carries the HTTP status and
// the API's stable error code.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("manyrows: %d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("manyrows: %d %s", e.Status, e.Code)
}

// ---- types ----

type User struct {
	ID              string  `json:"id"`
	Email           string  `json:"email"`
	Enabled         bool    `json:"enabled"`
	EmailVerifiedAt *string `json:"emailVerifiedAt,omitempty"`
	PasswordSetAt   *string `json:"passwordSetAt,omitempty"`
	TOTPEnabled     bool    `json:"totpEnabled"`
	Source          string  `json:"source"`
}

type UserFieldValue struct {
	ID          string          `json:"id"`
	UserID      string          `json:"userId"`
	UserFieldID string          `json:"userFieldId"`
	Value       json.RawMessage `json:"value,omitempty"`
	UpdatedAt   string          `json:"updatedAt"`
	UpdatedBy   string          `json:"updatedBy"`
}

// ServerUser is a user with their roles, permissions, and field values in this app.
type ServerUser struct {
	User        User             `json:"user"`
	Roles       []string         `json:"roles"`
	Permissions []string         `json:"permissions"`
	Fields      []UserFieldValue `json:"fields"`
}

type Member struct {
	UserID          string   `json:"userId"`
	Email           string   `json:"email"`
	Name            string   `json:"name"`
	Enabled         bool     `json:"enabled"`
	EmailVerifiedAt *string  `json:"emailVerifiedAt,omitempty"`
	PasswordSetAt   *string  `json:"passwordSetAt,omitempty"`
	LastLoginAt     *string  `json:"lastLoginAt,omitempty"`
	Source          string   `json:"source"`
	AddedAt         string   `json:"addedAt"`
	Roles           []string `json:"roles"`
}

type MembersList struct {
	Members  []Member `json:"members"`
	Total    int      `json:"total"`
	Page     int      `json:"page"`
	PageSize int      `json:"pageSize"`
}

type CheckPermissionResult struct {
	Allowed    bool   `json:"allowed"`
	Permission string `json:"permission"`
	AccountID  string `json:"accountId"`
}

type RoleSummary struct {
	Slug        string   `json:"slug"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

type PermissionSummary struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type CreateUserInput struct {
	Email         string   `json:"email"`
	EmailVerified bool     `json:"emailVerified,omitempty"`
	Roles         []string `json:"roles,omitempty"`
}

type CreateUserResult struct {
	User    User     `json:"user"`
	Created bool     `json:"created"`
	Roles   []string `json:"roles"`
}

type UserStatus struct {
	UserID string `json:"userId"`
	Status string `json:"status"`
}

type RemoveUserResult struct {
	RemovedFromApp  bool `json:"removedFromApp"`
	IdentityDeleted bool `json:"identityDeleted"`
}

type MagicLinkResult struct {
	URL       string `json:"url"`
	ExpiresAt string `json:"expiresAt"`
}

type Session struct {
	ID         string `json:"id"`
	CreatedAt  string `json:"createdAt"`
	LastSeenAt string `json:"lastSeenAt"`
	ExpiresAt  string `json:"expiresAt"`
	UserAgent  string `json:"userAgent,omitempty"`
	IP         string `json:"ip,omitempty"`
}

type AuthLogEntry struct {
	ID            string `json:"id"`
	CreatedAt     string `json:"createdAt"`
	Event         string `json:"event"`
	Method        string `json:"method,omitempty"`
	Outcome       string `json:"outcome"`
	FailureReason string `json:"failureReason,omitempty"`
	ActorType     string `json:"actorType"`
	IP            string `json:"ip,omitempty"`
	UserAgent     string `json:"userAgent,omitempty"`
	RequestID     string `json:"requestId,omitempty"`
}

type AuthLogsPage struct {
	Logs     []AuthLogEntry `json:"logs"`
	Total    int            `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"pageSize"`
}

type UserField struct {
	ID           string `json:"id"`
	UserPoolID   string `json:"userPoolId"`
	Key          string `json:"key"`
	ValueType    string `json:"valueType"`
	Visibility   string `json:"visibility"`
	UserEditable bool   `json:"userEditable"`
	Label        string `json:"label"`
	Status       string `json:"status"`
	CreatedAt    string `json:"createdAt"`
	UpdatedAt    string `json:"updatedAt"`
	CreatedBy    string `json:"createdBy"`
}

type DeliveryConfigItem struct {
	Key      string          `json:"key"`
	Type     string          `json:"type"`
	Value    json.RawMessage `json:"value,omitempty"`
	IsSet    *bool           `json:"isSet,omitempty"`
	Envelope json.RawMessage `json:"envelope,omitempty"`
}

type DeliveryFlagItem struct {
	Key     string   `json:"key"`
	Enabled bool     `json:"enabled"`
	RoleIDs []string `json:"roleIds,omitempty"`
}

type Delivery struct {
	WorkspaceID string `json:"workspaceId"`
	ProductID   string `json:"productId"`
	AppID       string `json:"appId"`
	UpdatedAt   string `json:"updatedAt"`
	Config      struct {
		Public  []DeliveryConfigItem `json:"public"`
		Private []DeliveryConfigItem `json:"private"`
		Secrets []DeliveryConfigItem `json:"secrets"`
	} `json:"config"`
	Flags struct {
		Client []DeliveryFlagItem `json:"client"`
		Server []DeliveryFlagItem `json:"server"`
	} `json:"flags"`
}

// ---- Delivery ----

// GetDelivery returns all config values and feature flags for the app.
func (c *Client) GetDelivery(ctx context.Context) (*Delivery, error) {
	var out Delivery
	return &out, c.do(ctx, http.MethodGet, "/", nil, nil, &out)
}

// ---- Authorization ----

// CheckPermission reports whether a member has a permission in this app.
func (c *Client) CheckPermission(ctx context.Context, userID, permission string) (*CheckPermissionResult, error) {
	var out CheckPermissionResult
	q := url.Values{"accountId": {userID}, "permission": {permission}}
	return &out, c.do(ctx, http.MethodGet, "/check-permission", q, nil, &out)
}

// ListRoles returns the product's roles, each with the permission slugs it grants.
func (c *Client) ListRoles(ctx context.Context) ([]RoleSummary, error) {
	var out struct {
		Roles []RoleSummary `json:"roles"`
	}
	return out.Roles, c.do(ctx, http.MethodGet, "/roles", nil, nil, &out)
}

// ListPermissions returns the product's permissions.
func (c *Client) ListPermissions(ctx context.Context) ([]PermissionSummary, error) {
	var out struct {
		Permissions []PermissionSummary `json:"permissions"`
	}
	return out.Permissions, c.do(ctx, http.MethodGet, "/permissions", nil, nil, &out)
}

// ---- Users ----

// ListUsersParams filters the member list. Zero values are omitted.
type ListUsersParams struct {
	Search   string
	Page     int
	PageSize int
}

// ListUsers lists the app's members (Search is an email substring filter).
func (c *Client) ListUsers(ctx context.Context, p ListUsersParams) (*MembersList, error) {
	q := url.Values{}
	if p.Search != "" {
		q.Set("search", p.Search)
	}
	if p.Page > 0 {
		q.Set("page", strconv.Itoa(p.Page))
	}
	if p.PageSize > 0 {
		q.Set("pageSize", strconv.Itoa(p.PageSize))
	}
	var out MembersList
	return &out, c.do(ctx, http.MethodGet, "/users", q, nil, &out)
}

// GetUserByEmail looks up a member by exact email.
func (c *Client) GetUserByEmail(ctx context.Context, email string) (*ServerUser, error) {
	var out ServerUser
	return &out, c.do(ctx, http.MethodGet, "/users", url.Values{"email": {email}}, nil, &out)
}

// GetUser fetches a member by id.
func (c *Client) GetUser(ctx context.Context, userID string) (*ServerUser, error) {
	var out ServerUser
	return &out, c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(userID), nil, nil, &out)
}

// CreateUser provisions a user: create-or-find by email in the pool and add to
// the app. Idempotent.
func (c *Client) CreateUser(ctx context.Context, in CreateUserInput) (*CreateUserResult, error) {
	var out CreateUserResult
	return &out, c.do(ctx, http.MethodPost, "/users", nil, in, &out)
}

// SetUserStatus suspends ("disabled") or re-enables ("active") a member in this app.
func (c *Client) SetUserStatus(ctx context.Context, userID, status string) (*UserStatus, error) {
	var out UserStatus
	body := map[string]string{"status": status}
	return &out, c.do(ctx, http.MethodPatch, "/users/"+url.PathEscape(userID), nil, body, &out)
}

// RemoveUser removes a member from the app; the pool identity is deleted too if
// the user is left in no other app.
func (c *Client) RemoveUser(ctx context.Context, userID string) (*RemoveUserResult, error) {
	var out RemoveUserResult
	return &out, c.do(ctx, http.MethodDelete, "/users/"+url.PathEscape(userID), nil, nil, &out)
}

// ReplaceUserRoles replaces a member's roles (full set of slugs; an empty slice
// clears them and revokes the user's sessions). Returns the resulting slugs.
func (c *Client) ReplaceUserRoles(ctx context.Context, userID string, roles []string) ([]string, error) {
	if roles == nil {
		roles = []string{}
	}
	var out struct {
		Roles []string `json:"roles"`
	}
	body := map[string][]string{"roles": roles}
	return out.Roles, c.do(ctx, http.MethodPut, "/users/"+url.PathEscape(userID)+"/roles", nil, body, &out)
}

// GetUserPermissions lists a member's direct permission overrides (slugs),
// separate from the permissions inherited via roles.
func (c *Client) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	var out struct {
		Permissions []string `json:"permissions"`
	}
	return out.Permissions, c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(userID)+"/permissions", nil, nil, &out)
}

// SetUserPermissions replaces a member's direct permission overrides (full set
// of slugs) and returns the result.
func (c *Client) SetUserPermissions(ctx context.Context, userID string, permissions []string) ([]string, error) {
	if permissions == nil {
		permissions = []string{}
	}
	var out struct {
		Permissions []string `json:"permissions"`
	}
	body := map[string][]string{"permissions": permissions}
	return out.Permissions, c.do(ctx, http.MethodPut, "/users/"+url.PathEscape(userID)+"/permissions", nil, body, &out)
}

// GetUserAuthLogs returns a member's authentication-event history for this app
// (newest first, paginated). Pass page/pageSize <= 0 to use the defaults.
func (c *Client) GetUserAuthLogs(ctx context.Context, userID string, page, pageSize int) (*AuthLogsPage, error) {
	q := url.Values{}
	if page > 0 {
		q.Set("page", strconv.Itoa(page))
	}
	if pageSize > 0 {
		q.Set("pageSize", strconv.Itoa(pageSize))
	}
	var out AuthLogsPage
	return &out, c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(userID)+"/auth-logs", q, nil, &out)
}

// RevokeUserSessions force-logs-out a member from this app and returns the count revoked.
func (c *Client) RevokeUserSessions(ctx context.Context, userID string) (int64, error) {
	var out struct {
		Revoked int64 `json:"revoked"`
	}
	return out.Revoked, c.do(ctx, http.MethodDelete, "/users/"+url.PathEscape(userID)+"/sessions", nil, nil, &out)
}

// ListUserSessions lists a member's active sessions for this app.
func (c *Client) ListUserSessions(ctx context.Context, userID string) ([]Session, error) {
	var out struct {
		Sessions []Session `json:"sessions"`
	}
	return out.Sessions, c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(userID)+"/sessions", nil, nil, &out)
}

// RevokeUserSession revokes a single session of a member.
func (c *Client) RevokeUserSession(ctx context.Context, userID, sessionID string) error {
	path := "/users/" + url.PathEscape(userID) + "/sessions/" + url.PathEscape(sessionID)
	return c.do(ctx, http.MethodDelete, path, nil, nil, nil)
}

// SetUserPassword sets or replaces a member's password (enforced against the app's policy).
func (c *Client) SetUserPassword(ctx context.Context, userID, password string) error {
	body := map[string]string{"password": password}
	return c.do(ctx, http.MethodPut, "/users/"+url.PathEscape(userID)+"/password", nil, body, nil)
}

// ClearUserPassword removes a member's password (email+password sign-in disabled until reset).
func (c *Client) ClearUserPassword(ctx context.Context, userID string) error {
	return c.do(ctx, http.MethodDelete, "/users/"+url.PathEscape(userID)+"/password", nil, nil, nil)
}

// SetUserEmailVerified marks a member's email verified or unverified (a
// pool-level attribute, so it applies across every app sharing the pool).
func (c *Client) SetUserEmailVerified(ctx context.Context, userID string, verified bool) error {
	body := map[string]bool{"verified": verified}
	return c.do(ctx, http.MethodPut, "/users/"+url.PathEscape(userID)+"/email-verified", nil, body, nil)
}

// CreateMagicLink generates a one-time passwordless sign-in link for a member
// (requires the app's primary auth method to be Magic Link).
func (c *Client) CreateMagicLink(ctx context.Context, userID string, rememberMe bool) (*MagicLinkResult, error) {
	var out MagicLinkResult
	body := map[string]bool{"rememberMe": rememberMe}
	return &out, c.do(ctx, http.MethodPost, "/users/"+url.PathEscape(userID)+"/magic-link", nil, body, &out)
}

// ---- User fields ----

// ListUserFields returns the pool's user-field definitions.
func (c *Client) ListUserFields(ctx context.Context) ([]UserField, error) {
	var out struct {
		UserFields []UserField `json:"userFields"`
	}
	return out.UserFields, c.do(ctx, http.MethodGet, "/user-fields", nil, nil, &out)
}

// GetUserFieldValues returns a member's field values.
func (c *Client) GetUserFieldValues(ctx context.Context, userID string) ([]UserFieldValue, error) {
	var out struct {
		Values []UserFieldValue `json:"values"`
	}
	return out.Values, c.do(ctx, http.MethodGet, "/user-fields/users/"+url.PathEscape(userID), nil, nil, &out)
}

// SetUserFieldValue sets a member's value for a field (validated server-side
// against the field's type). value is JSON-encoded as sent.
func (c *Client) SetUserFieldValue(ctx context.Context, fieldID, userID string, value any) (*UserFieldValue, error) {
	var out struct {
		Value UserFieldValue `json:"value"`
	}
	body := map[string]any{"value": value}
	path := "/user-fields/" + url.PathEscape(fieldID) + "/users/" + url.PathEscape(userID)
	return &out.Value, c.do(ctx, http.MethodPut, path, nil, body, &out)
}

// DeleteUserFieldValue clears a member's value for a field.
func (c *Client) DeleteUserFieldValue(ctx context.Context, fieldID, userID string) error {
	path := "/user-fields/" + url.PathEscape(fieldID) + "/users/" + url.PathEscape(userID)
	return c.do(ctx, http.MethodDelete, path, nil, nil, nil)
}

// ---- internal ----

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("manyrows: encode request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, reqBody)
	if err != nil {
		return fmt.Errorf("manyrows: build request: %w", err)
	}
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("manyrows: request failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		apiErr := &Error{Status: res.StatusCode, Code: fmt.Sprintf("http_%d", res.StatusCode), Message: http.StatusText(res.StatusCode)}
		var parsed struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if data, _ := io.ReadAll(res.Body); len(data) > 0 {
			if json.Unmarshal(data, &parsed) == nil {
				if parsed.Error != "" {
					apiErr.Code = parsed.Error
				}
				if parsed.Message != "" {
					apiErr.Message = parsed.Message
				}
			}
		}
		return apiErr
	}

	if out == nil || res.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		return fmt.Errorf("manyrows: decode response: %w", err)
	}
	return nil
}
