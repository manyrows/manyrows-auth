# manyrows server-go

Typed Go client for the ManyRows **server-to-server API** — call it from your
backend to manage and authorize users. Standard library only, no dependencies.

```bash
go get github.com/manyrows/manyrows-auth/server-go
```

## Usage

```go
import manyrows "github.com/manyrows/manyrows-auth/server-go"

client, err := manyrows.New(manyrows.Options{
    BaseURL:   "https://auth.example.com",
    Workspace: "acme",
    AppID:     "3f2a1c8e-…",
    APIKey:    os.Getenv("MANYROWS_API_KEY"), // mr_<prefix>_<secret>
})
if err != nil {
    log.Fatal(err)
}

// Authorize an action
res, err := client.CheckPermission(ctx, userID, "posts:read")
// res.Allowed

// Provision a user and grant a role (idempotent)
created, err := client.CreateUser(ctx, manyrows.CreateUserInput{
    Email:         "alice@example.com",
    EmailVerified: true,
    Roles:         []string{"editor"},
})

// Suspend, then re-enable
_, err = client.SetUserStatus(ctx, created.User.ID, "disabled")
_, err = client.SetUserStatus(ctx, created.User.ID, "active")

// Passwordless onboarding link (requires magic-link auth on the app)
link, err := client.CreateMagicLink(ctx, created.User.ID, false)
// link.URL
```

Every call is scoped to the one app and to its **members** — the user pool only
shares credentials across apps, it is not an access boundary.

## Errors

Non-2xx responses return a `*manyrows.Error` carrying the HTTP status and the
API's stable error code:

```go
_, err := client.GetUser(ctx, userID)
var apiErr *manyrows.Error
if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
    // not a member of this app
}
```

## API

| Method | Endpoint |
| --- | --- |
| `GetDelivery(ctx)` | `GET /` |
| `CheckPermission(ctx, userID, permission)` | `GET /check-permission` |
| `ListRoles(ctx)` / `ListPermissions(ctx)` | `GET /roles` · `/permissions` |
| `ListUsers(ctx, ListUsersParams{…})` | `GET /users` |
| `GetUserByEmail(ctx, email)` / `GetUser(ctx, userID)` | `GET /users` |
| `CreateUser(ctx, CreateUserInput{…})` | `POST /users` |
| `BatchCreateUsers(ctx, BatchCreateUsersInput{…})` | `POST /users:batch` |
| `SetUserStatus(ctx, userID, "active"\|"disabled")` | `PATCH /users/{id}` |
| `RemoveUser(ctx, userID)` | `DELETE /users/{id}` |
| `ReplaceUserRoles(ctx, userID, roles)` | `PUT /users/{id}/roles` |
| `GetUserPermissions(ctx, userID)` / `SetUserPermissions(ctx, userID, perms)` | `GET` · `PUT /users/{id}/permissions` |
| `RevokeUserSessions(ctx, userID)` | `DELETE /users/{id}/sessions` |
| `ListUserSessions(ctx, userID)` / `RevokeUserSession(ctx, userID, sessionID)` | `GET` · `DELETE /users/{id}/sessions[/{sid}]` |
| `SetUserPassword(ctx, userID, password)` / `ClearUserPassword(ctx, userID)` | `PUT` · `DELETE /users/{id}/password` |
| `SetUserEmailVerified(ctx, userID, verified)` | `PUT /users/{id}/email-verified` |
| `CreateMagicLink(ctx, userID, rememberMe)` | `POST /users/{id}/magic-link` |
| `GetUserAuthLogs(ctx, userID, page, pageSize)` | `GET /users/{id}/auth-logs` |
| `ListAuthLogs(ctx, AuthLogsParams{…})` | `GET /auth-logs` |
| `ListUserFields(ctx)` | `GET /user-fields` |
| `GetUserFieldValues(ctx, userID)` | `GET /user-fields/users/{id}` |
| `SetUserFieldValue(ctx, fieldID, userID, value)` | `PUT /user-fields/{fieldId}/users/{id}` |
| `DeleteUserFieldValue(ctx, fieldID, userID)` | `DELETE /user-fields/{fieldId}/users/{id}` |
| `SetConfigValue(ctx, configKey, value)` / `DeleteConfigValue(ctx, configKey)` | `PUT` · `DELETE /config/{key}` |
| `SetFeatureFlag(ctx, flagKey, enabled, roles)` / `DeleteFeatureFlag(ctx, flagKey)` | `PUT` · `DELETE /features/{key}` |
| `ResetUserTOTP(ctx, userID)` / `UnlockUser(ctx, userID)` | `DELETE /users/{id}/totp` · `POST .../unlock` |
| `ListUserIdentities(ctx, userID)` / `DeleteUserIdentity(ctx, userID, provider)` | `GET` · `DELETE /users/{id}/identities[/{provider}]` |
| `ListUserPasskeys(ctx, userID)` / `DeleteUserPasskey(ctx, userID, passkeyID)` | `GET` · `DELETE /users/{id}/passkeys[/{pid}]` |

The full HTTP contract is in [`docs/server-api.openapi.yaml`](../docs/server-api.openapi.yaml).

## License

MIT
