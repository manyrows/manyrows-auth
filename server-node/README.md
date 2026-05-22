# @manyrows/server-node

Typed client for the ManyRows **server-to-server API** — call it from your
backend to manage and authorize users. Runs on Node 18+ (or any runtime with a
global `fetch`); no dependencies.

```bash
npm install @manyrows/server-node
```

## Usage

```ts
import { ManyRowsServer } from "@manyrows/server-node";

const mr = new ManyRowsServer({
  baseUrl: "https://auth.example.com",
  workspace: "acme",
  appId: "3f2a1c8e-…",
  apiKey: process.env.MANYROWS_API_KEY!, // mr_<prefix>_<secret>
});

// Authorize an action
const { allowed } = await mr.checkPermission(userId, "posts:read");

// Provision a user and grant a role (idempotent)
const { user, created } = await mr.createUser({
  email: "alice@example.com",
  emailVerified: true,
  roles: ["editor"],
});

// Suspend, then re-enable
await mr.setUserStatus(user.id, "disabled");
await mr.setUserStatus(user.id, "active");

// Passwordless onboarding link (requires magic-link auth on the app)
const { url } = await mr.createMagicLink(user.id);
```

Every call is scoped to the one app and to its **members** — the user pool only
shares credentials across apps, it is not an access boundary.

## Errors

Non-2xx responses throw a `ManyRowsServerError` carrying the HTTP `status` and
the API's stable error `code`:

```ts
import { ManyRowsServerError } from "@manyrows/server-node";

try {
  await mr.getUser(userId);
} catch (err) {
  if (err instanceof ManyRowsServerError && err.status === 404) {
    // not a member of this app
  }
}
```

## API

| Method | Endpoint |
| --- | --- |
| `getDelivery()` | `GET /` |
| `checkPermission(userId, permission)` | `GET /check-permission` |
| `listRoles()` / `listPermissions()` | `GET /roles` · `/permissions` |
| `getRole(slug)` / `getPermission(slug)` | `GET /roles/{slug}` · `/permissions/{slug}` |
| `createRole({slug,name,permissions?})` / `updateRole(slug, patch)` / `deleteRole(slug)` | `POST /roles` · `PATCH`·`DELETE /roles/{slug}` |
| `createPermission({slug,name})` / `updatePermission(slug,name)` / `deletePermission(slug)` | `POST /permissions` · `PATCH`·`DELETE /permissions/{slug}` |
| `listUsers({ search?, page?, pageSize? })` | `GET /users` |
| `getUserByEmail(email)` / `getUser(userId)` | `GET /users` |
| `createUser({ email, emailVerified?, roles? })` | `POST /users` |
| `batchCreateUsers(emails, { emailVerified?, roles? })` | `POST /users:batch` |
| `setUserStatus(userId, "active" \| "disabled")` | `PATCH /users/{id}` |
| `removeUser(userId)` | `DELETE /users/{id}` |
| `replaceUserRoles(userId, roles)` | `PUT /users/{id}/roles` |
| `addUserRole(userId, slug)` / `removeUserRole(userId, slug)` | `POST` · `DELETE /users/{id}/roles/{slug}` |
| `getUserPermissions(userId)` / `setUserPermissions(userId, perms)` | `GET` · `PUT /users/{id}/permissions` |
| `revokeUserSessions(userId)` | `DELETE /users/{id}/sessions` |
| `listUserSessions(userId)` / `revokeUserSession(userId, sessionId)` | `GET` · `DELETE /users/{id}/sessions[/{sid}]` |
| `setUserPassword(userId, password)` / `clearUserPassword(userId)` | `PUT` · `DELETE /users/{id}/password` |
| `setUserEmailVerified(userId, verified)` | `PUT /users/{id}/email-verified` |
| `setUserEnabled(userId, enabled)` | `PUT /users/{id}/enabled` (pool-wide ban) |
| `changeUserEmail(userId, email)` | `PUT /users/{id}/email` |
| `createMagicLink(userId, { rememberMe? })` | `POST /users/{id}/magic-link` |
| `getUserAuthLogs(userId, { page?, pageSize? })` | `GET /users/{id}/auth-logs` |
| `listAuthLogs({ since?, until?, outcome?, page?, pageSize? })` | `GET /auth-logs` |
| `listWebhooks()` / `createWebhook({ url, events, description? })` | `GET` · `POST /webhooks` |
| `getWebhook(id)` / `updateWebhook(id, patch)` / `deleteWebhook(id)` | `GET` · `PATCH` · `DELETE /webhooks/{id}` |
| `rotateWebhookSecret(id)` | `POST /webhooks/{id}/rotate-secret` |
| `listUserFields()` | `GET /user-fields` |
| `getUserFieldValues(userId)` | `GET /user-fields/users/{id}` |
| `setUserFieldValue(fieldId, userId, value)` | `PUT /user-fields/{fieldId}/users/{id}` |
| `deleteUserFieldValue(fieldId, userId)` | `DELETE /user-fields/{fieldId}/users/{id}` |
| `getConfigValue(configKey)` / `setConfigValue(configKey, value)` / `deleteConfigValue(configKey)` | `GET` · `PUT` · `DELETE /config/{key}` |
| `getFeatureFlagOverride(flagKey)` | `GET /features/{key}` |
| `setFeatureFlagOverride(flagKey, enabled, roles?)` / `clearFeatureFlagOverride(flagKey)` | `PUT` · `DELETE /features/{key}` |
| `listConfigKeys()` / `getConfigKey(key)` | `GET /config-keys` · `/config-keys/{key}` |
| `createConfigKey(...)` / `updateConfigKey(key, patch)` / `deleteConfigKey(key)` | `POST /config-keys` · `PATCH`·`DELETE /config-keys/{key}` |
| `listFeatureFlags()` / `getFeatureFlag(key)` | `GET /feature-flags` · `/feature-flags/{key}` |
| `createFeatureFlag(...)` / `updateFeatureFlag(key, patch)` / `deleteFeatureFlag(key)` | `POST /feature-flags` · `PATCH`·`DELETE /feature-flags/{key}` |
| `resetUserTotp(userId)` / `unlockUser(userId)` | `DELETE /users/{id}/totp` · `POST .../unlock` |
| `listUserIdentities(userId)` / `deleteUserIdentity(userId, provider)` | `GET` · `DELETE /users/{id}/identities[/{provider}]` |
| `listUserPasskeys(userId)` / `deleteUserPasskey(userId, passkeyId)` | `GET` · `DELETE /users/{id}/passkeys[/{pid}]` |

The full HTTP contract is in [`docs/server-api.openapi.yaml`](../docs/server-api.openapi.yaml).

## License

MIT
