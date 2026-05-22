/**
 * @manyrows/server-node — a typed client for the ManyRows server-to-server API.
 *
 * For use from your backend (Node 18+, or any runtime with a global `fetch`).
 * Authenticate with a workspace API key; every call is scoped to one app.
 *
 * ```ts
 * const mr = new ManyRowsServer({
 *   baseUrl: "https://auth.example.com",
 *   workspace: "acme",
 *   appId: "3f2a…",
 *   apiKey: process.env.MANYROWS_API_KEY!,
 * });
 * const { allowed } = await mr.checkPermission(userId, "posts:read");
 * ```
 */

export interface ManyRowsServerOptions {
  /** Base URL of your ManyRows host, e.g. `https://auth.example.com`. */
  baseUrl: string;
  /** Workspace slug. */
  workspace: string;
  /** App ID (uuid). */
  appId: string;
  /** Server API key (`mr_<prefix>_<secret>`). */
  apiKey: string;
  /** Override the fetch implementation (defaults to the global `fetch`). */
  fetch?: typeof globalThis.fetch;
}

export type UserSource =
  | "invited"
  | "registered"
  | "google"
  | "apple"
  | "microsoft"
  | "github"
  | "external";

export interface User {
  id: string;
  email: string;
  enabled: boolean;
  emailVerifiedAt?: string | null;
  passwordSetAt?: string | null;
  totpEnabled: boolean;
  source: UserSource;
}

export interface UserFieldValue {
  id: string;
  userId: string;
  userFieldId: string;
  value: unknown;
  updatedAt: string;
  updatedBy: string;
}

/** A user with their roles, permissions, and field values in this app. */
export interface ServerUser {
  user: User;
  roles: string[];
  permissions: string[];
  fields: UserFieldValue[];
}

export interface Member {
  userId: string;
  email: string;
  name: string;
  enabled: boolean;
  emailVerifiedAt?: string | null;
  passwordSetAt?: string | null;
  lastLoginAt?: string | null;
  source: string;
  addedAt: string;
  roles: string[];
}

export interface MembersList {
  members: Member[];
  total: number;
  page: number;
  pageSize: number;
}

export interface CheckPermissionResult {
  allowed: boolean;
  permission: string;
  accountId: string;
}

export interface RoleSummary {
  slug: string;
  name: string;
  /** Permission slugs this role grants. */
  permissions: string[];
}

export interface PermissionSummary {
  slug: string;
  name: string;
}

export interface CreateUserInput {
  email: string;
  /** Mark the address verified (you vouch for it). Defaults to false. */
  emailVerified?: boolean;
  /** Role slugs to assign in this app. */
  roles?: string[];
  /** Email the user a branded invitation after provisioning (requires an App URL). */
  sendInvite?: boolean;
}

export interface CreateUserResult {
  user: User;
  /** True when a new identity was created; false when an existing one was reused. */
  created: boolean;
  roles: string[];
  /** True when sendInvite was requested and the email was sent. */
  invited?: boolean;
}

export interface BatchUserResult {
  email: string;
  userId?: string;
  created: boolean;
  /** Set when this email failed; the rest of the batch still succeed. */
  error?: string;
}

export type AppUserStatus = "active" | "disabled";

export interface UserStatusResult {
  userId: string;
  status: AppUserStatus;
}

export interface RemoveUserResult {
  removedFromApp: boolean;
  /** True when the pool identity was also deleted (the user was left in no other app). */
  identityDeleted: boolean;
}

export interface MagicLinkResult {
  url: string;
  expiresAt: string;
}

export interface Session {
  id: string;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  userAgent?: string;
  ip?: string;
}

export interface AuthLogEntry {
  id: string;
  createdAt: string;
  event: string;
  method?: string;
  outcome: string;
  failureReason?: string;
  actorType: string;
  ip?: string;
  userAgent?: string;
  requestId?: string;
}

export interface AuthLogsPage {
  logs: AuthLogEntry[];
  total: number;
  page: number;
  pageSize: number;
}

export interface Identity {
  provider: string;
  providerSubject?: string;
  providerEmail?: string;
  createdAt: string;
  lastLoginAt: string;
}

export interface Passkey {
  id: string;
  name?: string;
  transports?: string[];
  createdAt: string;
  lastUsedAt?: string;
}

export interface Webhook {
  id: string;
  appId: string;
  url: string;
  /** HMAC signing secret — present only in the create response. */
  secret?: string;
  events: string[];
  status: "active" | "disabled";
  description: string;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

export interface UserField {
  id: string;
  userPoolId: string;
  key: string;
  valueType: "string" | "bool" | "date";
  visibility: "client" | "server";
  userEditable: boolean;
  label: string;
  status: string;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

export interface DeliveryConfigItem {
  key: string;
  type: string;
  value?: unknown;
  isSet?: boolean;
  envelope?: unknown;
}

export interface DeliveryFlagItem {
  key: string;
  enabled: boolean;
  roleIds?: string[];
}

export interface Delivery {
  workspaceId: string;
  productId: string;
  appId: string;
  updatedAt: string;
  config: {
    public: DeliveryConfigItem[];
    private: DeliveryConfigItem[];
    secrets: DeliveryConfigItem[];
  };
  flags: {
    client: DeliveryFlagItem[];
    server: DeliveryFlagItem[];
  };
}

/** Thrown on any non-2xx response; carries the API's `{ error, message }`. */
export class ManyRowsServerError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message || code || `HTTP ${status}`);
    this.name = "ManyRowsServerError";
    this.status = status;
    this.code = code;
  }
}

type Query = Record<string, string | number | boolean | undefined>;

export class ManyRowsServer {
  private readonly base: string;
  private readonly apiKey: string;
  private readonly fetchImpl: typeof globalThis.fetch;

  constructor(opts: ManyRowsServerOptions) {
    if (!opts.baseUrl) throw new Error("ManyRowsServer: baseUrl is required");
    if (!opts.workspace) throw new Error("ManyRowsServer: workspace is required");
    if (!opts.appId) throw new Error("ManyRowsServer: appId is required");
    if (!opts.apiKey) throw new Error("ManyRowsServer: apiKey is required");

    const root = opts.baseUrl.replace(/\/+$/, "");
    this.base = `${root}/x/${encodeURIComponent(opts.workspace)}/api/v1/apps/${encodeURIComponent(opts.appId)}`;
    this.apiKey = opts.apiKey;

    const f = opts.fetch ?? globalThis.fetch;
    if (typeof f !== "function") {
      throw new Error("ManyRowsServer: no global fetch; pass opts.fetch (Node 18+ has fetch built in)");
    }
    this.fetchImpl = f;
  }

  // ---- Delivery ----

  /** All config values and feature flags for the app. */
  getDelivery(): Promise<Delivery> {
    return this.request<Delivery>("GET", "/");
  }

  // ---- Authorization ----

  /** Whether a member has a permission in this app. */
  checkPermission(userId: string, permission: string): Promise<CheckPermissionResult> {
    return this.request("GET", "/check-permission", { query: { accountId: userId, permission } });
  }

  /** The product's roles, each with the permission slugs it grants. */
  async listRoles(): Promise<RoleSummary[]> {
    const { roles } = await this.request<{ roles: RoleSummary[] }>("GET", "/roles");
    return roles;
  }

  /** The product's permissions. */
  async listPermissions(): Promise<PermissionSummary[]> {
    const { permissions } = await this.request<{ permissions: PermissionSummary[] }>("GET", "/permissions");
    return permissions;
  }

  // ---- Users ----

  /** List the app's members (paginated; `search` is an email substring filter). */
  listUsers(opts: { search?: string; page?: number; pageSize?: number } = {}): Promise<MembersList> {
    return this.request("GET", "/users", {
      query: { search: opts.search, page: opts.page, pageSize: opts.pageSize },
    });
  }

  /** Look up a member by exact email (with roles, permissions, fields). */
  getUserByEmail(email: string): Promise<ServerUser> {
    return this.request("GET", "/users", { query: { email } });
  }

  /** Fetch a member by id (with roles, permissions, fields). */
  getUser(userId: string): Promise<ServerUser> {
    return this.request("GET", `/users/${encodeURIComponent(userId)}`);
  }

  /** Provision a user: create-or-find by email in the pool and add to the app. Idempotent. */
  createUser(input: CreateUserInput): Promise<CreateUserResult> {
    return this.request("POST", "/users", { body: input });
  }

  /**
   * Provision up to 100 users at once, all with the same optional roles.
   * Each email is reported independently in the result, so one bad email
   * doesn't sink the rest. Idempotent per email.
   */
  async batchCreateUsers(
    emails: string[],
    opts: { emailVerified?: boolean; roles?: string[] } = {},
  ): Promise<BatchUserResult[]> {
    const { results } = await this.request<{ results: BatchUserResult[] }>("POST", "/users:batch", {
      body: { emails, emailVerified: opts.emailVerified, roles: opts.roles },
    });
    return results;
  }

  /** Suspend (`disabled`) or re-enable (`active`) a member in this app. */
  setUserStatus(userId: string, status: AppUserStatus): Promise<UserStatusResult> {
    return this.request("PATCH", `/users/${encodeURIComponent(userId)}`, { body: { status } });
  }

  /** Remove a member from the app; prunes the pool identity if it's left in no other app. */
  removeUser(userId: string): Promise<RemoveUserResult> {
    return this.request("DELETE", `/users/${encodeURIComponent(userId)}`);
  }

  /** Replace a member's roles (full set of slugs; `[]` clears them and revokes sessions). */
  replaceUserRoles(userId: string, roles: string[]): Promise<{ roles: string[] }> {
    return this.request("PUT", `/users/${encodeURIComponent(userId)}/roles`, { body: { roles } });
  }

  /** A member's direct permission overrides (slugs), separate from role-granted permissions. */
  async getUserPermissions(userId: string): Promise<string[]> {
    const { permissions } = await this.request<{ permissions: string[] }>(
      "GET",
      `/users/${encodeURIComponent(userId)}/permissions`,
    );
    return permissions;
  }

  /** Replace a member's direct permission overrides (full set of slugs). Returns the result. */
  async setUserPermissions(userId: string, permissions: string[]): Promise<string[]> {
    const res = await this.request<{ permissions: string[] }>(
      "PUT",
      `/users/${encodeURIComponent(userId)}/permissions`,
      { body: { permissions } },
    );
    return res.permissions;
  }

  /** A member's authentication-event history for this app (newest first, paginated). */
  getUserAuthLogs(userId: string, opts: { page?: number; pageSize?: number } = {}): Promise<AuthLogsPage> {
    return this.request("GET", `/users/${encodeURIComponent(userId)}/auth-logs`, {
      query: { page: opts.page, pageSize: opts.pageSize },
    });
  }

  /** App-wide auth-event history (all users), for SIEM/analytics ingestion. */
  listAuthLogs(
    opts: { since?: string; until?: string; outcome?: "success" | "failure"; page?: number; pageSize?: number } = {},
  ): Promise<AuthLogsPage> {
    return this.request("GET", "/auth-logs", {
      query: { since: opts.since, until: opts.until, outcome: opts.outcome, page: opts.page, pageSize: opts.pageSize },
    });
  }

  /** List the app's webhook subscriptions (signing secrets redacted). */
  async listWebhooks(): Promise<Webhook[]> {
    const { webhooks } = await this.request<{ webhooks: Webhook[] }>("GET", "/webhooks");
    return webhooks;
  }

  /** Register a webhook. The returned `secret` is shown only here — store it. */
  createWebhook(input: { url: string; events: string[]; description?: string }): Promise<Webhook> {
    return this.request("POST", "/webhooks", { body: input });
  }

  /** Get one webhook (secret redacted). */
  getWebhook(webhookId: string): Promise<Webhook> {
    return this.request("GET", `/webhooks/${encodeURIComponent(webhookId)}`);
  }

  /** Update a webhook (URL, events, status, description). */
  updateWebhook(
    webhookId: string,
    patch: { url?: string; events?: string[]; status?: "active" | "disabled"; description?: string },
  ): Promise<Webhook> {
    return this.request("PATCH", `/webhooks/${encodeURIComponent(webhookId)}`, { body: patch });
  }

  /** Delete a webhook. */
  deleteWebhook(webhookId: string): Promise<void> {
    return this.request("DELETE", `/webhooks/${encodeURIComponent(webhookId)}`, { expectNoContent: true });
  }

  /** Force-logout: revoke all of a member's sessions for this app. */
  revokeUserSessions(userId: string): Promise<{ revoked: number }> {
    return this.request("DELETE", `/users/${encodeURIComponent(userId)}/sessions`);
  }

  /** List a member's active sessions for this app. */
  async listUserSessions(userId: string): Promise<Session[]> {
    const { sessions } = await this.request<{ sessions: Session[] }>(
      "GET",
      `/users/${encodeURIComponent(userId)}/sessions`,
    );
    return sessions;
  }

  /** Revoke a single session of a member. */
  revokeUserSession(userId: string, sessionId: string): Promise<void> {
    return this.request(
      "DELETE",
      `/users/${encodeURIComponent(userId)}/sessions/${encodeURIComponent(sessionId)}`,
      { expectNoContent: true },
    );
  }

  /** Set (or replace) a member's password; enforced against the app's policy. */
  setUserPassword(userId: string, password: string): Promise<void> {
    return this.request("PUT", `/users/${encodeURIComponent(userId)}/password`, {
      body: { password },
      expectNoContent: true,
    });
  }

  /** Clear a member's password (email+password sign-in disabled until a new one is set). */
  clearUserPassword(userId: string): Promise<void> {
    return this.request("DELETE", `/users/${encodeURIComponent(userId)}/password`, { expectNoContent: true });
  }

  /** Mark a member's email verified or unverified (a pool-level attribute). */
  setUserEmailVerified(userId: string, verified: boolean): Promise<void> {
    return this.request("PUT", `/users/${encodeURIComponent(userId)}/email-verified`, {
      body: { verified },
      expectNoContent: true,
    });
  }

  /** Generate a one-time passwordless sign-in link for a member (requires magic-link auth). */
  createMagicLink(userId: string, opts: { rememberMe?: boolean } = {}): Promise<MagicLinkResult> {
    return this.request("POST", `/users/${encodeURIComponent(userId)}/magic-link`, { body: opts });
  }

  // ---- User fields ----

  /** The pool's user-field definitions. */
  async listUserFields(): Promise<UserField[]> {
    const { userFields } = await this.request<{ userFields: UserField[] }>("GET", "/user-fields");
    return userFields;
  }

  /** A member's field values. */
  async getUserFieldValues(userId: string): Promise<UserFieldValue[]> {
    const { values } = await this.request<{ values: UserFieldValue[] }>(
      "GET",
      `/user-fields/users/${encodeURIComponent(userId)}`,
    );
    return values;
  }

  /** Set a member's value for a field (validated server-side against the field's type). */
  async setUserFieldValue(fieldId: string, userId: string, value: unknown): Promise<UserFieldValue> {
    const res = await this.request<{ value: UserFieldValue }>(
      "PUT",
      `/user-fields/${encodeURIComponent(fieldId)}/users/${encodeURIComponent(userId)}`,
      { body: { value } },
    );
    return res.value;
  }

  /** Clear a member's value for a field. */
  deleteUserFieldValue(fieldId: string, userId: string): Promise<void> {
    return this.request(
      "DELETE",
      `/user-fields/${encodeURIComponent(fieldId)}/users/${encodeURIComponent(userId)}`,
      { expectNoContent: true },
    );
  }

  /** Set this app's value for a public/private config key (read back via getDelivery). */
  setConfigValue(configKey: string, value: unknown): Promise<void> {
    return this.request("PUT", `/config/${encodeURIComponent(configKey)}`, {
      body: { value },
      expectNoContent: true,
    });
  }

  /** Clear this app's value for a config key. */
  deleteConfigValue(configKey: string): Promise<void> {
    return this.request("DELETE", `/config/${encodeURIComponent(configKey)}`, { expectNoContent: true });
  }

  /** Set this app's feature-flag override, optionally targeting role slugs. */
  setFeatureFlag(flagKey: string, enabled: boolean, roles?: string[]): Promise<void> {
    return this.request("PUT", `/features/${encodeURIComponent(flagKey)}`, {
      body: { enabled, roles },
      expectNoContent: true,
    });
  }

  /** Clear this app's feature-flag override (falls back to the flag's default). */
  deleteFeatureFlag(flagKey: string): Promise<void> {
    return this.request("DELETE", `/features/${encodeURIComponent(flagKey)}`, { expectNoContent: true });
  }

  /** Reset (disable) a member's 2FA — for a user who lost their authenticator. */
  resetUserTotp(userId: string): Promise<void> {
    return this.request("DELETE", `/users/${encodeURIComponent(userId)}/totp`, { expectNoContent: true });
  }

  /** Clear a failed-login lockout on a member. */
  unlockUser(userId: string): Promise<void> {
    return this.request("POST", `/users/${encodeURIComponent(userId)}/unlock`, { expectNoContent: true });
  }

  /** A member's linked SSO/OAuth identities. */
  async listUserIdentities(userId: string): Promise<Identity[]> {
    const { identities } = await this.request<{ identities: Identity[] }>(
      "GET",
      `/users/${encodeURIComponent(userId)}/identities`,
    );
    return identities;
  }

  /** Unlink a member's SSO identity for a provider (e.g. "google"). */
  deleteUserIdentity(userId: string, provider: string): Promise<void> {
    return this.request(
      "DELETE",
      `/users/${encodeURIComponent(userId)}/identities/${encodeURIComponent(provider)}`,
      { expectNoContent: true },
    );
  }

  /** A member's passkeys (WebAuthn credentials) for this app. */
  async listUserPasskeys(userId: string): Promise<Passkey[]> {
    const { passkeys } = await this.request<{ passkeys: Passkey[] }>(
      "GET",
      `/users/${encodeURIComponent(userId)}/passkeys`,
    );
    return passkeys;
  }

  /** Remove one of a member's passkeys. */
  deleteUserPasskey(userId: string, passkeyId: string): Promise<void> {
    return this.request(
      "DELETE",
      `/users/${encodeURIComponent(userId)}/passkeys/${encodeURIComponent(passkeyId)}`,
      { expectNoContent: true },
    );
  }

  // ---- internal ----

  private async request<T>(
    method: string,
    path: string,
    opts: { query?: Query; body?: unknown; expectNoContent?: boolean } = {},
  ): Promise<T> {
    let url = this.base + path;
    if (opts.query) {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(opts.query)) {
        if (v !== undefined && v !== null && v !== "") qs.set(k, String(v));
      }
      const s = qs.toString();
      if (s) url += `?${s}`;
    }

    const headers: Record<string, string> = {
      "X-API-Key": this.apiKey,
      Accept: "application/json",
    };
    let body: string | undefined;
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(opts.body);
    }

    const res = await this.fetchImpl(url, { method, headers, body });

    if (!res.ok) {
      let code = `http_${res.status}`;
      let message = res.statusText;
      try {
        const data = (await res.json()) as { error?: string; message?: string };
        if (data.error) code = data.error;
        if (data.message) message = data.message;
      } catch {
        // non-JSON error body — keep the status-derived defaults
      }
      throw new ManyRowsServerError(res.status, code, message);
    }

    if (opts.expectNoContent || res.status === 204) {
      return undefined as T;
    }
    return (await res.json()) as T;
  }
}
