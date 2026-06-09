// appkit-react/hooks.ts — convenience hooks for common data access
import { useCallback } from "react";
import { useAppKit } from "./AppKit";
import type {
  AppKitAccount,
  AppKitFeatureFlag,
  AppKitConfigValue,
  AppKitOrganization,
  AppKitOrganizationMember,
  AppKitOrganizationInvite,
  AppKitCreatedOrganization,
} from "./types";

/**
 * Returns the authenticated user's account, or null if not authenticated.
 *
 * ```tsx
 * const user = useUser();
 * if (!user) return <p>Not logged in</p>;
 * return <p>Hello, {user.name || user.email}</p>;
 * ```
 */
export function useUser(): AppKitAccount | null {
  const { snapshot } = useAppKit();
  return snapshot?.appData?.account ?? null;
}

/**
 * Returns the user's roles in the current app.
 *
 * ```tsx
 * const roles = useRoles(); // ["admin", "editor"]
 * ```
 */
export function useRoles(): string[] {
  const { snapshot } = useAppKit();
  return snapshot?.appData?.roles ?? [];
}

/**
 * Returns the user's permissions in the current app.
 *
 * ```tsx
 * const permissions = usePermissions(); // ["read", "write", "delete"]
 * ```
 */
export function usePermissions(): string[] {
  const { snapshot } = useAppKit();
  return snapshot?.appData?.permissions ?? [];
}

/**
 * Returns true if the user has the given permission.
 *
 * ```tsx
 * const canEdit = usePermission("edit"); // true
 * ```
 */
export function usePermission(permission: string): boolean {
  const perms = usePermissions();
  return perms.includes(permission);
}

/**
 * Returns true if the user has the given role.
 *
 * ```tsx
 * const isAdmin = useRole("admin"); // true
 * ```
 */
export function useRole(role: string): boolean {
  const roles = useRoles();
  return roles.includes(role);
}

/**
 * Returns all feature flags for the current app/environment.
 *
 * ```tsx
 * const flags = useFeatureFlags(); // [{ key: "dark-mode", enabled: true }]
 * ```
 */
export function useFeatureFlags(): AppKitFeatureFlag[] {
  const { snapshot } = useAppKit();
  return (snapshot?.appData?.featureFlags ?? []) as AppKitFeatureFlag[];
}

/**
 * Returns whether a specific feature flag is enabled.
 *
 * ```tsx
 * const darkMode = useFeatureFlag("dark-mode"); // true
 * ```
 */
export function useFeatureFlag(key: string): boolean {
  const flags = useFeatureFlags();
  const flag = flags.find((f) => f.key === key);
  return flag?.enabled ?? false;
}

/**
 * Returns all config values for the current app/environment.
 *
 * ```tsx
 * const config = useConfig(); // [{ key: "api-url", type: "string", value: "https://..." }]
 * ```
 */
export function useConfig(): AppKitConfigValue[] {
  const { snapshot } = useAppKit();
  return (snapshot?.appData?.config ?? []) as AppKitConfigValue[];
}

/**
 * Returns a specific config value by key, or the fallback if not found.
 *
 * ```tsx
 * const apiUrl = useConfigValue("api-url"); // "https://api.example.com"
 * const limit = useConfigValue("max-items", 100); // 100 if not set
 * ```
 */
export function useConfigValue<T = unknown>(key: string, fallback?: T): T | undefined {
  const config = useConfig();
  const entry = config.find((c) => c.key === key);
  return entry?.value !== undefined ? (entry.value as T) : fallback;
}

/**
 * Returns the JWT token for making authenticated API calls.
 *
 * ```tsx
 * const token = useToken();
 * fetch("/api/data", { headers: { Authorization: `Bearer ${token}` } });
 * ```
 */
export function useToken(): string | null {
  const { snapshot } = useAppKit();
  return snapshot?.jwtToken ?? null;
}

/**
 * Returns a `fetch` wrapper that automatically includes the Bearer token
 * in the Authorization header. Use this for making authenticated API calls
 * to your own backend.
 *
 * ```tsx
 * const authFetch = useAuthFetch();
 *
 * // Works just like fetch, but with auth headers added
 * const res = await authFetch("/api/favourites");
 * const data = await res.json();
 *
 * // POST with body
 * await authFetch("/api/favourites/42", { method: "POST" });
 * ```
 */
export function useAuthFetch(): (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken ?? null;

  return useCallback(
    (input: RequestInfo | URL, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (token) {
        headers.set("Authorization", `Bearer ${token}`);
      }
      return fetch(input, { ...init, headers });
    },
    [token],
  );
}

/**
 * Returns a function to update the current user's profile.
 * After updating, call `refresh()` to reload the snapshot with the new values.
 *
 * ```tsx
 * const updateProfile = useUpdateProfile();
 * await updateProfile({ displayName: "Jane Doe" });
 * ```
 */
export function useUpdateProfile(): (update: { displayName: string }) => Promise<void> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;

  return useCallback(async (update: { displayName: string }) => {
    if (!token || !baseURL) {
      throw new Error("Not authenticated");
    }

    const res = await fetch(`${baseURL}/a/profile/display-name`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ displayName: update.displayName }),
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body?.issues?.[0]?.message || body?.error || "Failed to update profile");
    }
  }, [token, baseURL]);
}

/**
 * Returns a function to change the signed-in user's password.
 *
 * Pass `currentPassword` for the password-change path. The server requires
 * it whenever the user already has a password set; supplying it
 * incorrectly throws `error.invalidCurrentPassword`.
 *
 * ```tsx
 * const setPassword = useSetPassword();
 * await setPassword({ password: "newPw1234567", currentPassword: "oldPw" });
 * ```
 *
 * **OAuth-only / passkey-only users (no password ever set)** can't use
 * this hook to install an initial password — the server gates that path
 * on a recent email-OTP at this app (`error.passwordSetRequiresOTP`)
 * to stop a stolen access token from silently installing a backdoor
 * password. Drive those users through the AppKit `<Auth>` Profile
 * dialog's password tab, which performs the
 * `/auth/forgot-password` → `/auth/reset-password` ceremony.
 */
interface SetPasswordParams {
  /** New password to set. Must meet the configured minimum length. */
  password: string;
  /** Required when the user already has a password set. */
  currentPassword?: string;
}

export function useSetPassword(): (params: SetPasswordParams) => Promise<void> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;

  return useCallback(async (params: SetPasswordParams) => {
    if (!token || !baseURL) {
      throw new Error("Not authenticated");
    }

    const body: Record<string, unknown> = { password: params.password };
    if (params.currentPassword) {
      body.currentPassword = params.currentPassword;
    }

    const res = await fetch(`${baseURL}/a/set-password`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody?.issues?.[0]?.message || errBody?.error || "Failed to set password");
    }
  }, [token, baseURL]);
}

/**
 * Returns the session's active organization, or null when there is none
 * (a user in no orgs, or an app without organizations enabled).
 *
 * ```tsx
 * const org = useOrganization();
 * if (org) return <p>Acting in {org.name} ({org.orgRole})</p>;
 * ```
 */
export function useOrganization(): AppKitOrganization | null {
  const { snapshot } = useAppKit();
  return snapshot?.appData?.organization ?? null;
}

/**
 * Returns every organization the user belongs to (for a switcher). Empty
 * when the user belongs to none or the app doesn't have organizations enabled.
 *
 * ```tsx
 * const orgs = useOrganizationList();
 * ```
 */
export function useOrganizationList(): AppKitOrganization[] {
  const { snapshot } = useAppKit();
  return snapshot?.appData?.organizations ?? [];
}

/**
 * Returns a function that switches the session's active organization.
 *
 * On success it refreshes the snapshot — switching changes authorization,
 * so roles/permissions/active-org re-resolve for the new org — and resolves
 * with the new active organization. Throws if the user is not an active
 * member of the target org (or orgs aren't enabled for the app).
 *
 * ```tsx
 * const setActiveOrganization = useSetActiveOrganization();
 * await setActiveOrganization(org.id);
 * ```
 */
export function useSetActiveOrganization(): (orgId: string) => Promise<AppKitOrganization> {
  const { snapshot, refresh } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;

  return useCallback(async (orgId: string) => {
    if (!token || !baseURL) {
      throw new Error("Not authenticated");
    }

    const res = await fetch(`${baseURL}/a/session/organization`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ organizationId: orgId }),
    });

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody?.issues?.[0]?.message || errBody?.error || "Failed to switch organization");
    }

    const body = await res.json().catch(() => ({}));
    // Re-resolve appData (roles/permissions/active org) for the new org.
    refresh();
    return body?.organization as AppKitOrganization;
  }, [token, baseURL, refresh]);
}

// =====================
// Self-serve organization management
// =====================
//
// These wrap the authed /a/organizations/* endpoints. Authorization is
// enforced server-side by the caller's org tier (owner/admin/member); a call
// the user isn't allowed to make rejects with the server's error code.

/** Internal: authed JSON request against the app's /a/* surface. */
async function orgFetch(
  token: string | null | undefined,
  baseURL: string | null | undefined,
  path: string,
  init: RequestInit,
  failMsg: string,
): Promise<unknown> {
  if (!token || !baseURL) {
    throw new Error("Not authenticated");
  }
  const res = await fetch(`${baseURL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}`, ...(init.headers ?? {}) },
  });
  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    throw new Error((errBody as { issues?: { message?: string }[]; error?: string })?.issues?.[0]?.message
      || (errBody as { error?: string })?.error || failMsg);
  }
  if (res.status === 204) return undefined;
  return res.json().catch(() => ({}));
}

/**
 * Returns a function to create an organization (self-serve). The app must have
 * `org_creation_policy = self_serve`; otherwise the server rejects with
 * `error.forbidden`. The creator is seeded as the owner. Refreshes the snapshot
 * so the new org appears in `useOrganizationList()`.
 *
 * ```tsx
 * const createOrg = useCreateOrganization();
 * const org = await createOrg({ name: "Acme" });
 * ```
 */
export function useCreateOrganization(): (params: { name: string; slug?: string }) => Promise<AppKitCreatedOrganization> {
  const { snapshot, refresh } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(
    async (params: { name: string; slug?: string }) => {
      const org = (await orgFetch(token, baseURL, `/a/organizations`, {
        method: "POST",
        body: JSON.stringify({ name: params.name, slug: params.slug ?? "" }),
      }, "Failed to create organization")) as AppKitCreatedOrganization;
      refresh();
      return org;
    },
    [token, baseURL, refresh],
  );
}

/**
 * Returns a function to rename an organization (owner/admin). Refreshes the
 * snapshot so the new name shows in `useOrganizationList()`.
 */
export function useRenameOrganization(): (orgId: string, params: { name?: string; slug?: string }) => Promise<void> {
  const { snapshot, refresh } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(
    async (orgId: string, params: { name?: string; slug?: string }) => {
      await orgFetch(token, baseURL, `/a/organizations/${orgId}`, {
        method: "PATCH",
        body: JSON.stringify(params),
      }, "Failed to rename organization");
      refresh();
    },
    [token, baseURL, refresh],
  );
}

/**
 * Returns a function to archive an organization (owner-only). Reversible
 * operator-side. Refreshes the snapshot.
 */
export function useArchiveOrganization(): (orgId: string) => Promise<void> {
  const { snapshot, refresh } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(
    async (orgId: string) => {
      await orgFetch(token, baseURL, `/a/organizations/${orgId}`, { method: "DELETE" }, "Failed to archive organization");
      refresh();
    },
    [token, baseURL, refresh],
  );
}

/**
 * Returns a function that fetches an organization's members (any active member
 * may read). Not part of the snapshot — call it on demand.
 *
 * ```tsx
 * const listMembers = useOrganizationMembers();
 * const members = await listMembers(org.id);
 * ```
 */
export function useOrganizationMembers(): (orgId: string) => Promise<AppKitOrganizationMember[]> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(
    async (orgId: string) => {
      const body = (await orgFetch(token, baseURL, `/a/organizations/${orgId}/members`, { method: "GET" },
        "Failed to load members")) as { members?: AppKitOrganizationMember[] };
      return body?.members ?? [];
    },
    [token, baseURL],
  );
}

/**
 * Returns a function to change a member's tier and/or project roles
 * (owner/admin). Pass either field. Last-owner demotion rejects with
 * `error.conflict`.
 */
export function useSetOrganizationMember(): (
  orgId: string,
  userId: string,
  params: { orgRole?: string; roleIds?: string[] },
) => Promise<void> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(
    async (orgId: string, userId: string, params: { orgRole?: string; roleIds?: string[] }) => {
      await orgFetch(token, baseURL, `/a/organizations/${orgId}/members/${userId}`, {
        method: "PATCH",
        body: JSON.stringify(params),
      }, "Failed to update member");
    },
    [token, baseURL],
  );
}

/**
 * Returns a function to remove a member, or leave the org (pass your own user
 * id). Removing someone else needs owner/admin; the last owner can't be
 * removed (`error.conflict`).
 */
export function useRemoveOrganizationMember(): (orgId: string, userId: string) => Promise<void> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(
    async (orgId: string, userId: string) => {
      await orgFetch(token, baseURL, `/a/organizations/${orgId}/members/${userId}`, { method: "DELETE" },
        "Failed to remove member");
    },
    [token, baseURL],
  );
}

/** Returns a function that fetches an organization's pending invites (owner/admin). */
export function useOrganizationInvites(): (orgId: string) => Promise<AppKitOrganizationInvite[]> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(
    async (orgId: string) => {
      const body = (await orgFetch(token, baseURL, `/a/organizations/${orgId}/invites`, { method: "GET" },
        "Failed to load invites")) as { invites?: AppKitOrganizationInvite[] };
      return body?.invites ?? [];
    },
    [token, baseURL],
  );
}

/**
 * Returns a function to invite an email to the organization (owner/admin). The
 * app must have an App URL configured for the accept link.
 */
export function useCreateOrganizationInvite(): (
  orgId: string,
  params: { email: string; orgRole?: string; roleIds?: string[] },
) => Promise<AppKitOrganizationInvite> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(
    async (orgId: string, params: { email: string; orgRole?: string; roleIds?: string[] }) => {
      return (await orgFetch(token, baseURL, `/a/organizations/${orgId}/invites`, {
        method: "POST",
        body: JSON.stringify(params),
      }, "Failed to send invitation")) as AppKitOrganizationInvite;
    },
    [token, baseURL],
  );
}

/** Returns a function to revoke a pending invite (owner/admin). */
export function useRevokeOrganizationInvite(): (orgId: string, inviteId: string) => Promise<void> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(
    async (orgId: string, inviteId: string) => {
      await orgFetch(token, baseURL, `/a/organizations/${orgId}/invites/${inviteId}`, { method: "DELETE" },
        "Failed to revoke invitation");
    },
    [token, baseURL],
  );
}
