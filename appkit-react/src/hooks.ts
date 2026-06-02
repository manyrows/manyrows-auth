// appkit-react/hooks.ts — convenience hooks for common data access
import { useCallback } from "react";
import { useAppKit } from "./AppKit";
import type { AppKitAccount, AppKitFeatureFlag, AppKitConfigValue } from "./types";

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
