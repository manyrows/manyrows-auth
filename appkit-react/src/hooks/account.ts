// appkit-react/src/hooks/account.ts — the signed-in user's own account:
// profile, password, identities, email change, user fields, deletion.
import { useCallback } from "react";
import { useAppKit } from "../AppKit";
import { authedJson } from "./shared";
import type { AppKitIdentity, AppKitUserField } from "../types";

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
 * Returns a function that lists the user's linked sign-in identities
 * (OAuth providers / external IdPs).
 *
 * ```tsx
 * const listIdentities = useIdentities();
 * const identities = await listIdentities(); // [{provider: "google", ...}]
 * ```
 */
export function useIdentities(): () => Promise<AppKitIdentity[]> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(async () => {
    const body = (await authedJson(token, baseURL, `/a/me/identities`, { method: "GET" },
      "Failed to load identities")) as { identities?: AppKitIdentity[] };
    return body?.identities ?? [];
  }, [token, baseURL]);
}

/**
 * Returns a function that unlinks a sign-in identity by provider name.
 * The server rejects removing the user's only way to sign in.
 *
 * ```tsx
 * const disconnectIdentity = useDisconnectIdentity();
 * await disconnectIdentity("google");
 * ```
 */
export function useDisconnectIdentity(): (provider: string) => Promise<void> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(async (provider: string) => {
    await authedJson(token, baseURL, `/a/me/identities/${encodeURIComponent(provider)}`,
      { method: "DELETE" }, "Failed to disconnect identity");
  }, [token, baseURL]);
}

/**
 * Returns a function that fetches the user's client-visible custom fields
 * with their current values.
 *
 * ```tsx
 * const getFields = useUserFields();
 * const fields = await getFields(); // [{key, type, label, value}]
 * ```
 */
export function useUserFields(): () => Promise<AppKitUserField[]> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(async () => {
    const body = (await authedJson(token, baseURL, `/a/me/fields`, { method: "GET" },
      "Failed to load user fields")) as { fields?: AppKitUserField[] };
    return body?.fields ?? [];
  }, [token, baseURL]);
}

/**
 * Returns a function that updates the user's custom fields. Pass a plain
 * key→value map; only client-writable fields are accepted. Resolves with
 * the updated field list.
 *
 * ```tsx
 * const updateFields = useUpdateUserFields();
 * await updateFields({ displayPronouns: "they/them" });
 * ```
 */
export function useUpdateUserFields(): (values: Record<string, unknown>) => Promise<AppKitUserField[]> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(async (values: Record<string, unknown>) => {
    const body = (await authedJson(token, baseURL, `/a/me/fields`, {
      method: "PATCH",
      body: JSON.stringify(values),
    }, "Failed to update user fields")) as { fields?: AppKitUserField[] };
    return body?.fields ?? [];
  }, [token, baseURL]);
}
