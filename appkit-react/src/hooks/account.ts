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
 * Disconnecting always succeeds — the server keeps no last-method guard because every user can recover via the email-based flows. Add your own confirmation UX.
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
 * Returns a function that updates the user's custom fields. Pass a flat key→value map (e.g. { plan: "team" }), not the AppKitUserField[] array returned by useUserFields(); only client-writable fields are accepted.
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

/**
 * Returns a function that permanently deletes the signed-in user's account
 * at this app, then signs them out. Requires the account password — users
 * without one (OAuth/passkey-only) must set a password first. Rejects with
 * `error.forbidden` when the app has account deletion disabled.
 *
 * ```tsx
 * const deleteAccount = useDeleteAccount();
 * await deleteAccount({ password });
 * ```
 */
export function useDeleteAccount(): (params: { password: string }) => Promise<void> {
  const { snapshot, logout } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(async (params: { password: string }) => {
    await authedJson(token, baseURL, `/a/me/delete`, {
      method: "POST",
      body: JSON.stringify({ password: params.password }),
    }, "Failed to delete account");
    await logout();
  }, [token, baseURL, logout]);
}

/**
 * Returns a function that starts an email change. The server sends a 6-digit
 * code to BOTH the current (old) address and the new address; complete the
 * change with `useVerifyEmailChange`, passing both codes. Requires the
 * current password.
 *
 * ```tsx
 * const requestEmailChange = useRequestEmailChange();
 * await requestEmailChange({ newEmail, password });
 * ```
 */
export function useRequestEmailChange(): (params: { newEmail: string; password: string }) => Promise<void> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(async (params: { newEmail: string; password: string }) => {
    await authedJson(token, baseURL, `/a/me/request-email-change`, {
      method: "POST",
      body: JSON.stringify({ newEmail: params.newEmail, password: params.password }),
    }, "Failed to request email change");
  }, [token, baseURL]);
}

/**
 * Returns a function that completes a pending email change. The request
 * step emails a 6-digit code to BOTH addresses — the code from the user's
 * current (old) address approves the change; the code from the new address
 * proves inbox ownership. Pass both. Refreshes the snapshot on success so
 * `useUser()` reflects the new email.
 *
 * ```tsx
 * const verifyEmailChange = useVerifyEmailChange();
 * await verifyEmailChange({ oldCode, newCode });
 * ```
 */
export function useVerifyEmailChange(): (params: { oldCode: string; newCode: string }) => Promise<void> {
  const { snapshot, refresh } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(async (params: { oldCode: string; newCode: string }) => {
    await authedJson(token, baseURL, `/a/me/verify-email-change`, {
      method: "POST",
      body: JSON.stringify({ oldCode: params.oldCode, newCode: params.newCode }),
    }, "Failed to verify email change");
    refresh();
  }, [token, baseURL, refresh]);
}

/**
 * Returns a function that emails the signed-in user a 6-digit verification
 * code. Use it before the sensitive hooks (`useStartTOTPSetup`,
 * `useDisableTOTP`, `useDeletePasskey`) for users without a password —
 * pass the received code as `{ code }` in `AppKitReauthParams`.
 *
 * ```tsx
 * const requestReauthCode = useRequestReauthCode();
 * await requestReauthCode();              // user receives email
 * await disableTOTP({ code: "123456" }); // user types the code
 * ```
 */
export function useRequestReauthCode(): () => Promise<void> {
  const { snapshot } = useAppKit();
  const baseURL = snapshot?.appBaseURL;
  const email = snapshot?.appData?.account?.email;
  return useCallback(async () => {
    if (!baseURL || !email) {
      throw new Error("Not authenticated");
    }
    const res = await fetch(`${baseURL}/auth/forgot-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error((errBody as { issues?: { message?: string }[] })?.issues?.[0]?.message
        || (errBody as { error?: string })?.error || "Failed to request verification code");
    }
  }, [baseURL, email]);
}
