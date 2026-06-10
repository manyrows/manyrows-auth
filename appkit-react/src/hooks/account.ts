// appkit-react/src/hooks/account.ts — the signed-in user's own account:
// profile, password, identities, email change, user fields, deletion.
import { useCallback } from "react";
import { useAppKit } from "../AppKit";

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
