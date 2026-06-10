// appkit-react/src/hooks/totp.ts — TOTP (authenticator-app 2FA) management
// for the signed-in user.
import { useCallback } from "react";
import { useAppKit } from "../AppKit";
import { authedJson } from "./shared";
import type { AppKitReauthParams, AppKitTOTPSetup } from "../types";

/**
 * Returns a function that begins TOTP enrollment. A sensitive operation —
 * pass `{password}` or `{code}` (see `useRequestReauthCode`). Resolves with
 * the shared secret and an `otpauth://` URI to render as a QR code; finish
 * enrollment with `useEnableTOTP`. Rejects with `error.totpAlreadyEnabled`
 * when 2FA is already on.
 *
 * ```tsx
 * const startTOTPSetup = useStartTOTPSetup();
 * const { secret, uri } = await startTOTPSetup({ password });
 * ```
 */
export function useStartTOTPSetup(): (reauth: AppKitReauthParams) => Promise<AppKitTOTPSetup> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(async (reauth: AppKitReauthParams) => {
    return (await authedJson(token, baseURL, `/a/totp/setup`, {
      method: "POST",
      body: JSON.stringify(reauth),
    }, "Failed to start 2FA setup")) as AppKitTOTPSetup;
  }, [token, baseURL]);
}

/**
 * Returns a function that completes TOTP enrollment by verifying a code from
 * the authenticator app. Resolves with single-use backup codes — show them
 * to the user ONCE; they are not retrievable later (only regenerable).
 * Refreshes the snapshot.
 *
 * ```tsx
 * const enableTOTP = useEnableTOTP();
 * const { backupCodes } = await enableTOTP({ code });
 * ```
 */
export function useEnableTOTP(): (params: { code: string }) => Promise<{ backupCodes: string[] }> {
  const { snapshot, refresh } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(async (params: { code: string }) => {
    const body = (await authedJson(token, baseURL, `/a/totp/enable`, {
      method: "POST",
      body: JSON.stringify({ code: params.code }),
    }, "Failed to enable 2FA")) as { backupCodes?: string[] };
    refresh();
    return { backupCodes: body?.backupCodes ?? [] };
  }, [token, baseURL, refresh]);
}

/**
 * Returns a function that disables TOTP. A sensitive operation — pass
 * `{password}` or `{code}` (see `useRequestReauthCode`). Refreshes the
 * snapshot.
 *
 * ```tsx
 * const disableTOTP = useDisableTOTP();
 * await disableTOTP({ password });
 * ```
 */
export function useDisableTOTP(): (reauth: AppKitReauthParams) => Promise<void> {
  const { snapshot, refresh } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(async (reauth: AppKitReauthParams) => {
    await authedJson(token, baseURL, `/a/totp/disable`, {
      method: "POST",
      body: JSON.stringify(reauth),
    }, "Failed to disable 2FA");
    refresh();
  }, [token, baseURL, refresh]);
}

/**
 * Returns a function that regenerates the user's TOTP backup codes,
 * invalidating the old set. Unlike the other sensitive hooks this endpoint
 * accepts the password ONLY (no email-code path).
 *
 * ```tsx
 * const regenerateBackupCodes = useRegenerateBackupCodes();
 * const { backupCodes } = await regenerateBackupCodes({ password });
 * ```
 */
export function useRegenerateBackupCodes(): (params: { password: string }) => Promise<{ backupCodes: string[] }> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(async (params: { password: string }) => {
    const body = (await authedJson(token, baseURL, `/a/totp/backup-codes`, {
      method: "POST",
      body: JSON.stringify({ password: params.password }),
    }, "Failed to regenerate backup codes")) as { backupCodes?: string[] };
    return { backupCodes: body?.backupCodes ?? [] };
  }, [token, baseURL]);
}
