// appkit-react/src/hooks/passkeys.ts — the signed-in user's passkeys:
// list, rename, delete, and the WebAuthn registration ceremony.
import { useCallback } from "react";
import { useAppKit } from "../AppKit";
import { authedJson } from "./shared";
import type { AppKitPasskey, AppKitReauthParams } from "../types";

/**
 * Returns a function that lists the user's registered passkeys.
 *
 * ```tsx
 * const listPasskeys = usePasskeys();
 * const passkeys = await listPasskeys();
 * ```
 */
export function usePasskeys(): () => Promise<AppKitPasskey[]> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(async () => {
    const body = (await authedJson(token, baseURL, `/a/passkeys`, { method: "GET" },
      "Failed to load passkeys")) as { passkeys?: AppKitPasskey[] };
    return body?.passkeys ?? [];
  }, [token, baseURL]);
}

/**
 * Returns a function that renames a passkey.
 *
 * ```tsx
 * const renamePasskey = useRenamePasskey();
 * await renamePasskey(passkey.id, { name: "Work laptop" });
 * ```
 */
export function useRenamePasskey(): (passkeyId: string, params: { name: string }) => Promise<void> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(async (passkeyId: string, params: { name: string }) => {
    await authedJson(token, baseURL, `/a/passkeys/${encodeURIComponent(passkeyId)}`, {
      method: "PATCH",
      body: JSON.stringify({ name: params.name }),
    }, "Failed to rename passkey");
  }, [token, baseURL]);
}

/**
 * Returns a function that deletes a passkey. A sensitive operation — the
 * server may require re-auth: pass `{password}` or `{code}` (request one
 * with `useRequestReauthCode()`).
 * The reauth proof travels in the DELETE request body — the server (and any
 * proxy in front of it) must forward DELETE bodies.
 *
 * ```tsx
 * const deletePasskey = useDeletePasskey();
 * await deletePasskey(passkey.id, { password });
 * ```
 */
export function useDeletePasskey(): (passkeyId: string, reauth?: AppKitReauthParams) => Promise<void> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(async (passkeyId: string, reauth?: AppKitReauthParams) => {
    await authedJson(token, baseURL, `/a/passkeys/${encodeURIComponent(passkeyId)}`, {
      method: "DELETE",
      body: JSON.stringify(reauth ?? {}),
    }, "Failed to delete passkey");
  }, [token, baseURL]);
}
