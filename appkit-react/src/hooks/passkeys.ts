// appkit-react/src/hooks/passkeys.ts — the signed-in user's passkeys:
// list, rename, delete, and the WebAuthn registration ceremony.
import { useCallback } from "react";
import { useAppKit } from "../AppKit";
import { authedJson } from "./shared";
import type { AppKitPasskey, AppKitReauthParams } from "../types";
import { decodeCreationOptions, encodeAttestationResponse, isPasskeySupported } from "../webauthn";
import type { CreationOptionsJSON } from "../webauthn";

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

/**
 * Returns a function that registers a new passkey for the signed-in user by
 * running the full WebAuthn ceremony: fetch a challenge, prompt the browser
 * (`navigator.credentials.create`), and store the credential. Resolves with
 * the new passkey.
 *
 * Throws `"Passkeys are not supported in this browser"` when WebAuthn is
 * unavailable, and `"Passkey registration was cancelled"` when the user
 * dismisses the browser prompt.
 *
 * ```tsx
 * const registerPasskey = useRegisterPasskey();
 * const passkey = await registerPasskey({ name: "MacBook" });
 * ```
 */
export function useRegisterPasskey(): (params?: { name?: string }) => Promise<AppKitPasskey> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(async (params?: { name?: string }) => {
    if (!isPasskeySupported()) {
      throw new Error("Passkeys are not supported in this browser");
    }
    const begin = (await authedJson(token, baseURL, `/a/passkey/register/begin`, { method: "POST" },
      "Failed to start passkey registration")) as { challengeId: string; publicKeyOptions: CreationOptionsJSON };

    let cred: Credential | null;
    try {
      cred = await navigator.credentials.create({ publicKey: decodeCreationOptions(begin.publicKeyOptions) });
    } catch (e) {
      if (e instanceof DOMException && e.name === "NotAllowedError") {
        throw new Error("Passkey registration was cancelled");
      }
      throw e;
    }
    if (!cred) {
      throw new Error("Passkey registration was cancelled");
    }

    const finish = (await authedJson(token, baseURL, `/a/passkey/register/finish`, {
      method: "POST",
      body: JSON.stringify({
        challengeId: begin.challengeId,
        name: params?.name,
        response: encodeAttestationResponse(cred as PublicKeyCredential),
      }),
    }, "Failed to register passkey")) as { passkey: AppKitPasskey };
    return finish.passkey;
  }, [token, baseURL]);
}
