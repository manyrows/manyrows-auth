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

/** Name carried by the error useRegisterPasskey throws on user cancellation. */
export const PASSKEY_CANCELLED = "PasskeyRegistrationCancelled";

function passkeyCancelledError(): Error {
  const err = new Error("Passkey registration was cancelled");
  err.name = PASSKEY_CANCELLED;
  return err;
}

/** True when an error came from the user dismissing the passkey prompt. */
export function isPasskeyCancelled(e: unknown): boolean {
  return e instanceof Error && e.name === PASSKEY_CANCELLED;
}

/** Error name when the authenticator already holds a passkey for this account. */
export const PASSKEY_ALREADY_REGISTERED = "PasskeyAlreadyRegistered";

function passkeyAlreadyRegisteredError(): Error {
  const err = new Error("This device already has a passkey for this account");
  err.name = PASSKEY_ALREADY_REGISTERED;
  return err;
}

/** True when registration failed because the authenticator is already enrolled. */
export function isPasskeyAlreadyRegistered(e: unknown): boolean {
  return e instanceof Error && e.name === PASSKEY_ALREADY_REGISTERED;
}

/**
 * Returns a function that registers a new passkey for the signed-in user by
 * running the full WebAuthn ceremony: fetch a challenge, prompt the browser
 * (`navigator.credentials.create`), and store the credential. Resolves with
 * the new passkey.
 *
 * Throws "Passkeys are not supported in this browser" when WebAuthn is
 * unavailable. On user cancellation (or prompt timeout) the thrown error has
 * name PASSKEY_CANCELLED — detect it with isPasskeyCancelled(err). When the
 * authenticator already holds a passkey for this account the thrown error has
 * name PASSKEY_ALREADY_REGISTERED — detect it with isPasskeyAlreadyRegistered(err).
 * Only one ceremony can run at a time; disable the triggering button while
 * the returned promise is pending.
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

    if (!begin?.challengeId || !begin?.publicKeyOptions) {
      throw new Error("Invalid passkey registration response");
    }

    let cred: Credential | null;
    try {
      cred = await navigator.credentials.create({ publicKey: decodeCreationOptions(begin.publicKeyOptions) });
    } catch (e) {
      const name = (e as { name?: string } | null)?.name;
      if (name === "InvalidStateError") {
        throw passkeyAlreadyRegisteredError();
      }
      if (name === "NotAllowedError" || name === "AbortError") {
        throw passkeyCancelledError();
      }
      throw e;
    }
    if (!cred) {
      throw passkeyCancelledError();
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
