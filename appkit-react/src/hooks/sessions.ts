// appkit-react/src/hooks/sessions.ts — the signed-in user's device sessions.
import { useCallback } from "react";
import { useAppKit } from "../AppKit";
import { authedJson } from "./shared";
import type { AppKitSession } from "../types";

/**
 * Returns a function that fetches the user's active sessions across devices.
 * The session making the call has `current: true`.
 *
 * ```tsx
 * const listSessions = useSessions();
 * const sessions = await listSessions();
 * ```
 */
export function useSessions(): () => Promise<AppKitSession[]> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(async () => {
    const body = (await authedJson(token, baseURL, `/a/me/sessions`, { method: "GET" },
      "Failed to load sessions")) as { sessions?: AppKitSession[] };
    return body?.sessions ?? [];
  }, [token, baseURL]);
}

/**
 * Returns a function that revokes one of the user's sessions ("sign out that
 * device"). The current session (`current: true`) cannot be revoked this way — the server rejects it; use `logout()` from `useAppKit()` instead.
 *
 * ```tsx
 * const revokeSession = useRevokeSession();
 * await revokeSession(session.id);
 * ```
 */
export function useRevokeSession(): (sessionId: string) => Promise<void> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(async (sessionId: string) => {
    await authedJson(token, baseURL, `/a/me/sessions/${encodeURIComponent(sessionId)}`,
      { method: "DELETE" }, "Failed to revoke session");
  }, [token, baseURL]);
}
