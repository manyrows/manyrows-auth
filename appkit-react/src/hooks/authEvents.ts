// appkit-react/src/hooks/authEvents.ts — internal: tracks snapshot status
// transitions and fires the host's onSignIn/onSignOut callbacks. Not part
// of the public API; <AppKit> wires it to its props.
import { useEffect, useRef } from "react";
import type { AppKitAccount, ManyRowsAppKitSnapshot } from "../types";

export function useAuthTransitions(
  snapshot: ManyRowsAppKitSnapshot | null,
  onSignIn?: (user: AppKitAccount) => void,
  onSignOut?: () => void,
): void {
  // Refs so callback identity changes don't re-run the transition effect.
  const signInRef = useRef(onSignIn);
  const signOutRef = useRef(onSignOut);
  useEffect(() => {
    signInRef.current = onSignIn;
    signOutRef.current = onSignOut;
  });

  // "checking" is transient (boot, token refresh) — ignoring it means an
  // authenticated → checking → authenticated round-trip fires nothing.
  const authStateRef = useRef<"authed" | "unauthed" | null>(null);
  useEffect(() => {
    const status = snapshot?.status;
    if (!status || status === "checking") return;
    const prev = authStateRef.current;
    if (status === "authenticated") {
      // Today's runtime always attaches an account to authenticated
      // snapshots; if a future runtime ever emits authenticated-before-
      // account, wait for the complete snapshot instead of swallowing
      // the sign-in event forever.
      const account = snapshot?.appData?.account;
      if (!account || prev === "authed") return;
      authStateRef.current = "authed";
      signInRef.current?.(account);
    } else {
      authStateRef.current = "unauthed";
      if (prev === "authed") {
        signOutRef.current?.();
      }
    }
  }, [snapshot]);
}
