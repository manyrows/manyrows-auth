import { describe, it, expect, vi } from "vitest";
import { renderHook } from "@testing-library/react";
import { makeSnapshot } from "./testUtils";
import type { ManyRowsAppKitSnapshot } from "../../types";
import { useAuthTransitions } from "../authEvents";

function setup(initial: ManyRowsAppKitSnapshot | null) {
  const onSignIn = vi.fn();
  const onSignOut = vi.fn();
  const view = renderHook(
    ({ snap }: { snap: ManyRowsAppKitSnapshot | null }) => useAuthTransitions(snap, onSignIn, onSignOut),
    { initialProps: { snap: initial } },
  );
  return { onSignIn, onSignOut, rerender: (snap: ManyRowsAppKitSnapshot | null) => view.rerender({ snap }) };
}

describe("useAuthTransitions", () => {
  it("fires onSignIn when an existing session resolves on load", () => {
    const { onSignIn, onSignOut, rerender } = setup(null);
    rerender(makeSnapshot({ status: "checking" }));
    expect(onSignIn).not.toHaveBeenCalled();
    rerender(makeSnapshot({ status: "authenticated" }));
    expect(onSignIn).toHaveBeenCalledTimes(1);
    expect(onSignIn).toHaveBeenCalledWith({ id: "u1", email: "u@example.com" });
    expect(onSignOut).not.toHaveBeenCalled();
  });

  it("does NOT fire onSignOut when the initial state is unauthenticated", () => {
    const { onSignIn, onSignOut, rerender } = setup(null);
    rerender(makeSnapshot({ status: "unauthenticated", jwtToken: null, appData: null }));
    expect(onSignIn).not.toHaveBeenCalled();
    expect(onSignOut).not.toHaveBeenCalled();
  });

  it("fires onSignOut on authenticated → unauthenticated", () => {
    const { onSignOut, rerender } = setup(makeSnapshot({ status: "authenticated" }));
    rerender(makeSnapshot({ status: "unauthenticated", jwtToken: null, appData: null }));
    expect(onSignOut).toHaveBeenCalledTimes(1);
  });

  it("does not re-fire onSignIn across a transient checking state", () => {
    const { onSignIn, rerender } = setup(makeSnapshot({ status: "authenticated" }));
    rerender(makeSnapshot({ status: "checking" }));
    rerender(makeSnapshot({ status: "authenticated" }));
    // initial render already counted one sign-in
    expect(onSignIn).toHaveBeenCalledTimes(1);
  });

  it("does not re-fire onSignIn on unrelated snapshot updates", () => {
    const { onSignIn, rerender } = setup(makeSnapshot({ status: "authenticated" }));
    rerender(makeSnapshot({ status: "authenticated", jwtToken: "tok-456" }));
    expect(onSignIn).toHaveBeenCalledTimes(1);
  });
});
