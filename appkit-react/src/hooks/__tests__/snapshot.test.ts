import { describe, it, expect, vi } from "vitest";
import { renderHook } from "@testing-library/react";
import type { ManyRowsAppKitSnapshot } from "../../types";
import { makeSnapshot } from "./testUtils";

const h = vi.hoisted(() => ({
  ctx: { snapshot: null as ManyRowsAppKitSnapshot | null, refresh: vi.fn(), logout: vi.fn() },
}));
vi.mock("../../AppKit", () => ({ useAppKit: () => h.ctx }));

import { useUser } from "../../hooks";

describe("useUser", () => {
  it("returns the account from the snapshot", () => {
    h.ctx.snapshot = makeSnapshot();
    const { result } = renderHook(() => useUser());
    expect(result.current).toEqual({ id: "u1", email: "u@example.com" });
  });

  it("returns null when unauthenticated", () => {
    h.ctx.snapshot = null;
    const { result } = renderHook(() => useUser());
    expect(result.current).toBeNull();
  });
});
