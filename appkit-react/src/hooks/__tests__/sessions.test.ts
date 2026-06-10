import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook } from "@testing-library/react";
import type { ManyRowsAppKitSnapshot } from "../../types";
import { makeSnapshot, stubFetch } from "./testUtils";

const h = vi.hoisted(() => ({
  ctx: { snapshot: null as ManyRowsAppKitSnapshot | null, refresh: vi.fn(), logout: vi.fn() },
}));
vi.mock("../../AppKit", () => ({ useAppKit: () => h.ctx }));

import { useSessions, useRevokeSession } from "../sessions";

beforeEach(() => {
  h.ctx.snapshot = makeSnapshot();
});

describe("useSessions", () => {
  it("GETs /a/me/sessions with the bearer token and unwraps {sessions}", async () => {
    const sessions = [
      { id: "s1", createdAt: "2026-01-01T00:00:00Z", lastSeenAt: "2026-01-02T00:00:00Z", current: true },
    ];
    const fetchMock = stubFetch(200, { sessions });
    const { result } = renderHook(() => useSessions());
    await expect(result.current()).resolves.toEqual(sessions);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/x/acme/apps/app1/a/me/sessions",
      expect.objectContaining({ method: "GET" }),
    );
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok-123");
  });

  it("returns [] when the response has no sessions key", async () => {
    stubFetch(200, {});
    const { result } = renderHook(() => useSessions());
    await expect(result.current()).resolves.toEqual([]);
  });

  it("throws the server error code on failure", async () => {
    stubFetch(401, { error: "error.unauthorized" });
    const { result } = renderHook(() => useSessions());
    await expect(result.current()).rejects.toThrow("error.unauthorized");
  });

  it("throws Not authenticated without a token", async () => {
    h.ctx.snapshot = makeSnapshot({ jwtToken: null });
    const { result } = renderHook(() => useSessions());
    await expect(result.current()).rejects.toThrow("Not authenticated");
  });
});

describe("useRevokeSession", () => {
  it("DELETEs /a/me/sessions/{id}", async () => {
    const fetchMock = stubFetch(204, undefined);
    const { result } = renderHook(() => useRevokeSession());
    await expect(result.current("s2")).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/x/acme/apps/app1/a/me/sessions/s2",
      expect.objectContaining({ method: "DELETE" }),
    );
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok-123");
  });
});
