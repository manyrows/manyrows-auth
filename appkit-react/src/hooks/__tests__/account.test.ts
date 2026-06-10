import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook } from "@testing-library/react";
import type { ManyRowsAppKitSnapshot } from "../../types";
import { makeSnapshot, stubFetch } from "./testUtils";

const h = vi.hoisted(() => ({
  ctx: { snapshot: null as ManyRowsAppKitSnapshot | null, refresh: vi.fn(), logout: vi.fn() },
}));
vi.mock("../../AppKit", () => ({ useAppKit: () => h.ctx }));

import { useIdentities, useDisconnectIdentity, useUserFields, useUpdateUserFields } from "../account";

beforeEach(() => {
  h.ctx.snapshot = makeSnapshot();
});

describe("useIdentities", () => {
  it("GETs /a/me/identities and unwraps {identities}", async () => {
    const identities = [
      { provider: "google", providerEmail: "u@gmail.com", createdAt: "2026-01-01T00:00:00Z", lastLoginAt: "2026-01-02T00:00:00Z" },
    ];
    const fetchMock = stubFetch(200, { identities });
    const { result } = renderHook(() => useIdentities());
    await expect(result.current()).resolves.toEqual(identities);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/x/acme/apps/app1/a/me/identities",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("returns [] when the response has no identities key", async () => {
    stubFetch(200, {});
    const { result } = renderHook(() => useIdentities());
    await expect(result.current()).resolves.toEqual([]);
  });
});

describe("useDisconnectIdentity", () => {
  it("DELETEs /a/me/identities/{provider}", async () => {
    const fetchMock = stubFetch(204, undefined);
    const { result } = renderHook(() => useDisconnectIdentity());
    await result.current("google");
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/x/acme/apps/app1/a/me/identities/google",
      expect.objectContaining({ method: "DELETE" }),
    );
  });

  it("surfaces the server error (e.g. last sign-in method)", async () => {
    stubFetch(409, { error: "error.conflict" });
    const { result } = renderHook(() => useDisconnectIdentity());
    await expect(result.current("google")).rejects.toThrow("error.conflict");
  });
});

describe("useUserFields", () => {
  it("GETs /a/me/fields and unwraps {fields}", async () => {
    const fields = [{ key: "plan", type: "string", label: "Plan", value: "pro" }];
    stubFetch(200, { fields });
    const { result } = renderHook(() => useUserFields());
    await expect(result.current()).resolves.toEqual(fields);
  });

  it("returns [] when the response has no fields key", async () => {
    stubFetch(200, {});
    const { result } = renderHook(() => useUserFields());
    await expect(result.current()).resolves.toEqual([]);
  });
});

describe("useUpdateUserFields", () => {
  it("PATCHes the raw key→value map and returns updated fields", async () => {
    const fields = [{ key: "plan", type: "string", label: "Plan", value: "team" }];
    const fetchMock = stubFetch(200, { fields });
    const { result } = renderHook(() => useUpdateUserFields());
    await expect(result.current({ plan: "team" })).resolves.toEqual(fields);
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(init.body as string)).toEqual({ plan: "team" });
  });
});
