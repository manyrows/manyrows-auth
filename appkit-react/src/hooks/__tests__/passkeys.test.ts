import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook } from "@testing-library/react";
import type { ManyRowsAppKitSnapshot } from "../../types";
import { makeSnapshot, stubFetch } from "./testUtils";

const h = vi.hoisted(() => ({
  ctx: { snapshot: null as ManyRowsAppKitSnapshot | null, refresh: vi.fn(), logout: vi.fn() },
}));
vi.mock("../../AppKit", () => ({ useAppKit: () => h.ctx }));

import { usePasskeys, useRenamePasskey, useDeletePasskey } from "../passkeys";

beforeEach(() => {
  h.ctx.snapshot = makeSnapshot();
});

describe("usePasskeys", () => {
  it("GETs /a/passkeys and unwraps {passkeys}", async () => {
    const passkeys = [{
      id: "pk1", name: "MacBook", transports: ["internal"],
      backupEligible: true, backupState: true,
      createdAt: "2026-01-01T00:00:00Z",
    }];
    const fetchMock = stubFetch(200, { passkeys });
    const { result } = renderHook(() => usePasskeys());
    await expect(result.current()).resolves.toEqual(passkeys);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/x/acme/apps/app1/a/passkeys",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("returns [] when the response has no passkeys key", async () => {
    stubFetch(200, {});
    const { result } = renderHook(() => usePasskeys());
    await expect(result.current()).resolves.toEqual([]);
  });
});

describe("useRenamePasskey", () => {
  it("PATCHes the new name", async () => {
    const fetchMock = stubFetch(200, {});
    const { result } = renderHook(() => useRenamePasskey());
    await result.current("pk1", { name: "Work laptop" });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/x/acme/apps/app1/a/passkeys/pk1",
      expect.objectContaining({ method: "PATCH" }),
    );
    expect(JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string))
      .toEqual({ name: "Work laptop" });
  });
});

describe("useDeletePasskey", () => {
  it("DELETEs with the reauth body", async () => {
    const fetchMock = stubFetch(204, undefined);
    const { result } = renderHook(() => useDeletePasskey());
    await result.current("pk1", { password: "hunter2hunter2" });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/x/acme/apps/app1/a/passkeys/pk1",
      expect.objectContaining({ method: "DELETE" }),
    );
    expect(JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string))
      .toEqual({ password: "hunter2hunter2" });
  });

  it("sends an empty body when no reauth given", async () => {
    const fetchMock = stubFetch(204, undefined);
    const { result } = renderHook(() => useDeletePasskey());
    await result.current("pk1");
    expect(JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string)).toEqual({});
  });

  it("surfaces the server error when reauth is required", async () => {
    stubFetch(401, { error: "error.reauthRequired" });
    const { result } = renderHook(() => useDeletePasskey());
    await expect(result.current("pk1")).rejects.toThrow("error.reauthRequired");
  });
});
