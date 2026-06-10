import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook } from "@testing-library/react";
import type { ManyRowsAppKitSnapshot } from "../../types";
import { makeSnapshot, stubFetch } from "./testUtils";

const h = vi.hoisted(() => ({
  ctx: { snapshot: null as ManyRowsAppKitSnapshot | null, refresh: vi.fn(), logout: vi.fn() },
}));
vi.mock("../../AppKit", () => ({ useAppKit: () => h.ctx }));

import { useStartTOTPSetup, useEnableTOTP, useDisableTOTP, useRegenerateBackupCodes } from "../totp";

beforeEach(() => {
  h.ctx.snapshot = makeSnapshot();
});

describe("useStartTOTPSetup", () => {
  it("POSTs reauth params and returns {secret, uri}", async () => {
    const fetchMock = stubFetch(200, { secret: "BASE32SECRET", uri: "otpauth://totp/..." });
    const { result } = renderHook(() => useStartTOTPSetup());
    await expect(result.current({ password: "hunter2hunter2" }))
      .resolves.toEqual({ secret: "BASE32SECRET", uri: "otpauth://totp/..." });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/x/acme/apps/app1/a/totp/setup",
      expect.objectContaining({ method: "POST" }),
    );
    expect(JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string))
      .toEqual({ password: "hunter2hunter2" });
  });

  it("surfaces error.totpAlreadyEnabled", async () => {
    stubFetch(409, { error: "error.totpAlreadyEnabled" });
    const { result } = renderHook(() => useStartTOTPSetup());
    await expect(result.current({ code: "123456" })).rejects.toThrow("error.totpAlreadyEnabled");
  });
});

describe("useEnableTOTP", () => {
  it("POSTs the code, returns backup codes, refreshes the snapshot", async () => {
    const fetchMock = stubFetch(200, { backupCodes: ["aaaa-bbbb"] });
    const { result } = renderHook(() => useEnableTOTP());
    await expect(result.current({ code: "123456" })).resolves.toEqual({ backupCodes: ["aaaa-bbbb"] });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/x/acme/apps/app1/a/totp/enable",
      expect.objectContaining({ method: "POST" }),
    );
    expect(JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string))
      .toEqual({ code: "123456" });
    expect(h.ctx.refresh).toHaveBeenCalledOnce();
  });
});

describe("useDisableTOTP", () => {
  it("POSTs reauth params and refreshes", async () => {
    const fetchMock = stubFetch(200, { ok: true });
    const { result } = renderHook(() => useDisableTOTP());
    await result.current({ code: "123456" });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/x/acme/apps/app1/a/totp/disable",
      expect.objectContaining({ method: "POST" }),
    );
    expect(JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string))
      .toEqual({ code: "123456" });
    expect(h.ctx.refresh).toHaveBeenCalledOnce();
  });
});

describe("useRegenerateBackupCodes", () => {
  it("POSTs the password (password-only endpoint) and returns new codes", async () => {
    const fetchMock = stubFetch(200, { backupCodes: ["cccc-dddd"] });
    const { result } = renderHook(() => useRegenerateBackupCodes());
    await expect(result.current({ password: "hunter2hunter2" }))
      .resolves.toEqual({ backupCodes: ["cccc-dddd"] });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/x/acme/apps/app1/a/totp/backup-codes",
      expect.objectContaining({ method: "POST" }),
    );
    expect(JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string))
      .toEqual({ password: "hunter2hunter2" });
  });
});
