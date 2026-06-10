import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook } from "@testing-library/react";
import type { ManyRowsAppKitSnapshot } from "../../types";
import { makeSnapshot, stubFetch } from "./testUtils";

const h = vi.hoisted(() => ({
  ctx: { snapshot: null as ManyRowsAppKitSnapshot | null, refresh: vi.fn(), logout: vi.fn() },
}));
vi.mock("../../AppKit", () => ({ useAppKit: () => h.ctx }));

import { useIdentities, useDisconnectIdentity, useUserFields, useUpdateUserFields, useDeleteAccount, useRequestEmailChange, useVerifyEmailChange, useRequestReauthCode } from "../account";

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

  it("surfaces server errors", async () => {
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

describe("useDeleteAccount", () => {
  it("POSTs the password to /a/me/delete and then logs out", async () => {
    const fetchMock = stubFetch(200, {});
    const { result } = renderHook(() => useDeleteAccount());
    await result.current({ password: "hunter2hunter2" });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/x/acme/apps/app1/a/me/delete",
      expect.objectContaining({ method: "POST" }),
    );
    expect(JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string))
      .toEqual({ password: "hunter2hunter2" });
    expect(h.ctx.logout).toHaveBeenCalledOnce();
  });

  it("does NOT log out when deletion fails", async () => {
    stubFetch(403, { error: "error.forbidden" });
    const { result } = renderHook(() => useDeleteAccount());
    await expect(result.current({ password: "x".repeat(12) })).rejects.toThrow("error.forbidden");
    expect(h.ctx.logout).not.toHaveBeenCalled();
  });
});

describe("useRequestEmailChange / useVerifyEmailChange", () => {
  it("POSTs newEmail+password to request-email-change", async () => {
    const fetchMock = stubFetch(200, {});
    const { result } = renderHook(() => useRequestEmailChange());
    await result.current({ newEmail: "new@example.com", password: "hunter2hunter2" });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/x/acme/apps/app1/a/me/request-email-change",
      expect.objectContaining({ method: "POST" }),
    );
    expect(JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string))
      .toEqual({ newEmail: "new@example.com", password: "hunter2hunter2" });
  });

  it("POSTs the code to verify-email-change and refreshes the snapshot", async () => {
    const fetchMock = stubFetch(200, {});
    const { result } = renderHook(() => useVerifyEmailChange());
    await result.current({ code: "123456" });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/x/acme/apps/app1/a/me/verify-email-change",
      expect.objectContaining({ method: "POST" }),
    );
    expect(h.ctx.refresh).toHaveBeenCalledOnce();
  });
});

describe("useRequestReauthCode", () => {
  it("POSTs the account email to the public forgot-password endpoint without a bearer header", async () => {
    const fetchMock = stubFetch(200, {});
    const { result } = renderHook(() => useRequestReauthCode());
    await result.current();
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/x/acme/apps/app1/auth/forgot-password",
      expect.objectContaining({ method: "POST" }),
    );
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual({ email: "u@example.com" });
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined();
  });

  it("throws when there is no signed-in account email", async () => {
    h.ctx.snapshot = makeSnapshot({ appData: null });
    const { result } = renderHook(() => useRequestReauthCode());
    await expect(result.current()).rejects.toThrow("Not authenticated");
  });
});
