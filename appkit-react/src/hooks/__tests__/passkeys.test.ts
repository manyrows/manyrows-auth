import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook } from "@testing-library/react";
import type { ManyRowsAppKitSnapshot } from "../../types";
import { makeSnapshot, stubFetch } from "./testUtils";

const h = vi.hoisted(() => ({
  ctx: { snapshot: null as ManyRowsAppKitSnapshot | null, refresh: vi.fn(), logout: vi.fn() },
}));
vi.mock("../../AppKit", () => ({ useAppKit: () => h.ctx }));

import { usePasskeys, useRenamePasskey, useDeletePasskey, useRegisterPasskey } from "../passkeys";

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

const CREATION_OPTIONS_JSON = {
  rp: { name: "Acme" },
  user: { id: "aGVsbG8", name: "u@example.com", displayName: "U" },
  challenge: "aGVsbG8",
  pubKeyCredParams: [{ type: "public-key", alg: -7 }],
};

function fakeCredential(): unknown {
  const bytes = new TextEncoder().encode("hello").buffer;
  return {
    id: "cred-1",
    rawId: bytes,
    authenticatorAttachment: "platform",
    getClientExtensionResults: () => ({}),
    response: { clientDataJSON: bytes, attestationObject: bytes, getTransports: () => ["internal"] },
  };
}

/** Make jsdom report passkey support and mock the create() ceremony. */
function stubWebAuthn(create: (opts?: CredentialCreationOptions) => Promise<unknown>) {
  vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() { /* marker */ });
  Object.defineProperty(navigator, "credentials", {
    configurable: true,
    value: { create },
  });
}

describe("useRegisterPasskey", () => {
  it("runs begin → credentials.create → finish and returns the passkey", async () => {
    const newPasskey = {
      id: "pk2", transports: ["internal"], backupEligible: false, backupState: false,
      createdAt: "2026-06-10T00:00:00Z",
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({
        ok: true, status: 200,
        json: async () => ({ challengeId: "ch-1", publicKeyOptions: CREATION_OPTIONS_JSON }),
      })
      .mockResolvedValueOnce({
        ok: true, status: 200,
        json: async () => ({ passkey: newPasskey }),
      });
    vi.stubGlobal("fetch", fetchMock);
    const create = vi.fn().mockResolvedValue(fakeCredential());
    stubWebAuthn(create);

    const { result } = renderHook(() => useRegisterPasskey());
    await expect(result.current({ name: "MacBook" })).resolves.toEqual(newPasskey);

    expect(fetchMock.mock.calls[0][0]).toBe("https://api.test/x/acme/apps/app1/a/passkey/register/begin");
    // The browser ceremony got decoded options (challenge as ArrayBuffer).
    const createArg = create.mock.calls[0][0] as CredentialCreationOptions;
    expect(new TextDecoder().decode(createArg.publicKey!.challenge as ArrayBuffer)).toBe("hello");
    // finish got the challengeId, name, and encoded response.
    expect(fetchMock.mock.calls[1][0]).toBe("https://api.test/x/acme/apps/app1/a/passkey/register/finish");
    const finishBody = JSON.parse((fetchMock.mock.calls[1][1] as RequestInit).body as string);
    expect(finishBody.challengeId).toBe("ch-1");
    expect(finishBody.name).toBe("MacBook");
    expect(finishBody.response.rawId).toBe("aGVsbG8");
  });

  it("throws a clear error when passkeys are unsupported", async () => {
    // No PublicKeyCredential stub → jsdom default (unsupported).
    const { result } = renderHook(() => useRegisterPasskey());
    await expect(result.current()).rejects.toThrow(/not supported/i);
  });

  it("maps user cancellation (NotAllowedError) to a friendly error", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true, status: 200,
      json: async () => ({ challengeId: "ch-1", publicKeyOptions: CREATION_OPTIONS_JSON }),
    }));
    stubWebAuthn(vi.fn().mockRejectedValue(new DOMException("denied", "NotAllowedError")));
    const { result } = renderHook(() => useRegisterPasskey());
    await expect(result.current()).rejects.toThrow(/cancelled/i);
  });
});
