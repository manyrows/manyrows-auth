// Shared helpers for hook tests. Each test file mocks ../../AppKit with a
// vi.hoisted context object; these helpers build snapshots and fetch mocks.
import { vi } from "vitest";
import type { ManyRowsAppKitSnapshot } from "../../types";

export function makeSnapshot(over: Partial<ManyRowsAppKitSnapshot> = {}): ManyRowsAppKitSnapshot {
  return {
    status: "authenticated",
    jwtToken: "tok-123",
    appData: {
      account: { id: "u1", email: "u@example.com" },
      workspaceSlug: "acme",
      workspaceName: "Acme",
      hasAppAccess: true,
      roles: ["admin"],
      permissions: ["read"],
    },
    workspaceBaseURL: "https://api.test/x/acme",
    appBaseURL: "https://api.test/x/acme/apps/app1",
    appId: "app1",
    app: null,
    ...over,
  };
}

/** Stub global fetch to resolve with the given status/body on every call. Returns the mock. */
export function stubFetch(status: number, body: unknown) {
  const fn = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}
