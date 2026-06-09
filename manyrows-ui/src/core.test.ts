import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { isSafeRedirectURL } from "./core.ts";

// isSafeRedirectURL must be same-origin only: the admin console session is
// cookie-borne, so following a redirect to any other origin while logged in
// is an open redirect on an auth surface.
describe("isSafeRedirectURL", () => {
  const ORIGIN = "https://admin.example.com";

  beforeEach(() => {
    (globalThis as unknown as { window: unknown }).window = {
      location: { origin: ORIGIN },
    };
  });
  afterEach(() => {
    delete (globalThis as unknown as { window?: unknown }).window;
  });

  it("accepts same-origin absolute URLs", () => {
    expect(isSafeRedirectURL(`${ORIGIN}/admin/login`)).toBe(true);
  });

  it("accepts relative paths (resolved against the current origin)", () => {
    expect(isSafeRedirectURL("/admin/login")).toBe(true);
  });

  it("rejects cross-origin https URLs", () => {
    expect(isSafeRedirectURL("https://attacker.example.com/steal")).toBe(false);
  });

  it("rejects protocol-relative URLs that point off-origin", () => {
    expect(isSafeRedirectURL("//attacker.example.com/")).toBe(false);
  });

  it("rejects a different scheme on the same host (origin includes scheme)", () => {
    expect(isSafeRedirectURL("http://admin.example.com/")).toBe(false);
  });

  it("rejects javascript: URLs", () => {
    expect(isSafeRedirectURL("javascript:alert(1)")).toBe(false);
  });

  it("rejects userinfo-confusion URLs (real host is the attacker)", () => {
    expect(
      isSafeRedirectURL("https://admin.example.com@attacker.example.com/"),
    ).toBe(false);
  });
});
