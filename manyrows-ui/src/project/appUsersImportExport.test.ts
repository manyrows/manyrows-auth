import { describe, it, expect } from "vitest";
import {
  buildExportEntry,
  buildExportFilename,
  parseUsersJson,
  toImportRows,
  summarizeImportResponse,
  extractErrorReason,
  resolveSlugsToIds,
  type ImportResponse,
} from "./appUsersImportExport";

// ===== buildExportEntry =====

describe("buildExportEntry", () => {
  const baseMember = {
    accountId: "acc-123",
    email: "alice@example.com",
  };

  it("includes id, email, enabled (defaulting to true), and roles", () => {
    const entry = buildExportEntry(baseMember, ["editor"]);
    expect(entry).toEqual({
      id: "acc-123",
      email: "alice@example.com",
      enabled: true,
      roles: ["editor"],
    });
  });

  it("preserves enabled=false", () => {
    const entry = buildExportEntry({ ...baseMember, enabled: false }, []);
    expect(entry.enabled).toBe(false);
  });

  it("treats enabled=undefined as true", () => {
    const entry = buildExportEntry(baseMember, []);
    expect(entry.enabled).toBe(true);
  });

  it("includes optional timestamps only when present", () => {
    const entry = buildExportEntry(
      { ...baseMember, emailVerifiedAt: "2026-01-15T10:30:00Z", passwordSetAt: null, lastLoginAt: "2026-04-01T00:00:00Z" },
      ["editor"],
    );
    expect(entry.emailVerifiedAt).toBe("2026-01-15T10:30:00Z");
    expect(entry.lastLoginAt).toBe("2026-04-01T00:00:00Z");
    expect("passwordSetAt" in entry).toBe(false);
  });

  it("omits the timestamps field entirely when null/undefined", () => {
    const entry = buildExportEntry(baseMember, []);
    expect("emailVerifiedAt" in entry).toBe(false);
    expect("passwordSetAt" in entry).toBe(false);
    expect("lastLoginAt" in entry).toBe(false);
  });

  it("omits permissions when empty", () => {
    const entry = buildExportEntry(baseMember, ["editor"], []);
    expect("permissions" in entry).toBe(false);
  });

  it("includes permissions when non-empty", () => {
    const entry = buildExportEntry(baseMember, ["editor"], ["read", "write"]);
    expect(entry.permissions).toEqual(["read", "write"]);
  });

  it("omits fields when empty object", () => {
    const entry = buildExportEntry(baseMember, ["editor"], [], {});
    expect("fields" in entry).toBe(false);
  });

  it("includes fields when non-empty", () => {
    const entry = buildExportEntry(baseMember, [], [], { name: "Alice", verified: true });
    expect(entry.fields).toEqual({ name: "Alice", verified: true });
  });
});

// ===== buildExportFilename =====

describe("buildExportFilename", () => {
  it("formats as users-{name}-{app}-{YYYY-MM-DD}.json", () => {
    const date = new Date("2026-04-24T12:34:56Z");
    expect(buildExportFilename("Drumkingdom", "Production", date)).toBe(
      "users-drumkingdom-production-2026-04-24.json",
    );
  });

  it("slugifies whitespace and non-alphanumerics for filesystem safety", () => {
    const date = new Date("2026-04-24T00:00:00Z");
    expect(buildExportFilename("Drum Kingdom!", "Prod (EU)", date)).toBe(
      "users-drum-kingdom-prod-eu-2026-04-24.json",
    );
  });

  it("uses the ISO date even with timezone-shifted input", () => {
    // 2026-04-23 23:30 UTC → still 2026-04-23 ISO date
    const date = new Date("2026-04-23T23:30:00Z");
    expect(buildExportFilename("a", "b", date)).toBe("users-a-b-2026-04-23.json");
  });
});

// ===== parseUsersJson =====

describe("parseUsersJson", () => {
  it("parses a top-level array of users", () => {
    const users = parseUsersJson('[{"email":"a@b.com"},{"email":"c@d.com"}]');
    expect(users).toHaveLength(2);
    expect(users[0].email).toBe("a@b.com");
  });

  it("returns an empty array for a non-array object", () => {
    expect(parseUsersJson('{"email":"x@y.com"}')).toEqual([]);
  });

  it("returns an empty array for a non-array primitive", () => {
    expect(parseUsersJson("42")).toEqual([]);
    expect(parseUsersJson('"hello"')).toEqual([]);
    expect(parseUsersJson("null")).toEqual([]);
  });

  it("throws on malformed JSON", () => {
    expect(() => parseUsersJson("{not json")).toThrow();
  });
});

// ===== toImportRows =====

describe("toImportRows", () => {
  it("preserves present-vs-absent and translates emailVerifiedAt", () => {
    const rows = toImportRows([
      { email: "a@x.com", roles: [], emailVerifiedAt: "2026-01-01T00:00:00Z", fields: { dept: "Eng" } },
      { email: "b@x.com", enabled: false },
    ]);
    expect(rows[0]).toEqual({ email: "a@x.com", roles: [], emailVerified: true, fields: { dept: "Eng" } });
    expect(rows[1]).toEqual({ email: "b@x.com", enabled: false });
    expect("roles" in rows[1]).toBe(false);
  });

  it("prefers an explicit emailVerified over emailVerifiedAt", () => {
    const rows = toImportRows([{ email: "c@x.com", emailVerified: false, emailVerifiedAt: "2026-01-01T00:00:00Z" }]);
    expect(rows[0].emailVerified).toBe(false);
  });
});

describe("summarizeImportResponse", () => {
  it("passes the summary through and flattens failures", () => {
    const resp: ImportResponse = {
      dryRun: false,
      summary: { total: 3, created: 1, updated: 0, skipped: 1, failed: 1 },
      rows: [
        { row: 1, email: "ok@x.com", outcome: "created" },
        { row: 2, email: "dup@x.com", outcome: "skipped" },
        { row: 3, email: "bad@x.com", outcome: "failed", errors: [{ field: "roles", message: "unknown role(s): nope" }] },
      ],
    };
    const { summary, failures } = summarizeImportResponse(resp);
    expect(summary.created).toBe(1);
    expect(failures).toEqual([{ email: "bad@x.com", reason: "roles: unknown role(s): nope" }]);
  });
});

// ===== extractErrorReason =====

describe("extractErrorReason", () => {
  // Minimal axios-error-shaped object without importing axios itself.
  const mkAxiosErr = (response: unknown, fallbackMessage = "Request failed") => ({
    isAxiosError: true,
    message: fallbackMessage,
    response,
  });

  it("prefers issues[0].message from a validation response", () => {
    const err = mkAxiosErr({
      data: {
        error: "validation",
        issues: [{ message: "email is invalid" }, { message: "name too long" }],
      },
    });
    expect(extractErrorReason(err)).toBe("email is invalid");
  });

  it("falls back to data.message when no issues", () => {
    const err = mkAxiosErr({ data: { message: "rate limit exceeded" } });
    expect(extractErrorReason(err)).toBe("rate limit exceeded");
  });

  it('falls back to data.error but ignores the generic "validation" sentinel', () => {
    const validationErr = mkAxiosErr({ data: { error: "validation" } });
    expect(extractErrorReason(validationErr)).toBe("Request failed"); // falls through to ax.message

    const specificErr = mkAxiosErr({ data: { error: "account already exists" } });
    expect(extractErrorReason(specificErr)).toBe("account already exists");
  });

  it("handles raw string responses, truncating long ones", () => {
    const short = mkAxiosErr({ data: "simple error" });
    expect(extractErrorReason(short)).toBe("simple error");

    const long = "x".repeat(500);
    const longErr = mkAxiosErr({ data: long });
    const reason = extractErrorReason(longErr);
    expect(reason.length).toBeLessThanOrEqual(301);
    expect(reason.endsWith("…")).toBe(true);
  });

  it("falls back to the axios error message when no response data", () => {
    const err = mkAxiosErr(undefined, "Network Error");
    expect(extractErrorReason(err)).toBe("Network Error");
  });

  it("handles plain Error objects", () => {
    expect(extractErrorReason(new Error("boom"))).toBe("boom");
  });

  it("handles non-error throws by stringifying", () => {
    expect(extractErrorReason("just a string")).toBe("just a string");
    expect(extractErrorReason(42)).toBe("42");
    expect(extractErrorReason(null)).toBe("null");
  });
});

// ===== resolveSlugsToIds =====

describe("resolveSlugsToIds", () => {
  const known = [
    { id: "r1", slug: "editor" },
    { id: "r2", slug: "viewer" },
    { id: "r3", slug: "admin" },
  ];

  it("returns IDs for known slugs", () => {
    const { ids, unknown } = resolveSlugsToIds(["editor", "admin"], known);
    expect(ids).toEqual(["r1", "r3"]);
    expect(unknown).toEqual([]);
  });

  it("collects unknown slugs separately", () => {
    const { ids, unknown } = resolveSlugsToIds(["editor", "ghost", "phantom"], known);
    expect(ids).toEqual(["r1"]);
    expect(unknown).toEqual(["ghost", "phantom"]);
  });

  it("handles empty input", () => {
    expect(resolveSlugsToIds([], known)).toEqual({ ids: [], unknown: [] });
  });

  it("handles an empty known set (everything is unknown)", () => {
    const { ids, unknown } = resolveSlugsToIds(["editor", "viewer"], []);
    expect(ids).toEqual([]);
    expect(unknown).toEqual(["editor", "viewer"]);
  });
});
