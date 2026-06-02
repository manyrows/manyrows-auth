// Pure helpers for the app-users import/export flow in AppUsers.tsx.
// Kept framework-free (no React, no axios, no MUI) so they can be unit-tested
// directly without a DOM or mocked providers.

import type { AxiosError } from "axios";

type ExportMember = {
  accountId: string;
  email: string;
  enabled?: boolean;
  emailVerifiedAt?: string | null;
  passwordSetAt?: string | null;
  lastLoginAt?: string | null;
};

type ExportEntry = {
  id: string;
  email: string;
  enabled: boolean;
  roles: string[];
  emailVerifiedAt?: string;
  passwordSetAt?: string;
  lastLoginAt?: string;
  permissions?: string[];
  fields?: Record<string, unknown>;
};

/**
 * Build one export entry for a single member. Optional timestamps are only
 * emitted when non-null so the JSON stays compact.
 */
export function buildExportEntry(
  member: ExportMember,
  roleSlugs: string[],
  directPermissionSlugs: string[] = [],
  fieldValues: Record<string, unknown> = {},
): ExportEntry {
  const entry: ExportEntry = {
    id: member.accountId,
    email: member.email,
    enabled: member.enabled !== false,
    roles: roleSlugs,
  };
  if (member.emailVerifiedAt) entry.emailVerifiedAt = member.emailVerifiedAt;
  if (member.passwordSetAt) entry.passwordSetAt = member.passwordSetAt;
  if (member.lastLoginAt) entry.lastLoginAt = member.lastLoginAt;
  if (directPermissionSlugs.length > 0) entry.permissions = directPermissionSlugs;
  if (Object.keys(fieldValues).length > 0) entry.fields = fieldValues;
  return entry;
}

/**
 * Produce a canonical filename for the export download.
 * Example: users-drum-kingdom-production-2026-04-24.json
 *
 * Project name is slugified at filename-building time (lower-cased,
 * whitespace + non-alphanumerics collapsed to a single hyphen) so
 * downloads stay file-system-safe regardless of what the admin called
 * the project.
 */
export function buildExportFilename(projectName: string, appName: string, date: Date): string {
  const iso = date.toISOString().slice(0, 10);
  return `users-${slugifyForFilename(projectName)}-${slugifyForFilename(appName)}-${iso}.json`;
}

function slugifyForFilename(s: string): string {
  return (s || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "project";
}

export type ImportUser = {
  email?: string;
  enabled?: boolean;
  roles?: string[];
  permissions?: string[];
  fields?: Record<string, unknown>;
};

/**
 * Parse a JSON string into an import users array. Returns [] for non-array
 * payloads (rather than throwing) so the caller can distinguish "valid JSON
 * but wrong shape" (empty array → "no users in file") from "malformed JSON"
 * (throws → "invalid JSON file").
 */
export function parseUsersJson(text: string): ImportUser[] {
  const data = JSON.parse(text);
  return Array.isArray(data) ? (data as ImportUser[]) : [];
}

type ImportPreview = {
  total: number;
  toCreate: number;
  toUpdate: number;
  missingEmail: number;
};

/**
 * Compute the create/update split for an import preview. Email matching is
 * case-insensitive. Rows without an email address are counted separately
 * (they'll fail at import time) so the preview numbers are honest.
 */
export function computeImportPreview(
  users: ImportUser[],
  existingEmailsLower: Set<string>,
): ImportPreview {
  let toCreate = 0;
  let toUpdate = 0;
  let missingEmail = 0;
  for (const u of users) {
    const email = u.email?.trim();
    if (!email) {
      missingEmail++;
      continue;
    }
    if (existingEmailsLower.has(email.toLowerCase())) {
      toUpdate++;
    } else {
      toCreate++;
    }
  }
  return { total: users.length, toCreate, toUpdate, missingEmail };
}

/**
 * Extract a human-readable failure reason from an axios error (or any thrown
 * value) for display in the import result dialog. Prefers, in order:
 *   1. data.issues[0].message (validation errors from the Go backend)
 *   2. data.message
 *   3. data.error (ignored if it's the generic "validation" tag)
 *   4. raw string body (truncated)
 *   5. err.message
 */
type ApiErrorBody = {
  issues?: { message?: string }[];
  message?: string;
  error?: string;
};

export function extractErrorReason(err: unknown): string {
  if (err && typeof err === "object" && "isAxiosError" in err && (err as AxiosError).isAxiosError) {
    const ax = err as AxiosError<ApiErrorBody | string | undefined>;
    const data = ax.response?.data;
    if (data && typeof data === "object") {
      const issues = data.issues;
      if (Array.isArray(issues) && issues.length > 0) {
        const msg = issues[0]?.message;
        if (typeof msg === "string" && msg.trim()) return msg.trim();
      }
      if (typeof data.message === "string" && data.message.trim()) return data.message.trim();
      if (typeof data.error === "string" && data.error.trim() && data.error !== "validation") return data.error.trim();
    }
    if (typeof data === "string" && data.trim()) {
      const s = data.trim();
      return s.length > 300 ? s.slice(0, 300) + "…" : s;
    }
    return ax.message || "Request failed";
  }
  if (err instanceof Error) return err.message;
  return String(err);
}

/**
 * Resolve a list of slugs against a known set of {slug, id} records.
 * Returns both the successfully-resolved IDs and the unknown slugs so the
 * caller can surface them rather than silently dropping assignments.
 */
export function resolveSlugsToIds<T extends { id: string; slug: string }>(
  slugs: string[],
  known: T[],
): { ids: string[]; unknown: string[] } {
  const bySlug = new Map(known.map((k) => [k.slug, k.id]));
  const ids: string[] = [];
  const unknown: string[] = [];
  for (const s of slugs) {
    const id = bySlug.get(s);
    if (id) ids.push(id);
    else unknown.push(s);
  }
  return { ids, unknown };
}
