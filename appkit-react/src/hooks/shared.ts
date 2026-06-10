// appkit-react/src/hooks/shared.ts — internal helpers for the authed /a/* hooks.
// Not exported from the package index.
import type { AppKitOrgListParams } from "../types";

/** Internal: authed JSON request against the app's /a/* surface. */
export async function authedJson(
  token: string | null | undefined,
  baseURL: string | null | undefined,
  path: string,
  init: RequestInit,
  failMsg: string,
): Promise<unknown> {
  if (!token || !baseURL) {
    throw new Error("Not authenticated");
  }
  const res = await fetch(`${baseURL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}`, ...(init.headers ?? {}) },
  });
  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    throw new Error((errBody as { issues?: { message?: string }[]; error?: string })?.issues?.[0]?.message
      || (errBody as { error?: string })?.error || failMsg);
  }
  if (res.status === 204) return undefined;
  return res.json().catch(() => ({}));
}

/** Internal: build the ?page&pageSize&search query string for list endpoints. */
export function listQuery(opts?: AppKitOrgListParams): string {
  if (!opts) return "";
  const p = new URLSearchParams();
  if (opts.page != null) p.set("page", String(opts.page));
  if (opts.pageSize != null) p.set("pageSize", String(opts.pageSize));
  if (opts.search) p.set("search", opts.search);
  const s = p.toString();
  return s ? `?${s}` : "";
}
