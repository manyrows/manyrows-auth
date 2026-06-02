import axios, { type AxiosError } from "axios";

// Shape of a validation issue returned by the server. The backend's
// `/api/...` handlers send these in `issues[]` on 400/422 responses.
type ApiIssue = { message?: string; code?: string };

type ApiErrorBody = {
  message?: string;
  error?: string;
  issues?: ApiIssue[];
};

function isAxiosErrorLike(err: unknown): err is AxiosError<unknown> {
  return axios.isAxiosError(err);
}

// apiErrorCode returns the machine-readable code of the first validation issue
// (e.g. "duplicate", "already_attached", "cross_product"), or null. Use it to
// branch on specific server errors without string-matching the message.
export function apiErrorCode(err: unknown): string | null {
  if (!isAxiosErrorLike(err)) return null;
  const data = err.response?.data;
  if (!data || typeof data !== "object") return null;
  const issues = (data as ApiErrorBody).issues;
  return (Array.isArray(issues) && issues[0]?.code) || null;
}

function pickServerMessage(data: unknown): string | null {
  if (typeof data === "string") {
    const trimmed = data.trim();
    return trimmed ? trimmed : null;
  }
  if (!data || typeof data !== "object") return null;
  const body = data as ApiErrorBody;
  if (Array.isArray(body.issues) && body.issues[0]?.message) {
    return body.issues[0].message;
  }
  if (typeof body.message === "string" && body.message.trim()) return body.message;
  if (typeof body.error === "string" && body.error.trim() && body.error !== "validation") {
    return body.error;
  }
  return null;
}

// extractApiError reduces an unknown thrown value to a human-readable string.
// Order of preference: server-provided message (string body / issues / message
// / error), then HTTP status, then the axios error message, then a generic
// fallback. Use this in catch blocks instead of hand-rolling
// `e?.response?.data?.message ?? e?.message ?? "Request failed"`.
export function extractApiError(err: unknown, fallback = "Request failed"): string {
  if (isAxiosErrorLike(err)) {
    const fromBody = pickServerMessage(err.response?.data);
    if (fromBody) return fromBody;
    if (err.response?.status) return `Request failed (${err.response.status})`;
    return err.message || fallback;
  }
  if (err instanceof Error && err.message) return err.message;
  if (typeof err === "string" && err.trim()) return err;
  return fallback;
}
