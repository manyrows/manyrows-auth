// Pulls a human-readable message out of an axios error response body.
//
// The ManyRows server uses three response shapes for errors:
//
//   1. Validation envelope:
//      { "error": "validation", "issues": [{ "field": "...", "code": "...", "message": "..." }] }
//   2. Plain message:
//      { "error": "error.someKey", "message": "Human-readable text" }
//   3. Bare error key:
//      { "error": "error.someKey" }
//
// Older code in Profile.tsx only read `data.message`, which silently
// dropped (1) and (3). This helper tries all three shapes and returns
// `fallback` when nothing usable is present (e.g. transport error,
// HTML error page, opaque 500).
export function extractApiErrorMessage(err: any, fallback: string): string {
  const data = err?.response?.data;

  if (typeof data === "string" && data.trim()) return data.trim();

  if (data && typeof data === "object") {
    if (Array.isArray(data.issues) && data.issues.length > 0) {
      const msg = data.issues[0]?.message;
      if (typeof msg === "string" && msg.trim()) return msg.trim();
    }
    const m =
      data.message ||
      // Skip "validation" — that's an envelope tag, not a user message.
      (data.error !== "validation" && data.error) ||
      data.details ||
      data.info ||
      "";
    if (typeof m === "string" && m.trim()) return m.trim();
  }

  return fallback;
}
