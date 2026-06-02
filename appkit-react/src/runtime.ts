import type { AppKitRuntime } from "./types";

/**
 * Returns true if the URL uses HTTPS or targets localhost (for development).
 * Used to prevent loading scripts from or sending tokens to untrusted origins.
 */
export function isSafeOrigin(url: string): boolean {
  const s = (url || "").trim().toLowerCase();
  if (s.startsWith("https://")) return true;
  if (
    s.startsWith("http://localhost") ||
    s.startsWith("http://127.0.0.1") ||
    s.startsWith("http://0.0.0.0")
  ) return true;
  return false;
}

/**
 * Validates a path passed to history.replaceState / pushState. Accepts only
 * same-origin paths starting with a single "/". Rejects:
 *   - Anything that's not a string.
 *   - Empty / whitespace.
 *   - Protocol-relative paths ("//evil.com/...") which would navigate
 *     cross-origin without a scheme.
 *   - Absolute URLs ("https://...", "javascript:...", "data:...").
 *   - Paths that don't start with "/".
 *
 * Returns the trimmed path on success, or null if the input is unsafe.
 *
 * Defence-in-depth for hosts that wire authRedirect / authRoutes from
 * URL query params — without this check, a malicious return_url could
 * land in the navigation primitive.
 */
export function sanitizeSameOriginPath(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const s = raw.trim();
  if (!s) return null;
  // Must start with a single "/", not "//" (protocol-relative).
  if (!s.startsWith("/")) return null;
  if (s.startsWith("//")) return null;
  // Belt and braces: no scheme markers.
  if (/^[a-z][a-z0-9+.-]*:/i.test(s)) return null;
  return s;
}

// Shape of the globals the runtime attaches when it boots. Mirrors what
// appkit-ui/main.tsx writes to window: a namespaced object plus a few
// back-compat function aliases.
type RuntimeGlobals = {
  ManyRows?: { AppKit?: AppKitRuntime };
  initManyRowsAppKit?: AppKitRuntime["init"];
  destroyManyRowsAppKit?: AppKitRuntime["destroy"];
  getManyRowsAppKitInfo?: AppKitRuntime["info"];
};

// isPlausibleRuntime sanity-checks the shape of an alleged AppKit
// runtime before the wrapper hands a customer's tokens / state
// callbacks to it. Same-origin scripts can write anything to
// window.ManyRows; this catches the common shapes of "another script
// claimed the namespace by accident" (or maliciously) — both the
// "obviously a different value" case (string, array) and the "shape
// mismatch" case (init is not a function) end up returning null
// from getManyRowsAppKitRuntime so the SDK times out cleanly with
// SCRIPT_TIMEOUT rather than silently invoking attacker code.
//
// Genuine impersonation by a same-origin script that copies the
// shape can't be prevented from JS land — that's a CSP / SRI
// problem, see the integrity prop for the runtime <script> tag.
// This check is defence-in-depth against accidental collision and
// trivial spoofing, not a substitute for those controls.
function isPlausibleRuntime(value: unknown): value is AppKitRuntime {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  if (typeof candidate.init !== "function") return false;
  if (candidate.destroy !== undefined && typeof candidate.destroy !== "function") return false;
  if (candidate.info !== undefined && typeof candidate.info !== "function") return false;
  if (candidate.version !== undefined && typeof candidate.version !== "string") return false;
  return true;
}

export function getManyRowsAppKitRuntime(): AppKitRuntime | null {
  const w = window as Window & RuntimeGlobals;

  // Preferred: namespaced. Shape-check before trusting it — a same-
  // origin script that wrote window.ManyRows for its own purposes
  // (or maliciously) shouldn't be invoked as the AppKit runtime.
  const ns = w.ManyRows?.AppKit;
  if (ns && isPlausibleRuntime(ns)) return ns;

  // Back-compat: function globals. Same shape check; the legacy
  // shape didn't ship with version/destroy/info, so a function-typed
  // init is the entire validation surface here.
  if (typeof w.initManyRowsAppKit === "function") {
    return {
      init: w.initManyRowsAppKit,
      destroy: w.destroyManyRowsAppKit,
      info: w.getManyRowsAppKitInfo,
    };
  }

  return null;
}

// isValidSRI accepts the algorithms allowed by the SubresourceIntegrity
// spec: sha256, sha384, sha512. Format is "<alg>-<base64>". A loose
// regex is enough — the browser rejects anything malformed regardless
// of what we hand it; we just want to avoid silently accepting an
// unknown shape that would let an attacker substitute a script by
// supplying an invalid integrity (browsers fail open on parse error
// in some older specs, fail closed in current).
const SRI_PATTERN = /^(sha256|sha384|sha512)-[A-Za-z0-9+/=]+$/;

export type EnsureScriptLoadedOptions = {
  /**
   * Optional Subresource Integrity hash. When provided, set as the
   * <script>'s integrity attribute so the browser refuses to execute
   * the script unless its bytes hash to this value. Defends against
   * a compromised CDN / build server / network attacker who has TLS
   * but not the build pipeline.
   */
  integrity?: string;
};

export function ensureScriptLoaded(
  src: string,
  timeoutMs: number,
  options: EnsureScriptLoadedOptions = {},
): Promise<void> {
  return new Promise((resolve, reject) => {
    if (typeof window === "undefined" || typeof document === "undefined") {
      resolve(); // SSR: noop
      return;
    }

    // Validate origin before injecting script
    if (!isSafeOrigin(src)) {
      reject(new Error(`Refused to load AppKit script from non-HTTPS origin: ${src}`));
      return;
    }

    // Validate the integrity value shape if supplied. A malformed
    // value would be a customer config bug; surface it loudly rather
    // than silently dropping the attribute (which would downgrade
    // the security guarantee).
    if (options.integrity !== undefined && !SRI_PATTERN.test(options.integrity)) {
      reject(new Error(
        `Refused to load AppKit script with invalid integrity value: ${options.integrity} ` +
          `(expected "sha256-<base64>", "sha384-<base64>", or "sha512-<base64>")`,
      ));
      return;
    }

    // Already present?
    const existing = Array.from(document.querySelectorAll('script[data-manyrows-appkit="true"]')).find(
      (el) => el.getAttribute("src") === src
    );
    if (existing) {
      resolve();
      return;
    }

    // If runtime already exists, we’re good.
    if (getManyRowsAppKitRuntime()) {
      resolve();
      return;
    }

    const s = document.createElement("script");
    s.src = src;
    s.async = true;
    s.crossOrigin = "anonymous";
    s.setAttribute("data-manyrows-appkit", "true");
    if (options.integrity) {
      s.integrity = options.integrity;
    }

    const timer = window.setTimeout(() => {
      cleanup();
      reject(new Error(`Timed out loading AppKit script after ${timeoutMs}ms: ${src}`));
    }, timeoutMs);

    function cleanup() {
      window.clearTimeout(timer);
      s.onload = null;
      s.onerror = null;
    }

    s.onload = () => {
      cleanup();
      resolve();
    };

    s.onerror = (e) => {
      cleanup();
      reject(e);
    };

    document.head.appendChild(s);
  });
}
