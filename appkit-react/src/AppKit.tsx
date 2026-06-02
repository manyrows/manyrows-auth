// appkit-react/AppKit.tsx
import React, {
  createContext,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";
import type {
  ManyRowsAppKitError,
  ManyRowsAppKitReady,
  ManyRowsAppKitHandle,
  ManyRowsAppKitSnapshot,
} from "./types";
import { ensureScriptLoaded, getManyRowsAppKitRuntime, isSafeOrigin, sanitizeSameOriginPath } from "./runtime";
import { ThemeCtx, useSystemColorMode, resolveTokens, type ThemeContextValue } from "./theme";

// -----------------------------
// Runtime-compatibility contract
// -----------------------------
//
// EXPECTED_RUNTIME_VERSION is the appkit-ui (window.ManyRows.AppKit)
// version this SDK was built and tested against. Used for the default
// drift check that fires when the operator's deployed ManyRows server
// serves a runtime that's older or on a different major than what
// this SDK expects.
//
// Bump when:
//   - the runtime gains a new API the SDK starts calling (bump minor)
//   - the runtime renames / removes something the SDK relies on
//     (bump major in BOTH this SDK and the runtime; coordinated
//     break is an explicit choice, not a drift)
//
// Customers can still set runtimeExactVersion / runtimeMinVersion
// props to override or tighten this — those are the explicit knobs.
const EXPECTED_RUNTIME_VERSION = "0.1.1";

// -----------------------------
// Tiny semver helpers (no deps)
// -----------------------------

type Semver = { major: number; minor: number; patch: number };

function parseSemver(v: unknown): Semver | null {
  if (typeof v !== "string") return null;
  const s = v.trim();
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(s);
  if (!m) return null;
  const major = Number(m[1]);
  const minor = Number(m[2]);
  const patch = Number(m[3]);
  if (!Number.isFinite(major) || !Number.isFinite(minor) || !Number.isFinite(patch)) return null;
  return { major, minor, patch };
}

function cmpSemver(a: Semver, b: Semver): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  return a.patch - b.patch;
}

function semverGte(runtimeVersion: unknown, minVersion: string): boolean {
  const r = parseSemver(runtimeVersion);
  const m = parseSemver(minVersion);
  if (!r || !m) return false;
  return cmpSemver(r, m) >= 0;
}

// -----------------------------
// Prod/dev safety helpers
// -----------------------------

function isProbablyProdBuild(): boolean {
  const g = globalThis as { process?: { env?: { NODE_ENV?: string } } };
  return g.process?.env?.NODE_ENV === "production";
}

function looksLikeLocalhost(url: string): boolean {
  const s = (url || "").trim().toLowerCase();
  return (
    s.startsWith("http://localhost") ||
    s.startsWith("https://localhost") ||
    s.startsWith("http://127.0.0.1") ||
    s.startsWith("https://127.0.0.1") ||
    s.startsWith("http://0.0.0.0") ||
    s.startsWith("https://0.0.0.0")
  );
}

function assertSafeURLs(
  baseURL: string,
  src: string,
  report: (err: ManyRowsAppKitError) => void,
): boolean {
  if (!isSafeOrigin(baseURL)) {
    report(
      mkErr("BASE_URL_NOT_ALLOWED_IN_PROD", "baseURL must use HTTPS (or localhost for development).", {
        baseURL,
      })
    );
    return false;
  }
  if (!isSafeOrigin(src)) {
    report(
      mkErr("SCRIPT_LOAD_FAILED", "Script src must use HTTPS (or localhost for development).", {
        src,
      })
    );
    return false;
  }
  return true;
}

// -----------------------------
// Auth predicate (snapshot is loose)
// -----------------------------

function isAuthedSnapshot(s: ManyRowsAppKitSnapshot | null | undefined): boolean {
  if (!s || typeof s !== "object") return false;
  if (s.status !== "authenticated") return false;
  if (!s.appData || typeof s.appData !== "object") return false;
  // don't over-constrain v0
  return true;
}

// -----------------------------
// Server-call avoidance: skip loading the runtime when we know
// there's no session to validate. Token storage keys mirror
// appkit-ui's StoredTokens format (see appkit-ui/src/AppKit.tsx).
// -----------------------------

// hasStoredToken was a runtime-load gate that's no longer used now that
// publicAccess pages always mount the runtime (so cookie-backed sessions
// in cookie mode get detected). Kept commented as documentation in
// case the optimization comes back.
//
// function hasStoredToken(workspace: string, appId: string): boolean { ... }

function makeUnauthedSnapshot(
  workspace: string,
  appId: string,
  baseURL: string,
): ManyRowsAppKitSnapshot {
  return {
    status: "unauthenticated",
    jwtToken: null,
    appData: null,
    workspaceBaseURL: `${baseURL}/${workspace}`,
    appBaseURL: `${baseURL}/${workspace}/apps/${appId}`,
    appId,
    app: null,
  };
}

// -----------------------------
// AppKit context + hook
// -----------------------------

type AppKitContextValue = {
  status: "idle" | "loading" | "mounted" | "error";
  error: ManyRowsAppKitError | null;

  readyInfo: ManyRowsAppKitReady | null;
  snapshot: ManyRowsAppKitSnapshot | null;

  // convenience derived flag
  isAuthenticated: boolean;

  // present when runtime supports handle API
  handle: ManyRowsAppKitHandle | null;

  // convenience methods (safe no-ops if handle missing)
  refresh: () => void;
  logout: () => Promise<void>;
  setToken: (tok: string | null) => void;
  destroy: () => void;
  info: () => ManyRowsAppKitReady | null;
  showProfile: () => void;
  hideProfile: () => void;
};

const Ctx = createContext<AppKitContextValue | null>(null);

export function useAppKit(): AppKitContextValue {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAppKit() must be used under <AppKit />");
  return v;
}

/**
 * Render children only when the AppKit runtime is authenticated and appData exists.
 * Use this to mount your customer app "behind" the AppKit login screen.
 */
export function AppKitAuthed(props: {
  children: React.ReactNode;
  /**
   * Optional: shown when not authenticated (or still checking).
   * Default: null (render nothing).
   */
  fallback?: React.ReactNode;
}) {
  const { isAuthenticated } = useAppKit();
  if (!isAuthenticated) return <>{props.fallback ?? null}</>;
  return <>{props.children}</>;
}

// -----------------------------
// Props
// -----------------------------

export type AppKitTheme = {
  primaryColor?: string;
  backgroundColor?: string;
  colorMode?: "light" | "dark" | "auto";
};

export type AppKitProps = {
  workspace: string;

  // ✅ replaces project+env
  appId: string;

  /**
   * Base URL of the ManyRows install (e.g. "https://auth.acme.com").
   * Required — there is no default. ManyRows is self-hosted, so the
   * SDK can't guess where your install lives. Pass the same hostname
   * end-users see in the address bar when they sign in.
   */
  baseURL: string;

  // ✅ Theme customization
  theme?: AppKitTheme;

  /**
   * URL of the AppKit runtime script.
   * Defaults to `{baseURL}/appkit/assets/appkit.js`.
   */
  src?: string;

  /**
   * Optional Subresource Integrity hash for the AppKit runtime
   * script. Format: "sha384-<base64-hash>" (or sha256/sha512). When
   * set, the browser refuses to execute the script unless its bytes
   * hash to the supplied value — defends against a compromised
   * ManyRows CDN / build server / network MITM (operator-friendly:
   * even if the install's TLS cert is mint, a malicious script
   * payload would be rejected).
   *
   * The hash is generated at AppKit build time and surfaced to
   * customers in the ManyRows install console. Omitting it falls
   * back to HTTPS-only protection (still checked).
   */
  integrity?: string;
  timeoutMs?: number;

  silent?: boolean;
  throwOnError?: boolean;
  debug?: boolean;

  onReady?: (info: ManyRowsAppKitReady) => void;
  onError?: (err: ManyRowsAppKitError) => void;

  /**
   * Fired for every snapshot update from the runtime (checking/unauth/authed/etc).
   */
  onState?: (snapshot: ManyRowsAppKitSnapshot | null) => void;

  /**
   * Fired when AppKit is authenticated and appData is available.
   * This is the correct place to render the customer app (imperative style).
   */
  onReadyState?: (snapshot: ManyRowsAppKitSnapshot) => void;

  className?: string;
  style?: React.CSSProperties;
  containerId?: string;

  runtimeMinVersion?: string;
  runtimeExactVersion?: string;

  loading?: React.ReactNode;
  errorUI?: (err: ManyRowsAppKitError) => React.ReactNode;
  hideLoadingUI?: boolean;
  hideErrorUI?: boolean;

  /**
   * When true, children are always visible regardless of auth state.
   * Use for apps that are publicly accessible with optional login.
   */
  publicAccess?: boolean;

  /**
   * When true, the runtime's built-in auth/login UI is hidden.
   * Use with `publicAccess` to control when the login screen is shown via routing.
   */
  hideAuthUI?: boolean;

  /**
   * When true, AppKit fetches `/a/app/` on bootstrap to populate
   * `featureFlags` and `config` on the snapshot. Default: false.
   * Apps that don't read either field should leave this off — it
   * saves a round trip on every page load.
   */
  loadAppRuntime?: boolean;

  // kept for future (no longer used now that env is arbitrary)
  allowDevEnvInProd?: boolean;
  blockLocalhostBaseURLInProd?: boolean;

  // Content rendered above the login/register card
  authHeader?: React.ReactNode;

  // Override any user-facing text in the auth UI (partial — English defaults apply for unset keys)
  labels?: Record<string, string>;

  // Which auth screen to show initially
  initialScreen?: "login" | "register" | "forgot-password";

  // Called when the user navigates between auth screens (e.g. clicks "Create account")
  onScreenChange?: (screen: "login" | "register" | "forgot-password") => void;

  // Map auth screens to URL paths. When set, AppKit automatically derives
  // initialScreen from the current URL, hides auth UI on non-auth pages,
  // and updates the URL when the user navigates between auth screens.
  // Explicit initialScreen/hideAuthUI/onScreenChange props take precedence.
  authRoutes?: Partial<Record<"login" | "register" | "forgot-password", string>>;

  // When set alongside authRoutes, automatically navigates to this path
  // after the user authenticates while on an auth route.
  authRedirect?: string;

  // When true, the auth form skips its full-viewport wrapper and flows inline
  // in the parent container. Use for embedded integrations (sidebars, modals,
  // small sections). Default: false (keeps the centered full-page layout).
  embedded?: boolean;

  // ✅ allow <AppKit>children</AppKit>
  children?: React.ReactNode;
};

// -----------------------------
// Errors / UI
// -----------------------------

function mkErr(
  code: ManyRowsAppKitError["code"],
  message: string,
  details?: unknown
): ManyRowsAppKitError {
  return { code, message, details };
}

function DefaultError({ err }: { err: ManyRowsAppKitError }) {
  const isDark = typeof window !== "undefined" && window.matchMedia?.("(prefers-color-scheme: dark)").matches;
  const border = isDark ? "rgba(248, 113, 113, 0.4)" : "rgba(220, 38, 38, 0.3)";
  const bg = isDark ? "rgba(127, 29, 29, 0.25)" : "rgba(220, 38, 38, 0.06)";
  const text = isDark ? "#fca5a5" : undefined;

  return (
    <div
      role="alert"
      style={{
        width: "100%",
        borderRadius: 10,
        border: `1px solid ${border}`,
        background: bg,
        padding: 12,
        color: text,
        fontFamily:
          'ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji"',
      }}
    >
      <div style={{ fontWeight: 700, marginBottom: 6 }}>ManyRows AppKit failed to load</div>
      <div style={{ fontSize: 13, marginBottom: 8 }}>
        <span style={{ fontWeight: 600 }}>{err.code}</span>: {err.message}
      </div>
      {err.details !== undefined && !isProbablyProdBuild() ? (
        <pre
          style={{
            fontSize: 12,
            margin: 0,
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
            opacity: 0.8,
          }}
        >
          {typeof err.details === "string" ? err.details : JSON.stringify(err.details, null, 2)}
        </pre>
      ) : null}
    </div>
  );
}

// -----------------------------
// Component
// -----------------------------

export function AppKit(props: AppKitProps) {
  const autoId = useId();
  const containerId = props.containerId ?? `manyrows-appkit-${autoId.replace(/[:]/g, "")}`;

  // baseURL is required. Don't fall back to a hardcoded host — the
  // SaaS pitch is gone, and a stale default would silently send a
  // self-hoster's traffic somewhere it shouldn't go.
  const resolvedBaseURL = props.baseURL?.trim() ?? "";
  if (!resolvedBaseURL) {
    throw new Error(
      "AppKit: `baseURL` is required (e.g. \"https://auth.yourdomain.com\"). " +
        "No default — pass your ManyRows install's hostname.",
    );
  }
  const resolvedSrc = props.src?.trim() || `${resolvedBaseURL}/appkit/assets/appkit.js`;

  // Resolve color mode + tokens
  const requestedMode = props.theme?.colorMode ?? "light";
  const systemMode = useSystemColorMode();
  const resolvedMode = requestedMode === "auto" ? systemMode : requestedMode;
  const tokens = useMemo(
    () => resolveTokens(resolvedMode, props.theme?.primaryColor),
    [resolvedMode, props.theme?.primaryColor],
  );
  const themeValue = useMemo<ThemeContextValue>(
    () => ({ colorMode: resolvedMode, tokens }),
    [resolvedMode, tokens],
  );

  // If host supplies children, we assume host wants to own the authed UI.
  // In that case, suppress the runtime's *default* authed screen by passing renderAuthed={() => null}.
  const hasChildren = React.Children.count(props.children) > 0;

  // Track current pathname so authRoutes reacts to client-side navigation
  const [pathname, setPathname] = useState(() => typeof window !== "undefined" ? window.location.pathname : "");

  const authRoutesEnabled = !!props.authRoutes;
  useEffect(() => {
    if (!props.authRoutes) return;
    const onNav = () => setPathname(window.location.pathname);
    window.addEventListener("popstate", onNav);
    // Intercept pushState/replaceState so we catch programmatic navigation (e.g. React Router)
    const origPush = history.pushState.bind(history);
    const origReplace = history.replaceState.bind(history);
    history.pushState = function (...args) { origPush(...args); onNav(); };
    history.replaceState = function (...args) { origReplace(...args); onNav(); };
    return () => {
      window.removeEventListener("popstate", onNav);
      history.pushState = origPush;
      history.replaceState = origReplace;
    };
    // We only care whether authRoutes was supplied at all — the
    // individual paths get read each render via props.authRoutes
    // directly, so re-installing the popstate listener every time the
    // authRoutes object identity changes would be churn for nothing.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authRoutesEnabled]);

  // Resolve hideAuthUI from authRoutes if not explicitly set
  const authRoutePaths = props.authRoutes ? Object.values(props.authRoutes) : [];
  const onAuthRoute = authRoutePaths.some(path => pathname === path);
  const resolvedHideAuthUI = props.hideAuthUI ?? (props.authRoutes ? !onAuthRoute : undefined);

  // Avoid loading the runtime (and calling the ManyRows API) when there's no
  // session to validate and the user isn't on an auth route. Consumer-visible
  // effect: `status: "unauthenticated"` snapshot fires immediately; the runtime
  // loads lazily once the user navigates to an auth route or a token appears.
  //
  // Only short-circuit when the host has signaled an alternative path to login:
  //   - `publicAccess`: children render in unauthed state (host owns the "log in" CTA), OR
  //   - `authRoutes`: login lives on a specific route, runtime mounts when user navigates there.
  // Without either, the host depends on the runtime's default login screen — so we must load it.
  //
  // authBump is incremented when a sibling AppKit instance broadcasts a
  // login/logout (see channel listener below). Used to be a dep of a
  // memoized hasToken signal that gated runtime loading; that
  // optimization was dropped (see the comment block below) but the
  // setter is still wired so the channel listener has somewhere to
  // signal.
  const [, setAuthBump] = useState(0);

  // Transport mode is resolved by the runtime itself (from the
  // server's app config, not a client prop). In cookie mode the
  // session lives in HttpOnly cookies invisible to JS, so
  // `hasStoredToken()` is no longer a reliable signal of "this user
  // might be authenticated". Public-access islands (e.g. a navbar
  // profile menu) need the runtime mounted unconditionally so its
  // boot-time probe can detect a cookie-backed session. Drops the
  // previous skip-runtime optimization for those pages; the boot
  // fetch is fast enough that the trade-off is fine.
  //
  // Sticky load: once the runtime has been mounted (initial token, navigated
  // to an auth route, or peer-broadcasted login), keep it mounted until this
  // <AppKit> unmounts. Logging out should NOT tear the runtime down — the
  // user might log right back in (e.g. via 1Password's autofill), and the
  // runtime is what holds the WebAuthn ceremony / login form / refresh
  // timer. Re-mounting on every auth flip also caused the cleanup at
  // line 745 to call handleRef.destroy() in the middle of an in-flight
  // navigator.credentials.get() — silently breaking passkey re-login.
  const baseShouldLoadRuntime = true;
  const [runtimeEverLoaded, setRuntimeEverLoaded] = useState(baseShouldLoadRuntime);
  useEffect(() => {
    if (baseShouldLoadRuntime && !runtimeEverLoaded) {
      setRuntimeEverLoaded(true);
    }
  }, [baseShouldLoadRuntime, runtimeEverLoaded]);
  const shouldLoadRuntime = baseShouldLoadRuntime || runtimeEverLoaded;

  const authChannelKey = useMemo(
    () => `manyrows:auth:${(props.workspace ?? "").trim()}:${(props.appId ?? "").trim() || "_"}`,
    [props.workspace, props.appId]
  );

  useEffect(() => {
    if (typeof window === "undefined" || typeof BroadcastChannel === "undefined") return;
    const ch = new BroadcastChannel(authChannelKey);
    ch.onmessage = (e) => {
      const m = e.data;
      if (!m || typeof m !== "object") return;
      if (m.type === "tokens" || m.type === "logout") {
        setAuthBump((n) => n + 1);
      }
    };
    return () => ch.close();
  }, [authChannelKey]);

  const initKey = useMemo(
    () =>
      [
        containerId,
        props.workspace,
        props.appId,
        resolvedBaseURL,
        resolvedSrc,
        props.runtimeMinVersion ?? "",
        props.runtimeExactVersion ?? "",
        props.allowDevEnvInProd ? "1" : "0",
        props.blockLocalhostBaseURLInProd === false ? "0" : "1",
        hasChildren ? "children:1" : "children:0",
        shouldLoadRuntime ? "load:1" : "load:0",
      ].join("|"),
    [
      containerId,
      props.workspace,
      props.appId,
      resolvedBaseURL,
      resolvedSrc,
      props.runtimeMinVersion,
      props.runtimeExactVersion,
      props.allowDevEnvInProd,
      props.blockLocalhostBaseURLInProd,
      hasChildren,
      shouldLoadRuntime,
    ]
  );

  const handleRef = useRef<ManyRowsAppKitHandle | null>(null);
  const [handle, setHandle] = useState<ManyRowsAppKitHandle | null>(null);

  const [status, setStatus] = useState<"idle" | "loading" | "mounted" | "error">("idle");
  const [lastError, setLastError] = useState<ManyRowsAppKitError | null>(null);

  const [readyInfo, setReadyInfo] = useState<ManyRowsAppKitReady | null>(null);
  const [snapshot, setSnapshot] = useState<ManyRowsAppKitSnapshot | null>(null);

  // Redirect away from auth routes after authentication.
  // authRedirect is host-supplied so we validate it before navigating —
  // hosts that wire it from URLSearchParams.get("return_url") could
  // otherwise pass arbitrary URLs through, opening an open-redirect
  // primitive on top of replaceState.
  useEffect(() => {
    if (!props.authRedirect || !onAuthRoute || !isAuthedSnapshot(snapshot)) return;
    const safe = sanitizeSameOriginPath(props.authRedirect);
    if (!safe) return;
    history.replaceState(null, '', safe);
    window.dispatchEvent(new PopStateEvent('popstate'));
  }, [props.authRedirect, onAuthRoute, snapshot]);

  useEffect(() => {
    let cancelled = false;

    setStatus("loading");
    setLastError(null);
    setReadyInfo(null);
    setSnapshot(null);
    handleRef.current = null;
    setHandle(null);

    const report = (err: ManyRowsAppKitError) => {
      setLastError(err);
      setStatus("error");

      if (!props.silent) {
        console.warn("[@manyrows/appkit-react]", err.code, err.message, err.details ?? "");
      }
      props.onError?.(err);
    };

    const init = async () => {
      if (!props.workspace?.trim() || !props.appId?.trim()) {
        report(
          mkErr("INVALID_PROPS", "workspace and appId are required.", {
            workspace: props.workspace,
            appId: props.appId,
          })
        );
        return;
      }

      // Short-circuit: no token stored and not on an auth route.
      // Emit a synthetic "unauthenticated" snapshot and skip the script load entirely.
      if (!shouldLoadRuntime) {
        if (cancelled) return;
        const syntheticSnapshot = makeUnauthedSnapshot(
          props.workspace.trim(),
          props.appId.trim(),
          resolvedBaseURL,
        );
        setSnapshot(syntheticSnapshot);
        setStatus("mounted");
        setLastError(null);
        props.onState?.(syntheticSnapshot);
        return;
      }

      if (!assertSafeURLs(resolvedBaseURL, resolvedSrc, report)) return;

      const prod = isProbablyProdBuild();

      if (
        prod &&
        props.blockLocalhostBaseURLInProd !== false &&
        looksLikeLocalhost(resolvedBaseURL)
      ) {
        report(
          mkErr(
            "BASE_URL_NOT_ALLOWED_IN_PROD",
            "localhost baseURL is not allowed in production builds.",
            { baseURL: resolvedBaseURL }
          )
        );
        return;
      }

      try {
        const timeoutMs = props.timeoutMs ?? 4000;

        await ensureScriptLoaded(resolvedSrc, timeoutMs, {
          integrity: props.integrity,
        });

        const start = Date.now();
        while (!getManyRowsAppKitRuntime() && Date.now() - start < timeoutMs) {
          if (cancelled) return;
          await new Promise((r) => setTimeout(r, 25));
        }

        const api = getManyRowsAppKitRuntime();
        if (!api) {
          report(
            mkErr(
              "SCRIPT_TIMEOUT",
              `AppKit runtime not found after loading script: ${resolvedSrc}`,
              { src: resolvedSrc }
            )
          );
          return;
        }

        const runtimeVersion: unknown = api.version;

        if (props.runtimeExactVersion) {
          const expected = props.runtimeExactVersion.trim();
          if (!expected) {
            report(mkErr("INVALID_PROPS", "runtimeExactVersion must be a non-empty string."));
            return;
          }
          const found = typeof runtimeVersion === "string" ? runtimeVersion.trim() : "";
          if (found !== expected) {
            report(
              mkErr("RUNTIME_VERSION_MISMATCH", "AppKit runtime version mismatch.", {
                expected,
                found: runtimeVersion,
              })
            );
            return;
          }
        } else if (props.runtimeMinVersion) {
          const min = props.runtimeMinVersion.trim();
          if (!min) {
            report(mkErr("INVALID_PROPS", "runtimeMinVersion must be a non-empty string."));
            return;
          }
          const ok = semverGte(runtimeVersion, min);
          if (!ok) {
            report(
              mkErr("RUNTIME_VERSION_TOO_OLD", "AppKit runtime is too old.", {
                requiredMin: min,
                found: runtimeVersion,
                parsedFound: parseSemver(runtimeVersion),
              })
            );
            return;
          }
        } else {
          // Default drift check: warn (don't fail) when the runtime
          // doesn't match what this SDK was built against. Two cases
          // worth surfacing:
          //   1. Runtime is older — operator hasn't upgraded ManyRows;
          //      newer SDK APIs may silently no-op or throw.
          //   2. Runtime is on a different major — coordinated break
          //      between SDK and server; behaviour likely diverged.
          // Both are loud-only — explicit pinning is via
          // runtimeExactVersion / runtimeMinVersion props.
          const expected = parseSemver(EXPECTED_RUNTIME_VERSION);
          const found = parseSemver(runtimeVersion);
          if (expected && found) {
            const olderThanExpected = cmpSemver(found, expected) < 0;
            const majorDiffers = expected.major !== found.major;
            if ((olderThanExpected || majorDiffers) && !props.silent) {
              console.warn(
                `[ManyRows AppKit] Runtime version drift: SDK expects ${EXPECTED_RUNTIME_VERSION}, ` +
                  `server is serving ${runtimeVersion}. ` +
                  (majorDiffers
                    ? "Different major — APIs may be incompatible. Upgrade either the SDK (npm) or the ManyRows server."
                    : "Server runtime is older than the SDK was built against — newer SDK APIs may not work. Upgrade the ManyRows server."),
              );
            }
          }
        }

        // Derive initialScreen / hideAuthUI / onScreenChange from authRoutes
        const authRouteEntries = props.authRoutes
          ? Object.entries(props.authRoutes) as [("login" | "register" | "forgot-password"), string][]
          : [];
        const matchedScreen = authRouteEntries.find(([, path]) => window.location.pathname === path)?.[0];

        const resolvedInitialScreen = props.initialScreen ?? matchedScreen;
        const resolvedOnScreenChange = props.onScreenChange ?? (props.authRoutes
          ? (screen: "login" | "register" | "forgot-password") => {
              const raw = props.authRoutes?.[screen];
              const path = sanitizeSameOriginPath(raw);
              if (path && window.location.pathname !== path) {
                window.history.replaceState(null, '', path);
              }
            }
          : undefined);

        const h = api.init({
          containerId,
          workspace: props.workspace.trim(),
          appId: props.appId.trim(),
          baseURL: resolvedBaseURL,
          theme: props.theme,
          authHeader: props.authHeader,
          labels: props.labels,
          initialScreen: resolvedInitialScreen,
          onScreenChange: resolvedOnScreenChange,
          silent: props.silent,
          throwOnError: props.throwOnError,
          debug: props.debug,
          loadAppRuntime: props.loadAppRuntime,
          embedded: props.embedded,

          // Tell the runtime to skip mounting <Auth> entirely when the
          // host's container is hidden (publicAccess + non-auth route).
          // CSS-hiding via display:none keeps Auth in the React tree,
          // and its conditional-mediation passkey effect would still
          // fire and pop the OS passkey picker on every public page.
          hideAuthUI: resolvedHideAuthUI,

          // If host provides children, hide runtime default authed UI.
          // Runtime will still render login / errors / forbidden screens as normal.
          renderAuthed: hasChildren ? (() => null) : undefined,

          onReady: (info: ManyRowsAppKitReady) => {
            if (cancelled) return;
            setStatus("mounted");
            setLastError(null);
            setReadyInfo(info);
            props.onReady?.(info);
          },

          onState: (s: ManyRowsAppKitSnapshot | null) => {
            if (cancelled) return;
            setSnapshot(s);
            props.onState?.(s);
          },

          onReadyState: (s: ManyRowsAppKitSnapshot) => {
            if (cancelled) return;
            props.onReadyState?.(s);
          },

          onError: (e: ManyRowsAppKitError) => {
            report(mkErr("RUNTIME_ERROR", "AppKit runtime error.", e));
          },
        });

        // Set handle BEFORE any callbacks fire to avoid stale null on first mount
        handleRef.current = h ?? null;
        setHandle(h ?? null);
      } catch (e) {
        report(mkErr("SCRIPT_LOAD_FAILED", "Failed to load AppKit script.", { error: e }));
      }
    };

    void init();

    return () => {
      cancelled = true;

      try {
        handleRef.current?.destroy?.();
      } catch {
        // ignore
      }

      try {
        const api = getManyRowsAppKitRuntime();
        api?.destroy?.(containerId);
      } catch {
        // ignore
      }

      handleRef.current = null;
      setHandle(null);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initKey]);

  const showLoading = status === "loading" && !props.hideLoadingUI;
  const showError = status === "error" && !!lastError && !props.hideErrorUI;

  const ctx: AppKitContextValue = useMemo(() => {
    return {
      status,
      error: lastError,
      readyInfo,
      snapshot,
      isAuthenticated: isAuthedSnapshot(snapshot),
      handle,

      refresh: () => {
        try {
          handle?.refresh?.();
        } catch {
          // ignore
        }
      },
      logout: async () => {
        try {
          await handle?.logout?.();
        } catch {
          // ignore
        }
      },
      setToken: (tok: string | null) => {
        try {
          handle?.setToken?.(tok);
        } catch {
          // ignore
        }
      },
      destroy: () => {
        try {
          handle?.destroy?.();
        } catch {
          // ignore
        }
      },
      info: () => {
        try {
          return handle?.info?.() ?? null;
        } catch {
          return null;
        }
      },
      showProfile: () => {
        try { handle?.showProfile?.(); } catch { /* runtime not yet mounted */ }
      },
      hideProfile: () => {
        try { handle?.hideProfile?.(); } catch { /* runtime not yet mounted */ }
      },
    };
  }, [status, lastError, readyInfo, snapshot, handle]);

  return (
    <ThemeCtx.Provider value={themeValue}>
      <Ctx.Provider value={ctx}>
        <div className={props.className} style={props.style}>
          {showLoading && props.loading ? props.loading : null}
          {showError && lastError
            ? props.errorUI
              ? props.errorUI(lastError)
              : <DefaultError err={lastError} />
            : null}

          {/* Runtime owns all UI inside this container */}
          <div id={containerId} style={resolvedHideAuthUI ? { display: "none" } : undefined} />

          {/* Host-side children (can use AppKitAuthed/useAppKit).
              Hidden until authenticated so children don't double-up
              with the runtime's own loading/login UI.

              When no hiding is needed, render children directly without a
              wrapping <div> so host layouts (e.g. flex columns with order
              on navbar/footer) can treat them as direct siblings of the
              runtime container above. */}
          {!props.publicAccess && !isAuthedSnapshot(snapshot)
            ? <div style={{ display: "none" }}>{props.children}</div>
            : props.children}
        </div>
      </Ctx.Provider>
    </ThemeCtx.Provider>
  );
}
