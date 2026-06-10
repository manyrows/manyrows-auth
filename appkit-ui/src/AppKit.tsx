// appkit-ui/AppKit.tsx
import * as React from "react";
import * as ReactDOM from "react-dom";
import axios from "axios";
import type { AxiosInstance, AxiosRequestConfig } from "axios";
import QRCode from "qrcode";

import "./appkit.css";
import Icon from "./Icon";
import Spinner from "./Spinner";
import { resolveTheme, AppKitThemeProvider, type AppKitThemeOptions } from "./theme";
import Profile from "./Profile";
import { useReauthGate, ReauthGateFields } from "./reauthGate";
import Auth, { type TokenPairResponse } from "./Auth";
import { UserButton } from "./UserButton";
import { ToastProvider, useToast } from "./Toast";
import { withDPoPHeader } from "./dpop";
import { extractInviteError, inviteErrorMessage } from "./inviteError";

// Shape-validate a BroadcastChannel token-pair message before treating it
// as auth tokens. Same-origin scripts can post arbitrary objects on the
// channel; without this gate they could write garbage to localStorage and
// trigger a refresh loop. Checks the three required fields (access /
// refresh / expiresIn) for plausible types — full JWT validation happens
// later when the server rejects malformed tokens.
function isValidTokenPair(v: unknown): v is TokenPairResponse {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  if (typeof o.accessToken !== "string" || o.accessToken.length === 0) return false;
  // refreshToken is non-empty in Tier 1 (bearer mode); in cookie
  // mode the value lives in an HttpOnly cookie and isn't visible to
  // JS, so the broadcast carries an empty / missing string. Allow
  // either — accessToken being present is the actual auth signal.
  if (o.refreshToken !== undefined && typeof o.refreshToken !== "string") return false;
  if (typeof o.expiresIn !== "number" || !Number.isFinite(o.expiresIn) || o.expiresIn <= 0) return false;
  // accessToken should look JWT-ish (three dot-separated segments). Cheap
  // sanity check; the server validates the signature.
  if (o.accessToken.split(".").length !== 3) return false;
  return true;
}

// Debug logger — only emits when debug flag is on
const DebugContext = React.createContext(false);
function useDebug() {
  const debug = React.useContext(DebugContext);
  return React.useMemo(() => ({
    log: debug ? (...args: unknown[]) => window.console.log("[AppKit]", ...args) : () => {},
    warn: debug ? (...args: unknown[]) => window.console.warn("[AppKit]", ...args) : () => {},
  }), [debug]);
}

function QRCodeImg({ data, size }: { data: string; size: number }) {
  const [src, setSrc] = React.useState<string | null>(null);
  React.useEffect(() => {
    let cancelled = false;
    QRCode.toDataURL(data, { width: size, margin: 1 }).then((url) => {
      if (!cancelled) setSrc(url);
    });
    return () => { cancelled = true; };
  }, [data, size]);
  if (!src) return null;
  return (
    <div style={{ padding: 16, background: "var(--ak-color-surface)", borderRadius: 8, border: "1px solid var(--ak-color-divider)" }}>
      <img src={src} alt="TOTP QR Code" width={size} height={size} />
    </div>
  );
}

// Default base URL when the host doesn't set one. The end-user UI is
// served by the ManyRows install itself, so the right answer is
// "wherever this bundle was loaded from" — same-origin.
function defaultBaseURL(): string {
  if (typeof window !== "undefined" && window.location?.origin) {
    return window.location.origin;
  }
  return "";
}
const DEFAULT_BASE_URL = defaultBaseURL();

// Module-scoped cache for the appBoot fetch. Multiple <AppKit>
// instances mounted on the same page (Astro islands, multi-mount
// React trees, etc.) hit the same boot endpoint redundantly otherwise.
// Cache the in-flight Promise so concurrent calls share one request,
// and keep the resolved value for a short TTL so a near-simultaneous
// mount also skips the network. Errors are not cached — bad responses
// drop out so a retry can succeed.
const APP_BOOT_TTL_MS = 30_000;

type BootCacheEntry = {
  promise: Promise<AppResource>;
  resolvedAt: number; // 0 while in flight; epoch ms once settled.
};

const appBootCache = new Map<string, BootCacheEntry>();

function getAppBoot(bootURL: string): Promise<AppResource> {
  const now = Date.now();
  const cached = appBootCache.get(bootURL);
  if (cached) {
    // Still fresh (or in flight): reuse it.
    if (cached.resolvedAt === 0 || now - cached.resolvedAt < APP_BOOT_TTL_MS) {
      return cached.promise;
    }
    appBootCache.delete(bootURL);
  }
  const entry: BootCacheEntry = {
    resolvedAt: 0,
    promise: axios
      .get<AppResource>(bootURL, { responseType: "json", withCredentials: false })
      .then((res) => {
        entry.resolvedAt = Date.now();
        return res.data;
      })
      .catch((err) => {
        // Don't cache failures — let the next caller retry.
        appBootCache.delete(bootURL);
        throw err;
      }),
  };
  appBootCache.set(bootURL, entry);
  return entry.promise;
}

// Module-scoped coalescer for short-lived per-request dedupe across
// <AppKit> mounts on the same page. Use cases: /auth/refresh and /me
// fired by N Astro islands at boot — without this, each island's
// auth state machine independently hits the network, leading to N
// requests instead of 1.
//
// Different from appBootCache (which has a 30s TTL): these promises
// clear as soon as they resolve. The point isn't to cache the
// response but to let the second-into-the-same-tick caller share
// the in-flight call.
const inFlight = new Map<string, Promise<any>>();

function coalesce<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const existing = inFlight.get(key) as Promise<T> | undefined;
  if (existing) return existing;
  const p = fn().finally(() => {
    // Clear once the call settles. Tiny micro-task delay keeps a
    // truly-back-to-back caller (within the same tick) attached.
    queueMicrotask(() => inFlight.delete(key));
  });
  inFlight.set(key, p);
  return p;
}

// Access tokens are short-lived, and without help the SDK only refreshes
// reactively (on a 401 it sees on its own /me etc. calls). Host apps that attach
// the bearer to their OWN requests can't lean on that, so the SDK also keeps the
// in-memory token fresh proactively: schedule a refresh shortly before expiry,
// and top the token up when the tab regains focus (timers are suspended while a
// tab is backgrounded or the machine sleeps). Both funnel through refreshOnce(),
// so they coalesce with reactive refreshes — never more than one /auth/refresh
// in flight.
const REFRESH_SKEW_MS = 60_000; // refresh this long before exp
const MIN_REFRESH_DELAY_MS = 1_000; // never schedule a 0ms/negative timer

// Decode a JWT's `exp` (ms since epoch) without verifying it — used only to
// schedule a proactive refresh. Returns null for a non-JWT / malformed token,
// in which case proactive scheduling is simply skipped.
function accessTokenExpMs(token: string): number | null {
  const payload = token.split(".")[1];
  if (!payload) return null;
  try {
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    const exp = (JSON.parse(json) as { exp?: unknown }).exp;
    return typeof exp === "number" ? exp * 1000 : null;
  } catch {
    return null;
  }
}

type AuthStatus = "checking" | "authenticated" | "unauthenticated";

// Tagged outcome of /auth/refresh — see doRefreshTokens. The
// "transient" tag is what protects the user's session from being
// torpedoed by a network blip (closed laptop, sleep, momentary
// connection loss).
type RefreshResult =
  | { kind: "ok"; token: string }
  | { kind: "auth_failed" }
  | { kind: "transient" };

export interface Account {
  id: string;
  email: string;
  name: string;
  metadata: Record<string, any>;
  appMetadata: Record<string, any>;
}

interface WorkspaceAccount {
  id: string;
  email: string;
  displayName: string;
  emailVerifiedAt?: string;
  passwordSetAt?: string;
  totpEnabled?: boolean;
  metadata: Record<string, any>;
  appMetadata: Record<string, any>;
}

// Combined identity response — workspace user + app-scoped claims in one call.
interface OrgMembership {
  id: string;
  name: string;
  slug: string;
  orgRole: string;
}

// Replaces the previous WorkspaceMeResponse + AppMeResponse pair.
interface AppMeResponse {
  user?: WorkspaceAccount;
  workspaceName: string;
  app: {
    name: string;
    hasAccess: boolean;
    roles: string[];
    permissions: string[];
    // Active org (null when none) + the user's org list. Both absent when
    // the app doesn't have organizations enabled.
    organization?: OrgMembership | null;
    organizations?: OrgMembership[];
  };
}

interface AppRuntimeResponse {
  featureFlags: any[];
  config: Array<{
    key: string;
    type: string;
    value?: any;
  }>;
}

// Server resource resolved via:
// GET /x/{workspaceSlug}/apps/{appId}
type AppResource = {
  id: string;
  name: string;
  workspaceSlug: string;
  workspaceName: string;
  allowRegistration: boolean;
  allowAccountDeletion?: boolean;
  allowEmailChange?: boolean;
  googleOAuthClientId?: string;
  primaryAuthMethod?: "password" | "code" | "none";
  appleEnabled?: boolean;
  microsoftEnabled?: boolean;
  githubEnabled?: boolean;
  kakaoEnabled?: boolean;
  naverEnabled?: boolean;
  externalIdps?: { slug: string; displayName: string; buttonIcon?: string }[];
  passkeyEnabled?: boolean;
  qrSignInEnabled?: boolean;
  hideBranding?: boolean;
  require2fa?: boolean;
  // Server-side selector for how the session token is delivered.
  // AppKit reads this on boot and configures fetch / storage behaviour
  // accordingly — no client-side prop. Operators toggle this under
  // Security → Sessions → Transport in the admin UI; the frontend
  // picks it up on the next page load.
  transportMode?: "local" | "bff" | "cookie";
};

interface AppData {
  account?: Account;
  workspaceSlug: string;
  workspaceName: string;

  hasAppAccess: boolean;
  roles: string[];
  permissions: string[];

  featureFlags?: any[];
  config?: Array<{ key: string; type: string; value?: any }>;
  organization?: OrgMembership | null;
  organizations?: OrgMembership[];
}

export type AppKitStateSnapshot = {
  status: AuthStatus;
  jwtToken: string | null;
  appData: AppData | null;

  workspaceBaseURL: string;
  appBaseURL: string;

  // resolved app mapping
  appId: string;
  app: AppResource | null;
};

type AppKitContextValue = AppKitStateSnapshot & {
  refresh: () => void;
  logout: () => Promise<void>;
  /**
   * An axios instance pre-wired for AppKit-authenticated calls.
   * - Adds `Authorization: Bearer <latest access token>` to every request,
   *   read from a ref so token rotations between awaits don't leave you
   *   holding a stale bearer (the classic "captured headers" bug).
   * - Routes through the global 401 interceptor so an expired token
   *   triggers a deduped refresh + retry transparently.
   *
   * Use this for any call against ManyRows that needs the access
   * token. Don't build `Authorization` headers yourself unless you
   * have a specific reason.
   */
  authedAxios: AxiosInstance;
};

const AppKitContext = React.createContext<AppKitContextValue | null>(null);

export function useManyRowsAppKit(): AppKitContextValue {
  const v = React.useContext(AppKitContext);
  if (!v) throw new Error("useManyRowsAppKit must be used under <AppKit/>");
  return v;
}

/** Convenience hook that returns just the authed axios instance. */
export function useAuthedAxios(): AxiosInstance {
  return useManyRowsAppKit().authedAxios;
}

interface AppKitProps {
  baseURL?: string;
  workspaceSlug: string;
  appId: string;
  theme?: AppKitThemeOptions;
  debug?: boolean;

  hostCallbacks?: {
    onAuthStatus?: (status: AuthStatus) => void;
    onJWT?: (jwt: string | null) => void;
    onLogin?: (jwt: string) => void;
    onLogout?: (reason: "manual" | "expired" | "cleared") => void;
  };

  renderAuthed?: (snapshot: AppKitStateSnapshot) => React.ReactNode;

  registerApi?: (api: {
    refresh: () => void;
    logout: () => Promise<void>;
    getSnapshot: () => AppKitStateSnapshot | null;
    showProfile: () => void;
    hideProfile: () => void;
  }) => void;

  onSnapshot?: (snap: AppKitStateSnapshot | null) => void;

  authHeader?: React.ReactNode;
  labels?: Partial<import("./Auth").AuthLabels>;
  initialScreen?: "login" | "register" | "forgot-password";
  onScreenChange?: (screen: "login" | "register" | "forgot-password") => void;

  // Prefill for the email field on the auth screens (e.g. an OIDC
  // login_hint). Initial value only — the user can edit it freely.
  loginHint?: string;

  // When true, Auth renders without its full-viewport wrapper so it flows
  // inline in the parent container. Default: false (centered full-page layout).
  embedded?: boolean;

  /**
   * When true, AppKit also fetches `/a/app/` on bootstrap to populate
   * `featureFlags` and `config` on the snapshot. Default: false. Apps
   * that don't read either field should leave this off — it saves a
   * round trip on every page load.
   */
  loadAppRuntime?: boolean;

  /**
   * When true, AppKit doesn't render its built-in Auth login UI on
   * unauthed pages. Auth state is still resolved (so the host can
   * react to `useAppKit().snapshot.status`); only the visual login
   * card is suppressed. Used by appkit-react when `publicAccess` is
   * on and the current path isn't one of the configured auth routes —
   * keeps the runtime from mounting the password / passkey forms on
   * a marketing or public content page, which would otherwise trigger
   * side effects like the conditional-mediation passkey prompt.
   */
  hideAuthUI?: boolean;
  /**
   * Suppress the "Sign in with phone" QR button on the login screen
   * even when the app has it enabled. Set by the QR /pair landing
   * page (the user is already on their phone approving a phone
   * sign-in — offering QR there is circular).
   */
  suppressQRSignIn?: boolean;
}

// =====================================
// Storage - Dual Token System
// =====================================

function tokenStorageKey(workspaceSlug: string, appId: string) {
  return `MR_TOKENS:${workspaceSlug}:${appId}`;
}

function legacyTokenStorageKey(workspaceSlug: string) {
  return `MR_TOKENS:${workspaceSlug}`;
}

interface StoredTokens {
  refreshToken: string;
}

function getStoredTokens(workspaceSlug: string, appId: string): StoredTokens | null {
  try {
    const raw = localStorage.getItem(tokenStorageKey(workspaceSlug, appId));
    if (!raw) {
      // One-time migration from legacy key (workspace-only) to app-scoped key
      const legacyRaw = localStorage.getItem(legacyTokenStorageKey(workspaceSlug));
      if (legacyRaw) {
        localStorage.setItem(tokenStorageKey(workspaceSlug, appId), legacyRaw);
        localStorage.removeItem(legacyTokenStorageKey(workspaceSlug));
        const parsed = JSON.parse(legacyRaw);
        if (parsed?.refreshToken && typeof parsed.refreshToken === "string") {
          return { refreshToken: parsed.refreshToken.trim() };
        }
      }
      return null;
    }
    const parsed = JSON.parse(raw);
    if (parsed?.refreshToken && typeof parsed.refreshToken === "string") {
      return { refreshToken: parsed.refreshToken.trim() };
    }
    return null;
  } catch {
    return null;
  }
}

function setStoredTokens(workspaceSlug: string, appId: string, tokens: StoredTokens | null) {
  try {
    const key = tokenStorageKey(workspaceSlug, appId);
    if (!tokens || !tokens.refreshToken) {
      localStorage.removeItem(key);
    } else {
      localStorage.setItem(key, JSON.stringify({ refreshToken: tokens.refreshToken }));
    }
  } catch {
    // ignore
  }
}

function clearTokenStorage(workspaceSlug: string, appId: string) {
  try {
    localStorage.removeItem(tokenStorageKey(workspaceSlug, appId));
  } catch {
    // ignore
  }
}

// =====================================
// HTTP helpers
// =====================================

function buildJwtRequestConf(jwtToken: string | null, cookieMode: boolean): AxiosRequestConfig {
  // Cookie mode: ManyRows-issued mr_at / mr_rt cookies travel back
  // to ManyRows directly (same-site only) → withCredentials: true.
  // Bearer-only Tier 1 keeps it false. The Authorization header
  // rides along when we have a JWT — useful in cookie mode too
  // because the server middleware accepts either one (cookie wins
  // on /refresh; Authorization is the fallback).
  const conf: AxiosRequestConfig = {
    responseType: "json",
    withCredentials: cookieMode,
  };

  if (jwtToken) {
    conf.headers = {
      ...(conf.headers || {}),
      Authorization: `Bearer ${jwtToken}`,
    };
  }

  return conf;
}

function joinURL(a: string, b: string) {
  const aa = (a || "").replace(/\/+$/, "");
  const bb = (b || "").replace(/^\/+/, "");
  return `${aa}/${bb}`;
}

function norm(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

// =====================================
// TOTP Setup Gate
// =====================================

// InviteErrorHandler runs once on mount (inside ToastProvider) to detect and
// surface a #mr_invite_error=<code> fragment that the server appends when
// an org-invite acceptance fails. It surgically removes only the
// mr_invite_error pair from the hash, leaving any other fragment params
// (e.g. session tokens) untouched. In practice an invite-error fragment
// never coexists with token fragments, but the strip is safe regardless.
function InviteErrorHandler() {
  const { showError } = useToast();
  React.useEffect(() => {
    const { code, rest } = extractInviteError(window.location.hash);
    if (!code) return;
    showError(inviteErrorMessage(code));
    window.history.replaceState(
      null,
      "",
      window.location.pathname + window.location.search + rest
    );
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  return null;
}

type TOTPSetupStep = "intro" | "scan" | "verify" | "backup" | "done";

function TOTPSetupGate({
  workspaceBaseURL,
  jwtToken,
  userEmail,
  primaryAuthMethod,
  onComplete,
  onLogout,
}: {
  workspaceBaseURL: string;
  jwtToken: string | null;
  userEmail: string | undefined;
  primaryAuthMethod: "password" | "code" | "none" | undefined;
  onComplete: () => void;
  onLogout: () => Promise<void>;
}) {
  const [step, setStep] = React.useState<TOTPSetupStep>("intro");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [totpUri, setTotpUri] = React.useState("");
  const [backupCodes, setBackupCodes] = React.useState<string[]>([]);
  const [verifyCode, setVerifyCode] = React.useState("");
  const [loggingOut, setLoggingOut] = React.useState(false);
  // hasPassword fetched on mount so the gate offers the password path
  // when viable. Default false (email-OTP only) is the safe fallback —
  // worst case is an extra round-trip for password users; the
  // alternative would be locking out OAuth-only users entirely.
  const [hasPassword, setHasPassword] = React.useState(false);

  const authHeaders = React.useMemo(
    () => ({
      headers: { Authorization: `Bearer ${jwtToken}` },
      withCredentials: false as const,
      responseType: "json" as const,
    }),
    [jwtToken]
  );

  React.useEffect(() => {
    let cancelled = false;
    axios.get(`${workspaceBaseURL}/a/me`, authHeaders)
      .then((res) => { if (!cancelled) setHasPassword(!!res.data?.hasPassword); })
      .catch(() => { /* keep default false on fetch failure */ });
    return () => { cancelled = true; };
  }, [workspaceBaseURL, authHeaders]);

  // Re-auth gate for /a/totp/setup. Backend (PR #3) requires
  // { password } or { code } so a stolen access token alone can't
  // bind an attacker-controlled authenticator before the user
  // notices. This UI fires right after login, so the user is
  // typically fresh and the friction is minimal.
  const setupGate = useReauthGate({
    primaryAuthMethod,
    hasPassword,
    userEmail,
    workspaceBaseUrl: workspaceBaseURL,
    axios,
    axiosConfig: authHeaders,
    setError,
  });

  const startSetup = async () => {
    const body = setupGate.body();
    if (!body) {
      setError(setupGate.usePasswordPath ? "Password is required to start setup" : "Enter the 6-digit code from your email");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await axios.post(`${workspaceBaseURL}/a/totp/setup`, body, authHeaders);
      setTotpUri(res.data.uri);
      setStep("scan");
      setupGate.reset();
    } catch (err: any) {
      const d = err.response?.data;
      setError(typeof d === "string" ? d : "Failed to start TOTP setup");
    } finally {
      setLoading(false);
    }
  };

  const verifyAndEnable = async () => {
    const trimmed = verifyCode.trim();
    if (!trimmed) return;
    setLoading(true);
    setError(null);
    try {
      const res = await axios.post(`${workspaceBaseURL}/a/totp/enable`, { code: trimmed }, authHeaders);
      setBackupCodes(res.data.backupCodes || []);
      setStep("backup");
    } catch (err: any) {
      const d = err.response?.data;
      setError(typeof d === "string" ? d : "Invalid code. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    setLoggingOut(true);
    try {
      await onLogout();
    } finally {
      setLoggingOut(false);
    }
  };

  const totpSecret = React.useMemo(() => {
    try {
      const url = new URL(totpUri);
      return url.searchParams.get("secret") || "";
    } catch {
      return "";
    }
  }, [totpUri]);

  return (
    <div style={{
      minHeight: "100vh",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      background: "var(--ak-color-bg)",
      padding: 16,
    }}>
      <div className="ak-card" style={{ maxWidth: 440, width: "100%" }}>
        <div className="ak-card-content" style={{ padding: 24 }}>
          <div className="ak-stack ak-gap-6 ak-items-center">
            <Icon name="shield" size={48} style={{ color: "var(--ak-color-primary)" }} />

            {step === "intro" && (
              <>
                <h2 className="ak-h6 ak-text-center" style={{ fontWeight: 600 }}>
                  Two-factor authentication required
                </h2>
                <p className="ak-body2 ak-text-secondary ak-text-center">
                  Two-factor authentication is required for this app. Verify your
                  identity below to start setup.
                </p>
                <div className="ak-field ak-w-full">
                  <ReauthGateFields
                    gate={setupGate}
                    loading={loading}
                    userEmail={userEmail}
                    inputClassName="ak-field-input"
                    buttonClassName="ak-btn ak-btn-outlined ak-btn-full"
                    Spinner={Spinner}
                  />
                </div>
                {error && (
                  <div className="ak-alert ak-alert-error ak-w-full" role="alert">
                    <span className="ak-alert-content">{error}</span>
                  </div>
                )}
                <button
                  className="ak-btn ak-btn-contained ak-btn-full"
                  onClick={startSetup}
                  disabled={loading || !setupGate.ready}
                >
                  {loading && <Spinner size={16} white />}
                  {loading ? "Setting up…" : "Continue"}
                </button>
                <button
                  className="ak-btn ak-btn-text ak-btn-sm"
                  onClick={handleLogout}
                  disabled={loggingOut}
                >
                  {loggingOut ? "Logging out…" : "Log out"}
                </button>
              </>
            )}

            {step === "scan" && (
              <>
                <h2 className="ak-h6 ak-text-center" style={{ fontWeight: 600 }}>
                  Scan QR code
                </h2>
                <p className="ak-body2 ak-text-secondary ak-text-center">
                  Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)
                </p>
                {totpUri && <QRCodeImg data={totpUri} size={200} />}
                {totpSecret && (
                  <div className="ak-w-full">
                    <span className="ak-caption ak-text-secondary ak-font-bold">
                      Manual entry key
                    </span>
                    <div className="ak-code-block">
                      {totpSecret}
                    </div>
                  </div>
                )}
                <button className="ak-btn ak-btn-contained ak-btn-full" onClick={() => setStep("verify")}>
                  Next
                </button>
              </>
            )}

            {step === "verify" && (
              <>
                <h2 className="ak-h6 ak-text-center" style={{ fontWeight: 600 }}>
                  Verify setup
                </h2>
                <p className="ak-body2 ak-text-secondary ak-text-center">
                  Enter the 6-digit code from your authenticator app to confirm setup.
                </p>
                {error && (
                  <div className="ak-alert ak-alert-error ak-w-full" role="alert">
                    <span className="ak-alert-content">{error}</span>
                  </div>
                )}
                <div className="ak-field ak-w-full">
                  <label className="ak-field-label">Verification code</label>
                  <input
                    className="ak-field-input"
                    value={verifyCode}
                    onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    onKeyDown={(e) => { if (e.key === "Enter") verifyAndEnable(); }}
                    placeholder="000000"
                    autoFocus
                    maxLength={6}
                    inputMode="numeric"
                    style={{ letterSpacing: "0.5em", textAlign: "center", fontSize: 20 }}
                  />
                </div>
                <button
                  className="ak-btn ak-btn-contained ak-btn-full"
                  onClick={verifyAndEnable}
                  disabled={loading || verifyCode.trim().length < 6}
                >
                  {loading && <Spinner size={16} white />}
                  {loading ? "Verifying…" : "Verify and enable"}
                </button>
                <button className="ak-btn ak-btn-text ak-btn-sm" onClick={() => { setStep("scan"); setError(null); }}>
                  Back
                </button>
              </>
            )}

            {step === "backup" && (
              <>
                <h2 className="ak-h6 ak-text-center" style={{ fontWeight: 600 }}>
                  Save backup codes
                </h2>
                <p className="ak-body2 ak-text-secondary ak-text-center">
                  Save these backup codes in a safe place. Each code can only be used once if you
                  lose access to your authenticator app.
                </p>
                <div className="ak-code-block ak-w-full" style={{ padding: 16, fontSize: 14 }}>
                  {backupCodes.map((code) => (
                    <div key={code}>{code}</div>
                  ))}
                </div>
                <button className="ak-btn ak-btn-contained ak-btn-full" onClick={onComplete}>
                  I've saved my backup codes
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// =====================================
// Error Boundary
// =====================================

class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; error: Error | null }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: 24, textAlign: "center" }}>
          <h2 className="ak-h6" style={{ fontWeight: 600, marginBottom: 8 }}>
            Something went wrong
          </h2>
          <p className="ak-body2 ak-text-secondary" style={{ marginBottom: 16 }}>
            {this.state.error?.message || "An unexpected error occurred."}
          </p>
          <button
            className="ak-btn ak-btn-outlined ak-btn-sm"
            onClick={() => this.setState({ hasError: false, error: null })}
          >
            Try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

// =====================================
// Component
// =====================================

export default function AppKit(props: AppKitProps) {
  const debug = !!props.debug;
  const log = useDebug();
  const appId = React.useMemo(() => norm(props.appId), [props.appId]);

  // ✅ Theme - detect system dark mode for "auto" colorMode
  const [systemDark, setSystemDark] = React.useState(() =>
    typeof window !== "undefined" && window.matchMedia?.("(prefers-color-scheme: dark)").matches
  );
  React.useEffect(() => {
    const mql = window.matchMedia?.("(prefers-color-scheme: dark)");
    if (!mql) return;
    const handler = (e: MediaQueryListEvent) => setSystemDark(e.matches);
    mql.addEventListener("change", handler);
    return () => mql.removeEventListener("change", handler);
  }, []);

  const theme = React.useMemo(() => resolveTheme(props.theme, systemDark), [props.theme, systemDark]);

  // ✅ baseURL optional w/ default
  const resolvedBaseURL = React.useMemo(() => {
    const b = norm(props.baseURL);
    return b || DEFAULT_BASE_URL;
  }, [props.baseURL]);

  const [app, setApp] = React.useState<AppResource | null>(null);

  // Transport mode collapses to two paths:
  //   transportMode === "cookie" → cookieMode=true. HttpOnly mr_at/mr_rt
  //                                cookies carry the session; JS never
  //                                touches the tokens.
  //   transportMode === "local"  → cookieMode=false. Bearer JWT in
  //                                localStorage, refresh token in
  //                                memory. Used for cross-origin SPAs.
  //
  // The legacy "bff" mode (customer proxies AppKit through their own
  // backend) is no longer supported on the SDK side — cookie mode
  // provides the same security guarantees (HttpOnly tokens) without
  // requiring the customer to run a proxy. A server returning
  // transportMode="bff" will be treated as cookie mode here.
  const transport = app?.transportMode ?? "local";
  const cookieMode = transport === "cookie" || transport === "bff";

  // Direct ManyRows base used for the boot fetch and for all auth/data calls.
  const directWorkspaceBaseURL = React.useMemo(() => {
    const base = norm(resolvedBaseURL);
    const ws = norm(props.workspaceSlug);
    return joinURL(base, `x/${ws}`);
  }, [resolvedBaseURL, props.workspaceSlug]);

  // Boot URL — public, no auth, used to discover the app's transport
  // mode and OAuth provider config.
  const bootURL = React.useMemo(() => {
    if (!norm(props.appId)) return directWorkspaceBaseURL;
    return `${directWorkspaceBaseURL}/apps/${encodeURIComponent(norm(props.appId))}`;
  }, [directWorkspaceBaseURL, props.appId]);

  const workspaceBaseURL = directWorkspaceBaseURL;

  const appBaseURL = React.useMemo(() => {
    if (!norm(props.appId)) return workspaceBaseURL;
    return `${workspaceBaseURL}/apps/${encodeURIComponent(norm(props.appId))}`;
  }, [workspaceBaseURL, props.appId]);

  const [appResolveError, setAppResolveError] = React.useState<string | null>(null);

  const [appData, setAppData] = React.useState<AppData | null>(null);
  const [authStatus, setAuthStatus] = React.useState<AuthStatus>("checking");
  const [loggingOut, setLoggingOut] = React.useState(false);
  const loggingOutRef = React.useRef(false);

  const [totpSetupNeeded, setTotpSetupNeeded] = React.useState(false);
  const [profileOpen, setProfileOpen] = React.useState(false);

  const [accessToken, _setAccessToken] = React.useState<string | null>(null);
  const [hadStoredToken] = React.useState(() => !!getStoredTokens(props.workspaceSlug, appId));
  const [refreshToken, setRefreshToken] = React.useState<string | null>(() => {
    const stored = getStoredTokens(props.workspaceSlug, appId);
    return stored?.refreshToken ?? null;
  });

  // In-flight refresh promise. When N concurrent calls 401 at once
  // (real production scenario: page reload after idle, multiple data
  // calls fly out simultaneously, all see the expired access token),
  // we want exactly ONE /auth/refresh round trip — not N. This ref
  // holds the live promise; the interceptor below awaits it.
  // Resolves to the new access token on success, null on failure.
  const refreshInFlightRef = React.useRef<Promise<RefreshResult> | null>(null);

  // Cross-instance auth sync. Each Astro island (or anywhere multiple
  // <AppKit> roots live in the same page) boots its own React state. When
  // one instance handles a login, refresh, or logout, the others have no
  // way to find out: the storage event doesn't fire on the originating
  // window, and there's no shared React context across roots.
  //
  // BroadcastChannel solves both same-tab cross-island and cross-tab sync
  // in one mechanism. Each instance opens a channel keyed by
  // (workspaceSlug, appId). Token-pair changes and logouts post a message;
  // peers apply the same state change with broadcast=false to avoid loops.
  // BroadcastChannel doesn't deliver messages back to the sender, so the
  // loop guard is belt-and-suspenders.
  const channelKey = React.useMemo(
    () => `manyrows:auth:${props.workspaceSlug}:${appId || "_"}`,
    [props.workspaceSlug, appId]
  );
  const channelRef = React.useRef<BroadcastChannel | null>(null);

  const jwtToken = accessToken;

  const latestSnapshotRef = React.useRef<AppKitStateSnapshot | null>(null);

  const fetchInProgress = React.useRef(false);

  const emitAuthStatus = React.useCallback(
    (s: AuthStatus) => {
      try { props.hostCallbacks?.onAuthStatus?.(s); } catch {}
    },
    [props.hostCallbacks]
  );

  const emitJWT = React.useCallback(
    (t: string | null) => {
      try { props.hostCallbacks?.onJWT?.(t); } catch {}
    },
    [props.hostCallbacks]
  );

  const buildSnapshot = React.useCallback(
    (status: AuthStatus, data: AppData | null, token: string | null): AppKitStateSnapshot => ({
      status,
      jwtToken: token,
      appData: data,
      workspaceBaseURL,
      appBaseURL,
      appId,
      app,
    }),
    [workspaceBaseURL, appBaseURL, appId, app]
  );

  const pushSnapshot = React.useCallback(
    (status: AuthStatus, data: AppData | null, token: string | null) => {
      const snap = buildSnapshot(status, data, token);
      latestSnapshotRef.current = snap;
      try { props.onSnapshot?.(snap); } catch {}
      return snap;
    },
    [buildSnapshot, props]
  );

  // Refresh outcome — see RefreshResult type above.
  //   "ok"          → use new bearer for retries
  //   "auth_failed" → server explicitly rejected (401/403). Session
  //                   genuinely dead. Clear tokens.
  //   "transient"   → network error, timeout, 5xx, CORS, DNS, no
  //                   refresh token. Session may still be valid; we
  //                   just couldn't reach the server. Reject the
  //                   current request only; DO NOT clear tokens
  //                   (would log the user out for a network blip).
  const doRefreshTokens = React.useCallback(async (): Promise<RefreshResult> => {
    if (loggingOutRef.current) {
      log.warn(`doRefreshTokens skipped: loggingOut=true`);
      return { kind: "transient" };
    }
    // Bearer mode: no token in React state ⇒ nothing to refresh.
    // Cookie mode: the refresh token is HttpOnly so JS never sees it;
    // we attempt /refresh blindly and the server 401s if no cookie.
    if (!refreshToken && !cookieMode) {
      log.warn(`doRefreshTokens skipped: no refresh token`);
      return { kind: "auth_failed" };
    }

    log.log("doRefreshTokens starting");
    try {
      const url = `${appBaseURL}/auth/refresh`;
      // Cookie mode: server reads mr_rt from the cookie, body can
      // be empty. Bearer mode: refreshToken in body, no cookies.
      const body = cookieMode ? {} : { refreshToken };
      const conf = await withDPoPHeader("POST", url, {
        withCredentials: cookieMode,
        responseType: "json" as const,
      }, { cookieMode });
      // Coalesce concurrent /auth/refresh across islands. Cookie mode:
      // all islands send the same cookie, so the URL alone is the key.
      // Bearer mode: include the refresh token so two sessions in the
      // same page (different tokens) don't collapse into one result.
      const cacheKey = cookieMode ? `refresh:${url}` : `refresh:${url}:${refreshToken}`;
      const res = await coalesce(cacheKey, () =>
        axios.post<{
          accessToken: string;
          refreshToken?: string;
          expiresAt: string;
          expiresIn: number;
        }>(url, body, conf),
      );

      const data = res.data;
      if (!data?.accessToken) return { kind: "transient" };
      // Server returns refreshToken in the body even in cookie mode
      // (for back-compat with bearer clients). In cookie mode we
      // ignore it — the browser already updated mr_rt from Set-Cookie.
      if (!cookieMode && !data.refreshToken) return { kind: "transient" };

      if (loggingOutRef.current) return { kind: "transient" };

      _setAccessToken(data.accessToken);
      if (!cookieMode) {
        setRefreshToken(data.refreshToken!);
        setStoredTokens(props.workspaceSlug, appId, { refreshToken: data.refreshToken! });
      }

      emitJWT(data.accessToken);

      // Tell sibling tabs about the rotated tokens so they don't keep
      // calling with the just-invalidated refresh-token family.
      try {
        channelRef.current?.postMessage({
          type: "tokens",
          tokens: {
            accessToken: data.accessToken,
            refreshToken: data.refreshToken,
            expiresIn: data.expiresIn,
            expiresAt: data.expiresAt,
          },
          keepSignedIn: true,
        });
      } catch {}

      return { kind: "ok", token: data.accessToken };
    } catch (err: any) {
      const status = err?.response?.status;
      log.warn(`doRefreshTokens failed: status=${status}`, err?.message);
      // Server explicitly invalidated the session: refresh token
      // expired, revoked, or rotated by a sibling tab. Logout is
      // the right outcome.
      //
      // No response at all (network down, browser sleep, CORS, DNS
      // fail) or a 5xx: the session might still be perfectly valid;
      // we just can't reach the server. Do NOT log the user out for
      // a transient connectivity blip — closing the laptop lid and
      // waking up offline shouldn't sign you out.
      if (status === 401 || status === 403) return { kind: "auth_failed" };
      return { kind: "transient" };
    }
  }, [refreshToken, appBaseURL, cookieMode, props.workspaceSlug, appId, emitJWT]);

  // refreshOnce dedupes concurrent /auth/refresh round trips. Five
  // calls that all 401 at once trigger one refresh promise that they
  // all await — not five. Returns the tagged RefreshResult so the
  // 401 interceptor can distinguish "session genuinely dead, log
  // out" from "transient blip, just reject and don't touch state".
  const refreshOnce = React.useCallback((): Promise<RefreshResult> => {
    if (refreshInFlightRef.current) return refreshInFlightRef.current;
    const p = doRefreshTokens().finally(() => {
      refreshInFlightRef.current = null;
    });
    refreshInFlightRef.current = p;
    return p;
  }, [doRefreshTokens]);

  // Proactive refresh: schedule a refresh shortly before the access token
  // expires so it never goes stale mid-session. Reschedules whenever the token
  // changes (each refresh mints a new exp). refreshOnce() dedupes, so this can't
  // race the reactive 401 path into a double /auth/refresh.
  React.useEffect(() => {
    if (!accessToken) return;
    const expMs = accessTokenExpMs(accessToken);
    if (expMs == null) return;
    const delay = Math.max(
      expMs - Date.now() - REFRESH_SKEW_MS,
      MIN_REFRESH_DELAY_MS
    );
    const timer = setTimeout(() => {
      void refreshOnce();
    }, delay);
    return () => clearTimeout(timer);
  }, [accessToken, refreshOnce]);

  // The proactive timer above is suspended while the tab is backgrounded or the
  // machine sleeps, so a token can expire while the user is away. Top it up when
  // the tab regains focus, before the host app's next request goes out.
  React.useEffect(() => {
    if (!accessToken) return;
    const refreshIfStale = () => {
      const expMs = accessTokenExpMs(accessToken);
      if (expMs != null && expMs - Date.now() <= REFRESH_SKEW_MS) {
        void refreshOnce();
      }
    };
    const onVisible = () => {
      if (document.visibilityState === "visible") refreshIfStale();
    };
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("focus", refreshIfStale);
    return () => {
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("focus", refreshIfStale);
    };
  }, [accessToken, refreshOnce]);

  const clearTokensSilently = React.useCallback(
    (reason: "expired" | "cleared", broadcast: boolean = true) => {
      _setAccessToken(null);

      setRefreshToken(null);
      clearTokenStorage(props.workspaceSlug, appId);
      emitJWT(null);

      try { props.hostCallbacks?.onLogout?.(reason); } catch {}

      setAppData(null);
      setAuthStatus("unauthenticated");
      emitAuthStatus("unauthenticated");
      pushSnapshot("unauthenticated", null, null);

      if (broadcast) {
        try { channelRef.current?.postMessage({ type: "logout", reason }); } catch {}
      }
    },
    [props.workspaceSlug, appId, emitJWT, props.hostCallbacks, emitAuthStatus, pushSnapshot]
  );

  const handleTokenPair = React.useCallback(
    (tokens: TokenPairResponse, keepSignedIn: boolean = true, broadcast: boolean = true) => {
      _setAccessToken(tokens.accessToken);
      emitJWT(tokens.accessToken);
      try { props.hostCallbacks?.onLogin?.(tokens.accessToken); } catch {}

      // Refresh-token persistence is bearer-mode only. In cookie mode
      // the server's HttpOnly mr_rt cookie IS the refresh credential;
      // the body's refreshToken is back-compat noise we deliberately
      // drop on the floor. Writing it to localStorage would defeat
      // the whole point of switching to cookies.
      if (!cookieMode) {
        setRefreshToken(tokens.refreshToken);
        if (keepSignedIn) {
          setStoredTokens(props.workspaceSlug, appId, { refreshToken: tokens.refreshToken });
        } else {
          clearTokenStorage(props.workspaceSlug, appId);
        }
      } else {
        // Defensive: if a previous session left tokens in localStorage
        // (e.g. operator just flipped transportMode from local→cookie),
        // wipe them so the next refresh doesn't accidentally fall back
        // to bearer-mode body and bypass the cookie path.
        clearTokenStorage(props.workspaceSlug, appId);
      }

      if (tokens.totpSetupRequired) {
        setTotpSetupNeeded(true);
      }

      setAppData(null);
      setAuthStatus("checking");
      emitAuthStatus("checking");
      pushSnapshot("checking", null, tokens.accessToken);

      if (broadcast) {
        try { channelRef.current?.postMessage({ type: "tokens", tokens, keepSignedIn }); } catch {}
      }
    },
    [props.workspaceSlug, appId, emitJWT, props.hostCallbacks, emitAuthStatus, pushSnapshot, cookieMode]
  );

  const requestConf = React.useMemo(
    () => buildJwtRequestConf(accessToken, cookieMode),
    [accessToken, cookieMode],
  );

  // ---------------------
  // API calls
  // ---------------------

  const getAppResource = React.useCallback(async (): Promise<AppResource> => {
    // The boot fetch is the public app config used to discover the
    // transport mode (cookie vs local), OAuth provider client ids,
    // password policy, etc. Fully public — no cookies, no auth — so
    // a standard CORS GET works as long as the customer added their
    // origin to the app's CORS allowlist.
    //
    // Deduped per bootURL: multiple <AppKit> mounts on the same page
    // (typical Astro-island setup, where each island gets its own
    // provider) would otherwise each fire the same GET. Cache the
    // in-flight Promise so concurrent first-paints share one
    // request, and cache the resolved value briefly so a second
    // mount appearing seconds later skips the round-trip too.
    return getAppBoot(bootURL);
  }, [bootURL]);

  const getAppMe = React.useCallback(
    async (): Promise<AppMeResponse> => {
      const url = `${appBaseURL}/a/me`;
      // Same coalescer as /refresh — concurrent islands share one
      // /me round trip. Key includes the bearer so two different
      // sessions on the same page don't collapse into one identity.
      const bearer = jwtTokenRef.current ?? "";
      const res = await coalesce(`me:${url}:${bearer}`, () =>
        axios.get<AppMeResponse>(url, requestConf),
      );
      return res.data;
    },
    [appBaseURL, requestConf]
  );

  const getAppRuntime = React.useCallback(
    async (): Promise<AppRuntimeResponse> => {
      const url = `${appBaseURL}/a/runtime`;
      const res = await axios.get<AppRuntimeResponse>(url, requestConf);
      return res.data;
    },
    [appBaseURL, requestConf]
  );

  // ---------------------
  // Resolve appId -> project/env
  // ---------------------

  const resolveApp = React.useCallback(async () => {
    setAppResolveError(null);

    if (!appId) {
      setApp(null);
      setAppResolveError("Missing appId.");
      return null;
    }

    try {
      const a = await getAppResource();

      if (norm(a.workspaceSlug) && norm(a.workspaceSlug) !== norm(props.workspaceSlug)) {
        setApp(null);
        setAppResolveError(
          `App belongs to workspace "${a.workspaceSlug}", but AppKit is mounted for "${props.workspaceSlug}".`
        );
        return null;
      }

      setApp(a);
      return a;
    } catch (err: any) {
      const status = err?.response?.status;
      if (status === 404) {
        setApp(null);
        setAppResolveError(`App not found for appId="${appId}".`);
        return null;
      }
      setApp(null);
      setAppResolveError("Failed to resolve appId. Please check that CORS is configured correctly for your domain.");
      return null;
    }
  }, [appId, getAppResource, props.workspaceSlug]);

  // ---------------------
  // Auth / app builder
  // ---------------------

  // Read-only refs so fetchAppData can branch on current state
  // without listing them in deps and getting recreated on every
  // appData/authStatus change (which would re-fire effects that
  // depend on it and cause loops).
  const authStatusRef = React.useRef(authStatus);
  const appDataRef = React.useRef(appData);
  React.useEffect(() => {
    authStatusRef.current = authStatus;
    appDataRef.current = appData;
  });

  const fetchAppData = React.useCallback(() => {
    if (!appId) {
      setAppData(null);
      setAuthStatus("unauthenticated");
      emitAuthStatus("unauthenticated");
      pushSnapshot("unauthenticated", null, jwtToken);
      fetchInProgress.current = false;
      return;
    }

    const ensureApp = app ? Promise.resolve(app) : resolveApp().then((a) => a);

    // Only flip to "checking" on cold boot. On a re-fetch (token
    // rotated, manual refresh, sibling component remount) we already
    // have appData and "authenticated" status — going back to
    // "checking" tears every consumer down to its skeleton state for
    // the duration of the round trip, which manifests as the
    // user being kicked back to the public-page view while clicking
    // around a logged-in session.
    if (authStatusRef.current === "checking" || !appDataRef.current) {
      setAuthStatus("checking");
      emitAuthStatus("checking");
      pushSnapshot("checking", null, jwtToken);
    }

    ensureApp
      .then((resolved) => {
        if (!resolved) {
          setAppData(null);
          setAuthStatus("unauthenticated");
          emitAuthStatus("unauthenticated");
          pushSnapshot("unauthenticated", null, jwtToken);
          return null;
        }

        // Read transport off the just-resolved app, NOT the outer
        // closure. The first invocation of fetchAppData captures
        // cookieMode at memoization time when `app` may still be null
        // (transport defaults to "local"). The resolveApp() promise
        // then settles inside .then() with the real app config, but
        // the closure keeps the stale mode — which would mis-classify
        // a cookie-mode boot as local and skip /a/me on cold load.
        const resolvedTransport = resolved.transportMode ?? "local";
        const isCookieMode = resolvedTransport === "cookie" || resolvedTransport === "bff";

        // Local (Bearer) mode: no JWT in memory means known-unauth.
        // Skip /a/me (would just 401) and render login.
        //
        // Cookie mode: the JWT only lives in memory until the page
        // reloads; the mr_at/mr_rt HttpOnly cookies are the durable
        // credential. On a cold load there's no jwtToken yet but the
        // cookies are valid; the server reads them and returns the
        // user. A 401 here (cookie expired/cleared) drops to the same
        // path as a bearer 401 → unauthenticated UI.
        if (!isCookieMode && !jwtToken) {
          setAppData(null);
          setAuthStatus("unauthenticated");
          emitAuthStatus("unauthenticated");
          pushSnapshot("unauthenticated", null, null);
          return null;
        }

        // Build the /a/me request config inline from the resolved
        // transport mode, NOT from `requestConf` in the outer closure.
        // requestConf was memoized when fetchAppData was created and
        // may still reflect transport=local (withCredentials: false)
        // because the first invocation of this callback runs before
        // the boot response has populated `app`. Going off `resolved`
        // here guarantees withCredentials is correct on the very first
        // /a/me — without it, a cookie-mode session 401s on cold load
        // because the browser strips the request's cookies (CORS rule:
        // no credentials allowed without withCredentials: true).
        const meHeaders: Record<string, string> = {};
        const tok = jwtTokenRef.current ?? "";
        if (tok) meHeaders.Authorization = `Bearer ${tok}`;
        const meConf = {
          headers: meHeaders,
          withCredentials: isCookieMode,
          responseType: "json" as const,
        };
        const meURL = `${appBaseURL}/a/me`;
        return coalesce(`me:${meURL}:${tok}`, () =>
          axios.get<AppMeResponse>(meURL, meConf),
        )
          .then((res) => res.data)
          .then((me) => {
            const acct = me.user;
            const needsSetup = !!(resolved.require2fa && acct && !acct.totpEnabled);

            const base: AppData = {
              account: acct ? {
                id: acct.id || "",
                email: acct.email,
                name: acct.displayName || acct.email || "",
                metadata: acct.metadata || {},
                appMetadata: acct.appMetadata || {},
              } : { id: "", email: "", name: "", metadata: {}, appMetadata: {} },
              workspaceSlug: props.workspaceSlug,
              workspaceName: me.workspaceName,
              hasAppAccess: !!me.app?.hasAccess,
              roles: me.app?.roles || [],
              permissions: me.app?.permissions || [],
              // Pass org context through to the snapshot for appkit-react's
              // org hooks. organizations stays undefined when the feature is
              // off (key omitted by the server) and is [] when enabled with
              // no memberships — preserving that distinction.
              organization: me.app?.organization ?? null,
              organizations: me.app?.organizations,
            };

            // /a/app/ (feature flags + config) is opt-in via `loadAppRuntime`.
            // Most apps don't use either — skip the round trip by default.
            if (!props.loadAppRuntime) {
              return Promise.resolve({ data: base, needsSetup });
            }

            return getAppRuntime()
              .then((rt) => {
                const next: AppData = {
                  ...base,
                  featureFlags: rt.featureFlags || [],
                  config: rt.config || [],
                };
                return { data: next, needsSetup };
              })
              .catch(() => ({
                data: { ...base, featureFlags: [], config: [] },
                needsSetup,
              }));
          })
          .then((result) => {
            if (!result || !result.data) return;

            setTotpSetupNeeded(result.needsSetup);
            setAppData(result.data);
            setAuthStatus("authenticated");

            if (result.needsSetup) {
              emitAuthStatus("checking");
              pushSnapshot("checking", null, jwtToken);
            } else {
              emitAuthStatus("authenticated");
              pushSnapshot("authenticated", result.data, jwtToken);
            }
          });
      })
      .catch((err) => {
        const status = err?.response?.status;
        log.warn(`fetchAppData failed: status=${status} hasToken=${!!jwtToken}`, err?.message);

        // 401 handling lives in the response interceptor (see
        // buildOnRejected): it does ONE refresh + retry, and on
        // refresh failure it calls clearTokensSilently("expired")
        // itself before re-rejecting. By the time a 401 bubbles up
        // here, one of two things is true:
        //
        //   1. The interceptor already cleared tokens (refresh failed
        //      OR retry-after-refresh also 401'd). authStatus is
        //      already "unauthenticated"; we have nothing to do.
        //   2. We have a sibling /a/me call that 401'd in parallel
        //      (Profile dialog, FavouritesProvider, SetupsProvider
        //      all hit /a/me on mount) and the interceptor retried
        //      one of them but a different one carries the rejected
        //      promise through here.
        //
        // The pre-fix code clear-tokens'd unconditionally on (1) and
        // also tore down auth state on (2), which made every visible
        // consumer remount with appData=null — the user gets bounced
        // back to the public-page state mid-session. Skipping the
        // re-clear here keeps the in-memory session intact when the
        // interceptor recovered, and lets the interceptor remain
        // the single source of truth for "tokens are gone."
        //
        // Cold-load case (jwtToken empty + cookie-mode cookies are
        // expired/missing): the interceptor's refresh attempt will
        // fail and it'll call clearTokensSilently for us; we just
        // need to make sure we don't STAY in "checking" forever, so
        // settle to unauthenticated only when authStatus is still
        // "checking" (i.e. the boot has never resolved).
        if (status === 401) {
          if (!jwtToken && authStatusRef.current === "checking") {
            setAppData(null);
            setAuthStatus("unauthenticated");
            emitAuthStatus("unauthenticated");
            pushSnapshot("unauthenticated", null, null);
          }
          return;
        }

        // Non-401 error during the initial boot: settle to
        // unauthenticated. After boot we have appData populated and
        // a network blip shouldn't bounce the user out — keep the
        // last-known-good state and let the next fetch retry.
        if (authStatusRef.current === "checking") {
          log.warn("fetchAppData non-401 error during boot — setting unauthenticated");
          setAppData(null);
          setAuthStatus("unauthenticated");
          emitAuthStatus("unauthenticated");
          pushSnapshot("unauthenticated", null, jwtToken);
        } else {
          log.warn("fetchAppData non-401 error post-boot — keeping current auth state");
        }
      })
      .finally(() => {
        fetchInProgress.current = false;
      });
  }, [
    appId,
    app,
    resolveApp,
    emitAuthStatus,
    getAppMe,
    getAppRuntime,
    jwtToken,
    props.workspaceSlug,
    props.loadAppRuntime,
    pushSnapshot,
    clearTokensSilently,
  ]);

  const logout = React.useCallback(async () => {
    if (loggingOut) return;

    setLoggingOut(true);
    loggingOutRef.current = true;

    try {
      // Hit ManyRows /a/logout with whatever credential we have —
      // bearer + cookies. Server clears mr_at / mr_rt and revokes
      // the session. Best-effort: a network failure here still
      // clears local state below.
      await axios.post(`${appBaseURL}/a/logout`, {}, requestConf);
    } catch {
      // ignore
    } finally {
      setLoggingOut(false);
      loggingOutRef.current = false;

      try { props.hostCallbacks?.onLogout?.("manual"); } catch {}

      clearTokensSilently("cleared");
    }
  }, [loggingOut, appBaseURL, requestConf, props.hostCallbacks, clearTokensSilently]);

  const onTokenPairReceived = React.useCallback(
    (tokens: TokenPairResponse, keepSignedIn: boolean = true) => {
      handleTokenPair(tokens, keepSignedIn);
    },
    [handleTokenPair]
  );

  // Refs to the latest handler implementations so the BroadcastChannel
  // listener can call them without retearing the channel every render.
  const handleTokenPairRef = React.useRef(handleTokenPair);
  const clearTokensSilentlyRef = React.useRef(clearTokensSilently);
  React.useEffect(() => {
    handleTokenPairRef.current = handleTokenPair;
    clearTokensSilentlyRef.current = clearTokensSilently;
  });

  React.useEffect(() => {
    if (typeof window === "undefined" || typeof BroadcastChannel === "undefined") return;
    const ch = new BroadcastChannel(channelKey);
    channelRef.current = ch;
    ch.onmessage = (e) => {
      const m = e.data;
      if (!m || typeof m !== "object") return;
      if (m.type === "tokens" && isValidTokenPair(m.tokens)) {
        // Shape-validate before treating the payload as auth tokens. The
        // BroadcastChannel is same-origin so a remote attacker can't post
        // here, but any same-origin script (extension content script, dev
        // tools, sibling widget) can — without this gate they could write
        // arbitrary strings to localStorage and schedule a refresh.
        const keep = m.keepSignedIn !== false;
        handleTokenPairRef.current(m.tokens as TokenPairResponse, keep, false);
      } else if (m.type === "logout") {
        const reason: "expired" | "cleared" = m.reason === "expired" ? "expired" : "cleared";
        clearTokensSilentlyRef.current(reason, false);
      }
    };
    return () => {
      ch.close();
      channelRef.current = null;
    };
  }, [channelKey]);

  // Latest-access-token ref. Used by authedAxios's request interceptor
  // so each outgoing call reads the freshly rotated bearer instead of
  // a value captured at React-render time.
  const jwtTokenRef = React.useRef(jwtToken);
  React.useEffect(() => { jwtTokenRef.current = jwtToken; }, [jwtToken]);

  // Reactive flag the authedAxios request interceptor reads to decide
  // whether to ship cookies. authedAxios itself is create-once (its
  // memo has empty deps so the instance identity stays stable across
  // renders — otherwise consumers holding a captured reference would
  // be using a stale instance), but the transport mode isn't known
  // until the app boot response resolves. Without this ref the
  // instance would be baked with withCredentials=false at first
  // render (cookieMode defaults to false) and never update, which
  // silently breaks every cookie-mode call (Profile's /a/me,
  // /a/passkeys, /a/me/sessions, ...) with a 401.
  const credentialModeRef = React.useRef(cookieMode);
  React.useEffect(() => {
    credentialModeRef.current = cookieMode;
  }, [cookieMode]);

  // Pre-wired axios instance exposed to consumers via context. Created
  // once per AppKit mount so the request interceptor's closure is
  // stable; the refs above mean it always sees the latest token /
  // credential mode without needing to recreate the instance on every
  // render. The 401-retry response interceptor (effect below) is also
  // installed on this instance — axios.create() does NOT inherit
  // interceptors from the default `axios`, so consumers using
  // authedAxios would otherwise miss the retry behavior.
  const authedAxios = React.useMemo(() => {
    const inst = axios.create();
    inst.interceptors.request.use((config) => {
      // Apply credential mode per-request — see credentialModeRef
      // above for why this can't live in axios.create({withCredentials}).
      // Don't override an explicit per-call override (some flows set
      // withCredentials: false deliberately).
      if (config.withCredentials === undefined) {
        config.withCredentials = credentialModeRef.current;
      }

      // Skip when Authorization is already set on this config — the
      // 401-retry path explicitly sets the freshly rotated bearer
      // before re-issuing the request, and we must NOT clobber it
      // with whatever the ref currently holds. The ref is updated by
      // a useEffect that hasn't necessarily run yet at retry time, so
      // it can be stale during a refresh-and-retry. Once-per-request
      // override is the right semantics anyway.
      const existing = (config.headers as any)?.Authorization;
      if (existing) return config;
      const tok = jwtTokenRef.current;
      if (tok) {
        config.headers = config.headers ?? {};
        (config.headers as any).Authorization = `Bearer ${tok}`;
      }
      return config;
    });
    return inst;
  }, []);

  // Reactive 401 handling: triggers a deduped refresh + retry. Only
  // retries calls to OUR base URLs (workspace / app-scoped); skips
  // auth-flow URLs themselves so refresh failures don't loop.
  // Single-shot retry per request.
  React.useEffect(() => {
    const isAuthFlowURL = (url: string): boolean =>
      /\/auth\/(refresh|login|logout|password|verify|register|forgot-password|reset-password|google|apple|microsoft|github|totp|passkey|oauth)/.test(url);

    const isOurURL = (url: string): boolean => {
      if (!url) return false;
      // axios sets cfg.url to whatever was passed; absolute URLs match
      // the workspace/app prefixes; relative URLs always belong to us
      // by definition (we're the only thing on the origin).
      if (url.startsWith("/")) return true;
      if (url.startsWith(workspaceBaseURL)) return true;
      if (url.startsWith(appBaseURL)) return true;
      return false;
    };

    const buildOnRejected = (instance: AxiosInstance) => async (error: any) => {
      const cfg: any = error?.config;
      const status = error?.response?.status;
      if (status !== 401 || !cfg) return Promise.reject(error);
      const url: string = cfg.url || "";
      if (!isOurURL(url)) return Promise.reject(error);
      if (isAuthFlowURL(url)) return Promise.reject(error);
      if (cfg.__akRetried) return Promise.reject(error);
      cfg.__akRetried = true;

      const result = await refreshOnce();
      if (result.kind === "auth_failed") {
        // Server explicitly invalidated the session (refresh token
        // expired / revoked / rotated by a sibling tab). Logout is
        // the right outcome.
        clearTokensSilently("expired");
        return Promise.reject(error);
      }
      if (result.kind === "transient") {
        // Couldn't even reach the server (network down, browser
        // sleep, CORS, 5xx). Reject this one request so callers see
        // the failure and can react, but DO NOT touch token state —
        // the user's session is almost certainly still valid and
        // logging them out for a network blip is hostile.
        return Promise.reject(error);
      }

      cfg.headers = { ...(cfg.headers || {}), Authorization: `Bearer ${result.token}` };
      return instance.request(cfg);
    };

    const globalId = axios.interceptors.response.use((r) => r, buildOnRejected(axios));
    const authedId = authedAxios.interceptors.response.use((r) => r, buildOnRejected(authedAxios));
    return () => {
      axios.interceptors.response.eject(globalId);
      authedAxios.interceptors.response.eject(authedId);
    };
  }, [workspaceBaseURL, appBaseURL, refreshOnce, clearTokensSilently, authedAxios]);

  const apiRef = React.useRef<{
    refresh: () => void;
    logout: () => Promise<void>;
    getSnapshot: () => AppKitStateSnapshot | null;
  } | null>(null);

  apiRef.current = {
    refresh: fetchAppData,
    logout,
    getSnapshot: () => latestSnapshotRef.current,
  };

  React.useEffect(() => {
    props.registerApi?.({
      refresh: () => apiRef.current?.refresh(),
      logout: async () => await apiRef.current?.logout(),
      getSnapshot: () => apiRef.current?.getSnapshot() ?? null,
      showProfile: () => setProfileOpen(true),
      hideProfile: () => setProfileOpen(false),
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const silentRefreshAttempted = React.useRef(false);
  const silentRefreshInProgress = React.useRef(false);
  // Dedupes the boot-time resolveApp kick-off. The effect can re-run
  // before resolveApp's promise settles (e.g. accessToken dep changes
  // from a sibling broadcast); without this we'd queue a fresh
  // /v1/...workspaces/.../apps/<id> per re-run.
  const appResolveKickedRef = React.useRef(false);
  // Tracks whether we've already fetched app data for the current
  // auth state. A successful /auth/refresh rotates accessToken (a
  // dep below), which would otherwise re-trigger this effect and
  // re-fetch /a/app/me — wasted work since user data doesn't change
  // on a rotation. Only re-fetch when auth state transitions
  // null<->!null.
  const lastFetchedAuthStateRef = React.useRef<"unknown" | "auth" | "noauth">("unknown");

  React.useEffect(() => {
    // First boot: app config not yet resolved. cookieMode is derived
    // from app.transportMode, so before resolveApp settles it reads
    // false regardless of the deployed app's actual transport. Doing
    // the auth dance under that wrong guess fires /a/me speculatively
    // (cookie mode picks up the URL on resolve), 401s, and triggers a
    // wasted reactive /auth/refresh — the visible me→refresh→me→refresh
    // duplication on cold boot. Resolve the app first, then let the
    // effect re-fire (fetchAppData identity changes when app populates,
    // which is a dep below) and proceed with cookieMode known.
    if (!app) {
      if (!appResolveKickedRef.current) {
        appResolveKickedRef.current = true;
        void resolveApp();
      }
      return;
    }

    // Proactively get a fresh access token before the first /a/me.
    // In cookie mode the refresh token is HttpOnly so !!refreshToken
    // is always false in JS — we still need to call /refresh (server
    // reads mr_rt from the cookie). Without this proactive call,
    // cookie-mode boots fall through to /a/me with whatever mr_at
    // the browser had, which is often expired (15-min TTL) after the
    // user's been away, and we'd rely entirely on the response
    // interceptor's refresh-and-retry to recover (fragile due to
    // effect-mount ordering races).
    const shouldAttempt = !accessToken && !silentRefreshAttempted.current && (cookieMode || !!refreshToken);
    if (shouldAttempt) {
      log.log(`silent refresh: starting (cookieMode=${cookieMode}, haveRefresh=${!!refreshToken})`);
      silentRefreshAttempted.current = true;
      silentRefreshInProgress.current = true;
      fetchInProgress.current = false;

      doRefreshTokens().then((result) => {
        silentRefreshInProgress.current = false;
        log.log(`silent refresh: ${result.kind}`);
        // Only treat an explicit auth_failed as logout. A transient
        // failure (network down, server unreachable, no refresh token
        // visible) shouldn't sign the user out — render the login
        // screen so the user can retry; the cookie/refresh-token may
        // come back next reload.
        if (result.kind === "auth_failed") {
          clearTokensSilently("expired");
          return;
        }
        if (result.kind === "transient") {
          // boot config (provider buttons, CORS, etc.) is already in
          // `app` thanks to the resolveApp gate at the top of this
          // effect, so we don't need fetchAppData to populate the
          // login UI. Calling /a/me here would 401 (we just failed to
          // refresh) and trigger the response interceptor's reactive
          // /auth/refresh — a second, redundant refresh on cold boot.
          // Set unauthenticated directly instead.
          setAppData(null);
          setAuthStatus("unauthenticated");
          emitAuthStatus("unauthenticated");
          pushSnapshot("unauthenticated", null, null);
          lastFetchedAuthStateRef.current = "noauth";
          return;
        }
        // "ok" — _setAccessToken inside doRefreshTokens re-triggers
        // this effect, which falls through to the fetchAppData branch
        // below.
      });
      return;
    }

    if (silentRefreshInProgress.current) return;

    // Skip the fetch when this is just a token rotation. fetchAppData
    // is in this effect's deps (and recreates on every accessToken
    // change), so without this gate a fast access-token TTL becomes
    // a /a/app/me-per-refresh loop. Exception: if we have no appData
    // yet, we DO need to fetch even if the auth state matches — this
    // covers the sibling-tab broadcast path where handleTokenPair
    // nulls appData on the receiving tab; without this check the
    // profile icon (and anything else reading appData.account) stays
    // gone until the page is reloaded.
    const currentAuthState: "auth" | "noauth" = accessToken ? "auth" : "noauth";
    if (lastFetchedAuthStateRef.current === currentAuthState && appDataRef.current) return;
    lastFetchedAuthStateRef.current = currentAuthState;

    if (fetchInProgress.current) return;
    fetchInProgress.current = true;

    fetchAppData();
  }, [fetchAppData, refreshToken, accessToken, doRefreshTokens, clearTokensSilently, cookieMode, app, resolveApp]);


  const ctx: AppKitContextValue = React.useMemo(
    () => ({
      status: authStatus,
      jwtToken,
      appData,
      workspaceBaseURL,
      appBaseURL,
      appId,
      app,
      refresh: fetchAppData,
      logout,
      authedAxios,
    }),
    [authStatus, jwtToken, appData, workspaceBaseURL, appBaseURL, appId, app, fetchAppData, logout, authedAxios]
  );

  // =====================================
  // UI
  // =====================================

  const authedSnapshot = latestSnapshotRef.current;
  const missingAppId = !appId;
  const configError = missingAppId || !!appResolveError;

  return (
    <DebugContext.Provider value={debug}>
    <AppKitThemeProvider theme={theme}>
      <ToastProvider>
      <InviteErrorHandler />
      <ErrorBoundary>
      <AppKitContext.Provider value={ctx}>
        {configError ? (
          <div style={{ padding: 16 }}>
            <div className="ak-stack ak-gap-4" style={{ maxWidth: 720 }}>
              <h2 className="ak-h6" style={{ fontWeight: 900 }}>Configuration error</h2>

              {missingAppId ? (
                <div className="ak-alert ak-alert-error" role="alert" style={{ borderRadius: 8 }}>
                  <span className="ak-alert-content">Missing <b>appId</b>. AppKit requires an explicit App ID.</span>
                </div>
              ) : (
                <div className="ak-alert ak-alert-error" role="alert" style={{ borderRadius: 8 }}>
                  <span className="ak-alert-content">{appResolveError || "Failed to resolve appId."}</span>
                </div>
              )}

              <hr className="ak-divider" />

              <p className="ak-caption ak-text-secondary">
                Base URL: <span className="ak-text-mono">{resolvedBaseURL}</span>
              </p>
              <p className="ak-caption ak-text-secondary">
                Workspace: <span className="ak-text-mono">{props.workspaceSlug}</span>
              </p>
              <p className="ak-caption ak-text-secondary">
                App ID: <span className="ak-text-mono">{appId || "(missing)"}</span>
              </p>

              <div className="ak-stack-row ak-gap-2">
                <button className="ak-btn ak-btn-outlined" onClick={fetchAppData}>Retry</button>
                <button
                  className="ak-btn ak-btn-outlined"
                  onClick={() => { setApp(null); setAppResolveError(null); fetchAppData(); }}
                >
                  Re-resolve
                </button>
              </div>
            </div>
          </div>
        ) : authStatus === "checking" ? (
          hadStoredToken || accessToken ? (
            <div style={{ minHeight: "100vh", background: "var(--ak-color-bg)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <Spinner size={32} />
            </div>
          ) : (
            <div style={{ minHeight: "100vh", background: "var(--ak-color-bg)", display: "flex", alignItems: "center" }}>
              <div className="ak-container">
                <div className="ak-card">
                  <div className="ak-card-content">
                    <div className="ak-stack ak-gap-5">
                      <div className="ak-skeleton" style={{ width: 120, height: 24 }} />
                      <div className="ak-skeleton" style={{ width: "80%", height: 16 }} />
                      <div className="ak-stack ak-gap-1">
                        <div className="ak-skeleton" style={{ width: 48, height: 12 }} />
                        <div className="ak-skeleton" style={{ width: "100%", height: 44, borderRadius: "var(--ak-radius-md)" }} />
                      </div>
                      <div className="ak-stack ak-gap-1">
                        <div className="ak-skeleton" style={{ width: 64, height: 12 }} />
                        <div className="ak-skeleton" style={{ width: "100%", height: 44, borderRadius: "var(--ak-radius-md)" }} />
                      </div>
                    </div>
                  </div>
                  <div className="ak-card-actions">
                    <div className="ak-skeleton" style={{ width: "100%", height: 46, borderRadius: "var(--ak-radius-lg)" }} />
                  </div>
                </div>
              </div>
            </div>
          )
        ) : authStatus === "unauthenticated" ? (
          props.hideAuthUI ? null :
          <Auth workspaceBaseUrl={appBaseURL} cookieMode={cookieMode} onTokenPair={onTokenPairReceived} allowRegistration={app?.allowRegistration} appId={app?.id} googleOAuthClientId={app?.googleOAuthClientId} appleEnabled={app?.appleEnabled} microsoftEnabled={app?.microsoftEnabled} githubEnabled={app?.githubEnabled} kakaoEnabled={app?.kakaoEnabled} naverEnabled={app?.naverEnabled} externalIdps={app?.externalIdps} primaryAuthMethod={app?.primaryAuthMethod} passkeyEnabled={app?.passkeyEnabled} qrSignInEnabled={app?.qrSignInEnabled && !props.suppressQRSignIn} hideBranding={app?.hideBranding} require2fa={app?.require2fa} header={props.authHeader} labels={props.labels} initialScreen={props.initialScreen} loginHint={props.loginHint} onScreenChange={props.onScreenChange} embedded={props.embedded} />
        ) : !appData ? (
          props.hideAuthUI ? null :
          <Auth workspaceBaseUrl={appBaseURL} cookieMode={cookieMode} onTokenPair={onTokenPairReceived} allowRegistration={app?.allowRegistration} appId={app?.id} googleOAuthClientId={app?.googleOAuthClientId} appleEnabled={app?.appleEnabled} microsoftEnabled={app?.microsoftEnabled} githubEnabled={app?.githubEnabled} kakaoEnabled={app?.kakaoEnabled} naverEnabled={app?.naverEnabled} externalIdps={app?.externalIdps} primaryAuthMethod={app?.primaryAuthMethod} passkeyEnabled={app?.passkeyEnabled} qrSignInEnabled={app?.qrSignInEnabled && !props.suppressQRSignIn} hideBranding={app?.hideBranding} require2fa={app?.require2fa} header={props.authHeader} labels={props.labels} initialScreen={props.initialScreen} loginHint={props.loginHint} onScreenChange={props.onScreenChange} embedded={props.embedded} />
        ) : totpSetupNeeded ? (
          <TOTPSetupGate
            workspaceBaseURL={appBaseURL}
            jwtToken={accessToken}
            userEmail={appData?.account?.email}
            primaryAuthMethod={app?.primaryAuthMethod}
            onComplete={() => { setTotpSetupNeeded(false); fetchAppData(); }}
            onLogout={logout}
          />
        ) : !appData.hasAppAccess ? (
          <div style={{ padding: 16 }}>
            <div className="ak-stack ak-gap-4" style={{ maxWidth: 720 }}>
              <h2 className="ak-h6" style={{ fontWeight: 900 }}>Forbidden</h2>

              <div className="ak-alert ak-alert-error" role="alert" style={{ borderRadius: 8 }}>
                <span className="ak-alert-content">You don't have access to this app.</span>
              </div>

              <div className="ak-stack-row ak-gap-2">
                <button className="ak-btn ak-btn-outlined" onClick={fetchAppData}>Retry</button>
                <button className="ak-btn ak-btn-contained" onClick={logout} disabled={loggingOut}>
                  {loggingOut ? "Logging out…" : "Log out"}
                </button>
              </div>

              <hr className="ak-divider" />

              <p className="ak-caption ak-text-secondary">
                User: <span className="ak-text-mono">{appData.account?.email || "(unknown)"}</span>
              </p>
              <p className="ak-caption ak-text-secondary">
                JWT: <span className="ak-text-mono">{jwtToken ? jwtToken.slice(0, 18) + "…" : "(none)"}</span>
              </p>
            </div>
          </div>
        ) : props.renderAuthed && authedSnapshot && authedSnapshot.status === "authenticated" ? (
          <>{props.renderAuthed(authedSnapshot)}</>
        ) : (
          <DefaultAuthedView appData={appData} appId={appId} />
        )}
      {/* Profile Dialog — portaled to body so it's not hidden by container display:none */}
      {profileOpen && ReactDOM.createPortal(
        <div style={{
          position: "fixed", inset: 0, zIndex: 9999,
          display: "flex", alignItems: "center", justifyContent: "center",
          ...theme.vars as any,
        }}>
          <div
            style={{ position: "absolute", inset: 0, background: "rgba(0,0,0,0.5)" }}
            onClick={() => setProfileOpen(false)}
          />
          <div style={{
            position: "relative", zIndex: 1,
            background: "var(--ak-color-card-bg, #fff)",
            borderRadius: 12,
            width: "100%", maxWidth: 500, maxHeight: "90vh",
            overflow: "auto",
            boxShadow: "0 8px 32px rgba(0,0,0,0.2)",
          }}>
            <Profile
              workspaceBaseUrl={appBaseURL}
              jwtToken={accessToken}
              user={appData?.account ? { id: appData.account.id || "", email: appData.account.email } : null}
              onBack={() => setProfileOpen(false)}
              hideBranding={app?.hideBranding}
              passkeyEnabled={app?.passkeyEnabled}
              allowAccountDeletion={app?.allowAccountDeletion ?? true}
              allowEmailChange={app?.allowEmailChange ?? true}
              primaryAuthMethod={app?.primaryAuthMethod}
              oauthEnabled={!!(app?.googleOAuthClientId || app?.appleEnabled || app?.microsoftEnabled || app?.githubEnabled || app?.kakaoEnabled || app?.naverEnabled || (app?.externalIdps && app.externalIdps.length > 0))}
              onLogout={logout}
            />
          </div>
        </div>,
        document.body,
      )}
      </AppKitContext.Provider>
      </ErrorBoundary>
      </ToastProvider>
    </AppKitThemeProvider>
    </DebugContext.Provider>
  );
}

// =====================================
// Default authenticated view (example)
// =====================================

function DefaultAuthedView({ appData, appId }: { appData: AppData; appId: string }) {
  return (
    <div style={{ minHeight: "100vh", background: "var(--ak-color-grey-50)", padding: "32px 0" }}>
      <div className="ak-stack ak-gap-6" style={{ maxWidth: 720, margin: "0 auto", padding: "0 16px" }}>
        {/* Header */}
        <div className="ak-card" style={{ background: "var(--ak-color-success-bg)", borderColor: "var(--ak-color-success)" }}>
          <div style={{ padding: "12px 16px" }}>
            <div className="ak-stack-row ak-items-center ak-justify-between ak-gap-4">
              <div className="ak-stack-row ak-items-center ak-gap-3">
                <Icon name="circle-check" style={{ color: "var(--ak-color-success)" }} />
                <div className="ak-stack ak-gap-0">
                  <p className="ak-body1 ak-font-bold">
                    Authenticated as {appData.account?.name || appData.account?.email}
                  </p>
                  <p className="ak-caption ak-text-secondary">{appData.account?.email}</p>
                </div>
              </div>
              <UserButton />
            </div>
          </div>
        </div>

        {/* Example Screen Banner */}
        <div className="ak-card" style={{ background: "var(--ak-color-info-bg)", borderColor: "var(--ak-color-info)" }}>
          <div style={{ padding: "12px 16px" }}>
            <div className="ak-stack-row ak-items-start ak-gap-3">
              <Icon name="code" style={{ color: "var(--ak-color-info)", marginTop: 2 }} />
              <div className="ak-stack ak-gap-2">
                <p className="ak-body2 ak-font-bold">This is an example screen</p>
                <p className="ak-body2 ak-text-secondary">
                  Replace this with your app by passing a <code style={{ background: "var(--ak-color-info-bg)", padding: "2px 6px", borderRadius: 4 }}>renderAuthed</code> prop
                  or wrapping your components with <code style={{ background: "var(--ak-color-info-bg)", padding: "2px 6px", borderRadius: 4 }}>&lt;AppKitAuthed&gt;</code>.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Context Info */}
        <div className="ak-card">
          <div className="ak-card-content">
            <p className="ak-overline ak-text-secondary">App</p>
            <div className="ak-stack ak-gap-2" style={{ marginTop: 8 }}>
              <div className="ak-stack-row ak-justify-between">
                <p className="ak-body2 ak-text-secondary">User</p>
                <p className="ak-body2 ak-font-bold">{appData.account?.email}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Roles & Permissions */}
        <div className="ak-stack-row ak-gap-4" style={{ flexWrap: "wrap" }}>
          <div className="ak-card ak-flex-1" style={{ minWidth: 200 }}>
            <div className="ak-card-content">
              <p className="ak-overline ak-text-secondary">Roles</p>
              <div className="ak-stack-row ak-flex-wrap ak-gap-2" style={{ marginTop: 8 }}>
                {appData.roles?.length ? (
                  appData.roles.map((role) => (
                    <span key={role} className="ak-chip ak-chip-outlined">{role}</span>
                  ))
                ) : (
                  <p className="ak-body2 ak-text-secondary">No roles assigned</p>
                )}
              </div>
            </div>
          </div>

          <div className="ak-card ak-flex-1" style={{ minWidth: 200 }}>
            <div className="ak-card-content">
              <p className="ak-overline ak-text-secondary">Permissions</p>
              <div className="ak-stack-row ak-flex-wrap ak-gap-2" style={{ marginTop: 8 }}>
                {appData.permissions?.length ? (
                  appData.permissions.map((perm) => (
                    <span key={perm} className="ak-chip ak-chip-outlined">{perm}</span>
                  ))
                ) : (
                  <p className="ak-body2 ak-text-secondary">No permissions</p>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Feature Flags */}
        {appData.featureFlags && appData.featureFlags.length > 0 && (
          <div className="ak-card">
            <div className="ak-card-content">
              <p className="ak-overline ak-text-secondary">Feature Flags</p>
              <div className="ak-stack-row ak-flex-wrap ak-gap-2" style={{ marginTop: 8 }}>
                {appData.featureFlags.map((flag: any, i: number) => (
                  <span
                    key={flag.key || i}
                    className={`ak-chip ${flag.enabled !== false ? "ak-chip-success" : "ak-chip-default"}`}
                  >
                    {flag.key || flag}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Code Example */}
        <div className="ak-card" style={{ background: "var(--ak-color-grey-900)" }}>
          <div className="ak-card-content">
            <p className="ak-overline" style={{ color: "var(--ak-color-grey-500)" }}>Quick Start</p>
            <pre style={{
              marginTop: 8,
              marginBottom: 0,
              padding: 0,
              fontSize: 13,
              fontFamily: "monospace",
              color: "var(--ak-color-grey-50)",
              overflow: "auto",
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
            }}>
{`<AppKit appId="${appId}">
  <AppKitAuthed>
    {({ appData }) => (
      <YourApp user={appData.account} />
    )}
  </AppKitAuthed>
</AppKit>`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
