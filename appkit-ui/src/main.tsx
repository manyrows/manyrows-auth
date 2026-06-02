// appkit-ui/main.tsx
import * as React from "react";
import { createRoot, type Root } from "react-dom/client";
import AppKit, { type AppKitStateSnapshot } from "./AppKit";

// -----------------------------
// Public types
// -----------------------------

export type ManyRowsAppKitErrorCode =
  | "NO_OPTIONS"
  | "BAD_OPTIONS"
  | "NO_CONTAINER"
  | "CONTAINER_NOT_FOUND"
  | "NO_WORKSPACE"
  | "NO_APP_ID"
  | "BAD_BASE_URL"
  | "MOUNT_FAILED";

export type ManyRowsAppKitError = {
  code: ManyRowsAppKitErrorCode;
  message: string;
  details?: unknown;
};

// This is what the host gets once ready.
export type ManyRowsAppKitReady = {
  container: HTMLElement;
  containerId?: string;

  workspace: string;
  appId: string;

  baseURL: string;
  version: string;
};

// v0 auth lifecycle
export type ManyRowsAppKitAuthStatus = "checking" | "authenticated" | "unauthenticated";

// event callbacks the host can hook
export type ManyRowsAppKitCallbacks = {
  onReady?: (info: ManyRowsAppKitReady) => void;
  onError?: (err: ManyRowsAppKitError) => void;

  onAuthStatus?: (status: ManyRowsAppKitAuthStatus) => void;
  onJWT?: (jwt: string | null) => void;

  // called when verify succeeds and token is set (before /me finishes)
  onLogin?: (jwt: string) => void;

  // called when logout happens (manual or 401 invalidates token)
  onLogout?: (reason: "manual" | "expired" | "cleared") => void;

  // fires for *every* snapshot (checking/unauth/authed/etc)
  onState?: (snapshot: AppKitStateSnapshot | null) => void;

  // called when AppKit is fully ready (authenticated + appData present)
  onReadyState?: (snapshot: AppKitStateSnapshot) => void;
};

export interface AppKitOptions extends ManyRowsAppKitCallbacks {
  // Preferred: pass an element directly (works great for React hosts)
  container?: HTMLElement | null;

  // Still supported: pass an element id
  containerId?: string;

  // REQUIRED: needed for /x/{workspaceSlug}/apps/{appId}
  workspace: string;

  // ✅ REQUIRED: identifies the app
  appId: string;

  // OPTIONAL: defaults to same-origin (window.location.origin), which
  // is right when this bundle is served by the ManyRows install
  // itself. Override only for unusual setups.
  baseURL?: string;

  // ✅ OPTIONAL: theme customization (free tier).
  // Richer branding (fonts, radius, card bg, custom CSS, white-label) is a paid
  // feature configured in the admin panel and applied server-side, not here.
  // Kept minimal on purpose so the paid system is additive, not a rug-pull.
  theme?: {
    primaryColor?: string;
    backgroundColor?: string;
    colorMode?: "light" | "dark" | "auto";
  };

  // OPTIONAL: if you want to render the customer app after login
  // (this runs inside the AppKit root)
  renderAuthed?: (snapshot: AppKitStateSnapshot) => React.ReactNode;

  // OPTIONAL: content rendered above the login/register card
  authHeader?: React.ReactNode;

  // OPTIONAL: override user-facing text in the auth UI (partial — English defaults for unset keys)
  labels?: Record<string, string>;

  // OPTIONAL: which auth screen to show initially ("login" | "register" | "forgot-password")
  initialScreen?: "login" | "register" | "forgot-password";

  // OPTIONAL: called when the user navigates between auth screens (e.g. clicks "Create account")
  onScreenChange?: (screen: "login" | "register" | "forgot-password") => void;

  // OPTIONAL: when true, the auth form skips its full-viewport wrapper and flows
  // inline in the parent container. Use for embedded integrations. Default: false.
  embedded?: boolean;

  // OPTIONAL: when true, AppKit doesn't render its built-in Auth login UI
  // on unauthed pages. Auth state is still resolved (so the host can react
  // to status updates); only the visual login card is suppressed. Used by
  // appkit-react when publicAccess is on and the current path isn't an
  // auth route — keeps the runtime from mounting the password / passkey
  // forms on a marketing page, which would otherwise trigger side effects
  // like the conditional-mediation passkey prompt.
  hideAuthUI?: boolean;

  // OPTIONAL: suppress the "Sign in with phone" (QR) button on the
  // login screen even when the app has qr_sign_in_enabled. Set by the
  // QR /pair landing page itself — the user is already on their phone
  // approving a phone sign-in, so offering "sign in with phone" there
  // is circular.
  suppressQRSignIn?: boolean;

  // Logging behavior
  silent?: boolean; // true => no console warnings/errors
  throwOnError?: boolean; // true => throw errors instead of (or in addition to) callbacks/logging
  debug?: boolean; // true => enable verbose console logging
}

export type ManyRowsAppKitHandle = {
  version: string;

  // Returns null until app is resolved.
  info(): ManyRowsAppKitReady | null;

  getState(): AppKitStateSnapshot | null;
  subscribe(fn: (s: AppKitStateSnapshot | null) => void): () => void;

  refresh(): void;
  logout(): Promise<void>;

  destroy(): void;

  showProfile(): void;
  hideProfile(): void;
};

// -----------------------------
// Versioning + global namespace
// -----------------------------

const APPKIT_VERSION = "0.1.1";

const GLOBAL_NS = "ManyRows";
const GLOBAL_API_KEY = "AppKit";

// Default base URL when the host doesn't set one — same-origin,
// since this bundle is served by the ManyRows install itself.
function defaultBaseURL(): string {
  if (typeof window !== "undefined" && window.location?.origin) {
    return window.location.origin;
  }
  return "";
}
const DEFAULT_BASE_URL = defaultBaseURL();

// -----------------------------
// Root management
// -----------------------------

type PendingReady = {
  container: HTMLElement;
  containerId?: string;
  workspace: string;
  appId: string;
  baseURL: string;
  version: string;
};

type MountRecord = {
  root: Root;
  container: HTMLElement;

  // delayed-ready: we only set lastReady once app is resolved
  lastReady?: ManyRowsAppKitReady;

  // temporary info until ready can be finalized
  pendingReady?: PendingReady;
  readyEmitted?: boolean;

  // live handle + subscription fanout
  handle: ManyRowsAppKitHandle;
  subscribers: Set<(s: AppKitStateSnapshot | null) => void>;
  latestSnapshot: AppKitStateSnapshot | null;

  // set by AppKit.tsx via props
  api?: {
    refresh: () => void;
    logout: () => Promise<void>;
    getSnapshot: () => AppKitStateSnapshot | null;
    showProfile: () => void;
    hideProfile: () => void;
  };
};

const mountsByContainer = new Map<HTMLElement, MountRecord>();

// -----------------------------
// Utilities
// -----------------------------

function norm(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

function createErr(
  code: ManyRowsAppKitErrorCode,
  message: string,
  details?: unknown
): ManyRowsAppKitError {
  return { code, message, details };
}

function emitError(opts: AppKitOptions | undefined, err: ManyRowsAppKitError): void {
  const silent = !!opts?.silent;

  if (!silent) {
    // eslint-disable-next-line no-console
    console.error(`[ManyRows AppKit] ${err.code}: ${err.message}`, err.details ?? "");
  }

  try {
    opts?.onError?.(err);
  } catch (cbErr) {
    if (!silent) {
      // eslint-disable-next-line no-console
      console.error("[ManyRows AppKit] onError callback threw:", cbErr);
    }
  }

  if (opts?.throwOnError) {
    throw Object.assign(new Error(`[ManyRows AppKit] ${err.code}: ${err.message}`), {
      appKitError: err,
    });
  }
}

function emitReady(opts: AppKitOptions | undefined, info: ManyRowsAppKitReady): void {
  try {
    opts?.onReady?.(info);
  } catch (cbErr) {
    const err = createErr("MOUNT_FAILED", "onReady callback threw.", cbErr);
    emitError(opts, err);
  }
}

function pickContainer(
  opts: AppKitOptions
): { el: HTMLElement; containerId?: string } | { error: ManyRowsAppKitError } {
  const direct = opts.container ?? null;
  if (direct instanceof HTMLElement) {
    return { el: direct };
  }

  const id = norm(opts.containerId);
  if (!id) {
    return {
      error: createErr(
        "NO_CONTAINER",
        "No container provided. Provide `container` (HTMLElement) or `containerId` (string).",
        { container: opts.container, containerId: opts.containerId }
      ),
    };
  }

  const el = document.getElementById(id);
  if (!el) {
    return {
      error: createErr("CONTAINER_NOT_FOUND", `No container element found for id="${id}".`, {
        containerId: id,
      }),
    };
  }

  return { el, containerId: id };
}

// -----------------------------
// Handle helpers
// -----------------------------

function makeHandle(rec: MountRecord): ManyRowsAppKitHandle {
  return {
    version: APPKIT_VERSION,
    info() {
      // delayed-ready contract
      return rec.lastReady ?? null;
    },
    getState() {
      return rec.latestSnapshot;
    },
    subscribe(fn) {
      rec.subscribers.add(fn);
      try {
        fn(rec.latestSnapshot);
      } catch {
        // ignore subscriber error
      }
      return () => rec.subscribers.delete(fn);
    },
    refresh() {
      rec.api?.refresh?.();
    },
    async logout() {
      await rec.api?.logout?.();
    },
    destroy() {
      destroyManyRowsAppKit(rec.container);
    },
    showProfile() {
      rec.api?.showProfile?.();
    },
    hideProfile() {
      rec.api?.hideProfile?.();
    },
  };
}

function fanout(rec: MountRecord, snap: AppKitStateSnapshot | null) {
  rec.latestSnapshot = snap;
  for (const fn of rec.subscribers) {
    try {
      fn(snap);
    } catch {
      // ignore
    }
  }
}

function tryFinalizeReadyFromSnapshot(
  rec: MountRecord,
  opts: AppKitOptions,
  snap: AppKitStateSnapshot | null
) {
  if (rec.readyEmitted) return;
  if (!rec.pendingReady) return;
  if (!snap) return;

  // Check if app is resolved
  const app = (snap as any)?.app;
  if (!app || !app.id) return;

  const pending = rec.pendingReady;

  const ready: ManyRowsAppKitReady = {
    container: pending.container,
    containerId: pending.containerId,
    workspace: pending.workspace,
    appId: pending.appId,
    baseURL: pending.baseURL,
    version: pending.version,
  };

  rec.lastReady = ready;
  rec.readyEmitted = true;
  rec.pendingReady = undefined;

  emitReady(opts, ready);
}

// -----------------------------
// Public API (versioned global)
// -----------------------------

export function initManyRowsAppKit(options: AppKitOptions): ManyRowsAppKitHandle | null {
  if (options?.debug) window.console.log(`[AppKit] v${APPKIT_VERSION}`);
  if (!options) {
    emitError(undefined, createErr("NO_OPTIONS", "No options provided."));
    return null;
  }
  if (typeof options !== "object") {
    emitError(undefined, createErr("BAD_OPTIONS", "Options must be an object.", options));
    return null;
  }

  const containerPick = pickContainer(options);
  if ("error" in containerPick) {
    emitError(options, containerPick.error);
    return null;
  }
  const { el, containerId } = containerPick;

  const workspaceSlug = norm(options.workspace);
  if (!workspaceSlug) {
    emitError(options, createErr("NO_WORKSPACE", "No workspace provided."));
    return null;
  }

  const appId = norm(options.appId);
  if (!appId) {
    emitError(options, createErr("NO_APP_ID", "No appId provided.", { appId: options.appId }));
    return null;
  }

  // ✅ baseURL optional: default to hosted ManyRows app
  const baseURL = norm(options.baseURL) || DEFAULT_BASE_URL;

  // Basic sanity check (must be absolute-ish). Keep non-fatal and allow override.
  // If it's empty after defaulting, something is very wrong.
  if (!baseURL) {
    emitError(options, createErr("BAD_BASE_URL", "Invalid baseURL.", { baseURL: options.baseURL }));
    return null;
  }

  // Create or reuse an existing root for this container
  let rec = mountsByContainer.get(el);
  if (!rec) {
    el.innerHTML = "";
    const root = createRoot(el);

    const dummyRec = {
      root,
      container: el,
      subscribers: new Set<(s: AppKitStateSnapshot | null) => void>(),
      latestSnapshot: null,
      readyEmitted: false,
    } as MountRecord;

    dummyRec.handle = makeHandle(dummyRec);
    rec = dummyRec;

    mountsByContainer.set(el, rec);
  }

  // delayed-ready: store pending, but do NOT emit onReady yet.
  rec.pendingReady = {
    container: el,
    containerId,
    workspace: workspaceSlug,
    appId,
    baseURL,
    version: APPKIT_VERSION,
  };
  rec.readyEmitted = false;
  rec.lastReady = undefined;

  // helper for AppKit.tsx to register its imperative api
  const registerApi = (api: MountRecord["api"]) => {
    rec!.api = api;
  };

  // state fanout + callbacks
  const onSnapshot = (snap: AppKitStateSnapshot | null) => {
    // 0) delayed-ready finalize when app is resolved
    tryFinalizeReadyFromSnapshot(rec!, options, snap);

    // 1) handle.subscribe fanout
    fanout(rec!, snap);

    // 2) every state change
    try {
      options.onState?.(snap);
    } catch (e) {
      emitError(options, createErr("MOUNT_FAILED", "onState callback threw.", e));
    }

    // 3) ready-for-customer-app moment
    if (snap && (snap as any).status === "authenticated" && (snap as any).appData) {
      try {
        options.onReadyState?.(snap);
      } catch (e) {
        emitError(options, createErr("MOUNT_FAILED", "onReadyState callback threw.", e));
      }
    }
  };

  try {
    rec.root.render(
      <AppKit
        baseURL={baseURL}
        workspaceSlug={workspaceSlug}
        appId={appId}
        theme={options.theme}
        debug={!!options.debug}
        hostCallbacks={{
          onAuthStatus: options.onAuthStatus,
          onJWT: options.onJWT,
          onLogin: options.onLogin,
          onLogout: options.onLogout,
        }}
        renderAuthed={options.renderAuthed}
        authHeader={options.authHeader}
        labels={options.labels}
        initialScreen={options.initialScreen}
        onScreenChange={options.onScreenChange}
        embedded={options.embedded}
        hideAuthUI={options.hideAuthUI}
        suppressQRSignIn={options.suppressQRSignIn}
        registerApi={registerApi}
        onSnapshot={onSnapshot}
      />
    );

    // NOTE: onReady is delayed until app mapping exists.
    return rec.handle;
  } catch (e) {
    emitError(options, createErr("MOUNT_FAILED", "Failed to mount AppKit.", e));
    return null;
  }
}

export function destroyManyRowsAppKit(containerOrId: HTMLElement | string): void {
  const el =
    typeof containerOrId === "string"
      ? document.getElementById(norm(containerOrId))
      : containerOrId;

  if (!el || !(el instanceof HTMLElement)) return;

  const rec = mountsByContainer.get(el);
  if (!rec) return;

  rec.root.unmount();
  mountsByContainer.delete(el);
  el.innerHTML = "";
}

export function getManyRowsAppKitInfo(
  containerOrId: HTMLElement | string
): ManyRowsAppKitReady | null {
  const el =
    typeof containerOrId === "string"
      ? document.getElementById(norm(containerOrId))
      : containerOrId;

  if (!el || !(el instanceof HTMLElement)) return null;

  // delayed-ready: info only available once finalized
  return mountsByContainer.get(el)?.lastReady ?? null;
}

// -----------------------------
// Attach to a versioned global:
// window.ManyRows.AppKit.init(...)
// -----------------------------

type GlobalNS = {
  [GLOBAL_API_KEY]?: {
    version: string;
    init: typeof initManyRowsAppKit;
    destroy: typeof destroyManyRowsAppKit;
    info: typeof getManyRowsAppKitInfo;
  };
};

const w = window as any;

if (!w[GLOBAL_NS]) w[GLOBAL_NS] = {} as GlobalNS;

w[GLOBAL_NS][GLOBAL_API_KEY] = {
  version: APPKIT_VERSION,
  init: initManyRowsAppKit,
  destroy: destroyManyRowsAppKit,
  info: getManyRowsAppKitInfo,
};

// Back-compat
w.initManyRowsAppKit = initManyRowsAppKit;
w.destroyManyRowsAppKit = destroyManyRowsAppKit;
w.getManyRowsAppKitInfo = getManyRowsAppKitInfo;
