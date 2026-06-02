// appkit-react/types.ts
import type { ReactNode } from "react";

export type ManyRowsAppKitErrorCode =
  | "RUNTIME_NOT_FOUND"
  | "SCRIPT_LOAD_FAILED"
  | "SCRIPT_TIMEOUT"
  | "RUNTIME_ERROR"
  | "RUNTIME_VERSION_MISMATCH"
  | "RUNTIME_VERSION_TOO_OLD"
  | "BASE_URL_NOT_ALLOWED_IN_PROD"
  | "INVALID_PROPS";

export type ManyRowsAppKitError = {
  code: ManyRowsAppKitErrorCode;
  message: string;
  details?: unknown;
};

export type ManyRowsAppKitReady = {
  container: HTMLElement;
  containerId?: string;

  workspace: string;
  appId: string;

  baseURL: string;
  version: string;
};

// ---- Snapshot types (mirrors appkit-ui's AppKitStateSnapshot) ----

export type AppKitAccount = {
  id: string;
  email: string;
};

export type AppKitFeatureFlag = {
  key: string;
  enabled: boolean;
};

export type AppKitConfigValue = {
  key: string;
  type: string;
  value?: unknown;
};

export type AppKitAppData = {
  account?: AppKitAccount;
  workspaceSlug: string;
  workspaceName: string;
  hasAppAccess: boolean;
  roles: string[];
  permissions: string[];
  featureFlags?: AppKitFeatureFlag[];
  config?: AppKitConfigValue[];
};

export type ManyRowsAppKitSnapshot = {
  status: "checking" | "authenticated" | "unauthenticated";
  jwtToken: string | null;
  appData: AppKitAppData | null;
  workspaceBaseURL: string;
  appBaseURL: string;
  appId: string;
  app: {
    id: string;
    name: string;
    workspaceSlug: string;
    workspaceName: string;
    allowRegistration: boolean;
    primaryAuthMethod?: "password" | "code" | "magicLink" | "none";
    googleOAuthClientId?: string;
    hideBranding?: boolean;
    require2fa?: boolean;
  } | null;
};

export type ManyRowsAppKitHandle = {
  version: string;
  info(): ManyRowsAppKitReady | null;

  getState(): ManyRowsAppKitSnapshot | null;
  subscribe(fn: (s: ManyRowsAppKitSnapshot | null) => void): () => void;

  refresh(): void;
  logout(): Promise<void>;
  setToken(tok: string | null): void;

  // Profile drawer/dialog — optional because older runtime versions
  // don't ship them; the wrapper guards both calls accordingly.
  showProfile?: () => void;
  hideProfile?: () => void;

  destroy(): void;
};

// Subset of AppKitOptions that appkit-react passes to the runtime —
// the authoritative shape lives in appkit-ui/src/main.tsx and includes
// more fields the wrapper doesn't expose directly. New runtime options
// can land here as the wrapper plumbs them through; unknown options
// the runtime doesn't recognize are ignored.
type AppKitInitOptions = {
  containerId: string;
  workspace: string;
  appId: string;
  baseURL?: string;

  // Theme tokens for the runtime's auth UI. Mirrors appkit-ui's
  // AppKitOptions['theme'] — free-tier surface only. Richer branding is a
  // paid, server-driven feature (admin panel), not a client prop.
  theme?: {
    primaryColor?: string;
    backgroundColor?: string;
    colorMode?: "light" | "dark" | "auto";
  };

  // Optional content rendered above the login/register card.
  authHeader?: ReactNode;

  // Partial overrides for user-facing strings; unset keys get English defaults.
  labels?: Record<string, string>;

  // Which auth screen to show initially, and a callback when the user
  // navigates between them (e.g. clicks "Create account").
  initialScreen?: "login" | "register" | "forgot-password";
  onScreenChange?: (screen: "login" | "register" | "forgot-password") => void;

  // ✅ optional: runtime can render a custom authed view (wrapper uses this internally)
  renderAuthed?: (snapshot: ManyRowsAppKitSnapshot) => ReactNode;

  onReady?: (info: ManyRowsAppKitReady) => void;
  onError?: (err: ManyRowsAppKitError) => void;

  // v0 state callbacks (from appkit-ui)
  onState?: (snapshot: ManyRowsAppKitSnapshot | null) => void;
  onReadyState?: (snapshot: ManyRowsAppKitSnapshot) => void;

  silent?: boolean;
  throwOnError?: boolean;
  debug?: boolean;

  // Suppress mounting the runtime's <Auth> entirely (publicAccess + non-auth
  // route). State still resolves so the host can react to auth status;
  // only the login card is hidden.
  hideAuthUI?: boolean;

  // Opt the runtime into loading the customer's downstream app bundle
  // after auth completes (set by the wrapper based on its own
  // loadAppRuntime prop).
  loadAppRuntime?: boolean;

  // When true, the auth form skips its full-viewport wrapper and flows inline
  // in the parent container. Use for embedded integrations (sidebars, modals,
  // small sections). Default: false (keeps the centered full-page layout).
  embedded?: boolean;
};

// Shape that window.ManyRows.AppKit (or the legacy function globals)
// exposes. Both variants now include version — first appkit-ui release
// to attach version is recent enough that the back-compat branch's
// previous omission was effectively dead.
export type AppKitRuntime = {
  init: (opts: AppKitInitOptions) => ManyRowsAppKitHandle | null;
  destroy?: (containerOrId: HTMLElement | string) => void;
  info?: (containerOrId: HTMLElement | string) => ManyRowsAppKitReady | null;
  version?: string;
};

