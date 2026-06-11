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
  /** Display name (the runtime falls back to email when unset). */
  name?: string;
  /** Admin-managed metadata (set in the ManyRows console). */
  metadata?: Record<string, unknown>;
  /** App-managed metadata (set via the server API). */
  appMetadata?: Record<string, unknown>;
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

export type AppKitOrganization = {
  id: string;
  name: string;
  slug: string;
  orgRole: string;
};

/** A project (app RBAC) role assigned to an organization membership. */
export type AppKitOrganizationRole = {
  id: string;
  slug: string;
  name: string;
};

/** A member of an organization, as returned by the members endpoint. */
export type AppKitOrganizationMember = {
  userId: string;
  email: string;
  orgRole: string; // tier: owner | admin | member
  status: string;
  roles: AppKitOrganizationRole[];
};

/** A pending invitation to join an organization. */
export type AppKitOrganizationInvite = {
  id: string;
  email: string;
  orgRole: string;
  status: string;
  invitedByEmail?: string;
  createdAt: string;
  expiresAt: string;
};

/** The organization shape returned when an org is created. */
export type AppKitCreatedOrganization = {
  id: string;
  name: string;
  slug: string;
  status: string;
};

/** Pagination + search options for the org member/invite listings. */
export type AppKitOrgListParams = {
  /** 0-based page index. */
  page?: number;
  /** Page size (default 50, capped at 200 server-side). */
  pageSize?: number;
  /** Case-insensitive email substring filter. */
  search?: string;
};

/** A page of organization members plus the total match count. */
export type AppKitOrganizationMemberPage = {
  members: AppKitOrganizationMember[];
  total: number;
  page: number;
  pageSize: number;
};

/** A page of organization invites plus the total match count. */
export type AppKitOrganizationInvitePage = {
  invites: AppKitOrganizationInvite[];
  total: number;
  page: number;
  pageSize: number;
};

/** An active device session, as returned by the sessions endpoint. */
export type AppKitSession = {
  id: string;
  createdAt: string;
  lastSeenAt: string;
  userAgent?: string;
  /** Human-readable device label derived from the user agent, e.g. "Chrome on macOS". */
  deviceLabel?: string;
  ip?: string;
  /** True for the session making the request. */
  current: boolean;
};

/** A registered passkey (WebAuthn credential). */
export type AppKitPasskey = {
  id: string;
  name?: string;
  transports: string[];
  aaguid?: string;
  authenticatorName?: string;
  backupEligible: boolean;
  backupState: boolean;
  createdAt: string;
  lastUsedAt?: string;
};

/** A linked sign-in identity (OAuth provider or external IdP). */
export type AppKitIdentity = {
  provider: string;
  providerEmail?: string;
  createdAt: string;
  lastLoginAt: string;
};

/** A client-visible custom user field with its current value. */
export type AppKitUserField = {
  key: string;
  type: string;
  label: string;
  value?: unknown;
};

/**
 * Proof of identity for sensitive operations (TOTP setup/disable, passkey
 * delete). Pass `password`, or for passwordless users request an email code
 * via `useRequestReauthCode()` and pass `code`.
 */
export type AppKitReauthParams =
  | { password: string; code?: never }
  | { code: string; password?: never };

/** The TOTP enrollment material returned by useStartTOTPSetup. */
export type AppKitTOTPSetup = {
  /** Base32 secret for manual entry. */
  secret: string;
  /** otpauth:// URL — render as a QR code. */
  uri: string;
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
  // The session's active organization, or null when there is none. Absent
  // (undefined) when the app doesn't have organizations enabled.
  organization?: AppKitOrganization | null;
  // Every organization the user belongs to. Absent (undefined) when the orgs
  // feature is off; [] when enabled but the user belongs to none.
  organizations?: AppKitOrganization[];
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

  // Prefill for the sign-in email field (initial value only — the user
  // can edit it). Used by the OIDC login shim to thread login_hint.
  loginHint?: string;

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

