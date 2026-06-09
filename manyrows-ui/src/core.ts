export interface Account {
  id: string;
  email: string;
  name: string;
  validatedAt?: Date;
  language?: string;
  totpEnabled?: boolean;
  isSuper?: boolean;
}

// WorkspaceMember is the per-app user row returned by the AppUsers list
// endpoint: an account plus its app-scoped role, activity stats and tags.
// Shared so the data hook (useAppUsers) and the screens that model the
// same rows (Sessions, WorkspaceUsers) can reference it without importing
// from a screen module.
export interface WorkspaceMember {
  accountId: string;
  email: string;
  enabled?: boolean;
  emailVerifiedAt?: string | null;
  passwordSetAt?: string | null;
  lastLoginAt?: string | null;
  source?: string;
  createdAt?: string | null;
  displayName?: string;
  role?: string;
  // Per-app activity stats (populated by the AppUsers list endpoint).
  activeSessions?: number;
  loginFailures7d?: number;
  // Free-form tags (populated by the AppUsers list endpoint when an app
  // context is resolvable).
  tags?: string[];
}

export type EnabledFilter = "" | "enabled" | "disabled";
// RoleFilter values: "" (any), "without" (no roles), or a role UUID.
export type RoleFilter = string;

export interface Workspace {
  id: string;
  name: string;
  slug: string;
  status: string;
  createdAt: Date;
  role: string;
  projects: Project[];
  cookieDomain?: string | null;
  // First-boot setup checklist state. Both nullable; non-null means
  // "done". UI uses these to render the workspace-home checklist card
  // until either dismissed or all items complete.
  setupChecklistDismissedAt?: string | null;
  setupTestEmailSentAt?: string | null;
}

export interface Project {
  id: string;
  workspaceId: string;
  name: string;
  createdAt: string;
  updatedAt: string;
  createdBy?: string;
}

export interface Permission {
  id: string;
  projectId: string;
  name: string;
  slug: string;
  group?: string;
  createdAt?: string;
  updatedAt?: string;
}

export type AppType = "dev" | "staging" | "prod";

export interface App {
  id: string;
  projectId: string;
  type: AppType | string;
  // projectName is the parent project's name, populated by the server
  // on every read. There is no freeform apps.name anymore - the visible
  // app label is computed from project + env type via appDisplayName.
  projectName?: string;
  userPoolId?: string;
  // userPoolName is the identity pool's display name, populated by the
  // server via subquery. Admin views surface it as the "Users here =
  // Users in pool X" signal (especially when multiple apps share a
  // pool for SSO).
  userPoolName?: string;
  enabled?: boolean;
  appUrl?: string;
  authDomain?: string;
  createdAt: string;
  updatedAt: string;
}

// appTypeLabel maps an app's type to the human-readable label.
// Sites that want to show "what kind of app is this" reach for this
// helper instead of hand-rolling the switch.
export function appTypeLabel(app: { type?: AppType | string } | null | undefined): string {
  switch (app?.type) {
    case "prod": return "Production";
    case "staging": return "Staging";
    case "dev": return "Development";
    default: return app?.type ? String(app.type) : "";
  }
}

// appDisplayName composes the visible app label from the parent
// project's name + env-type suffix ("Drum Kingdom (Staging)"). Prod
// drops the suffix - one prod per project, no ambiguity to resolve.
export function appDisplayName(
  app: { type?: AppType | string; projectName?: string } | null | undefined,
): string {
  const name = app?.projectName ?? "";
  if (!name) return "(unnamed app)";
  switch (app?.type) {
    case "prod": return name;
    case "staging": return `${name} (Staging)`;
    case "dev": return `${name} (Dev)`;
    default: return name;
  }
}

// isProdApp reports whether an app targets the production environment.
// Screens use it to gate destructive/elevated confirmations.
export function isProdApp(app: { type?: AppType | string } | null | undefined): boolean {
  return app?.type === "prod";
}

export type ConfigExposure = "public" | "private" | "secret";

export type ConfigValueType =
  | "string"
  | "int"
  | "decimal"
  | "bool"
  | "string[]"
  | "int[]"
  | "decimal[]"
  | "bool[]"
  | "json";

type ConfigKeyStatus = "active" | "archived";

export type ConfigKey = {
  id: string;
  projectId: string;

  // stable identifier used by SDKs/integrations
  key: string;

  // optional human help text
  description?: string | null;

  exposure: ConfigExposure;

  valueType: ConfigValueType;

  status: ConfigKeyStatus;

  createdAt: string;
  updatedAt: string;
  createdBy: string;
};

export type ConfigValue = {
  id: string;

  projectId: string;
  appId: string;
  configKeyId: string;

  // for non-secret: value_json returned as JSON (decoded to JS)
  // for secret: omitted (write-only)
  value?: unknown | null;

  // for secret: true if set, omitted/false if unset
  hasSecret?: boolean;

  updatedAt: string;
  updatedBy: string;
};


export interface ProjectMemberRole {
  id: string;
  projectId: string;
  appId?: string | null; // null = project-wide (all apps)
  userId: string;
  roleId: string;
  createdAt: string;
}

export interface Role {
  id: string;
  projectId: string;
  name: string;
  slug: string;
  permissions: Permission[];
  createdAt: string;
  updatedAt: string;
}

export type FeatureFlag = {
  id: string;
  projectId: string;
  key: string;
  description?: string | null;
  defaultEnabled: boolean;
  scope: string,
  status: string;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
};

export type FeatureFlagOverride = {
  id: string;
  projectId: string;
  appId: string;
  featureFlagId: string;
  enabled: boolean;
  roleIds?: string[];
  status: string;
  updatedAt: string;
  updatedBy: string;
};

export interface APIKey {
  id: string;
  name: string;
  prefix: string;
  scope: string; // "read" | "read_write"
  expiresAt?: string | null;
  lastUsedAt?: string | null;
  createdAt: string;
}

// User Fields
export type UserFieldValueType = "string" | "bool" | "date";
export type UserFieldVisibility = "client" | "server";

export type UserField = {
  id: string;
  projectId: string;
  key: string;
  valueType: UserFieldValueType;
  visibility: UserFieldVisibility;
  userEditable: boolean;
  label?: string | null;
  status: string;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
};

export interface CorsOrigin {
  id: string;
  appId: string;
  origin: string;
  createdAt: string;
}

// isSafeRedirectURL guards a client-side navigation (e.g. following a backend
// logout redirect). It must be SAME-ORIGIN, not merely "any http(s) URL": the
// admin console session is cookie-borne, so navigating to an attacker origin
// while logged in is an open-redirect on an auth surface. Relative URLs resolve
// against the current origin; an absolute cross-origin URL keeps its own origin
// and is rejected.
export function isSafeRedirectURL(url: string): boolean {
  try {
    const u = new URL(url, window.location.origin);
    return u.origin === window.location.origin;
  } catch {
    return false;
  }
}