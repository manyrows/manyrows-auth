import * as React from "react";
import axios from "axios";
import { useTranslation } from "react-i18next";
import type { App, Product, ProductMemberRole, Role } from "../core.ts";
import { extractApiError } from "../lib/apiError.ts";
import type { EnabledFilter, RoleFilter, WorkspaceMember } from "./AppUsers.tsx";

// Data layer for the App Users screen: the read API (roles/apps/member-roles
// + the app-filtered, paged member list) and the useAppUsers hook that owns
// the related state, filters, paging and the two loaders. Split out of
// AppUsers.tsx so that (large) file stays presentation-focused.
//
// NOTE: this module imports ONLY types from AppUsers.tsx (erased at build), so
// there is no runtime import cycle even though AppUsers.tsx imports values
// (the hook, the fetchers, the two URL builders) from here.

function rolesUrl(project: Product) {
  return `/admin/workspace/${project.workspaceId}/products/${project.id}/roles`;
}

function appsUrl(project: Product) {
  return `/admin/workspace/${project.workspaceId}/products/${project.id}/apps`;
}

export function projectMemberRolesUrl(project: Product) {
  return `/admin/workspace/${project.workspaceId}/products/${project.id}/memberRoles`;
}

// project members filtered by app (server-side)
export function projectMembersUrl(project: Product) {
  return `/admin/workspace/${project.workspaceId}/products/${project.id}/members`;
}

// Raw member shape returned by /projectMembers. Several keys are aliased for
// back-compat with older server responses (userId vs accountId, addedAt vs
// createdAt, nested account.email). Anything not present here is dropped by
// the normalizer below.
type RawMember = {
  id?: string;
  accountId?: string;
  workspaceAccountId?: string;
  userId?: string;
  account?: { id?: string; email?: string; Email?: string };
  email?: string;
  displayName?: string;
  name?: string;
  enabled?: boolean;
  role?: string;
  emailVerifiedAt?: string | null;
  passwordSetAt?: string | null;
  lastLoginAt?: string | null;
  source?: string;
  addedAt?: string | null;
  createdAt?: string | null;
  activeSessions?: number;
  loginFailures7d?: number;
  tags?: string[];
};

type ProductMembersResponse = {
  members: RawMember[];
  membersTotal: number;
  page?: number;
  pageSize?: number;
  emailQuery?: string;
};

export async function getProductMembersPaged(
  project: Product,
  appId: string,
  page: number,
  pageSize: number,
  emailQuery: string,
  inactiveDays: number = 0,
  enabledFilter: EnabledFilter = "",
  roleFilter: RoleFilter = "",
): Promise<{ members: WorkspaceMember[]; total: number }> {
  const r = await axios.get<ProductMembersResponse>(projectMembersUrl(project), {
    params: {
      appId,
      page,
      pageSize,
      email: emailQuery.trim() || undefined,
      inactiveDays: inactiveDays > 0 ? inactiveDays : undefined,
      enabled: enabledFilter || undefined,
      role: roleFilter || undefined,
    },
  });

  const raw = r.data?.members ?? [];
  const members: WorkspaceMember[] = raw.map((m) => {
    const accountId = m.userId ?? m.workspaceAccountId ?? m.accountId ?? m.account?.id ?? m.id ?? "";
    const email = m.email ?? m.account?.email ?? m.account?.Email ?? "";
    const displayName = m.displayName ?? m.name ?? "";
    const enabled = m.enabled ?? true;
    return {
      accountId,
      email,
      displayName,
      enabled,
      role: m.role,
      emailVerifiedAt: m.emailVerifiedAt ?? null,
      passwordSetAt: m.passwordSetAt ?? null,
      lastLoginAt: m.lastLoginAt ?? null,
      source: m.source ?? "invited",
      createdAt: m.addedAt ?? m.createdAt ?? null,
      activeSessions: typeof m.activeSessions === "number" ? m.activeSessions : 0,
      loginFailures7d: typeof m.loginFailures7d === "number" ? m.loginFailures7d : 0,
      tags: Array.isArray(m.tags) ? m.tags : [],
    };
  });

  const total = typeof r.data?.membersTotal === "number" ? r.data.membersTotal : members.length;
  return { members, total };
}

async function getRoles(project: Product): Promise<Role[]> {
  const r = await axios.get(rolesUrl(project));
  return (r.data?.roles ?? r.data ?? []) as Role[];
}

async function getApps(project: Product): Promise<App[]> {
  const r = await axios.get(appsUrl(project));
  return (r.data?.apps ?? r.data ?? []) as App[];
}

export async function getProductMemberRoles(project: Product): Promise<ProductMemberRole[]> {
  const r = await axios.get(projectMemberRolesUrl(project));
  return (r.data?.memberRoles ?? r.data ?? []) as ProductMemberRole[];
}

// useAppUsers owns the data layer for the screen: roles/apps/member-roles
// (core) and the app-filtered, paged member list, plus the filter/search/
// paging state those depend on and the two loaders. Returns state + setters
// with the same names the component used inline, so callers read like before.
export function useAppUsers(project: Product, appIdProp?: string) {
  const { t } = useTranslation();
  const fixedApp = !!appIdProp;

  // Two independent fetch lifecycles - refreshCore loads roles/apps/
  // memberRoles, refreshList loads the actual member rows. Sharing
  // one `loading` flag races: whichever finishes first flips it to
  // false and uncovers the other's empty initial state (e.g. roles=[]
  // briefly renders the "no roles yet" warning before the core fetch
  // resolves). Track them separately and OR them at render time.
  const [coreLoading, setCoreLoading] = React.useState(true);
  const [listLoading, setListLoading] = React.useState(false);
  const loading = coreLoading || listLoading;
  const [err, setErr] = React.useState<string | null>(null);

  const [roles, setRoles] = React.useState<Role[]>([]);
  const [apps, setApps] = React.useState<App[]>([]);
  const [memberRoles, setMemberRolesState] = React.useState<ProductMemberRole[]>([]);
  // Selected app (REQUIRED)
  const [selectedAppId, setSelectedAppId] = React.useState<string>(appIdProp || "");
  React.useEffect(() => {
    if (appIdProp) setSelectedAppId(appIdProp);
  }, [appIdProp]);
  const selectedApp = React.useMemo(
    () => apps.find((e) => e.id === selectedAppId) || null,
    [apps, selectedAppId],
  );

  // project members list (app-filtered server-side)
  const [projectMembers, setProductMembers] = React.useState<WorkspaceMember[]>([]);
  const [projectMembersTotal, setProductMembersTotal] = React.useState(0);

  const hasApps = apps.length > 0;
  const hasRoles = roles.length > 0;

  // App URL for invite email + app ID for the per-user activity dialog
  // (both loaded when an app is selected).
  const [appUrl, setAppUrl] = React.useState<string | null>(null);
  const [currentAppId, setCurrentAppId] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (!selectedAppId) { setAppUrl(null); setCurrentAppId(null); return; }
    let alive = true;
    axios.get(`${appsUrl(project)}`).then((res) => {
      if (!alive) return;
      const apps = (res.data?.apps ?? []) as App[];
      const app = apps.find((a) => a.id === selectedAppId);
      setAppUrl(app?.appUrl || null);
      setCurrentAppId(app?.id || null);
    }).catch(() => { if (alive) { setAppUrl(null); setCurrentAppId(null); } });
    return () => { alive = false; };
  }, [selectedAppId, project]);

  // "Inactive users" segment: 0 = show everyone, otherwise users whose
  // last_login_at is older than N days (or never logged in) are shown.
  const [inactiveFilterDays, setInactiveFilterDays] = React.useState<number>(0);
  // Enabled/disabled segment: "" = both, "enabled" = users.enabled only,
  // "disabled" = !users.enabled only.
  const [enabledFilter, setEnabledFilter] = React.useState<EnabledFilter>("");
  // Role-presence segment: "" = any, "with" = members with >=1 role,
  // "without" = members with no role in this app.
  const [roleFilter, setRoleFilter] = React.useState<RoleFilter>("");

  // Paging/search for the app-filtered list
  const [memberPage, setMemberPage] = React.useState(0);
  const [membersPerPage, setMembersPerPage] = React.useState(25);
  const initialEmail = React.useMemo(() => new URLSearchParams(window.location.search).get("email") || "", []);
  const [memberSearchDraft, setMemberSearchDraft] = React.useState(initialEmail);
  const [memberSearchApplied, setMemberSearchApplied] = React.useState(initialEmail);

  const searchActive = memberSearchApplied.trim().length > 0;
  const draftDiffers = memberSearchDraft.trim() !== memberSearchApplied.trim();

  const roleById = React.useMemo(() => {
    const m = new Map<string, Role>();
    for (const r of roles) m.set(r.id, r);
    return m;
  }, [roles]);

  // For selected app only: accountId -> roleIds
  const rolesByAccountForSelectedApp = React.useMemo(() => {
    const m = new Map<string, string[]>();
    if (!selectedAppId) return m;

    for (const mr of memberRoles) {
      if (mr.appId !== selectedAppId) continue;
      const cur = m.get(mr.userId) ?? [];
      cur.push(mr.roleId);
      m.set(mr.userId, cur);
    }
    return m;
  }, [memberRoles, selectedAppId]);

  // Ref to track current selectedAppId without causing dependency cycle
  const selectedAppIdRef = React.useRef(selectedAppId);
  selectedAppIdRef.current = selectedAppId;

  // Generation counters for the two loaders: only the most recently-initiated
  // load commits its result. Without this, rapid app/paging/search/filter
  // changes (or a mutation-triggered reload racing an effect-triggered one)
  // let a slow older response overwrite a newer one — last-to-*complete* wins
  // instead of last-requested.
  const coreReqId = React.useRef(0);
  const refreshCore = React.useCallback(async () => {
    const reqId = ++coreReqId.current;
    setCoreLoading(true);
    setErr(null);
    try {
      const [r, fetchedApps, pmr] = await Promise.all([
        getRoles(project),
        getApps(project),
        getProductMemberRoles(project),
      ]);
      if (reqId !== coreReqId.current) return;

      setRoles(r);
      setApps(fetchedApps);
      setMemberRolesState(pmr);

      if (!fixedApp && !selectedAppIdRef.current) {
        if (fetchedApps[0]) setSelectedAppId(fetchedApps[0].id);
      }
    } catch (e) {
      if (reqId !== coreReqId.current) return;
      setErr(extractApiError(e, t("projectMembers.failedToLoadCore", { defaultValue: "Failed to load roles/apps" })));
    } finally {
      if (reqId === coreReqId.current) setCoreLoading(false);
    }
  }, [project]);

  React.useEffect(() => {
    refreshCore();
  }, [refreshCore]);

  // list load: depends on selected app + paging/search
  const listReqId = React.useRef(0);
  const refreshList = React.useCallback(async () => {
    if (!selectedAppId) return;

    const reqId = ++listReqId.current;
    setListLoading(true);
    setErr(null);
    try {
      const pmPaged = await getProductMembersPaged(project, selectedAppId, memberPage, membersPerPage, memberSearchApplied, inactiveFilterDays, enabledFilter, roleFilter);
      if (reqId !== listReqId.current) return;
      setProductMembers(pmPaged.members);
      setProductMembersTotal(pmPaged.total);
    } catch (e) {
      if (reqId !== listReqId.current) return;
      setErr(extractApiError(e, t("projectMembers.failedToLoadList", { defaultValue: "Failed to load product members" })));
    } finally {
      if (reqId === listReqId.current) setListLoading(false);
    }
  }, [project, selectedAppId, memberPage, membersPerPage, memberSearchApplied, inactiveFilterDays, enabledFilter, roleFilter]);

  React.useEffect(() => {
    refreshList();
  }, [refreshList]);

  return {
    loading,
    err,
    setErr,
    roles,
    apps,
    setMemberRolesState,
    selectedAppId,
    setSelectedAppId,
    selectedApp,
    projectMembers,
    setProductMembers,
    projectMembersTotal,
    hasApps,
    hasRoles,
    appUrl,
    currentAppId,
    inactiveFilterDays,
    setInactiveFilterDays,
    enabledFilter,
    setEnabledFilter,
    roleFilter,
    setRoleFilter,
    memberPage,
    setMemberPage,
    membersPerPage,
    setMembersPerPage,
    memberSearchDraft,
    setMemberSearchDraft,
    memberSearchApplied,
    setMemberSearchApplied,
    searchActive,
    draftDiffers,
    roleById,
    rolesByAccountForSelectedApp,
    refreshCore,
    refreshList,
  };
}
