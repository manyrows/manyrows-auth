import * as React from "react";
import axios from "axios";
import type {App, Permission, Product, ProductMemberRole, Role, UserField} from "../core.ts";
import { appTypeLabel } from "../core.ts";
import { extractApiError } from "../lib/apiError.ts";
import {
  Alert,
  Autocomplete,
  Box,
  Button,
  Checkbox,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControl,
  FormControlLabel,
  IconButton,
  InputAdornment,
  LinearProgress,
  MenuItem,
  Paper,
  Select,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { Activity, CircleCheck, CircleX, FileDown, FileUp, Layers, Link2, Lock, Plus, RefreshCw, Save, Search, SquarePen, Tag, Trash2, Users, X } from "lucide-react";
import EmptyState from "../components/EmptyState.tsx";
import {useSnackbar} from "notistack";
import {Link as RouterLink, useNavigate} from "react-router-dom";
import {useTranslation, Trans} from "react-i18next";
import { alpha } from "../colors.ts";
import {
  buildExportEntry,
  buildExportFilename,
  parseUsersJson,
  computeImportPreview,
  extractErrorReason,
  type ImportUser,
} from "./appUsersImportExport";

const tc = { code: <code />, b: <b />, strong: <strong /> };

type TFunc = (key: string, opts?: Record<string, unknown>) => string;

const UserActivityDialog = React.lazy(() => import("./UserActivityDialog.tsx"));
const UserTagsDialog = React.lazy(() => import("./UserTagsDialog.tsx"));

/** ===== Types ===== */

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

interface Props {
  project: Product;
  appId?: string;
}

/** ===== API helpers ===== */

function rolesUrl(project: Product) {
  return `/admin/workspace/${project.workspaceId}/products/${project.id}/roles`;
}

function appsUrl(project: Product) {
  return `/admin/workspace/${project.workspaceId}/products/${project.id}/apps`;
}

function projectMemberRolesUrl(project: Product) {
  return `/admin/workspace/${project.workspaceId}/products/${project.id}/memberRoles`;
}

function projectMemberRolesForAccountUrl(project: Product, accountId: string) {
  return `${projectMemberRolesUrl(project)}/${accountId}`;
}

// project members filtered by app (server-side)
function projectMembersUrl(project: Product) {
  return `/admin/workspace/${project.workspaceId}/products/${project.id}/members`;
}

async function setUserEnabled(workspaceId: string, userId: string, enabled: boolean): Promise<void> {
  await axios.patch(`/admin/workspace/${workspaceId}/accounts/${userId}/status`, { enabled });
}

async function clearUserPassword(workspaceId: string, userId: string): Promise<void> {
  await axios.delete(`/admin/workspace/${workspaceId}/accounts/${userId}/password`);
}

// Account-recovery support ops (app-scoped, mirror the identities/passkeys admin paths).
async function resetUserTotp(workspaceId: string, productId: string, appId: string, userId: string): Promise<void> {
  await axios.delete(`/admin/workspace/${workspaceId}/products/${productId}/apps/${appId}/users/${userId}/totp`);
}

async function unlockUserAccount(workspaceId: string, productId: string, appId: string, userId: string): Promise<void> {
  await axios.post(`/admin/workspace/${workspaceId}/products/${productId}/apps/${appId}/users/${userId}/unlock`);
}

function appUserBase(workspaceId: string, productId: string, appId: string, userId: string): string {
  return `/admin/workspace/${workspaceId}/products/${productId}/apps/${appId}/users/${userId}`;
}

async function adminSetUserPassword(workspaceId: string, productId: string, appId: string, userId: string, password: string): Promise<void> {
  await axios.put(`${appUserBase(workspaceId, productId, appId, userId)}/password`, { password });
}

async function adminSetUserEmailVerified(workspaceId: string, productId: string, appId: string, userId: string, verified: boolean): Promise<void> {
  await axios.put(`${appUserBase(workspaceId, productId, appId, userId)}/email-verified`, { verified });
}

async function adminCreateUserMagicLink(workspaceId: string, productId: string, appId: string, userId: string): Promise<string> {
  const r = await axios.post<{ url: string }>(`${appUserBase(workspaceId, productId, appId, userId)}/magic-link`, {});
  return r.data.url;
}

async function adminCheckUserPermission(workspaceId: string, productId: string, appId: string, userId: string, permission: string): Promise<boolean> {
  const r = await axios.get<{ allowed: boolean }>(`${appUserBase(workspaceId, productId, appId, userId)}/check-permission`, { params: { permission } });
  return r.data.allowed;
}

// workspace accounts (so we can resolve email -> accountId when adding)
function workspaceAccountsUrl(workspaceId: string) {
  return `/admin/workspace/${workspaceId}/accounts`;
}

// Collapse the raw users.source enum (registered / google / apple /
// microsoft / github / invited) into two human-friendly buckets.
// Admins don't care which OAuth provider - they care whether the
// user signed up themselves or was added by an admin via invite or
// bulk import.
function sourceLabel(source: string): string {
  if (source === "invited") return "Added by admin";
  return "Signed up";
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

type EnabledFilter = "" | "enabled" | "disabled";
// RoleFilter values: "" (any), "without" (no roles), or a role UUID.
type RoleFilter = string;

async function getProductMembersPaged(
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

// Create a new user for an app.
// roleIds is required by the server unless the app has a DefaultRoleID
// configured - passing them here lets the server insert the user and the
// project_member_roles row in a single transaction.
async function createWorkspaceAccount(workspaceId: string, email: string, appId: string, roleIds: string[], sendInvite?: boolean): Promise<{ id: string; email: string; created: boolean; inviteEmailSent?: boolean; inviteEmailError?: string }> {
  const r = await axios.post<{ id: string; email: string; created: boolean; inviteEmailSent?: boolean; inviteEmailError?: string }>(workspaceAccountsUrl(workspaceId), {
    email: email.trim().toLowerCase(),
    appId,
    roleIds,
    sendInvite: !!sendInvite,
  });
  return r.data;
}

async function getRoles(project: Product): Promise<Role[]> {
  const r = await axios.get(rolesUrl(project));
  return (r.data?.roles ?? r.data ?? []) as Role[];
}

async function getApps(project: Product): Promise<App[]> {
  const r = await axios.get(appsUrl(project));
  return (r.data?.apps ?? r.data ?? []) as App[];
}

async function getProductMemberRoles(project: Product): Promise<ProductMemberRole[]> {
  const r = await axios.get(projectMemberRolesUrl(project));
  return (r.data?.memberRoles ?? r.data ?? []) as ProductMemberRole[];
}

async function setMemberRolesForApp(
  project: Product,
  accountId: string,
  roleIds: string[],
  appId: string,
): Promise<void> {
  await axios.put(projectMemberRolesForAccountUrl(project, accountId), {
    roleIds,
    appId, // ALWAYS required
  });
}

// Fully remove a user from an app: server clears their roles +
// permission overrides for the app, deletes the app_users membership
// row, and revokes their sessions for the app. (Clearing roles alone
// left them a member with no roles — roles are optional.)
async function removeAppMember(
  project: Product,
  accountId: string,
  appId: string,
): Promise<void> {
  await axios.delete(`${projectMembersUrl(project)}/${accountId}`, {
    params: { appId },
  });
}



function displayMember(m: WorkspaceMember): string {
  return (m.email && m.email.trim()) || m.accountId;
}
/** ===== Dialog: confirm remove member (from app) ===== */

function ConfirmRemoveMemberDialog(props: {
  open: boolean;
  member: WorkspaceMember | null;
  onClose: () => void;
  onConfirm: () => void;
  loading: boolean;
  t: TFunc;
}) {
  const { open, member, onClose, onConfirm, loading, t } = props;

  return (
    <Dialog open={open} onClose={loading ? undefined : onClose} fullWidth maxWidth="sm">
      <DialogTitle>{t("projectMembers.removeDialog.title")}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 1 }}>
          <Box>
            <Typography variant="subtitle2">{t("projectMembers.removeDialog.member")}</Typography>
            <Typography variant="body2" color="text.secondary">
              {member ? displayMember(member) : "-"}
            </Typography>
          </Box>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} color="inherit" disabled={loading}>
          {t("projectMembers.removeDialog.cancel")}
        </Button>
        <Button
          variant="contained"
          color="error"
          startIcon={<Trash2 size={14} strokeWidth={1.75} />}
          onClick={onConfirm}
          disabled={loading || !member}
        >
          {loading ? t("projectMembers.removeDialog.removing") : t("projectMembers.removeDialog.remove")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/** ===== Dialog: Add/Edit member roles (app REQUIRED) ===== */

function MemberRolesDialog(props: {
  open: boolean;
  mode: "add" | "edit";
  appName: string;
  workspaceId: string;
  // poolId scopes the add-mode autocomplete so we only suggest
  // existing identities in the same pool. May be empty while the
  // selected app is still loading.
  poolId: string;

  // add mode: member selection
  selectedMemberToAdd: WorkspaceMember | null;
  setSelectedMemberToAdd: (v: WorkspaceMember | null) => void;

  // edit mode
  member: WorkspaceMember | null;

  roles: Role[];
  selectedRoleIds: Set<string>;
  setSelectedRoleIds: (next: Set<string>) => void;

  onClose: () => void;
  onSave: () => void;
  saving: boolean;
  requireRoleSelectionToSave: boolean;
  sendInvite: boolean;
  setSendInvite: (v: boolean) => void;
  appUrl: string | null;
  t: TFunc;
}) {
  const {
    open,
    mode,
    appName,
    workspaceId,
    poolId,
    selectedMemberToAdd,
    setSelectedMemberToAdd,
    member,
    roles,
    selectedRoleIds,
    setSelectedRoleIds,
    onClose,
    onSave,
    saving,
    requireRoleSelectionToSave,
    sendInvite,
    setSendInvite,
    appUrl,
    t,
  } = props;

  // Pool-scoped email autocomplete: typing prefix-matches existing
  // identities in the app's pool so admins don't have to remember the
  // exact email when re-adding a known user. freeSolo so brand-new
  // emails (new invites) still go through.
  const [acOptions, setAcOptions] = React.useState<WorkspaceMember[]>([]);
  const [acInput, setAcInput] = React.useState("");

  React.useEffect(() => {
    if (!open || mode !== "add") return;
    if (!poolId) { setAcOptions([]); return; }
    if (acInput.trim().length < 2) { setAcOptions([]); return; }

    let cancelled = false;
    const timer = setTimeout(async () => {
      try {
        const res = await axios.get(`/admin/workspace/${workspaceId}/accounts`, {
          params: { poolId, email: acInput.trim(), limit: 10 },
        });
        if (cancelled) return;
        type RawAccount = { id?: string; email?: string };
        const accounts = ((res.data?.accounts ?? []) as RawAccount[]).map((a) => ({
          accountId: a.id ?? "",
          email: a.email ?? "",
        }));
        setAcOptions(accounts);
      } catch {
        if (!cancelled) setAcOptions([]);
      }
    }, 250);

    return () => { cancelled = true; clearTimeout(timer); };
  }, [acInput, open, mode, poolId, workspaceId]);

  React.useEffect(() => {
    if (open) { setAcOptions([]); setAcInput(""); }
  }, [open]);

  const title = mode === "add" ? t("projectMembers.dialog.addTitle") : t("projectMembers.dialog.editTitle");

  const total = roles.length;
  const hasSelectedRole = selectedRoleIds.size > 0;

  const selectAll = () => setSelectedRoleIds(new Set(roles.map((r) => r.id)));
  const deselectAll = () => setSelectedRoleIds(new Set());

  const toggleRole = (roleId: string) => {
    const next = new Set(selectedRoleIds);
    if (next.has(roleId)) next.delete(roleId);
    else next.add(roleId);
    setSelectedRoleIds(next);
  };

  const hasValidMemberSelection = selectedMemberToAdd && selectedMemberToAdd.email && selectedMemberToAdd.email.trim().length > 0;
  // Roles are optional post user-pool refactor; a member can sit in
  // app_users with zero roles and the customer backend decides what
  // their token can do.
  const canSave =
    (!requireRoleSelectionToSave || hasSelectedRole) &&
    (mode === "add" ? hasValidMemberSelection : !!member);

  return (
    <Dialog open={open} onClose={saving ? undefined : onClose} fullWidth maxWidth="md">
      <DialogTitle>{title}</DialogTitle>

      <Box
        component="form"
        onSubmit={(e) => {
          e.preventDefault();
          if (canSave && !saving) onSave();
        }}
      >
        <DialogContent>
          <Stack spacing={3} sx={{ pt: 0 }}>
            {mode === "edit" && (
              <Alert severity="info">
                <Trans i18nKey="projectMembers.dialog.editInfo" values={{ app: appName }} components={tc} />
              </Alert>
            )}

            {mode === "add" ? (
              <Autocomplete<WorkspaceMember, false, false, true>
                freeSolo
                options={acOptions}
                getOptionLabel={(opt) => typeof opt === "string" ? opt : opt.email}
                isOptionEqualToValue={(a, b) => a.email === b.email}
                inputValue={acInput}
                onInputChange={(_, value) => {
                  setAcInput(value);
                  setSelectedMemberToAdd({ accountId: "", email: value.trim() });
                }}
                onChange={(_, value) => {
                  if (value && typeof value !== "string") {
                    setSelectedMemberToAdd({ accountId: value.accountId, email: value.email });
                    setAcInput(value.email);
                  }
                }}
                renderInput={(params) => (
                  <TextField
                    {...params}
                    label={t("projectMembers.dialog.emailLabel")}
                    placeholder="user@example.com"
                    autoFocus
                    size="small"
                    inputMode="email"
                  />
                )}
                renderOption={(props, option) => (
                  <li {...props} key={typeof option === "string" ? option : option.accountId || option.email}>
                    <Typography variant="body2">{typeof option === "string" ? option : option.email}</Typography>
                  </li>
                )}
                filterOptions={(x) => x}
                size="small"
                fullWidth
              />
            ) : (
              <Box>
                <Typography variant="subtitle2">{t("projectMembers.dialog.member")}</Typography>
                <Typography variant="body2" color="text.secondary">
                  {member ? displayMember(member) : "-"}
                </Typography>
                {member?.accountId && (
                  <Typography variant="caption" color="text.disabled" sx={{ fontFamily: "var(--font-mono)", fontSize: "0.7rem" }}>
                    {member.accountId}
                  </Typography>
                )}
              </Box>
            )}

            {mode === "add" && (
              <FormControlLabel
                control={
                  <Checkbox
                    checked={sendInvite}
                    onChange={(e) => setSendInvite(e.target.checked)}
                    disabled={!appUrl}
                  />
                }
                label={
                  <Stack spacing={0}>
                    <Typography variant="body2">
                      {t("projectMembers.dialog.sendInvite", { defaultValue: "Send invite email" })}
                    </Typography>
                    {!appUrl && (
                      <Typography variant="caption" color="text.secondary">
                        {t("projectMembers.dialog.sendInviteNoUrl", { defaultValue: "Set an App URL in app settings first" })}
                      </Typography>
                    )}
                  </Stack>
                }
                sx={{ ml: 0 }}
              />
            )}

            <Divider />

            {total === 0 ? (
              <Alert severity="warning">{t("projectMembers.dialog.noRolesWarning")}</Alert>
            ) : (
              <>
                <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
                  <Typography variant="subtitle2">{t("projectMembers.dialog.roles")}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {t("projectMembers.dialog.rolesSelected", { selected: selectedRoleIds.size, total })}
                  </Typography>
                  <Box sx={{ flex: 1 }} />
                  <Button size="small" onClick={selectAll}>
                    {t("projectMembers.dialog.selectAll")}
                  </Button>
                  <Button size="small" onClick={deselectAll}>
                    {t("projectMembers.dialog.deselectAll")}
                  </Button>
                </Stack>

                {requireRoleSelectionToSave && !hasSelectedRole && (
                  <Alert severity="warning">{t("projectMembers.dialog.selectRoleWarning")}</Alert>
                )}

                <Stack spacing={0.5}>
                  {roles
                    .slice()
                    .sort((a, b) => a.name.localeCompare(b.name))
                    .map((r) => (
                      <FormControlLabel
                        key={r.id}
                        control={<Checkbox checked={selectedRoleIds.has(r.id)} onChange={() => toggleRole(r.id)} />}
                        label={
                          <Stack spacing={0}>
                            <Typography variant="body2">{r.name}</Typography>
                            <Typography variant="caption" sx={{ fontFamily: "var(--font-mono)", color: "text.secondary" }}>
                              {r.slug}
                            </Typography>
                          </Stack>
                        }
                      />
                    ))}
                </Stack>

                {!requireRoleSelectionToSave && !hasSelectedRole && (
                  <Alert severity="info">
                    <Trans i18nKey="projectMembers.dialog.noRolesInfo" values={{ app: appName }} components={tc} />
                  </Alert>
                )}
              </>
            )}
          </Stack>
        </DialogContent>

        <DialogActions>
          <Button onClick={onClose} color="inherit" disabled={saving}>
            {t("projectMembers.dialog.cancel")}
          </Button>
          <Button type="submit" variant="contained" startIcon={<Save size={14} strokeWidth={1.75} />} disabled={!canSave || saving}>
            {saving ? t("projectMembers.dialog.saving") : t("projectMembers.dialog.save")}
          </Button>
        </DialogActions>
      </Box>
    </Dialog>
  );
}

/** ===== Page ===== */

export default function AppUsers({ project, appId: appIdProp }: Props) {
  const { enqueueSnackbar } = useSnackbar();
  const navigate = useNavigate();
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

  // Per-user activity drill-down dialog state.
  const [activityUser, setActivityUser] = React.useState<{ id: string; email: string } | null>(null);
  const openActivityDialog = (userId: string, email: string) => {
    setActivityUser({ id: userId, email });
  };
  const closeActivityDialog = () => setActivityUser(null);

  // Tag-edit dialog state.
  const [tagsUser, setTagsUser] = React.useState<{ id: string; email: string; tags: string[] } | null>(null);
  const openTagsDialog = (m: WorkspaceMember) => {
    setTagsUser({ id: m.accountId, email: m.email, tags: m.tags ?? [] });
  };
  const closeTagsDialog = () => setTagsUser(null);
  const onTagsSaved = (userId: string, tags: string[]) => {
    setProductMembers((prev) =>
      prev.map((m) => (m.accountId === userId ? { ...m, tags } : m)),
    );
  };

  // "Inactive users" segment: 0 = show everyone, otherwise users whose
  // last_login_at is older than N days (or never logged in) are shown.
  const [inactiveFilterDays, setInactiveFilterDays] = React.useState<number>(0);
  // Enabled/disabled segment: "" = both, "enabled" = users.enabled only,
  // "disabled" = !users.enabled only.
  const [enabledFilter, setEnabledFilter] = React.useState<EnabledFilter>("");
  // Role-presence segment: "" = any, "with" = members with >=1 role,
  // "without" = members with no role in this app.
  const [roleFilter, setRoleFilter] = React.useState<RoleFilter>("");

  // Bulk actions: multi-select state + dialog state.
  type BulkError = { id: string; email: string; message: string };
  const [selectedIds, setSelectedIds] = React.useState<Set<string>>(new Set());
  const [bulkMode, setBulkMode] = React.useState<"disable" | "enable" | "delete" | null>(null);
  const [bulkLoading, setBulkLoading] = React.useState(false);
  const [bulkProgress, setBulkProgress] = React.useState<{ done: number; total: number; errors: BulkError[] }>({ done: 0, total: 0, errors: [] });

  const toggleSelect = React.useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);
  const clearSelection = React.useCallback(() => setSelectedIds(new Set()), []);

  const goApps = React.useCallback(() => {
    navigate(`/app/workspace/${project.workspaceId}/products/${project.id}/apps`);
  }, [navigate, project.workspaceId, project.id]);

  const goRoles = React.useCallback(() => {
    navigate(`/app/workspace/${project.workspaceId}/products/${project.id}/roles`);
  }, [navigate, project.workspaceId, project.id]);

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

  // Drop selection whenever the visible page contents change so we don't
  // operate on a user that scrolled out of view.
  React.useEffect(() => {
    clearSelection();
  }, [memberPage, memberSearchApplied, inactiveFilterDays, enabledFilter, roleFilter, selectedAppId, clearSelection]);

  // Dialog state (add/edit)
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [dialogMode, setDialogMode] = React.useState<"add" | "edit">("add");
  const [dialogMember, setDialogMember] = React.useState<WorkspaceMember | null>(null);
  const [dialogRoleIds, setDialogRoleIds] = React.useState<Set<string>>(new Set());
  const [dialogSaving, setDialogSaving] = React.useState(false);

  // add mode: member selection via autocomplete
  const [dialogSelectedMember, setDialogSelectedMember] = React.useState<WorkspaceMember | null>(null);

  const [dialogSendInvite, setDialogSendInvite] = React.useState(false);

  // Dialog state (remove)
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [deleteMember, setDeleteMember] = React.useState<WorkspaceMember | null>(null);
  const [deleteLoading, setDeleteLoading] = React.useState(false);

  // Enable/disable confirmation dialog
  const [toggleOpen, setToggleOpen] = React.useState(false);
  const [toggleMember, setToggleMember] = React.useState<WorkspaceMember | null>(null);
  const [toggleLoading, setToggleLoading] = React.useState(false);

  // Clear-password confirmation dialog
  const [clearPwOpen, setClearPwOpen] = React.useState(false);
  const [clearPwMember, setClearPwMember] = React.useState<WorkspaceMember | null>(null);
  const [clearPwLoading, setClearPwLoading] = React.useState(false);
  const [resetTotpOpen, setResetTotpOpen] = React.useState(false);
  const [resetTotpLoading, setResetTotpLoading] = React.useState(false);
  const [unlockOpen, setUnlockOpen] = React.useState(false);
  const [unlockLoading, setUnlockLoading] = React.useState(false);
  const [setPwOpen, setSetPwOpen] = React.useState(false);
  const [setPwValue, setSetPwValue] = React.useState("");
  const [setPwLoading, setSetPwLoading] = React.useState(false);
  const [magicLinkUrl, setMagicLinkUrl] = React.useState<string | null>(null);
  const [magicLinkLoading, setMagicLinkLoading] = React.useState(false);
  const [emailVerifyLoading, setEmailVerifyLoading] = React.useState(false);
  const [checkPerm, setCheckPerm] = React.useState("");
  const [checkPermResult, setCheckPermResult] = React.useState<boolean | null>(null);
  const [checkPermLoading, setCheckPermLoading] = React.useState(false);

  // User info dialog
  const [infoOpen, setInfoOpen] = React.useState(false);
  const [infoMember, setInfoMember] = React.useState<WorkspaceMember | null>(null);

  // Direct permissions in info dialog
  const [allPermissions, setAllPermissions] = React.useState<{ id: string; name: string; slug: string }[]>([]);
  const [directPermIds, setDirectPermIds] = React.useState<Set<string>>(new Set());
  const [directPermEditing, setDirectPermEditing] = React.useState(false);
  const [directPermSaving, setDirectPermSaving] = React.useState(false);

  // Linked OAuth identities (Google/Apple/Microsoft/GitHub) in info dialog
  type UserIdentity = { provider: string; providerEmail?: string; createdAt: string; lastLoginAt: string };
  const [identities, setIdentities] = React.useState<UserIdentity[]>([]);
  const [identitiesLoading, setIdentitiesLoading] = React.useState(false);
  const PROVIDER_LABEL: Record<string, string> = { google: "Google", apple: "Apple", microsoft: "Microsoft", github: "GitHub", kakao: "Kakao", naver: "Naver" };

  const loadIdentities = React.useCallback(async (userId: string, appId: string) => {
    setIdentitiesLoading(true);
    try {
      const r = await axios.get<{ identities: UserIdentity[] }>(
        `/admin/workspace/${project.workspaceId}/products/${project.id}/apps/${appId}/users/${userId}/identities`,
      );
      setIdentities(r.data?.identities ?? []);
    } catch {
      setIdentities([]);
    } finally {
      setIdentitiesLoading(false);
    }
  }, [project.workspaceId, project.id]);

  const memberPermsUrl = `/admin/workspace/${project.workspaceId}/products/${project.id}/memberPermissions`;
  const permissionsUrl = `/admin/workspace/${project.workspaceId}/products/${project.id}/permissions`;

  const loadDirectPerms = React.useCallback(async (userId: string, appId: string) => {
    try {
      const [permsRes, directRes] = await Promise.all([
        axios.get(permissionsUrl),
        axios.get(`${memberPermsUrl}/${userId}`, { params: { appId: appId } }),
      ]);
      const perms = (permsRes.data?.permissions ?? []) as Permission[];
      setAllPermissions(perms.map((p) => ({ id: p.id, name: p.name, slug: p.slug })));
      setDirectPermIds(new Set((directRes.data?.permissionIds ?? []) as string[]));
      setDirectPermEditing(false);
    } catch {
      // non-critical
    }
  }, [permissionsUrl, memberPermsUrl]);

  const saveDirectPerms = async () => {
    if (!infoMember || !selectedAppId) return;
    setDirectPermSaving(true);
    try {
      await axios.put(`${memberPermsUrl}/${infoMember.accountId}`, {
        appId: selectedAppId,
        permissionIds: [...directPermIds],
      });
      setDirectPermEditing(false);
      enqueueSnackbar(t("projectMembers.permissionsSaved", { defaultValue: "Permissions saved" }), { variant: "success" });
    } catch {
      enqueueSnackbar(t("projectMembers.permissionsSaveFailed", { defaultValue: "Failed to save permissions" }), { variant: "error" });
    } finally {
      setDirectPermSaving(false);
    }
  };

  // User fields in info dialog
  const [userFields, setUserFields] = React.useState<{ id: string; key: string; valueType: string; label?: string | null }[]>([]);
  const [userFieldValues, setUserFieldValues] = React.useState<Record<string, string>>({});
  const [userFieldEdits, setUserFieldEdits] = React.useState<Record<string, string>>({});
  const [userFieldEditing, setUserFieldEditing] = React.useState(false);
  const [userFieldSaving, setUserFieldSaving] = React.useState(false);

  const userFieldsUrl = selectedApp?.userPoolId
    ? `/admin/workspace/${project.workspaceId}/userPools/${selectedApp.userPoolId}/userFields`
    : "";

  const loadUserFields = React.useCallback(async (userId: string) => {
    if (!userFieldsUrl) return;
    try {
      const [fieldsRes, valuesRes] = await Promise.all([
        axios.get(userFieldsUrl),
        axios.get(`${userFieldsUrl}/values`, { params: { userId } }),
      ]);
      const fields = ((fieldsRes.data?.userFields ?? []) as UserField[]).filter((f) => f.status === "active");
      setUserFields(fields);

      type FieldValueRow = { userFieldId: string; value: unknown };
      const vals: Record<string, unknown> = {};
      const edits: Record<string, string> = {};
      for (const v of (valuesRes.data?.values ?? []) as FieldValueRow[]) {
        vals[v.userFieldId] = v.value;
      }
      for (const f of fields) {
        const raw = vals[f.id];
        edits[f.id] = raw !== undefined && raw !== null ? (typeof raw === "string" ? raw : JSON.stringify(raw)) : "";
      }
      setUserFieldValues(edits);
      setUserFieldEdits(edits);
      setUserFieldEditing(false);
    } catch {
      // non-critical
    }
  }, [userFieldsUrl]);

  const openInfoDialog = (member: WorkspaceMember) => {
    setInfoMember(member);
    setInfoOpen(true);
    setUserFields([]);
    setUserFieldValues({});
    setUserFieldEdits({});
    setUserFieldEditing(false);
    setDirectPermIds(new Set());
    setDirectPermEditing(false);
    setIdentities([]);
    void loadUserFields(member.accountId);
    if (selectedAppId) {
      void loadDirectPerms(member.accountId, selectedAppId);
      void loadIdentities(member.accountId, selectedAppId);
    }
  };

  const closeInfoDialog = () => {
    // Only trigger the exit animation here; clearing infoMember is deferred to
    // the Dialog's onExited so the content doesn't unmount mid-fade (which
    // leaves the static title flashing on its own).
    setInfoOpen(false);
  };

  const saveAllUserFields = async () => {
    if (!infoMember) return;
    setUserFieldSaving(true);
    try {
      for (const f of userFields) {
        if (userFieldEdits[f.id] === userFieldValues[f.id]) continue; // unchanged
        const jsonValue: string | boolean = f.valueType === "bool"
          ? userFieldEdits[f.id] === "true"
          : userFieldEdits[f.id];
        await axios.put(`${userFieldsUrl}/${f.id}/users/${infoMember.accountId}`, { value: jsonValue });
      }
      setUserFieldValues({ ...userFieldEdits });
      setUserFieldEditing(false);
      enqueueSnackbar(t("projectMembers.fieldsSaved", { defaultValue: "Fields saved" }), { variant: "success" });
    } catch {
      enqueueSnackbar(t("projectMembers.fieldsSaveFailed", { defaultValue: "Failed to save fields" }), { variant: "error" });
    } finally {
      setUserFieldSaving(false);
    }
  };

  const closeDialog = () => {
    setDialogOpen(false);
    setDialogMode("add");
    setDialogMember(null);
    setDialogSelectedMember(null);
    setDialogRoleIds(new Set());
    setDialogSendInvite(false);
    setDialogSaving(false);
    setErr(null);
  };

  const openAddDialog = async () => {
    if (!hasApps) {
      enqueueSnackbar(t("projectMembers.createAppFirst"), { variant: "warning" });
      return;
    }
    if (!hasRoles) {
      enqueueSnackbar(t("projectMembers.createRoleFirst"), { variant: "warning" });
      return;
    }

    setDialogMode("add");
    setDialogMember(null);
    setDialogSelectedMember(null);
    setDialogRoleIds(new Set());
    setDialogOpen(true);

  };

  const openEditDialog = (member: WorkspaceMember) => {
    if (!selectedAppId) return;

    setDialogMode("edit");
    setDialogMember(member);
    const current = rolesByAccountForSelectedApp.get(member.accountId) ?? [];
    setDialogRoleIds(new Set(current));
    setDialogOpen(true);
  };

  const openDeleteDialog = (member: WorkspaceMember) => {
    setDeleteMember(member);
    setDeleteOpen(true);
  };

  const closeDeleteDialog = () => {
    if (deleteLoading) return;
    setDeleteOpen(false);
    setDeleteMember(null);
  };

  const saveDialog = async () => {
    if (dialogMode === "add") {
      if (!dialogSelectedMember || !dialogSelectedMember.email) {
        enqueueSnackbar(t("projectMembers.enterEmail"), { variant: "warning" });
        return;
      }
      // Basic email validation
      const email = dialogSelectedMember.email.trim().toLowerCase();
      if (!email.includes("@") || !email.includes(".")) {
        enqueueSnackbar(t("projectMembers.validEmail"), { variant: "warning" });
        return;
      }
      // Roles are optional post user-pool refactor; the server adds the
      // app_users membership row regardless of role selection.
    } else {
      // edit mode still requires a single selected app
      if (!selectedAppId) {
        enqueueSnackbar(t("projectMembers.selectAppRequired"), { variant: "warning" });
        return;
      }
    }

    setErr(null);
    setDialogSaving(true);

    try {
      let accountId = dialogMember?.accountId ?? "";

      let inviteWarn: string | null = null;
      if (dialogMode === "add") {
        // Create-or-find user AND set their roles in one server-side
        // transaction. Roles are optional; the server creates the
        // app_users membership row either way and replaces any
        // existing role rows with the supplied set (empty = clear).
        const result = await createWorkspaceAccount(project.workspaceId, dialogSelectedMember!.email, selectedAppId, [...dialogRoleIds], dialogSendInvite);
        accountId = result.id;
        // The membership is created regardless; the invite email is
        // best-effort. Surface a failure instead of pretending success.
        if (dialogSendInvite && result.inviteEmailSent === false) {
          inviteWarn = result.inviteEmailError
            ? t("projectMembers.inviteEmailFailedReason", { reason: result.inviteEmailError, defaultValue: "User added, but the invite email failed: {{reason}}" })
            : t("projectMembers.inviteEmailFailed", { defaultValue: "User added, but the invite email could not be sent." });
        }
      } else {
        await setMemberRolesForApp(project, accountId, [...dialogRoleIds], selectedAppId);
      }

      // refresh roles + list
      const pmr = await getProductMemberRoles(project);
      setMemberRolesState(pmr);
      await refreshList();

      const message = dialogMode === "add"
        ? t("projectMembers.memberAdded", { count: 1 })
        : t("projectMembers.memberRolesSaved");
      enqueueSnackbar(message, { variant: "success" });
      if (inviteWarn) enqueueSnackbar(inviteWarn, { variant: "warning", autoHideDuration: 8000 });
      closeDialog();
    } catch (e) {
      const errMsg = extractApiError(e, t("projectMembers.failedToSave"));
      setErr(errMsg);
      enqueueSnackbar(errMsg, { variant: "error" });
    } finally {
      setDialogSaving(false);
    }
  };

  // Concurrency cap for the bulk loop: 5 in flight at a time. Sequential is
  // too slow at 200+ users; full parallel risks overwhelming rate limits.
  const BULK_CONCURRENCY = 5;

  const runBulkAction = async (idsOverride?: string[]) => {
    if (!bulkMode) return;
    if (bulkMode === "delete" && !selectedAppId) return;

    // Snapshot emails for nice error labels even if the row scrolls out.
    const emailById = new Map(projectMembers.map((m) => [m.accountId, m.email]));

    const ids = idsOverride ?? Array.from(selectedIds);
    if (ids.length === 0) return;

    setBulkLoading(true);
    setBulkProgress({ done: 0, total: ids.length, errors: [] });
    setErr(null);

    const failures: BulkError[] = [];
    let done = 0;

    for (let i = 0; i < ids.length; i += BULK_CONCURRENCY) {
      const chunk = ids.slice(i, i + BULK_CONCURRENCY);
      const results = await Promise.all(
        chunk.map(async (id): Promise<BulkError | null> => {
          try {
            if (bulkMode === "disable") {
              await setUserEnabled(project.workspaceId, id, false);
            } else if (bulkMode === "enable") {
              await setUserEnabled(project.workspaceId, id, true);
            } else if (bulkMode === "delete") {
              await removeAppMember(project, id, selectedAppId);
            }
            return null;
          } catch (e) {
            return {
              id,
              email: emailById.get(id) ?? id,
              message: extractApiError(e, t("projectMembers.bulkItemFailed", { defaultValue: "Failed" })),
            };
          }
        }),
      );

      for (const r of results) {
        done++;
        if (r) failures.push(r);
      }
      setBulkProgress({ done, total: ids.length, errors: [...failures] });
    }

    setBulkLoading(false);

    // Refresh data - even if some failed, the successes need to show.
    if (bulkMode === "delete") {
      try {
        const pmr = await getProductMemberRoles(project);
        setMemberRolesState(pmr);
      } catch {
        /* non-fatal */
      }
    }
    await refreshList();

    const verb = bulkMode === "disable"
      ? t("projectMembers.bulkVerbDisabled", { defaultValue: "disabled" })
      : bulkMode === "enable"
        ? t("projectMembers.bulkVerbEnabled", { defaultValue: "enabled" })
        : t("projectMembers.bulkVerbRemoved", { defaultValue: "removed" });
    const okCount = ids.length - failures.length;

    if (failures.length === 0) {
      enqueueSnackbar(t("projectMembers.bulkSuccess", { count: ids.length, verb, defaultValue: "{{count}} users {{verb}}" }), { variant: "success" });
      setBulkMode(null);
      clearSelection();
    } else {
      // Keep the dialog open so the user can see which users failed and
      // retry just those - the snackbar alone hides the detail.
      enqueueSnackbar(t("projectMembers.bulkPartialSnack", { ok: okCount, verb, fail: failures.length, defaultValue: "{{ok}} {{verb}}, {{fail}} failed" }), { variant: "warning" });
    }
  };

  const retryFailedBulk = () => {
    const failedIds = bulkProgress.errors.map((e) => e.id);
    if (failedIds.length === 0) return;
    runBulkAction(failedIds);
  };

  const closeBulkDialog = () => {
    if (bulkLoading) return;
    setBulkMode(null);
    setBulkProgress({ done: 0, total: 0, errors: [] });
    clearSelection();
  };

  const confirmDeleteMember = async () => {
    if (!deleteMember) return;
    if (!selectedAppId) return;

    setDeleteLoading(true);
    setErr(null);

    try {
      await removeAppMember(project, deleteMember.accountId, selectedAppId);

      const pmr = await getProductMemberRoles(project);
      setMemberRolesState(pmr);
      await refreshList();

      enqueueSnackbar(t("projectMembers.memberRemoved"), { variant: "success" });
      closeDeleteDialog();
    } catch (e) {
      setErr(extractApiError(e, t("projectMembers.failedToRemove")));
      enqueueSnackbar(t("projectMembers.failedToRemove"), { variant: "error" });
    } finally {
      setDeleteLoading(false);
    }
  };


  const handleApplySearch = () => {
    setMemberPage(0);
    setMemberSearchApplied(memberSearchDraft.trim());
  };

  const handleClearSearch = () => {
    setMemberSearchDraft("");
    setMemberPage(0);
    setMemberSearchApplied("");
  };

  const appOptions = React.useMemo(() => {
    return apps
      .slice()
      .sort((a, b) => appTypeLabel(a).localeCompare(appTypeLabel(b)));
  }, [apps]);

  // === Export / Import ===
  type ImportPreview = { filename: string; users: ImportUser[]; toCreate: number; toUpdate: number };
  type ImportError = { email: string; reason: string };
  type ImportResult = { imported: number; failed: number; errors: ImportError[] };

  const fileInputRef = React.useRef<HTMLInputElement>(null);
  const [importing, setImporting] = React.useState(false);
  const [exporting, setExporting] = React.useState(false);
  const [importPreview, setImportPreview] = React.useState<ImportPreview | null>(null);
  const [importProgress, setImportProgress] = React.useState<{ current: number; total: number } | null>(null);
  const [importResult, setImportResult] = React.useState<ImportResult | null>(null);

  const handleExport = async () => {
    if (!selectedAppId) return;
    const poolId = selectedApp?.userPoolId;
    setExporting(true);
    try {
      // Fetch all members, fresh roles, permissions, and field schemas in parallel
      const [{ members: allMembers }, pmr, permsRes, fieldsRes] = await Promise.all([
        getProductMembersPaged(project, selectedAppId, 0, 10000, ""),
        getProductMemberRoles(project),
        axios.get(`/admin/workspace/${project.workspaceId}/products/${project.id}/permissions`),
        poolId
          ? axios.get(`/admin/workspace/${project.workspaceId}/userPools/${poolId}/userFields`)
          : Promise.resolve({ data: { userFields: [] } }),
      ]);
      const permsRaw = (permsRes.data?.permissions ?? []) as Permission[];
      const permissionsList: { id: string; slug: string }[] = permsRaw.map((p) => ({ id: p.id, slug: p.slug }));
      const permById = new Map(permissionsList.map((p) => [p.id, p.slug]));

      // Build fresh role map for this app
      const freshRolesByAccount = new Map<string, string[]>();
      for (const mr of pmr) {
        if (mr.appId !== selectedAppId) continue;
        const cur = freshRolesByAccount.get(mr.userId) ?? [];
        cur.push(mr.roleId);
        freshRolesByAccount.set(mr.userId, cur);
      }

      const fields = ((fieldsRes.data?.userFields ?? []) as UserField[]).filter((f) => f.status === "active");

      // Fetch field values per user (batched in groups of 10 to avoid overwhelming the server)
      const exportData: Record<string, unknown>[] = [];
      for (let i = 0; i < allMembers.length; i += 10) {
        const batch = allMembers.slice(i, i + 10);
        const batchResults = await Promise.all(batch.map(async (m) => {
          const roleIds = freshRolesByAccount.get(m.accountId) ?? [];
          const roleSlugs = roleIds.map((id) => roleById.get(id)?.slug ?? id);
          let directPermSlugs: string[] = [];
          const fieldValues: Record<string, unknown> = {};

          // Fetch direct permissions
          try {
            const dpRes = await axios.get(`/admin/workspace/${project.workspaceId}/products/${project.id}/memberPermissions/${m.accountId}`, { params: { appId: selectedAppId } });
            const dpIds: string[] = dpRes.data?.permissionIds ?? [];
            directPermSlugs = dpIds.map((id) => permById.get(id) ?? id).filter(Boolean) as string[];
          } catch { /* skip on error */ }

          // Fetch user field values
          if (fields.length > 0 && poolId) {
            try {
              const valRes = await axios.get(`/admin/workspace/${project.workspaceId}/userPools/${poolId}/userFields/values`, { params: { userId: m.accountId } });
              type FieldValueRow = { userFieldId: string; value?: unknown };
              const vals = (valRes.data?.values ?? []) as FieldValueRow[];
              for (const f of fields) {
                const v = vals.find((val) => val.userFieldId === f.id);
                if (v !== undefined && v.value !== undefined) fieldValues[f.key] = v.value;
              }
            } catch { /* skip field values on error */ }
          }
          return buildExportEntry(m, roleSlugs, directPermSlugs, fieldValues);
        }));
        exportData.push(...batchResults);
      }

      const json = JSON.stringify(exportData, null, 2);
      const blob = new Blob([json], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const appName = appTypeLabel(selectedApp) || "app";
      a.download = buildExportFilename(project.name, appName, new Date());
      a.click();
      URL.revokeObjectURL(url);
      enqueueSnackbar(t("projectMembers.exportSuccess", { count: exportData.length, defaultValue: "Exported {{count}} users" }), { variant: "success" });
    } catch {
      enqueueSnackbar(t("projectMembers.exportFailed", { defaultValue: "Failed to export users" }), { variant: "error" });
    } finally {
      setExporting(false);
    }
  };

  // Step 1: parse file, compute preview (how many will be created vs updated), show dialog.
  const handleImportFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !selectedAppId) return;
    e.target.value = ""; // allow re-selecting the same file later

    setImporting(true);
    try {
      const text = await file.text();
      const users = parseUsersJson(text);

      if (users.length === 0) {
        enqueueSnackbar(t("projectMembers.importNoUsers", { defaultValue: "No users found in file" }), { variant: "warning" });
        return;
      }

      // Fetch existing members so we can count create vs. update before touching anything.
      const { members: existing } = await getProductMembersPaged(project, selectedAppId, 0, 10000, "");
      const existingEmailsLower = new Set(existing.map((m) => m.email.toLowerCase()));
      const { toCreate, toUpdate } = computeImportPreview(users, existingEmailsLower);

      setImportPreview({ filename: file.name, users, toCreate, toUpdate });
    } catch {
      enqueueSnackbar(t("projectMembers.importInvalidJson", { defaultValue: "Invalid JSON file" }), { variant: "error" });
    } finally {
      setImporting(false);
    }
  };

  // Step 2: user confirmed preview. Actually run the import, tracking progress + per-row errors.
  const runImport = async () => {
    if (!importPreview || !selectedAppId) return;
    const users = importPreview.users;

    setImportProgress({ current: 0, total: users.length });

    // Load field schemas + permissions once for slug-to-ID resolution.
    let fieldSchemas: { id: string; key: string }[] = [];
    let permissionsList: { id: string; slug: string }[] = [];
    const hasFields = users.some((u) => u.fields && Object.keys(u.fields).length > 0);
    const hasPerms = users.some((u) => u.permissions && u.permissions.length > 0);
    const preloadPromises: Promise<void>[] = [];
    const importPoolId = selectedApp?.userPoolId;
    if (hasFields && importPoolId) {
      preloadPromises.push(
        axios.get(`/admin/workspace/${project.workspaceId}/userPools/${importPoolId}/userFields`)
          .then((res) => { fieldSchemas = ((res.data?.userFields ?? []) as UserField[]).filter((f) => f.status === "active"); })
          .catch(() => {}),
      );
    }
    if (hasPerms) {
      preloadPromises.push(
        axios.get(`/admin/workspace/${project.workspaceId}/products/${project.id}/permissions`)
          .then((res) => {
            const list = (res.data?.permissions ?? []) as Permission[];
            permissionsList = list.map((p) => ({ id: p.id, slug: p.slug }));
          })
          .catch(() => {}),
      );
    }
    await Promise.all(preloadPromises);

    const errors: ImportError[] = [];
    let imported = 0;

    for (let i = 0; i < users.length; i++) {
      const u = users[i];
      const email = u.email || "(no email)";
      try {
        if (!u.email) throw new Error("missing email");
        const importRoleIds = (u.roles ?? [])
          .map((slug) => roles.find((r) => r.slug === slug)?.id)
          .filter(Boolean) as string[];
        const result = await createWorkspaceAccount(project.workspaceId, u.email, selectedAppId, importRoleIds);
        if (u.enabled === false) {
          await setUserEnabled(project.workspaceId, result.id, false);
        }
        if (u.permissions && u.permissions.length > 0 && permissionsList.length > 0) {
          const permIds = u.permissions
            .map((slug) => permissionsList.find((p) => p.slug === slug)?.id)
            .filter(Boolean) as string[];
          if (permIds.length > 0) {
            await axios.put(
              `/admin/workspace/${project.workspaceId}/products/${project.id}/memberPermissions/${result.id}`,
              { appId: selectedAppId, permissionIds: permIds },
            );
          }
        }
        if (u.fields && fieldSchemas.length > 0 && importPoolId) {
          for (const [key, value] of Object.entries(u.fields)) {
            const field = fieldSchemas.find((f) => f.key === key);
            if (field) {
              await axios.put(
                `/admin/workspace/${project.workspaceId}/userPools/${importPoolId}/userFields/${field.id}/users/${result.id}`,
                { value },
              );
            }
          }
        }
        imported++;
      } catch (err) {
        errors.push({ email, reason: extractErrorReason(err) });
      }
      setImportProgress({ current: i + 1, total: users.length });
    }

    setImportPreview(null);
    setImportProgress(null);
    setImportResult({ imported, failed: errors.length, errors });
    await refreshCore();
  };

  const addDisabled = !hasApps || !hasRoles;
  const addTooltip = !hasApps
    ? t("projectMembers.createAppFirst")
    : !hasRoles
      ? t("projectMembers.createRoleFirst")
      : t("projectMembers.addToApps");

  return (
    <Box>
      <Stack spacing={2.5}>
        {/* Header */}
        <Stack direction="row" alignItems="flex-end" spacing={1.5} sx={{ flexWrap: "wrap", gap: 1 }}>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 0.5 }}>
              <Box sx={{ width: 28, height: 2, bgcolor: "primary.main", borderRadius: 1, flexShrink: 0 }} />
              <Typography
                sx={{
                  fontFamily: "var(--font-serif)",
                  fontSize: 28,
                  fontWeight: 500,
                  letterSpacing: "-0.025em",
                  lineHeight: 1.2,
                  fontOpticalSizing: "auto",
                  pb: "2px",
                }}
              >
                {t("projectMembers.title")}
              </Typography>
              <Chip
                size="small"
                label={projectMembersTotal === 1 ? t("projectMembers.count", { count: projectMembersTotal }) : t("projectMembers.countPlural", { count: projectMembersTotal })}
                variant="outlined"
                sx={{
                  height: 20,
                  fontSize: 10.5,
                  fontWeight: 500,
                  fontFamily: "var(--font-mono)",
                }}
              />
            </Stack>
            {selectedApp?.userPoolName && (
              // Show which pool these users live in. Multiple apps
              // can point at the same pool (SSO between products);
              // surfacing the name + a link to the pools page is the
              // operator's signal that "Users here = Users in pool X".
              <Stack direction="row" spacing={0.75} alignItems="center" sx={{ mt: 0.25, ml: 4.75 }}>
                <Typography variant="caption" color="text.disabled" sx={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>
                  {t("projectMembers.poolLabel", { defaultValue: "pool" })}
                </Typography>
                <RouterLink
                  to={`/app/workspace/${project.workspaceId}/userPools`}
                  style={{ color: "inherit", textDecoration: "none" }}
                >
                  <Typography
                    variant="caption"
                    sx={{
                      fontSize: 12,
                      color: "primary.main",
                      "&:hover": { textDecoration: "underline" },
                    }}
                  >
                    {selectedApp.userPoolName}
                  </Typography>
                </RouterLink>
              </Stack>
            )}
          </Box>
          <Tooltip title={t("projectMembers.refresh")}>
            <span>
              <IconButton size="small" onClick={refreshList} disabled={loading || !selectedAppId}>
                <RefreshCw size={14} strokeWidth={1.75} />
              </IconButton>
            </span>
          </Tooltip>
          <Tooltip title={t("projectMembers.exportTooltip", { defaultValue: "Export users as JSON" })}>
            <span>
              <IconButton size="small" onClick={handleExport} disabled={!selectedAppId || loading || exporting}>
                {exporting ? <CircularProgress size={16} /> : <FileDown size={14} strokeWidth={1.75} />}
              </IconButton>
            </span>
          </Tooltip>
          <Tooltip title={t("projectMembers.importTooltip", { defaultValue: "Import users from JSON" })}>
            <span>
              <IconButton size="small" onClick={() => fileInputRef.current?.click()} disabled={!selectedAppId || loading || importing}>
                {importing ? <CircularProgress size={16} /> : <FileUp size={14} strokeWidth={1.75} />}
              </IconButton>
            </span>
          </Tooltip>
          <input ref={fileInputRef} type="file" accept=".json" hidden onChange={handleImportFileSelect} />
          <Tooltip title={addTooltip}>
            <span>
              <Button
                size="small"
                variant="contained"
                startIcon={<Plus size={14} strokeWidth={1.75} />}
                onClick={openAddDialog}
                disableElevation
                disabled={addDisabled}
                sx={{ borderRadius: 2, textTransform: "none" }}
              >
                {t("projectMembers.addMember")}
              </Button>
            </span>
          </Tooltip>
        </Stack>

        {/* App selector - only shown when app is not fixed via prop */}
        {!fixedApp && (
          loading ? null : !hasApps ? (
            <Paper variant="outlined" sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha("rgb(251, 191, 36)", 0.04) }}>
              <Stack direction="row" spacing={2} alignItems="center">
                <Box
                  sx={{
                    width: 40,
                    height: 40,
                    borderRadius: 2,
                    bgcolor: alpha("rgb(251, 191, 36)", 0.12),
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}
                >
                  <Box component="span" sx={{ color: "warning.main", fontSize: 20 }}><Layers size={14} strokeWidth={1.75} /></Box>
                </Box>
                <Box sx={{ flex: 1 }}>
                  <Typography sx={{ fontWeight: 500 }}>{t("projectMembers.noApps")}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {t("projectMembers.noAppDesc")}
                  </Typography>
                </Box>
                <Button size="small" variant="outlined" onClick={goApps} sx={{ borderRadius: 2, textTransform: "none" }}>
                  {t("projectMembers.createApp")}
                </Button>
              </Stack>
            </Paper>
          ) : (
            <Paper variant="outlined" sx={{ p: 2, borderRadius: 2 }}>
              <Stack direction={{ xs: "column", sm: "row" }} spacing={2} alignItems={{ sm: "center" }}>
                <Stack direction="row" spacing={1.5} alignItems="center">
                  <Box component="span" sx={{ color: "text.secondary", fontSize: 20 }}><Layers size={14} strokeWidth={1.75} /></Box>
                  <Typography sx={{ fontSize: 14, fontWeight: 500 }}>{t("projectMembers.app")}</Typography>
                </Stack>
                <FormControl size="small" sx={{ minWidth: 240 }}>
                  <Select
                    value={selectedAppId}
                    onChange={(e) => {
                      const next = String(e.target.value || "");
                      setSelectedAppId(next);
                      setMemberPage(0);
                    }}
                    displayEmpty
                  >
                    {appOptions.map((app) => (
                      <MenuItem key={app.id} value={app.id}>
                        <Typography variant="body2">{appTypeLabel(app)}</Typography>
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
                <Typography variant="body2" color="text.secondary" sx={{ display: { xs: "none", md: "block" } }}>
                  {t("projectMembers.perApp")}
                </Typography>
              </Stack>
            </Paper>
          )
        )}

        {/* Search controls - inline */}
        {selectedAppId && (
          <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap", alignItems: "center" }}>
            <TextField
              size="small"
              value={memberSearchDraft}
              onChange={(e) => setMemberSearchDraft(e.target.value)}
              placeholder={t("projectMembers.searchPlaceholder")}
              inputMode="email"
              sx={{ maxWidth: 320, flex: 1 }}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  handleApplySearch();
                }
              }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Box component="span" sx={{ color: "text.disabled" }}><Search size={14} strokeWidth={1.75} /></Box>
                  </InputAdornment>
                ),
                endAdornment: memberSearchDraft ? (
                  <InputAdornment position="end">
                    <Stack direction="row" spacing={0.5} alignItems="center">
                      {draftDiffers && (
                        <Button size="small" onClick={handleApplySearch} sx={{ minWidth: 0, px: 1, textTransform: "none" }}>
                          {t("projectMembers.searchBtn")}
                        </Button>
                      )}
                      <IconButton size="small" onClick={handleClearSearch} aria-label={t("projectMembers.clearSearch")}>
                        <X size={14} strokeWidth={1.75} />
                      </IconButton>
                    </Stack>
                  </InputAdornment>
                ) : undefined,
              }}
            />
            <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap" }}>
              <Chip
                size="small"
                label={t("projectMembers.filterAll", { defaultValue: "All" })}
                color={inactiveFilterDays === 0 ? "primary" : "default"}
                variant={inactiveFilterDays === 0 ? "filled" : "outlined"}
                onClick={() => { setInactiveFilterDays(0); setMemberPage(0); }}
              />
              <Chip
                size="small"
                label={t("projectMembers.filterInactive30d", { defaultValue: "Inactive 30d+" })}
                color={inactiveFilterDays === 30 ? "primary" : "default"}
                variant={inactiveFilterDays === 30 ? "filled" : "outlined"}
                onClick={() => { setInactiveFilterDays(30); setMemberPage(0); }}
              />
              <Chip
                size="small"
                label={t("projectMembers.filterInactive60d", { defaultValue: "60d+" })}
                color={inactiveFilterDays === 60 ? "primary" : "default"}
                variant={inactiveFilterDays === 60 ? "filled" : "outlined"}
                onClick={() => { setInactiveFilterDays(60); setMemberPage(0); }}
              />
              <Chip
                size="small"
                label={t("projectMembers.filterInactive90d", { defaultValue: "90d+" })}
                color={inactiveFilterDays === 90 ? "primary" : "default"}
                variant={inactiveFilterDays === 90 ? "filled" : "outlined"}
                onClick={() => { setInactiveFilterDays(90); setMemberPage(0); }}
              />
              <Select
                size="small"
                value={enabledFilter}
                onChange={(e) => {
                  setEnabledFilter((e.target.value || "") as EnabledFilter);
                  setMemberPage(0);
                }}
                displayEmpty
                sx={{ height: 30, minWidth: 130, ml: 0.5, fontSize: 13 }}
              >
                <MenuItem value="">
                  {t("projectMembers.filterStatusAll", { defaultValue: "Any status" })}
                </MenuItem>
                <MenuItem value="enabled">
                  {t("projectMembers.filterEnabled", { defaultValue: "Enabled" })}
                </MenuItem>
                <MenuItem value="disabled">
                  {t("projectMembers.filterDisabled", { defaultValue: "Disabled" })}
                </MenuItem>
              </Select>
              <Select
                size="small"
                value={roleFilter}
                onChange={(e) => {
                  setRoleFilter(String(e.target.value || "") as RoleFilter);
                  setMemberPage(0);
                }}
                displayEmpty
                sx={{ height: 30, minWidth: 150, fontSize: 13 }}
              >
                <MenuItem value="">
                  {t("projectMembers.filterRoleAll", { defaultValue: "Any role" })}
                </MenuItem>
                <MenuItem value="without">
                  {t("projectMembers.filterRoleWithout", { defaultValue: "No role" })}
                </MenuItem>
                {roles.length > 0 && <Divider sx={{ my: 0.5 }} />}
                {roles
                  .slice()
                  .sort((a, b) => a.name.localeCompare(b.name))
                  .map((r) => (
                    <MenuItem key={r.id} value={r.id}>
                      {r.name}
                    </MenuItem>
                  ))}
              </Select>
            </Stack>
          </Stack>
        )}

        {err && <Alert severity="error">{err}</Alert>}

        {loading ? (
          <Paper variant="outlined" sx={{ p: 4, borderRadius: 2, textAlign: "center" }}>
            <CircularProgress size={24} sx={{ mb: 1 }} />
            <Typography variant="body2" color="text.secondary">
              {t("projectMembers.loading")}
            </Typography>
          </Paper>
        ) : !selectedAppId ? (
          <EmptyState
            icon={<Users size={18} strokeWidth={1.75} />}
            title={t("projectMembers.selectApp")}
          />
        ) : !hasRoles ? (
          <Paper variant="outlined" sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha("rgb(251, 191, 36)", 0.04) }}>
            <Stack direction="row" spacing={2} alignItems="center">
              <Box
                sx={{
                  width: 40,
                  height: 40,
                  borderRadius: 2,
                  bgcolor: alpha("rgb(251, 191, 36)", 0.12),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <Box component="span" sx={{ color: "warning.main", fontSize: 20 }}><Users size={14} strokeWidth={1.75} /></Box>
              </Box>
              <Box sx={{ flex: 1 }}>
                <Typography sx={{ fontWeight: 500 }}>{t("projectMembers.noRoles")}</Typography>
                <Typography variant="body2" color="text.secondary">
                  {t("projectMembers.noRolesDesc")}
                </Typography>
              </Box>
              <Button size="small" variant="outlined" onClick={goRoles} sx={{ borderRadius: 2, textTransform: "none" }}>
                {t("projectMembers.createRole")}
              </Button>
            </Stack>
          </Paper>
        ) : projectMembers.length === 0 ? (
          <Paper variant="outlined" sx={{ p: 3, borderRadius: 2, textAlign: "center" }}>
            {searchActive ? (
              <Stack spacing={1.5} alignItems="center">
                <Box component="span" sx={{ fontSize: 48, color: "text.disabled" }}><Search size={14} strokeWidth={1.75} /></Box>
                <Typography color="text.secondary">
                  <Trans i18nKey="projectMembers.noMatch" values={{ query: memberSearchApplied, app: appTypeLabel(selectedApp) }} components={tc} />
                </Typography>
                <Button size="small" variant="outlined" onClick={handleClearSearch} sx={{ borderRadius: 2, textTransform: "none" }}>
                  {t("projectMembers.clearSearch")}
                </Button>
              </Stack>
            ) : (
              <Stack spacing={1.5} alignItems="center">
                <Box component="span" sx={{ fontSize: 48, color: "text.disabled" }}><Users size={14} strokeWidth={1.75} /></Box>
                <Typography color="text.secondary">
                  <Trans i18nKey="projectMembers.noMembersInEnv" values={{ app: appTypeLabel(selectedApp) }} components={tc} />
                </Typography>
                <Button
                  size="small"
                  variant="contained"
                  startIcon={<Plus size={14} strokeWidth={1.75} />}
                  onClick={openAddDialog}
                  disableElevation
                  sx={{ borderRadius: 2, textTransform: "none" }}
                >
                  {t("projectMembers.addFirstMember")}
                </Button>
              </Stack>
            )}
          </Paper>
        ) : (
          <>
            {selectedIds.size > 0 && (
              <Paper
                variant="outlined"
                sx={{
                  p: 1.25,
                  mb: 1,
                  display: "flex",
                  alignItems: "center",
                  gap: 1,
                  flexWrap: "wrap",
                  bgcolor: "action.hover",
                  borderRadius: 2,
                }}
              >
                <Typography variant="body2" sx={{ fontWeight: 600, mr: 1 }}>
                  {t("projectMembers.bulkSelected", { defaultValue: "{{count}} selected", count: selectedIds.size })}
                </Typography>
                <Button size="small" variant="outlined" onClick={() => setBulkMode("disable")}>
                  {t("projectMembers.bulkDisable", { defaultValue: "Disable" })}
                </Button>
                <Button size="small" variant="outlined" onClick={() => setBulkMode("enable")}>
                  {t("projectMembers.bulkEnable", { defaultValue: "Enable" })}
                </Button>
                <Button size="small" variant="outlined" color="error" onClick={() => setBulkMode("delete")}>
                  {t("projectMembers.bulkRemove", { defaultValue: "Remove from app" })}
                </Button>
                <Box sx={{ flex: 1 }} />
                <Button size="small" onClick={clearSelection}>
                  {t("common.clear", { defaultValue: "Clear" })}
                </Button>
              </Paper>
            )}
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell padding="checkbox">
                    <Checkbox
                      size="small"
                      indeterminate={selectedIds.size > 0 && selectedIds.size < projectMembers.length}
                      checked={projectMembers.length > 0 && selectedIds.size === projectMembers.length}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedIds(new Set(projectMembers.map((m) => m.accountId)));
                        } else {
                          clearSelection();
                        }
                      }}
                    />
                  </TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{t("auth.email")}</TableCell>
                  <TableCell sx={{ fontWeight: 600, width: 160 }}>{t("projectMembers.userId", "ID")}</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{t("projectMembers.roles", "Roles")}</TableCell>
                  <TableCell sx={{ fontWeight: 600, width: 110 }}>{t("projectMembers.lastLogin", "Last Login")}</TableCell>
                  <TableCell sx={{ fontWeight: 600, width: 90 }}>{t("projectMembers.source", { defaultValue: "Source" })}</TableCell>
                  <TableCell sx={{ fontWeight: 600, width: 50 }} align="center">{t("projectMembers.auth", "Auth")}</TableCell>
                  <TableCell sx={{ fontWeight: 600, width: 70 }} align="center">{t("projectMembers.sessions", { defaultValue: "Sessions" })}</TableCell>
                  <TableCell sx={{ fontWeight: 600, width: 90 }} align="center">{t("projectMembers.failures7d", { defaultValue: "Fails (7d)" })}</TableCell>
                  <TableCell sx={{ fontWeight: 600, width: 80 }}>{t("projectMembers.status", "Status")}</TableCell>
                  <TableCell sx={{ fontWeight: 600, width: 100 }} />
                </TableRow>
              </TableHead>
              <TableBody>
                {projectMembers.map((m) => {
                  const roleIds = rolesByAccountForSelectedApp.get(m.accountId) ?? [];
                  const roleChips = roleIds.map((rid) => roleById.get(rid)).filter(Boolean) as Role[];

                  return (
                    <TableRow
                      key={m.accountId}
                      hover
                      sx={{ cursor: "pointer" }}
                      onClick={() => openInfoDialog(m)}
                      selected={selectedIds.has(m.accountId)}
                    >
                      <TableCell padding="checkbox" onClick={(e) => e.stopPropagation()}>
                        <Checkbox
                          size="small"
                          checked={selectedIds.has(m.accountId)}
                          onChange={() => toggleSelect(m.accountId)}
                        />
                      </TableCell>
                      <TableCell>
                        <Stack spacing={0.25}>
                          <Typography variant="body2" noWrap title={m.email}>
                            {m.email}
                          </Typography>
                          {m.tags && m.tags.length > 0 && (
                            <Stack direction="row" spacing={0.25} sx={{ flexWrap: "wrap", gap: 0.25 }}>
                              {m.tags.slice(0, 3).map((tag) => (
                                <Chip
                                  key={tag}
                                  size="small"
                                  label={tag}
                                  variant="outlined"
                                  sx={{ height: 16, fontSize: 9, "& .MuiChip-label": { px: 0.75 } }}
                                />
                              ))}
                              {m.tags.length > 3 && (
                                <Typography variant="caption" color="text.disabled" sx={{ fontSize: 9, alignSelf: "center" }}>
                                  +{m.tags.length - 3}
                                </Typography>
                              )}
                            </Stack>
                          )}
                        </Stack>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption" color="text.disabled" noWrap title={m.accountId} sx={{ fontFamily: "var(--font-mono)", fontSize: "0.7rem" }}>
                          {m.accountId}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        {roleChips.length === 0 ? (
                          <Chip
                            size="small"
                            label={t("projectMembers.noRolesChip")}
                            sx={{
                              height: 22,
                              fontSize: 11,
                              bgcolor: alpha("rgb(239, 68, 68)", 0.08),
                              color: "error.main",
                              border: "none",
                            }}
                          />
                        ) : (
                          <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                            {roleChips
                              .slice()
                              .sort((a, b) => a.name.localeCompare(b.name))
                              .map((r) => (
                                <Chip
                                  key={r.id}
                                  size="small"
                                  label={r.name}
                                  sx={{
                                    height: 22,
                                    fontSize: 11,
                                    bgcolor: "action.selected",
                                    color: "primary.main",
                                    border: "none",
                                  }}
                                />
                              ))}
                          </Stack>
                        )}
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption" color="text.secondary" noWrap>
                          {m.lastLoginAt ? new Date(m.lastLoginAt).toLocaleDateString() : "-"}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        {m.source ? (
                          <Chip
                            size="small"
                            label={sourceLabel(m.source)}
                            variant="outlined"
                            sx={{ height: 20, fontSize: 10 }}
                          />
                        ) : (
                          <Typography variant="caption" color="text.disabled">-</Typography>
                        )}
                      </TableCell>
                      <TableCell align="center">
                        <Stack direction="row" spacing={0.25} justifyContent="center">
                          <Tooltip title={m.emailVerifiedAt ? t("projectMembers.emailVerified", "Email verified") : t("projectMembers.emailNotVerified", "Email not verified")}>
                            <Box component="span" sx={{ fontSize: 16, color: m.emailVerifiedAt ? "success.main" : "text.disabled" }}>
                              {(m.emailVerifiedAt) ? <CircleCheck size={14} strokeWidth={1.75} /> : <CircleX size={14} strokeWidth={1.75} />}
                            </Box>
                          </Tooltip>
                          {m.passwordSetAt && (
                            <Tooltip title={t("projectMembers.passwordSet", "Password set")}>
                              <Box component="span" sx={{ fontSize: 16, color: "success.main" }}>
                                <Lock size={14} strokeWidth={1.75} />
                              </Box>
                            </Tooltip>
                          )}
                        </Stack>
                      </TableCell>
                      <TableCell align="center">
                        <Typography
                          variant="caption"
                          color={(m.activeSessions ?? 0) > 0 ? "text.primary" : "text.disabled"}
                          sx={{ fontWeight: (m.activeSessions ?? 0) > 0 ? 600 : 400 }}
                        >
                          {m.activeSessions ?? 0}
                        </Typography>
                      </TableCell>
                      <TableCell align="center">
                        {(m.loginFailures7d ?? 0) > 0 ? (
                          <Chip
                            size="small"
                            label={m.loginFailures7d}
                            color="error"
                            variant="outlined"
                            sx={{ height: 20, minWidth: 28, fontSize: 11, fontWeight: 600 }}
                          />
                        ) : (
                          <Typography variant="caption" color="text.disabled">-</Typography>
                        )}
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={m.enabled !== false ? t("projectMembers.enabled", "Enabled") : t("projectMembers.disabled", "Disabled")}
                          variant={m.enabled !== false ? "filled" : "outlined"}
                          sx={
                            m.enabled !== false
                              ? {
                                  height: 22,
                                  fontSize: 11,
                                  // override the global filled-chip neutral so
                                  // Enabled stands out against the warm palette
                                  bgcolor: "success.main",
                                  color: "#fff",
                                }
                              : {
                                  height: 22,
                                  fontSize: 11,
                                  borderColor: "error.main",
                                  color: "error.main",
                                }
                          }
                        />
                      </TableCell>
                      <TableCell>
                        <Stack direction="row" spacing={0.5}>
                          <Tooltip title={t("projectMembers.viewActivity", { defaultValue: "View activity" })}>
                            <span>
                              <IconButton
                                size="small"
                                disabled={!currentAppId}
                                onClick={(e) => { e.stopPropagation(); if (currentAppId) openActivityDialog(m.accountId, m.email); }}
                              >
                                <Activity size={14} strokeWidth={1.75} />
                              </IconButton>
                            </span>
                          </Tooltip>
                          <Tooltip title={t("projectMembers.editTags", { defaultValue: "Edit tags" })}>
                            <span>
                              <IconButton
                                size="small"
                                disabled={!currentAppId}
                                onClick={(e) => { e.stopPropagation(); if (currentAppId) openTagsDialog(m); }}
                              >
                                <Tag size={14} strokeWidth={1.75} />
                              </IconButton>
                            </span>
                          </Tooltip>
                          <Tooltip title={t("projectMembers.editRoles")}>
                            <IconButton size="small" onClick={(e) => { e.stopPropagation(); openEditDialog(m); }}>
                              <SquarePen size={14} strokeWidth={1.75} />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title={t("projectMembers.removeFromApp")}>
                            <IconButton size="small" color="error" onClick={(e) => { e.stopPropagation(); openDeleteDialog(m); }}>
                              <Trash2 size={14} strokeWidth={1.75} />
                            </IconButton>
                          </Tooltip>
                        </Stack>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            <TablePagination
              component="div"
              count={projectMembersTotal}
              page={memberPage}
              onPageChange={(_, next) => setMemberPage(next)}
              rowsPerPage={membersPerPage}
              onRowsPerPageChange={(e) => {
                const next = parseInt(e.target.value, 10);
                setMembersPerPage(Number.isFinite(next) ? next : 25);
                setMemberPage(0);
              }}
              rowsPerPageOptions={[25, 50, 100]}
              labelRowsPerPage={t("projectMembers.perPage")}
            />
          </TableContainer>
          </>
        )}
      </Stack>

      <MemberRolesDialog
        open={dialogOpen}
        mode={dialogMode}
        appName={appTypeLabel(selectedApp) || t("projectMembers.app")}
        workspaceId={project.workspaceId}
        poolId={selectedApp?.userPoolId || ""}
        selectedMemberToAdd={dialogSelectedMember}
        setSelectedMemberToAdd={setDialogSelectedMember}
        member={dialogMember}
        roles={roles}
        selectedRoleIds={dialogRoleIds}
        setSelectedRoleIds={setDialogRoleIds}
        onClose={closeDialog}
        onSave={saveDialog}
        saving={dialogSaving}
        requireRoleSelectionToSave={false}
        sendInvite={dialogSendInvite}
        setSendInvite={setDialogSendInvite}
        appUrl={appUrl}
        t={t}
      />

      <ConfirmRemoveMemberDialog
        open={deleteOpen}
        member={deleteMember}
        onClose={closeDeleteDialog}
        onConfirm={confirmDeleteMember}
        loading={deleteLoading}
        t={t}
      />

      {/* User info dialog */}
      <Dialog
        open={infoOpen}
        onClose={closeInfoDialog}
        fullWidth
        maxWidth="sm"
        TransitionProps={{ onExited: () => setInfoMember(null) }}
      >
        <DialogTitle>{t("projectMembers.userInfo", "User Info")}</DialogTitle>
        <DialogContent>
          {infoMember && (
            <Stack spacing={2} sx={{ pt: 1 }}>
              <Stack direction="row" spacing={1}>
                <Button
                  variant="outlined"
                  size="small"
                  onClick={() => {
                    closeInfoDialog();
                    const path = window.location.pathname.replace(/\/members$/, "/sessions");
                    navigate(`${path}?email=${encodeURIComponent(infoMember.email)}`);
                  }}
                  sx={{ textTransform: "none", fontSize: 12 }}
                >
                  {t("projectMembers.viewSessions", "Sessions")}
                </Button>
                <Button
                  variant="outlined"
                  size="small"
                  onClick={() => {
                    closeInfoDialog();
                    // Reuse the AuthLogs page with a subjectUserId pre-filter.
                    // Same pattern as Sessions above - keeps the per-user view
                    // a deep-link to the main page rather than a duplicate
                    // table inside this dialog.
                    const path = window.location.pathname.replace(/\/members$/, "/auth-logs");
                    navigate(`${path}?subjectUserId=${encodeURIComponent(infoMember.accountId)}`);
                  }}
                  sx={{ textTransform: "none", fontSize: 12 }}
                >
                  {t("projectMembers.viewAuthActivity", "Auth activity")}
                </Button>
                <Button
                  variant="outlined"
                  size="small"
                  onClick={() => { closeInfoDialog(); openEditDialog(infoMember); }}
                  sx={{ textTransform: "none", fontSize: 12 }}
                >
                  {t("projectMembers.editRoles")}
                </Button>
              </Stack>

              <Divider />

              <Stack spacing={0.5}>
                <Typography variant="caption" color="text.secondary">{t("auth.email")}</Typography>
                <Typography variant="body2">{infoMember.email}</Typography>
              </Stack>

              <Stack spacing={0.5}>
                <Typography variant="caption" color="text.secondary">{t("projectMembers.userId", "ID")}</Typography>
                <Typography variant="body2" sx={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem" }}>{infoMember.accountId}</Typography>
              </Stack>

              <Divider />

              <Stack direction="row" spacing={3}>
                <Stack spacing={0.5}>
                  <Typography variant="caption" color="text.secondary">{t("projectMembers.emailVerifiedLabel", "Email Verified")}</Typography>
                  <Typography variant="body2">
                    {infoMember.emailVerifiedAt ? new Date(infoMember.emailVerifiedAt).toLocaleString() : "-"}
                  </Typography>
                </Stack>
                <Stack spacing={0.5}>
                  <Typography variant="caption" color="text.secondary">{t("projectMembers.passwordSetLabel", "Password Set")}</Typography>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <Typography variant="body2">
                      {infoMember.passwordSetAt ? new Date(infoMember.passwordSetAt).toLocaleString() : "-"}
                    </Typography>
                    {infoMember.passwordSetAt && (
                      <Button
                        size="small"
                        variant="text"
                        onClick={() => { setClearPwMember(infoMember); setClearPwOpen(true); }}
                        sx={{ fontSize: 11, textTransform: "none", minWidth: 0, py: 0, color: "text.primary" }}
                      >
                        {t("projectMembers.clearPasswordBtn", { defaultValue: "Clear" })}
                      </Button>
                    )}
                  </Stack>
                </Stack>
              </Stack>

              <Stack spacing={0.5}>
                <Typography variant="caption" color="text.secondary">{t("projectMembers.accountRecovery", "Account recovery")}</Typography>
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  <Button size="small" variant="outlined" onClick={() => setResetTotpOpen(true)} sx={{ textTransform: "none", fontSize: 12 }}>
                    {t("projectMembers.reset2fa", "Reset 2FA")}
                  </Button>
                  <Button size="small" variant="outlined" onClick={() => setUnlockOpen(true)} sx={{ textTransform: "none", fontSize: 12 }}>
                    {t("projectMembers.unlockAccount", "Unlock account")}
                  </Button>
                  <Button size="small" variant="outlined" onClick={() => { setSetPwValue(""); setSetPwOpen(true); }} sx={{ textTransform: "none", fontSize: 12 }}>
                    {t("projectMembers.setPassword", "Set password")}
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    disabled={magicLinkLoading}
                    onClick={async () => {
                      if (!infoMember || !selectedAppId) return;
                      setMagicLinkLoading(true);
                      try {
                        const url = await adminCreateUserMagicLink(project.workspaceId, project.id, selectedAppId, infoMember.accountId);
                        setMagicLinkUrl(url);
                      } catch {
                        enqueueSnackbar(t("projectMembers.magicLinkFailed", "Failed to generate link (app must use magic-link sign-in)"), { variant: "error" });
                      } finally {
                        setMagicLinkLoading(false);
                      }
                    }}
                    sx={{ textTransform: "none", fontSize: 12 }}
                  >
                    {t("projectMembers.magicLink", "Magic link")}
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    disabled={emailVerifyLoading}
                    onClick={async () => {
                      if (!infoMember || !selectedAppId) return;
                      const next = !infoMember.emailVerifiedAt;
                      setEmailVerifyLoading(true);
                      try {
                        await adminSetUserEmailVerified(project.workspaceId, project.id, selectedAppId, infoMember.accountId, next);
                        enqueueSnackbar(next ? t("projectMembers.emailMarkedVerified", "Email marked verified") : t("projectMembers.emailMarkedUnverified", "Email marked unverified"), { variant: "success" });
                        await refreshList();
                        setInfoOpen(false);
                        setInfoMember(null);
                      } catch {
                        enqueueSnackbar(t("projectMembers.emailVerifyFailed", "Failed to update email-verified"), { variant: "error" });
                      } finally {
                        setEmailVerifyLoading(false);
                      }
                    }}
                    sx={{ textTransform: "none", fontSize: 12 }}
                  >
                    {infoMember.emailVerifiedAt ? t("projectMembers.markUnverified", "Mark unverified") : t("projectMembers.markVerified", "Mark verified")}
                  </Button>
                </Stack>
                <Stack direction="row" spacing={1} alignItems="center">
                  <TextField
                    size="small"
                    placeholder={t("projectMembers.permissionSlug", "permission:slug")}
                    value={checkPerm}
                    onChange={(e) => { setCheckPerm(e.target.value); setCheckPermResult(null); }}
                    sx={{ "& .MuiInputBase-input": { fontSize: 12, py: 0.5 } }}
                  />
                  <Button
                    size="small"
                    variant="outlined"
                    disabled={checkPermLoading || !checkPerm.trim()}
                    onClick={async () => {
                      if (!infoMember || !selectedAppId) return;
                      setCheckPermLoading(true);
                      try {
                        const allowed = await adminCheckUserPermission(project.workspaceId, project.id, selectedAppId, infoMember.accountId, checkPerm.trim());
                        setCheckPermResult(allowed);
                      } catch {
                        enqueueSnackbar(t("projectMembers.checkPermFailed", "Failed to check permission"), { variant: "error" });
                      } finally {
                        setCheckPermLoading(false);
                      }
                    }}
                    sx={{ textTransform: "none", fontSize: 12 }}
                  >
                    {t("projectMembers.checkPermission", "Check")}
                  </Button>
                  {checkPermResult !== null && (
                    <Chip
                      size="small"
                      label={checkPermResult ? t("projectMembers.allowed", "Allowed") : t("projectMembers.denied", "Denied")}
                      color={checkPermResult ? "success" : "default"}
                    />
                  )}
                </Stack>
              </Stack>

              <Stack direction="row" spacing={3}>
                <Stack spacing={0.5}>
                  <Typography variant="caption" color="text.secondary">{t("projectMembers.lastLogin", "Last Login")}</Typography>
                  <Typography variant="body2">
                    {infoMember.lastLoginAt ? new Date(infoMember.lastLoginAt).toLocaleString() : "-"}
                  </Typography>
                </Stack>
                <Stack spacing={0.5}>
                  <Typography variant="caption" color="text.secondary">{t("projectMembers.createdAt", "Created")}</Typography>
                  <Typography variant="body2">
                    {infoMember.createdAt ? new Date(infoMember.createdAt).toLocaleString() : "-"}
                  </Typography>
                </Stack>
              </Stack>

              <Stack direction="row" spacing={1} alignItems="center">
                <Typography variant="caption" color="text.secondary">{t("projectMembers.status", "Status")}</Typography>
                <Chip
                  size="small"
                  label={infoMember.enabled !== false ? t("projectMembers.enabled", "Enabled") : t("projectMembers.disabled", "Disabled")}
                  variant={infoMember.enabled !== false ? "filled" : "outlined"}
                  sx={
                    infoMember.enabled !== false
                      ? { height: 22, fontSize: 11, bgcolor: "success.main", color: "#fff" }
                      : { height: 22, fontSize: 11, borderColor: "error.main", color: "error.main" }
                  }
                />
                <Button
                  size="small"
                  variant="text"
                  onClick={() => { setToggleMember(infoMember); setToggleOpen(true); }}
                  sx={{ fontSize: 12, textTransform: "none", color: "text.primary" }}
                >
                  {infoMember.enabled !== false
                    ? t("projectMembers.disableBtn", "Disable")
                    : t("projectMembers.enableBtn", "Enable")}
                </Button>
              </Stack>

              {/* Connected social accounts */}
              <Divider />
              <Stack spacing={0.75}>
                <Typography sx={{ fontFamily: "var(--font-mono)", textTransform: "uppercase", letterSpacing: "0.14em", fontSize: 10, fontWeight: 500, color: "text.disabled" }}>
                  {t("projectMembers.connectedAccounts", "Connected Accounts")}
                </Typography>
                {identitiesLoading ? (
                  <CircularProgress size={14} />
                ) : identities.length === 0 ? (
                  <Typography variant="caption" color="text.disabled">
                    {t("projectMembers.noIdentities", "No social accounts linked")}
                  </Typography>
                ) : (
                  <Stack spacing={0.5}>
                    {identities.map((i) => (
                      <Stack key={i.provider} direction="row" spacing={1} alignItems="center">
                        <Link2 size={12} strokeWidth={1.75} />
                        <Typography variant="body2" sx={{ fontWeight: 500 }}>
                          {PROVIDER_LABEL[i.provider] ?? i.provider}
                        </Typography>
                        {i.providerEmail && (
                          <Typography variant="caption" color="text.secondary">
                            {i.providerEmail}
                          </Typography>
                        )}
                      </Stack>
                    ))}
                  </Stack>
                )}
              </Stack>

              {/* Direct Permissions */}
              {allPermissions.length > 0 && (
                <>
                  <Divider />
                  <Stack direction="row" alignItems="center" justifyContent="space-between">
                    <Typography sx={{ fontFamily: "var(--font-mono)", textTransform: "uppercase", letterSpacing: "0.14em", fontSize: 10, fontWeight: 500, color: "text.disabled" }}>
                      {t("projectMembers.directPermissions", "Extra Permissions")}
                    </Typography>
                    {!directPermEditing && (
                      <Button size="small" onClick={() => setDirectPermEditing(true)} sx={{ textTransform: "none", fontSize: 12 }}>
                        {t("common.edit", "Edit")}
                      </Button>
                    )}
                  </Stack>
                  {directPermEditing ? (
                    <Stack spacing={0.5}>
                      {allPermissions.map((p) => (
                        <FormControlLabel
                          key={p.id}
                          control={
                            <Checkbox
                              size="small"
                              checked={directPermIds.has(p.id)}
                              onChange={() => {
                                setDirectPermIds((prev) => {
                                  const next = new Set(prev);
                                  if (next.has(p.id)) next.delete(p.id); else next.add(p.id);
                                  return next;
                                });
                              }}
                              disabled={directPermSaving}
                            />
                          }
                          label={<Typography variant="body2">{p.name} <Typography component="span" variant="caption" color="text.secondary">({p.slug})</Typography></Typography>}
                          sx={{ ml: 0 }}
                        />
                      ))}
                      <Stack direction="row" spacing={1}>
                        <Button size="small" variant="outlined" onClick={() => { setDirectPermEditing(false); if (infoMember && selectedAppId) void loadDirectPerms(infoMember.accountId, selectedAppId); }} disabled={directPermSaving} sx={{ textTransform: "none", fontSize: 12 }}>
                          {t("common.cancel", "Cancel")}
                        </Button>
                        <Button size="small" variant="contained" onClick={() => void saveDirectPerms()} disabled={directPermSaving} sx={{ textTransform: "none", fontSize: 12 }}>
                          {directPermSaving ? t("common.saving", "Saving...") : t("common.save", "Save")}
                        </Button>
                      </Stack>
                    </Stack>
                  ) : (
                    <Stack spacing={0.5}>
                      {directPermIds.size === 0 ? (
                        <Typography variant="body2" color="text.secondary">{t("projectMembers.none", { defaultValue: "None" })}</Typography>
                      ) : (
                        allPermissions.filter((p) => directPermIds.has(p.id)).map((p) => (
                          <Typography key={p.id} variant="body2">{p.name} <Typography component="span" variant="caption" color="text.secondary">({p.slug})</Typography></Typography>
                        ))
                      )}
                    </Stack>
                  )}
                </>
              )}

              {/* User Fields */}
              {userFields.length > 0 && (
                <>
                  <Divider />
                  <Stack direction="row" alignItems="center" justifyContent="space-between">
                    <Typography sx={{ fontFamily: "var(--font-mono)", textTransform: "uppercase", letterSpacing: "0.14em", fontSize: 10, fontWeight: 500, color: "text.disabled" }}>
                      {t("projectMembers.userFields", "User Fields")}
                    </Typography>
                    {!userFieldEditing && (
                      <Button size="small" onClick={() => setUserFieldEditing(true)} sx={{ textTransform: "none", fontSize: 12 }}>
                        {t("common.edit", "Edit")}
                      </Button>
                    )}
                  </Stack>
                  {userFieldEditing ? (
                    <Stack spacing={1.5}>
                      {userFields.map((f) => (
                        <Stack key={f.id}>
                          {f.valueType === "bool" ? (
                            <FormControlLabel
                              control={
                                <Checkbox
                                  size="small"
                                  checked={userFieldEdits[f.id] === "true"}
                                  onChange={(e) => {
                                    const val = e.target.checked ? "true" : "false";
                                    setUserFieldEdits((prev) => ({ ...prev, [f.id]: val }));
                                  }}
                                  disabled={userFieldSaving}
                                />
                              }
                              label={<Typography variant="body2">{f.label || f.key}</Typography>}
                              sx={{ ml: 0 }}
                            />
                          ) : (
                            <TextField
                              size="small"
                              label={f.label || f.key}
                              type={f.valueType === "date" ? "date" : "text"}
                              value={userFieldEdits[f.id] ?? ""}
                              onChange={(e) => setUserFieldEdits((prev) => ({ ...prev, [f.id]: e.target.value }))}
                              disabled={userFieldSaving}
                              fullWidth
                              InputLabelProps={f.valueType === "date" ? { shrink: true } : undefined}
                            />
                          )}
                        </Stack>
                      ))}
                      <Stack direction="row" spacing={1}>
                        <Button
                          size="small"
                          variant="outlined"
                          onClick={() => { setUserFieldEditing(false); setUserFieldEdits({ ...userFieldValues }); }}
                          disabled={userFieldSaving}
                          sx={{ textTransform: "none", fontSize: 12 }}
                        >
                          {t("common.cancel", "Cancel")}
                        </Button>
                        <Button
                          size="small"
                          variant="contained"
                          onClick={() => void saveAllUserFields()}
                          disabled={userFieldSaving}
                          sx={{ textTransform: "none", fontSize: 12 }}
                        >
                          {userFieldSaving ? t("common.saving", "Saving...") : t("common.save", "Save")}
                        </Button>
                      </Stack>
                    </Stack>
                  ) : (
                    <Stack spacing={1}>
                      {userFields.map((f) => (
                        <Stack key={f.id} spacing={0.5}>
                          <Typography variant="caption" color="text.secondary">{f.label || f.key}</Typography>
                          <Typography variant="body2">
                            {f.valueType === "bool"
                              ? (userFieldValues[f.id] === "true" ? t("projectMembers.yes", { defaultValue: "Yes" }) : t("projectMembers.no", { defaultValue: "No" }))
                              : (userFieldValues[f.id] || "-")}
                          </Typography>
                        </Stack>
                      ))}
                    </Stack>
                  )}
                </>
              )}
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={closeInfoDialog}>{t("common.close")}</Button>
        </DialogActions>
      </Dialog>

      {/* Enable/Disable confirmation dialog */}
      <Dialog
        open={toggleOpen}
        onClose={toggleLoading ? undefined : () => { setToggleOpen(false); setToggleMember(null); }}
        fullWidth
        maxWidth="xs"
      >
        <DialogTitle>
          {toggleMember?.enabled !== false
            ? t("projectMembers.disableTitle", "Disable user")
            : t("projectMembers.enableTitle", "Enable user")}
        </DialogTitle>
        <DialogContent>
          <Stack spacing={1.5} sx={{ pt: 1 }}>
            <Typography variant="body2" color="text.secondary">
              {toggleMember?.enabled !== false
                ? t("projectMembers.disableBody", "This user will no longer be able to log in. All active sessions will be revoked.")
                : t("projectMembers.enableBody", "This user will be able to log in again.")}
            </Typography>
            <Typography variant="body2" fontWeight={500}>{toggleMember?.email}</Typography>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => { setToggleOpen(false); setToggleMember(null); }}
            disabled={toggleLoading}
          >
            {t("common.cancel")}
          </Button>
          <Button
            variant="contained"
            disableElevation
            color={toggleMember?.enabled !== false ? "error" : "primary"}
            disabled={toggleLoading}
            onClick={async () => {
              if (!toggleMember) return;
              setToggleLoading(true);
              try {
                const newEnabled = toggleMember.enabled === false;
                await setUserEnabled(project.workspaceId, toggleMember.accountId, newEnabled);
                setToggleOpen(false);
                setToggleMember(null);
                setInfoOpen(false);
                setInfoMember(null);
                await refreshList();
                enqueueSnackbar(
                  newEnabled
                    ? t("projectMembers.userEnabled", "User enabled")
                    : t("projectMembers.userDisabled", "User disabled"),
                  { variant: "success" },
                );
              } catch {
                enqueueSnackbar(t("projectMembers.failedToSave"), { variant: "error" });
              } finally {
                setToggleLoading(false);
              }
            }}
          >
            {toggleLoading
              ? "..."
              : toggleMember?.enabled !== false
                ? t("projectMembers.disableBtn", "Disable")
                : t("projectMembers.enableBtn", "Enable")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Clear-password confirmation. Destructive but recoverable -
          the user can set a new password via /auth/forgot-password
          (or in-profile set-password) to restore email/password
          sign-in. OAuth + passkey are unaffected. All active
          sessions are revoked server-side as part of the operation. */}
      <Dialog
        open={clearPwOpen}
        onClose={() => clearPwLoading ? null : (setClearPwOpen(false), setClearPwMember(null))}
        maxWidth="xs"
        fullWidth
      >
        <DialogTitle>{t("projectMembers.clearPwTitle", { defaultValue: "Clear password?" })}</DialogTitle>
        <DialogContent>
          <Stack spacing={1.5}>
            <Typography variant="body2">
              {t("projectMembers.clearPwBody", { defaultValue: "The user's password will be unset. They can no longer sign in with email + password until they reset via the forgot-password flow. OAuth and passkey sign-in are unaffected." })}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              <Trans i18nKey="projectMembers.clearPwSessions" values={{ email: clearPwMember?.email }} components={tc}>
                All active sessions for <strong>{"{{email}}"}</strong> will also be revoked.
              </Trans>
            </Typography>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => { setClearPwOpen(false); setClearPwMember(null); }}
            disabled={clearPwLoading}
          >
            {t("common.cancel")}
          </Button>
          <Button
            variant="contained"
            disableElevation
            color="error"
            disabled={clearPwLoading}
            onClick={async () => {
              if (!clearPwMember) return;
              setClearPwLoading(true);
              try {
                await clearUserPassword(project.workspaceId, clearPwMember.accountId);
                setClearPwOpen(false);
                setClearPwMember(null);
                setInfoOpen(false);
                setInfoMember(null);
                await refreshList();
                enqueueSnackbar(t("projectMembers.passwordCleared", { defaultValue: "Password cleared" }), { variant: "success" });
              } catch {
                enqueueSnackbar(t("projectMembers.passwordClearFailed", { defaultValue: "Failed to clear password" }), { variant: "error" });
              } finally {
                setClearPwLoading(false);
              }
            }}
          >
            {clearPwLoading ? "..." : t("projectMembers.clearPasswordAction", { defaultValue: "Clear password" })}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Reset 2FA — removes the user's authenticator so a locked-out user can re-enroll. */}
      <Dialog
        open={resetTotpOpen}
        onClose={() => (resetTotpLoading ? null : setResetTotpOpen(false))}
        maxWidth="xs"
        fullWidth
      >
        <DialogTitle>{t("projectMembers.reset2fa", "Reset 2FA")}?</DialogTitle>
        <DialogContent>
          <Typography variant="body2">
            {t("projectMembers.reset2faBody", "The user's two-factor authentication (authenticator app) will be removed. They'll sign in without a second factor until they set it up again — use this when a user has lost their authenticator.")}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setResetTotpOpen(false)} disabled={resetTotpLoading}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="contained"
            disableElevation
            color="error"
            disabled={resetTotpLoading}
            onClick={async () => {
              if (!infoMember || !selectedAppId) return;
              setResetTotpLoading(true);
              try {
                await resetUserTotp(project.workspaceId, project.id, selectedAppId, infoMember.accountId);
                setResetTotpOpen(false);
                enqueueSnackbar(t("projectMembers.reset2faDone", "2FA reset"), { variant: "success" });
              } catch {
                enqueueSnackbar(t("projectMembers.reset2faFailed", "Failed to reset 2FA"), { variant: "error" });
              } finally {
                setResetTotpLoading(false);
              }
            }}
          >
            {resetTotpLoading ? "..." : t("projectMembers.reset2fa", "Reset 2FA")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Unlock account — clears a failed-login lockout. */}
      <Dialog
        open={unlockOpen}
        onClose={() => (unlockLoading ? null : setUnlockOpen(false))}
        maxWidth="xs"
        fullWidth
      >
        <DialogTitle>{t("projectMembers.unlockAccount", "Unlock account")}?</DialogTitle>
        <DialogContent>
          <Typography variant="body2">
            {t("projectMembers.unlockBody", "Clears a failed-login lockout so the user can sign in again immediately.")}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setUnlockOpen(false)} disabled={unlockLoading}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="contained"
            disableElevation
            disabled={unlockLoading}
            onClick={async () => {
              if (!infoMember || !selectedAppId) return;
              setUnlockLoading(true);
              try {
                await unlockUserAccount(project.workspaceId, project.id, selectedAppId, infoMember.accountId);
                setUnlockOpen(false);
                enqueueSnackbar(t("projectMembers.unlockDone", "Account unlocked"), { variant: "success" });
              } catch {
                enqueueSnackbar(t("projectMembers.unlockFailed", "Failed to unlock account"), { variant: "error" });
              } finally {
                setUnlockLoading(false);
              }
            }}
          >
            {unlockLoading ? "..." : t("projectMembers.unlockAccount", "Unlock account")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Set password */}
      <Dialog open={setPwOpen} onClose={() => (setPwLoading ? null : setSetPwOpen(false))} maxWidth="xs" fullWidth>
        <DialogTitle>{t("projectMembers.setPassword", "Set password")}</DialogTitle>
        <DialogContent>
          <Stack spacing={1.5} sx={{ pt: 1 }}>
            <Typography variant="body2" color="text.secondary">
              {t("projectMembers.setPasswordBody", "Set a new password for this user; it must meet the app's password policy. The user can sign in with it immediately.")}
            </Typography>
            <TextField
              type="password"
              size="small"
              autoFocus
              fullWidth
              label={t("projectMembers.newPassword", "New password")}
              value={setPwValue}
              onChange={(e) => setSetPwValue(e.target.value)}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSetPwOpen(false)} disabled={setPwLoading}>{t("common.cancel")}</Button>
          <Button
            variant="contained"
            disableElevation
            disabled={setPwLoading || !setPwValue}
            onClick={async () => {
              if (!infoMember || !selectedAppId) return;
              setSetPwLoading(true);
              try {
                await adminSetUserPassword(project.workspaceId, project.id, selectedAppId, infoMember.accountId, setPwValue);
                setSetPwOpen(false);
                setSetPwValue("");
                enqueueSnackbar(t("projectMembers.passwordSet", "Password set"), { variant: "success" });
                await refreshList();
              } catch (e) {
                const code = (e as { response?: { data?: { error?: string } } })?.response?.data?.error;
                const weak = code === "error.passwordTooWeak" || code === "error.passwordTooShort";
                enqueueSnackbar(
                  weak
                    ? t("projectMembers.passwordTooWeak", "Password doesn't meet the app's policy")
                    : t("projectMembers.passwordSetFailed", "Failed to set password"),
                  { variant: "error" },
                );
              } finally {
                setSetPwLoading(false);
              }
            }}
          >
            {setPwLoading ? "..." : t("projectMembers.setPassword", "Set password")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Magic-link result */}
      <Dialog open={magicLinkUrl !== null} onClose={() => setMagicLinkUrl(null)} maxWidth="sm" fullWidth>
        <DialogTitle>{t("projectMembers.magicLink", "Magic link")}</DialogTitle>
        <DialogContent>
          <Stack spacing={1.5} sx={{ pt: 1 }}>
            <Typography variant="body2" color="text.secondary">
              {t("projectMembers.magicLinkBody", "A one-time sign-in link for this user (expires in 15 minutes). Copy it and send it to them securely.")}
            </Typography>
            <TextField
              size="small"
              fullWidth
              multiline
              value={magicLinkUrl ?? ""}
              InputProps={{ readOnly: true }}
              sx={{ "& textarea": { fontFamily: "var(--font-mono)", fontSize: 12 } }}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              if (magicLinkUrl) {
                void navigator.clipboard?.writeText(magicLinkUrl);
                enqueueSnackbar(t("projectMembers.copied", "Copied"), { variant: "success" });
              }
            }}
          >
            {t("projectMembers.copy", "Copy")}
          </Button>
          <Button variant="contained" disableElevation onClick={() => setMagicLinkUrl(null)}>
            {t("common.close", "Close")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Import preview / progress dialog */}
      <Dialog
        open={!!importPreview}
        onClose={() => { if (!importProgress) setImportPreview(null); }}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>{t("projectMembers.importTitle", { defaultValue: "Import users" })}</DialogTitle>
        <DialogContent>
          {importProgress ? (
            <Stack spacing={2} sx={{ mt: 1 }}>
              <Typography variant="body2">
                {t("projectMembers.importingProgress", { current: importProgress.current, total: importProgress.total, defaultValue: "Importing {{current}} of {{total}}…" })}
              </Typography>
              <LinearProgress
                variant="determinate"
                value={(importProgress.current / Math.max(importProgress.total, 1)) * 100}
              />
            </Stack>
          ) : importPreview ? (
            <Stack spacing={1.5} sx={{ mt: 1 }}>
              <Typography variant="body2" color="text.secondary">
                <Trans i18nKey="projectMembers.importFrom" values={{ filename: importPreview.filename }} components={tc}>
                  From <code>{"{{filename}}"}</code>
                </Trans>
              </Typography>
              <Typography>
                <Trans i18nKey="projectMembers.importUsersInFile" count={importPreview.users.length} values={{ count: importPreview.users.length }} components={tc}>
                  <b>{"{{count}}"}</b> users in file:
                </Trans>
              </Typography>
              <Box sx={{ pl: 2 }}>
                <Typography variant="body2" color="success.main">
                  • {t("projectMembers.importWillCreate", { count: importPreview.toCreate, defaultValue: "{{count}} will be created" })}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  • {t("projectMembers.importWillUpdate", { count: importPreview.toUpdate, defaultValue: "{{count}} will be updated (email already exists)" })}
                </Typography>
              </Box>
              <Alert severity="info" sx={{ mt: 1, fontSize: 13 }}>
                {t("projectMembers.importNote", { defaultValue: "Roles and field values will be applied. Unknown role/permission/field slugs are silently skipped; check the result for errors." })}
              </Alert>
            </Stack>
          ) : null}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setImportPreview(null)} disabled={!!importProgress}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button
            onClick={runImport}
            variant="contained"
            disabled={!!importProgress || !importPreview || importPreview.users.length === 0}
          >
            {importProgress ? t("projectMembers.importingShort", { defaultValue: "Importing…" }) : t("projectMembers.importN", { count: importPreview?.users.length ?? 0, defaultValue: "Import {{count}}" })}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Import result dialog */}
      <Dialog
        open={!!importResult}
        onClose={() => setImportResult(null)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>{t("projectMembers.importComplete", { defaultValue: "Import complete" })}</DialogTitle>
        <DialogContent>
          {importResult && (
            <Stack spacing={1.5} sx={{ mt: 1 }}>
              <Typography color="success.main">
                <Trans i18nKey="projectMembers.importedCount" values={{ count: importResult.imported }} components={tc}>
                  Imported: <b>{"{{count}}"}</b>
                </Trans>
              </Typography>
              {importResult.failed > 0 && (
                <>
                  <Typography color="error.main">
                    <Trans i18nKey="projectMembers.failedCount" values={{ count: importResult.failed }} components={tc}>
                      Failed: <b>{"{{count}}"}</b>
                    </Trans>
                  </Typography>
                  <Box
                    sx={{
                      maxHeight: 320,
                      overflow: "auto",
                      border: "1px solid",
                      borderColor: "divider",
                      borderRadius: 1,
                      p: 1.5,
                    }}
                  >
                    {importResult.errors.map((err, i) => (
                      <Box key={i} sx={{ mb: 1.25, "&:last-of-type": { mb: 0 } }}>
                        <Typography variant="body2" sx={{ fontFamily: "var(--font-mono)", fontWeight: 600 }}>
                          {err.email}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {err.reason}
                        </Typography>
                      </Box>
                    ))}
                  </Box>
                </>
              )}
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setImportResult(null)} variant="contained">
            {t("common.close", { defaultValue: "Close" })}
          </Button>
        </DialogActions>
      </Dialog>

      {activityUser && currentAppId && (
        <React.Suspense fallback={null}>
          <UserActivityDialog
            open
            onClose={closeActivityDialog}
            workspaceId={project.workspaceId}
            productId={project.id}
            appId={currentAppId}
            userId={activityUser.id}
            userEmail={activityUser.email}
          />
        </React.Suspense>
      )}

      {tagsUser && currentAppId && (
        <React.Suspense fallback={null}>
          <UserTagsDialog
            open
            onClose={closeTagsDialog}
            onSaved={(tags) => onTagsSaved(tagsUser.id, tags)}
            workspaceId={project.workspaceId}
            productId={project.id}
            appId={currentAppId}
            userId={tagsUser.id}
            userEmail={tagsUser.email}
            initialTags={tagsUser.tags}
          />
        </React.Suspense>
      )}

      <Dialog
        open={!!bulkMode}
        onClose={closeBulkDialog}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>
          {bulkMode === "disable" && t("projectMembers.bulkDisableTitle", { defaultValue: "Disable {{count}} users?", count: selectedIds.size })}
          {bulkMode === "enable" && t("projectMembers.bulkEnableTitle", { defaultValue: "Enable {{count}} users?", count: selectedIds.size })}
          {bulkMode === "delete" && t("projectMembers.bulkRemoveTitle", { defaultValue: "Remove {{count}} users from this app?", count: selectedIds.size })}
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {bulkMode === "disable" && t("projectMembers.bulkDisableBody", { defaultValue: "Disabled users can't sign in. They keep all roles and data - re-enable any time." })}
            {bulkMode === "enable" && t("projectMembers.bulkEnableBody", { defaultValue: "Re-enables sign-in for the selected users." })}
            {bulkMode === "delete" && t("projectMembers.bulkRemoveBody", { defaultValue: "Removes the selected users from this app — their roles, permission overrides, and sessions for this app are cleared. Their account and pool data are kept." })}
          </Typography>
          {(bulkLoading || bulkProgress.total > 0) && (
            <Box sx={{ mb: bulkProgress.errors.length > 0 ? 2 : 0 }}>
              <LinearProgress
                variant="determinate"
                value={bulkProgress.total === 0 ? 0 : (bulkProgress.done / bulkProgress.total) * 100}
                sx={{ mb: 1 }}
              />
              <Typography variant="caption" color="text.secondary">
                {bulkProgress.done} / {bulkProgress.total}
                {bulkProgress.errors.length > 0 && ` · ${bulkProgress.errors.length} failed`}
              </Typography>
            </Box>
          )}
          {!bulkLoading && bulkProgress.errors.length > 0 && (
            <Box>
              <Alert severity="warning" sx={{ mb: 1 }}>
                {t("projectMembers.bulkPartialFailure", {
                  defaultValue: "{{ok}} succeeded, {{fail}} failed. Review and retry below.",
                  ok: bulkProgress.total - bulkProgress.errors.length,
                  fail: bulkProgress.errors.length,
                })}
              </Alert>
              <Box sx={{ maxHeight: 240, overflowY: "auto", border: "1px solid", borderColor: "divider", borderRadius: 1 }}>
                {bulkProgress.errors.map((e) => (
                  <Box
                    key={e.id}
                    sx={{
                      px: 1.5,
                      py: 0.75,
                      display: "flex",
                      justifyContent: "space-between",
                      gap: 2,
                      borderBottom: "1px solid",
                      borderColor: "divider",
                      "&:last-child": { borderBottom: 0 },
                    }}
                  >
                    <Typography variant="body2" noWrap title={e.email} sx={{ flex: 1, minWidth: 0 }}>
                      {e.email}
                    </Typography>
                    <Typography variant="caption" color="error" noWrap title={e.message} sx={{ flex: 2, minWidth: 0, textAlign: "right" }}>
                      {e.message}
                    </Typography>
                  </Box>
                ))}
              </Box>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          {!bulkLoading && bulkProgress.errors.length > 0 ? (
            <>
              <Button onClick={closeBulkDialog} color="inherit">
                {t("common.close")}
              </Button>
              <Button
                onClick={retryFailedBulk}
                variant="contained"
                color={bulkMode === "delete" ? "error" : "primary"}
              >
                {t("projectMembers.bulkRetryFailed", {
                  defaultValue: "Retry {{count}} failed",
                  count: bulkProgress.errors.length,
                })}
              </Button>
            </>
          ) : (
            <>
              <Button onClick={closeBulkDialog} disabled={bulkLoading} color="inherit">
                {t("common.cancel")}
              </Button>
              <Button
                onClick={() => runBulkAction()}
                disabled={bulkLoading || selectedIds.size === 0}
                variant="contained"
                color={bulkMode === "delete" ? "error" : "primary"}
              >
                {bulkLoading ? `${bulkProgress.done}/${bulkProgress.total}` : t("common.confirm", { defaultValue: "Confirm" })}
              </Button>
            </>
          )}
        </DialogActions>
      </Dialog>
    </Box>
  );
}
