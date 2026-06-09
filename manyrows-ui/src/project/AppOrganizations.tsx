import * as React from "react";
import axios from "axios";
import { useSnackbar } from "notistack";
import { useTranslation } from "react-i18next";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  IconButton,
  MenuItem,
  Paper,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { Archive, ArchiveRestore, Copy, SquarePen, Trash2, TriangleAlert, Users } from "lucide-react";
import type { Project, Workspace } from "../core.ts";
import type { App } from "./AppAuthMethods.tsx";
import { errText } from "./AppAuthMethods.tsx";
import Loader from "../Loader.tsx";
import PageHeader from "../components/PageHeader.tsx";
import SaveBar from "../components/SaveBar.tsx";

interface Props {
  project: Project;
  workspace: Workspace;
  appId: string;
}

interface OrgRow {
  id: string;
  name: string;
  slug: string;
  status: string;
  memberCount: number;
  createdAt: string;
}

interface OrgMemberRole {
  id: string;
  slug: string;
  name: string;
}

interface OrgMember {
  userId: string;
  email: string;
  orgRole: string; // org tier: owner | admin | member
  status: string;
  roles: OrgMemberRole[]; // project (app RBAC) roles assigned in THIS org
}

interface OrgInvite {
  id: string;
  email: string;
  orgRole: string;
  status: string;
  invitedByEmail?: string;
  createdAt: string;
  expiresAt: string;
}

function fmtDate(d?: string): string {
  if (!d) return "-";
  const date = new Date(d);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleDateString();
}

export default function AppOrganizations({ project, appId }: Props) {
  const { enqueueSnackbar } = useSnackbar();
  const { t } = useTranslation();

  const projectURL = `/admin/workspace/${project.workspaceId}/projects/${project.id}`;
  const appsBaseURL = `${projectURL}/apps`;
  const appURL = `${appsBaseURL}/${appId}`;

  const [loading, setLoading] = React.useState(true);
  const [app, setApp] = React.useState<App | null>(null);
  const [orgs, setOrgs] = React.useState<OrgRow[]>([]);

  // Status filter — archived orgs are hidden by default.
  const [statusFilter, setStatusFilter] = React.useState<"active" | "archived" | "all">("active");

  // Enable toggle
  const [enabled, setEnabled] = React.useState(false);
  const [savingEnabled, setSavingEnabled] = React.useState(false);
  const persistedEnabled = !!app?.organizationsEnabled;
  const enabledDirty = enabled !== persistedEnabled;

  // Members dialog
  const [membersOpen, setMembersOpen] = React.useState(false);
  const [membersOrg, setMembersOrg] = React.useState<OrgRow | null>(null);
  const [members, setMembers] = React.useState<OrgMember[]>([]);
  const [membersLoading, setMembersLoading] = React.useState(false);

  // Creation-policy selector
  const [savingPolicy, setSavingPolicy] = React.useState(false);

  // Per-member editing (tier + project roles) and removal (admin).
  const [roleCatalog, setRoleCatalog] = React.useState<OrgMemberRole[]>([]);
  const [editRolesMember, setEditRolesMember] = React.useState<OrgMember | null>(null);
  const [editTier, setEditTier] = React.useState<string>("member");
  const [editRoleIds, setEditRoleIds] = React.useState<string[]>([]);
  const [editRolesSaving, setEditRolesSaving] = React.useState(false);
  const [removeMember, setRemoveMember] = React.useState<OrgMember | null>(null);
  const [removeSaving, setRemoveSaving] = React.useState(false);

  // Add existing app user to the org
  const [addEmail, setAddEmail] = React.useState("");
  const [addTier, setAddTier] = React.useState("member");
  const [addSaving, setAddSaving] = React.useState(false);

  // Pending invites (within the members dialog)
  const [invites, setInvites] = React.useState<OrgInvite[]>([]);
  const [inviteEmail, setInviteEmail] = React.useState("");
  const [inviteTier, setInviteTier] = React.useState("member");
  const [inviteSaving, setInviteSaving] = React.useState(false);
  const [revokingInviteId, setRevokingInviteId] = React.useState<string | null>(null);

  // Create organization dialog
  const [createOpen, setCreateOpen] = React.useState(false);
  const [createName, setCreateName] = React.useState("");
  const [createSaving, setCreateSaving] = React.useState(false);

  // Rename dialog
  const [renameOpen, setRenameOpen] = React.useState(false);
  const [renameOrg, setRenameOrg] = React.useState<OrgRow | null>(null);
  const [renameValue, setRenameValue] = React.useState("");
  const [renameSaving, setRenameSaving] = React.useState(false);

  // Archive dialog
  const [archiveOpen, setArchiveOpen] = React.useState(false);
  const [archiveOrg, setArchiveOrg] = React.useState<OrgRow | null>(null);
  const [archiveSaving, setArchiveSaving] = React.useState(false);

  // Restore (unarchive) — direct action, no confirm dialog. Tracks the in-flight row.
  const [restoringId, setRestoringId] = React.useState<string | null>(null);

  // Delete (permanent) — archived orgs only; type-the-name to confirm.
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [deleteOrg, setDeleteOrg] = React.useState<OrgRow | null>(null);
  const [deleteConfirm, setDeleteConfirm] = React.useState("");
  const [deleteSaving, setDeleteSaving] = React.useState(false);

  const loadOrgs = React.useCallback(async () => {
    try {
      const res = await axios.get<{ organizations: OrgRow[] }>(`${appURL}/organizations`);
      setOrgs(res.data.organizations || []);
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    }
  }, [appURL, enqueueSnackbar]);

  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    axios
      .get<App>(`${appURL}/`)
      .then(async (res) => {
        if (!alive) return;
        setApp(res.data);
        setEnabled(!!res.data.organizationsEnabled);
        await loadOrgs();
      })
      .catch((e) => {
        if (!alive) return;
        enqueueSnackbar(errText(e), { variant: "error" });
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [appURL, loadOrgs, enqueueSnackbar]);

  async function saveEnabled() {
    setSavingEnabled(true);
    try {
      const res = await axios.put<App>(`${appURL}/organizations-enabled`, { organizationsEnabled: enabled });
      setApp(res.data);
      setEnabled(!!res.data.organizationsEnabled);
      enqueueSnackbar(
        t("organizations.enabledUpdated", {
          defaultValue: "Organizations setting updated for all apps in this project",
        }),
        { variant: "success" },
      );
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setSavingEnabled(false);
    }
  }

  async function openMembers(org: OrgRow) {
    setMembersOrg(org);
    setMembers([]);
    setInvites([]);
    setAddEmail("");
    setAddTier("member");
    setInviteEmail("");
    setInviteTier("member");
    setMembersOpen(true);
    setMembersLoading(true);
    try {
      // Load members, pending invites, and (once) the project's role catalog.
      const [mRes, iRes] = await Promise.all([
        axios.get<{ members: OrgMember[] }>(`${appURL}/organizations/${org.id}/members`),
        axios.get<{ invites: OrgInvite[] }>(`${appURL}/organizations/${org.id}/invites`),
        roleCatalog.length > 0
          ? Promise.resolve(null)
          : axios
              .get<{ roles: OrgMemberRole[] }>(`${projectURL}/roles`)
              .then((r) => setRoleCatalog(r.data.roles || [])),
      ]);
      setMembers(mRes.data.members || []);
      setInvites(iRes.data.invites || []);
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setMembersLoading(false);
    }
  }

  async function addMemberSubmit() {
    if (!membersOrg || !addEmail.trim()) return;
    setAddSaving(true);
    try {
      const res = await axios.post<OrgMember>(`${appURL}/organizations/${membersOrg.id}/members`, {
        email: addEmail.trim(),
        orgRole: addTier,
      });
      setMembers((prev) => [...prev, res.data].sort((a, b) => (a.email || "").localeCompare(b.email || "")));
      setAddEmail("");
      setAddTier("member");
      enqueueSnackbar(t("organizations.memberAdded", { defaultValue: "Member added" }), { variant: "success" });
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setAddSaving(false);
    }
  }

  async function inviteSubmit() {
    if (!membersOrg || !inviteEmail.trim()) return;
    setInviteSaving(true);
    try {
      const res = await axios.post<OrgInvite>(`${appURL}/organizations/${membersOrg.id}/invites`, {
        email: inviteEmail.trim(),
        orgRole: inviteTier,
      });
      setInvites((prev) => [res.data, ...prev]);
      setInviteEmail("");
      setInviteTier("member");
      enqueueSnackbar(t("organizations.inviteSent", { defaultValue: "Invitation sent" }), { variant: "success" });
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setInviteSaving(false);
    }
  }

  async function revokeInvite(inviteId: string) {
    if (!membersOrg) return;
    setRevokingInviteId(inviteId);
    try {
      await axios.delete(`${appURL}/organizations/${membersOrg.id}/invites/${inviteId}`);
      setInvites((prev) => prev.filter((i) => i.id !== inviteId));
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setRevokingInviteId(null);
    }
  }

  async function createOrgSubmit() {
    if (!createName.trim()) return;
    setCreateSaving(true);
    try {
      await axios.post(`${appURL}/organizations`, { name: createName.trim() });
      await loadOrgs();
      enqueueSnackbar(t("organizations.created", { defaultValue: "Organization created" }), { variant: "success" });
      setCreateOpen(false);
      setCreateName("");
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setCreateSaving(false);
    }
  }

  function openEditMember(m: OrgMember) {
    setEditRolesMember(m);
    setEditTier(m.orgRole);
    setEditRoleIds(m.roles ? m.roles.map((r) => r.id) : []);
  }

  async function saveMember() {
    if (!membersOrg || !editRolesMember) return;
    setEditRolesSaving(true);
    try {
      const base = `${appURL}/organizations/${membersOrg.id}/members/${editRolesMember.userId}`;
      // Tier first so a last-owner 409 aborts before any role write.
      if (editTier !== editRolesMember.orgRole) {
        await axios.patch(base, { orgRole: editTier });
      }
      const curIds = [...(editRolesMember.roles ?? []).map((r) => r.id)].sort();
      const newIds = [...editRoleIds].sort();
      const rolesChanged = curIds.length !== newIds.length || curIds.some((id, i) => id !== newIds[i]);
      if (rolesChanged) {
        await axios.put(`${base}/roles`, { roleIds: editRoleIds });
      }
      const chosen = roleCatalog.filter((r) => editRoleIds.includes(r.id));
      setMembers((prev) =>
        prev.map((m) => (m.userId === editRolesMember.userId ? { ...m, orgRole: editTier, roles: chosen } : m)),
      );
      enqueueSnackbar(t("organizations.memberUpdated", { defaultValue: "Member updated" }), { variant: "success" });
      setEditRolesMember(null);
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setEditRolesSaving(false);
    }
  }

  async function confirmRemoveMember() {
    if (!membersOrg || !removeMember) return;
    setRemoveSaving(true);
    try {
      await axios.delete(`${appURL}/organizations/${membersOrg.id}/members/${removeMember.userId}`);
      setMembers((prev) => prev.filter((m) => m.userId !== removeMember.userId));
      enqueueSnackbar(t("organizations.memberRemoved", { defaultValue: "Member removed" }), { variant: "success" });
      setRemoveMember(null);
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setRemoveSaving(false);
    }
  }

  async function savePolicy(policy: string) {
    setSavingPolicy(true);
    try {
      const res = await axios.put<App>(`${appURL}/organizations-creation-policy`, { orgCreationPolicy: policy });
      setApp(res.data);
      enqueueSnackbar(t("organizations.policyUpdated", { defaultValue: "Creation policy updated" }), {
        variant: "success",
      });
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setSavingPolicy(false);
    }
  }

  function openRename(org: OrgRow) {
    setRenameOrg(org);
    setRenameValue(org.name);
    setRenameOpen(true);
  }

  async function saveRename() {
    if (!renameOrg) return;
    const name = renameValue.trim();
    if (!name) return;
    setRenameSaving(true);
    try {
      await axios.patch(`${appURL}/organizations/${renameOrg.id}`, { name });
      setRenameOpen(false);
      setRenameOrg(null);
      await loadOrgs();
      enqueueSnackbar(t("organizations.renamed", { defaultValue: "Organization renamed" }), { variant: "success" });
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setRenameSaving(false);
    }
  }

  function openArchive(org: OrgRow) {
    setArchiveOrg(org);
    setArchiveOpen(true);
  }

  async function confirmArchive() {
    if (!archiveOrg) return;
    setArchiveSaving(true);
    try {
      await axios.delete(`${appURL}/organizations/${archiveOrg.id}`);
      setArchiveOpen(false);
      setArchiveOrg(null);
      await loadOrgs();
      enqueueSnackbar(t("organizations.archived", { defaultValue: "Organization archived" }), { variant: "success" });
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setArchiveSaving(false);
    }
  }

  async function doRestore(org: OrgRow) {
    setRestoringId(org.id);
    try {
      await axios.post(`${appURL}/organizations/${org.id}/restore`);
      await loadOrgs();
      enqueueSnackbar(t("organizations.restored", { defaultValue: "Organization restored" }), { variant: "success" });
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setRestoringId(null);
    }
  }

  function openDelete(org: OrgRow) {
    setDeleteOrg(org);
    setDeleteConfirm("");
    setDeleteOpen(true);
  }

  async function confirmDelete() {
    if (!deleteOrg) return;
    setDeleteSaving(true);
    try {
      await axios.delete(`${appURL}/organizations/${deleteOrg.id}/permanent`);
      setDeleteOpen(false);
      setDeleteOrg(null);
      await loadOrgs();
      enqueueSnackbar(t("organizations.deleted", { defaultValue: "Organization deleted" }), { variant: "success" });
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setDeleteSaving(false);
    }
  }

  const visibleOrgs = statusFilter === "all" ? orgs : orgs.filter((o) => o.status === statusFilter);

  if (loading) return <Loader />;

  return (
    <Box>
      <PageHeader title={t("organizations.title", { defaultValue: "Organizations" })} mb={2} />

      <Stack spacing={3}>
        {/* Enable card */}
        <Box sx={{ border: "1px solid", borderColor: "divider", borderRadius: 2, p: 2.5, bgcolor: "background.paper" }}>
          <FormControlLabel
            control={<Switch checked={enabled} onChange={(_, v) => setEnabled(v)} disabled={savingEnabled} />}
            label={
              <Stack>
                <Typography variant="body2" sx={{ fontWeight: 500 }}>
                  {t("organizations.enableLabel", { defaultValue: "Organizations enabled" })}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {t("organizations.enableHelp", {
                    defaultValue:
                      "Let end-users belong to organizations (tenants). This applies to every app in this project. A consuming app can't create organizations until this is on. Default off.",
                  })}
                </Typography>
              </Stack>
            }
            sx={{ alignItems: "flex-start", ml: 0 }}
          />
          <SaveBar
            dirty={enabledDirty}
            saving={savingEnabled}
            onSave={() => void saveEnabled()}
            onDiscard={() => setEnabled(persistedEnabled)}
          />

          {/* Creation policy — only meaningful once orgs are enabled. */}
          {persistedEnabled && (
            <Box sx={{ mt: 2, pt: 2, borderTop: "1px solid", borderColor: "divider" }}>
              <TextField
                select
                size="small"
                label={t("organizations.creationPolicyLabel", { defaultValue: "Who can create organizations" })}
                value={app?.orgCreationPolicy ?? "invite_only"}
                onChange={(e) => void savePolicy(e.target.value)}
                disabled={savingPolicy}
                sx={{ minWidth: 320 }}
                helperText={t("organizations.creationPolicyHelp", {
                  defaultValue:
                    "Gates the end-user self-serve create endpoint. Backends can always provision organizations via the server API.",
                })}
              >
                <MenuItem value="invite_only">
                  {t("organizations.policy.inviteOnly", { defaultValue: "Invite only (no self-serve)" })}
                </MenuItem>
                <MenuItem value="self_serve">
                  {t("organizations.policy.selfServe", { defaultValue: "Anyone can self-serve" })}
                </MenuItem>
                <MenuItem value="admin_only">
                  {t("organizations.policy.adminOnly", { defaultValue: "Admins only (backend / API)" })}
                </MenuItem>
              </TextField>
            </Box>
          )}
        </Box>

        {/* Create organization (admin can seed an org directly). */}
        {persistedEnabled && (
          <Stack direction="row" justifyContent="flex-start">
            <Button
              variant="contained"
              size="small"
              onClick={() => {
                setCreateName("");
                setCreateOpen(true);
              }}
            >
              {t("organizations.newOrg", { defaultValue: "New organization" })}
            </Button>
          </Stack>
        )}

        {/* Status filter (only meaningful once at least one org exists) */}
        {orgs.length > 0 && (
          <Stack direction="row" justifyContent="flex-end">
            <TextField
              select
              size="small"
              label={t("organizations.filter.status", { defaultValue: "Status" })}
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as "active" | "archived" | "all")}
              sx={{ minWidth: 160 }}
            >
              <MenuItem value="active">{t("organizations.status.active", { defaultValue: "Active" })}</MenuItem>
              <MenuItem value="archived">{t("organizations.status.archived", { defaultValue: "Archived" })}</MenuItem>
              <MenuItem value="all">{t("organizations.filter.all", { defaultValue: "All" })}</MenuItem>
            </TextField>
          </Stack>
        )}

        {/* Org list */}
        {orgs.length === 0 ? (
          <Alert severity="info">
            {enabled
              ? t("organizations.emptyEnabled", {
                  defaultValue: "No organizations yet. They appear here once the consuming app creates them.",
                })
              : t("organizations.emptyDisabled", {
                  defaultValue: "Organizations are off for this app. Turn them on above to start creating tenants.",
                })}
          </Alert>
        ) : visibleOrgs.length === 0 ? (
          <Alert severity="info">
            {t("organizations.noneForFilter", { defaultValue: "No organizations match this filter." })}
          </Alert>
        ) : (
          <TableContainer component={Paper} variant="outlined" sx={{ borderRadius: 2 }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell><Typography variant="subtitle2">{t("organizations.col.name", { defaultValue: "Name" })}</Typography></TableCell>
                  <TableCell><Typography variant="subtitle2">{t("organizations.col.id", { defaultValue: "ID" })}</Typography></TableCell>
                  <TableCell><Typography variant="subtitle2">{t("organizations.col.slug", { defaultValue: "Slug" })}</Typography></TableCell>
                  <TableCell><Typography variant="subtitle2">{t("organizations.col.status", { defaultValue: "Status" })}</Typography></TableCell>
                  <TableCell align="center"><Typography variant="subtitle2">{t("organizations.col.members", { defaultValue: "Members" })}</Typography></TableCell>
                  <TableCell><Typography variant="subtitle2">{t("organizations.col.created", { defaultValue: "Created" })}</Typography></TableCell>
                  <TableCell align="right"><Typography variant="subtitle2">{t("organizations.col.actions", { defaultValue: "Actions" })}</Typography></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {visibleOrgs.map((org) => {
                  const archived = org.status === "archived";
                  return (
                    <TableRow key={org.id} hover sx={{ opacity: archived ? 0.6 : 1 }}>
                      <TableCell>{org.name}</TableCell>
                      <TableCell>
                        <Stack direction="row" spacing={0.5} alignItems="center">
                          <Typography sx={{ fontFamily: "var(--font-mono)", fontSize: 12.5, color: "text.secondary" }}>
                            {org.id}
                          </Typography>
                          <Tooltip title={t("organizations.copyId", { defaultValue: "Copy ID" })}>
                            <IconButton
                              size="small"
                              onClick={() => {
                                navigator.clipboard.writeText(org.id).then(
                                  () => enqueueSnackbar(t("organizations.idCopied", { defaultValue: "Organization ID copied" }), { variant: "success" }),
                                  () => enqueueSnackbar(t("organizations.copyFailed", { defaultValue: "Copy failed" }), { variant: "error" }),
                                );
                              }}
                              sx={{ color: "text.secondary" }}
                            >
                              <Copy size={12} strokeWidth={1.75} />
                            </IconButton>
                          </Tooltip>
                        </Stack>
                      </TableCell>
                      <TableCell>
                        <Typography sx={{ fontFamily: "var(--font-mono)", fontSize: 12.5 }}>{org.slug}</Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={
                            archived
                              ? t("organizations.status.archived", { defaultValue: "Archived" })
                              : t("organizations.status.active", { defaultValue: "Active" })
                          }
                          variant="outlined"
                          sx={{ height: 20, fontSize: 10.5, ...(!archived && { borderColor: "success.main", color: "success.main" }) }}
                        />
                      </TableCell>
                      <TableCell align="center">{org.memberCount}</TableCell>
                      <TableCell>{fmtDate(org.createdAt)}</TableCell>
                      <TableCell align="right">
                        <Stack direction="row" spacing={0.5} justifyContent="flex-end">
                          <Tooltip title={t("organizations.viewMembers", { defaultValue: "View members" })}>
                            <IconButton size="small" onClick={() => void openMembers(org)}>
                              <Users size={14} strokeWidth={1.75} />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title={t("organizations.rename", { defaultValue: "Rename" })}>
                            <IconButton size="small" onClick={() => openRename(org)}>
                              <SquarePen size={14} strokeWidth={1.75} />
                            </IconButton>
                          </Tooltip>
                          {archived ? (
                            <>
                              <Tooltip title={t("organizations.restore", { defaultValue: "Restore" })}>
                                <span>
                                  <IconButton
                                    size="small"
                                    disabled={restoringId === org.id}
                                    onClick={() => void doRestore(org)}
                                  >
                                    <ArchiveRestore size={14} strokeWidth={1.75} />
                                  </IconButton>
                                </span>
                              </Tooltip>
                              <Tooltip title={t("organizations.delete", { defaultValue: "Delete" })}>
                                <span>
                                  <IconButton size="small" color="error" disabled={restoringId === org.id} onClick={() => openDelete(org)}>
                                    <Trash2 size={14} strokeWidth={1.75} />
                                  </IconButton>
                                </span>
                              </Tooltip>
                            </>
                          ) : (
                            <Tooltip title={t("organizations.archive", { defaultValue: "Archive" })}>
                              <span>
                                <IconButton size="small" onClick={() => openArchive(org)}>
                                  <Archive size={14} strokeWidth={1.75} />
                                </IconButton>
                              </span>
                            </Tooltip>
                          )}
                        </Stack>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Stack>

      {/* Members dialog */}
      <Dialog open={membersOpen} onClose={() => setMembersOpen(false)} fullWidth maxWidth="md">
        <DialogTitle>
          {t("organizations.membersTitle", { defaultValue: "Members" })}
          {membersOrg ? ` — ${membersOrg.name}` : ""}
        </DialogTitle>
        <DialogContent dividers>
          {membersLoading ? (
            <Stack alignItems="center" sx={{ py: 3 }}>
              <CircularProgress size={20} />
            </Stack>
          ) : members.length === 0 ? (
            <Typography variant="body2" color="text.secondary">
              {t("organizations.noMembers", { defaultValue: "No members." })}
            </Typography>
          ) : (
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>{t("organizations.col.email", { defaultValue: "Email" })}</TableCell>
                  <TableCell>{t("organizations.col.tier", { defaultValue: "Tier" })}</TableCell>
                  <TableCell>{t("organizations.col.roles", { defaultValue: "Roles" })}</TableCell>
                  <TableCell>{t("organizations.col.status", { defaultValue: "Status" })}</TableCell>
                  <TableCell align="right">{t("organizations.col.actions", { defaultValue: "Actions" })}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {members.map((m) => (
                  <TableRow key={m.userId}>
                    <TableCell>{m.email || m.userId}</TableCell>
                    <TableCell>{m.orgRole}</TableCell>
                    <TableCell>
                      {m.roles && m.roles.length > 0 ? (
                        <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                          {m.roles.map((r) => (
                            <Chip key={r.id} size="small" label={r.name || r.slug} />
                          ))}
                        </Stack>
                      ) : (
                        <Typography variant="body2" color="text.secondary">
                          —
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell>{m.status}</TableCell>
                    <TableCell align="right">
                      <Stack direction="row" spacing={0.5} justifyContent="flex-end">
                        <Tooltip title={t("organizations.editMember", { defaultValue: "Edit member" })}>
                          <IconButton size="small" onClick={() => openEditMember(m)}>
                            <SquarePen size={15} />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title={t("organizations.removeMember", { defaultValue: "Remove member" })}>
                          <IconButton size="small" color="error" onClick={() => setRemoveMember(m)}>
                            <Trash2 size={15} />
                          </IconButton>
                        </Tooltip>
                      </Stack>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          {!membersLoading && membersOrg?.status === "active" && (
            <Stack spacing={2.5} sx={{ mt: 3 }}>
              {/* Add an existing app user */}
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  {t("organizations.addMemberTitle", { defaultValue: "Add existing user" })}
                </Typography>
                <Stack direction="row" spacing={1} alignItems="center">
                  <TextField
                    size="small"
                    fullWidth
                    placeholder={t("organizations.addMemberEmail", { defaultValue: "user@example.com" })}
                    value={addEmail}
                    onChange={(e) => setAddEmail(e.target.value)}
                  />
                  <TextField
                    select
                    size="small"
                    value={addTier}
                    onChange={(e) => setAddTier(e.target.value)}
                    sx={{ minWidth: 120 }}
                  >
                    <MenuItem value="owner">owner</MenuItem>
                    <MenuItem value="admin">admin</MenuItem>
                    <MenuItem value="member">member</MenuItem>
                  </TextField>
                  <Button
                    variant="outlined"
                    onClick={() => void addMemberSubmit()}
                    disabled={addSaving || !addEmail.trim()}
                  >
                    {t("organizations.add", { defaultValue: "Add" })}
                  </Button>
                </Stack>
                <Typography variant="caption" color="text.secondary">
                  {t("organizations.addMemberHelp", {
                    defaultValue:
                      "The user must already belong to this app. To bring in a new email, send an invitation below.",
                  })}
                </Typography>
              </Box>

              {/* Pending invitations */}
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  {t("organizations.invitesTitle", { defaultValue: "Pending invitations" })}
                </Typography>
                {invites.length === 0 ? (
                  <Typography variant="body2" color="text.secondary">
                    {t("organizations.noInvites", { defaultValue: "No pending invitations." })}
                  </Typography>
                ) : (
                  <Table size="small">
                    <TableBody>
                      {invites.map((inv) => (
                        <TableRow key={inv.id}>
                          <TableCell>{inv.email}</TableCell>
                          <TableCell>{inv.orgRole}</TableCell>
                          <TableCell align="right">
                            <Button
                              size="small"
                              color="error"
                              onClick={() => void revokeInvite(inv.id)}
                              disabled={revokingInviteId === inv.id}
                            >
                              {t("organizations.revoke", { defaultValue: "Revoke" })}
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
                <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 1 }}>
                  <TextField
                    size="small"
                    fullWidth
                    placeholder={t("organizations.inviteEmail", { defaultValue: "invite@example.com" })}
                    value={inviteEmail}
                    onChange={(e) => setInviteEmail(e.target.value)}
                  />
                  <TextField
                    select
                    size="small"
                    value={inviteTier}
                    onChange={(e) => setInviteTier(e.target.value)}
                    sx={{ minWidth: 120 }}
                  >
                    <MenuItem value="owner">owner</MenuItem>
                    <MenuItem value="admin">admin</MenuItem>
                    <MenuItem value="member">member</MenuItem>
                  </TextField>
                  <Button
                    variant="outlined"
                    onClick={() => void inviteSubmit()}
                    disabled={inviteSaving || !inviteEmail.trim()}
                  >
                    {t("organizations.invite", { defaultValue: "Invite" })}
                  </Button>
                </Stack>
              </Box>
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setMembersOpen(false)}>{t("common.close", { defaultValue: "Close" })}</Button>
        </DialogActions>
      </Dialog>

      {/* Create organization dialog */}
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} fullWidth maxWidth="xs">
        <DialogTitle>{t("organizations.createTitle", { defaultValue: "New organization" })}</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            fullWidth
            margin="dense"
            label={t("organizations.nameLabel", { defaultValue: "Name" })}
            value={createName}
            onChange={(e) => setCreateName(e.target.value)}
          />
          <Typography variant="caption" color="text.secondary">
            {t("organizations.createHelp", {
              defaultValue: "Creates an empty organization. Add members or send invitations from its members dialog.",
            })}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)} disabled={createSaving}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button
            variant="contained"
            onClick={() => void createOrgSubmit()}
            disabled={createSaving || !createName.trim()}
          >
            {t("common.create", { defaultValue: "Create" })}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit member dialog (tier + project roles) */}
      <Dialog open={!!editRolesMember} onClose={() => setEditRolesMember(null)} fullWidth maxWidth="xs">
        <DialogTitle>
          {t("organizations.editMemberTitle", { defaultValue: "Edit member" })}
          {editRolesMember ? ` — ${editRolesMember.email || editRolesMember.userId}` : ""}
        </DialogTitle>
        <DialogContent dividers>
          <Stack spacing={2}>
            <TextField
              select
              size="small"
              fullWidth
              label={t("organizations.tierLabel", { defaultValue: "Tier" })}
              value={editTier}
              onChange={(e) => setEditTier(e.target.value)}
              helperText={t("organizations.tierHelp", {
                defaultValue: "owner/admin manage the org; the last owner can't be demoted.",
              })}
            >
              <MenuItem value="owner">owner</MenuItem>
              <MenuItem value="admin">admin</MenuItem>
              <MenuItem value="member">member</MenuItem>
            </TextField>

            <Box>
              <Typography variant="caption" color="text.secondary">
                {t("organizations.rolesLabel", { defaultValue: "Project roles" })}
              </Typography>
              {roleCatalog.length === 0 ? (
                <Typography variant="body2" color="text.secondary">
                  {t("organizations.noProjectRoles", { defaultValue: "No roles are defined for this project yet." })}
                </Typography>
              ) : (
                <Stack>
                  {roleCatalog.map((r) => (
                    <FormControlLabel
                      key={r.id}
                      control={
                        <Checkbox
                          checked={editRoleIds.includes(r.id)}
                          onChange={(e) =>
                            setEditRoleIds((prev) =>
                              e.target.checked ? [...prev, r.id] : prev.filter((id) => id !== r.id),
                            )
                          }
                        />
                      }
                      label={r.name || r.slug}
                    />
                  ))}
                </Stack>
              )}
            </Box>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditRolesMember(null)} disabled={editRolesSaving}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button variant="contained" onClick={() => void saveMember()} disabled={editRolesSaving}>
            {t("common.save", { defaultValue: "Save" })}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Remove member confirm dialog */}
      <Dialog open={!!removeMember} onClose={() => setRemoveMember(null)} fullWidth maxWidth="xs">
        <DialogTitle>{t("organizations.removeMemberTitle", { defaultValue: "Remove member" })}</DialogTitle>
        <DialogContent>
          <Typography variant="body2">
            {t("organizations.removeMemberConfirm", {
              defaultValue: "Remove {{email}} from {{org}}? They lose access to this organization.",
              email: removeMember?.email || removeMember?.userId,
              org: membersOrg?.name,
            })}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRemoveMember(null)} disabled={removeSaving}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button color="error" variant="contained" onClick={() => void confirmRemoveMember()} disabled={removeSaving}>
            {t("organizations.remove", { defaultValue: "Remove" })}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Rename dialog */}
      <Dialog open={renameOpen} onClose={() => setRenameOpen(false)} fullWidth maxWidth="xs">
        <DialogTitle>{t("organizations.renameTitle", { defaultValue: "Rename organization" })}</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            fullWidth
            size="small"
            sx={{ mt: 1 }}
            label={t("organizations.col.name", { defaultValue: "Name" })}
            value={renameValue}
            onChange={(e) => setRenameValue(e.target.value)}
            disabled={renameSaving}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRenameOpen(false)} disabled={renameSaving}>
            {t("apps.dialog.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button
            variant="contained"
            disableElevation
            onClick={() => void saveRename()}
            disabled={renameSaving || !renameValue.trim()}
          >
            {renameSaving ? <CircularProgress size={16} /> : t("apps.dialog.save", { defaultValue: "Save" })}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Archive confirm */}
      <Dialog open={archiveOpen} onClose={() => setArchiveOpen(false)} fullWidth maxWidth="xs">
        <DialogTitle>{t("organizations.archiveTitle", { defaultValue: "Archive organization" })}</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary">
            {t("organizations.archiveConfirm", {
              defaultValue: 'Archive "{{name}}"? Members lose access. You can restore it later from this list.',
              name: archiveOrg?.name,
            })}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setArchiveOpen(false)} disabled={archiveSaving}>
            {t("apps.dialog.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button color="error" variant="contained" disableElevation onClick={() => void confirmArchive()} disabled={archiveSaving}>
            {archiveSaving ? <CircularProgress size={16} /> : t("organizations.archive", { defaultValue: "Archive" })}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete (permanent) — archived orgs only, type-to-confirm */}
      <Dialog open={deleteOpen} onClose={() => !deleteSaving && setDeleteOpen(false)} fullWidth maxWidth="xs">
        <DialogTitle>{t("organizations.deleteTitle", { defaultValue: "Delete organization permanently" })}</DialogTitle>
        <Box
          component="form"
          onSubmit={(e) => {
            e.preventDefault();
            if (deleteConfirm.trim() === deleteOrg?.name) void confirmDelete();
          }}
        >
          <DialogContent>
            <Stack spacing={1.5}>
              <Alert severity="warning" icon={<TriangleAlert size={16} strokeWidth={1.75} />}>
                {t("organizations.deleteWarning", {
                  defaultValue:
                    'Permanently delete "{{name}}"? This cannot be undone. All members, roles, and invitations are removed. Your app must make sure nothing still references this organization before you delete it.',
                  name: deleteOrg?.name,
                })}
              </Alert>
              <Typography variant="body2" color="text.secondary">
                {t("organizations.typeToConfirm", {
                  name: deleteOrg?.name,
                  defaultValue: 'Type "{{name}}" to confirm.',
                })}
              </Typography>
              <TextField
                size="small"
                autoFocus
                value={deleteConfirm}
                onChange={(e) => setDeleteConfirm(e.target.value)}
                placeholder={deleteOrg?.name}
                disabled={deleteSaving}
              />
            </Stack>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDeleteOpen(false)} disabled={deleteSaving}>
              {t("apps.dialog.cancel", { defaultValue: "Cancel" })}
            </Button>
            <Button
              type="submit"
              variant="contained"
              color="error"
              disableElevation
              disabled={deleteConfirm.trim() !== deleteOrg?.name || deleteSaving}
            >
              {deleteSaving ? <CircularProgress size={16} /> : t("organizations.delete", { defaultValue: "Delete" })}
            </Button>
          </DialogActions>
        </Box>
      </Dialog>
    </Box>
  );
}
