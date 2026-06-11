import * as React from "react";
import axios from "axios";
import { useSnackbar } from "notistack";
import { useTranslation } from "react-i18next";
import {
  Box,
  Breadcrumbs,
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
  Link,
  MenuItem,
  Paper,
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
import { Ban, SquarePen, Trash2, UserCheck } from "lucide-react";
import type { Project } from "../core.ts";
import { errText } from "./AppAuthMethods.tsx";
import PageHeader from "../components/PageHeader.tsx";

export interface OrgSummary {
  id: string;
  name: string;
  slug: string;
  status: string;
}

interface OrgMemberRole {
  id: string;
  slug: string;
  name: string;
}

interface OrgMember {
  userId: string;
  email: string;
  orgRole: string; // tier: owner | admin | member
  status: string;
  roles: OrgMemberRole[];
}

interface OrgInvite {
  id: string;
  email: string;
  orgRole: string;
  status: string;
  createdAt: string;
  expiresAt: string;
}

interface Props {
  project: Project;
  appId: string;
  org: OrgSummary;
  onBack: () => void;
}

const TIERS = ["owner", "admin", "member"];

export default function AppOrganizationMembers({ project, appId, org, onBack }: Props) {
  const { enqueueSnackbar } = useSnackbar();
  const { t } = useTranslation();

  const projectURL = `/admin/workspace/${project.workspaceId}/projects/${project.id}`;
  const orgURL = `${projectURL}/apps/${appId}/organizations/${org.id}`;
  const isActive = org.status === "active";

  // Members (paginated + searched)
  const [members, setMembers] = React.useState<OrgMember[]>([]);
  const [membersTotal, setMembersTotal] = React.useState(0);
  const [membersLoading, setMembersLoading] = React.useState(true);
  const [page, setPage] = React.useState(0);
  const [pageSize, setPageSize] = React.useState(25);
  const [search, setSearch] = React.useState("");
  const [debouncedSearch, setDebouncedSearch] = React.useState("");
  const membersReqRef = React.useRef(0);

  // Invites (paginated)
  const [invites, setInvites] = React.useState<OrgInvite[]>([]);
  const [invitesTotal, setInvitesTotal] = React.useState(0);
  const [invPage, setInvPage] = React.useState(0);
  const invPageSize = 25;

  // Role catalog (for the edit dialog)
  const [roleCatalog, setRoleCatalog] = React.useState<OrgMemberRole[]>([]);

  // Add existing user
  const [addEmail, setAddEmail] = React.useState("");
  const [addTier, setAddTier] = React.useState("member");
  const [addSaving, setAddSaving] = React.useState(false);

  // Invite
  const [inviteEmail, setInviteEmail] = React.useState("");
  const [inviteTier, setInviteTier] = React.useState("member");
  const [inviteSaving, setInviteSaving] = React.useState(false);
  const [revokingId, setRevokingId] = React.useState<string | null>(null);

  // Edit member (tier + roles)
  const [editMember, setEditMember] = React.useState<OrgMember | null>(null);
  const [editTier, setEditTier] = React.useState("member");
  const [editRoleIds, setEditRoleIds] = React.useState<string[]>([]);
  const [editSaving, setEditSaving] = React.useState(false);

  // Remove member
  const [removeTarget, setRemoveTarget] = React.useState<OrgMember | null>(null);
  const [removeSaving, setRemoveSaving] = React.useState(false);

  // Suspend / reactivate member
  const [suspendTarget, setSuspendTarget] = React.useState<OrgMember | null>(null);
  const [suspendSaving, setSuspendSaving] = React.useState(false);

  const loadMembers = React.useCallback(
    async (p: number, ps: number, q: string) => {
      const gen = ++membersReqRef.current;
      setMembersLoading(true);
      try {
        const res = await axios.get<{ members: OrgMember[]; total: number }>(`${orgURL}/members`, {
          params: { page: p, pageSize: ps, search: q },
        });
        if (gen !== membersReqRef.current) return;
        setMembers(res.data.members || []);
        setMembersTotal(res.data.total || 0);
      } catch (e) {
        if (gen !== membersReqRef.current) return;
        enqueueSnackbar(errText(e), { variant: "error" });
      } finally {
        if (gen === membersReqRef.current) setMembersLoading(false);
      }
    },
    [orgURL, enqueueSnackbar],
  );

  const loadInvites = React.useCallback(
    async (p: number) => {
      try {
        const res = await axios.get<{ invites: OrgInvite[]; total: number }>(`${orgURL}/invites`, {
          params: { page: p, pageSize: invPageSize },
        });
        setInvites(res.data.invites || []);
        setInvitesTotal(res.data.total || 0);
      } catch (e) {
        enqueueSnackbar(errText(e), { variant: "error" });
      }
    },
    [orgURL, enqueueSnackbar],
  );

  // Debounce search → reset to first page.
  React.useEffect(() => {
    const id = setTimeout(() => {
      setDebouncedSearch(search);
      setPage(0);
    }, 300);
    return () => clearTimeout(id);
  }, [search]);

  React.useEffect(() => {
    void loadMembers(page, pageSize, debouncedSearch);
  }, [page, pageSize, debouncedSearch, loadMembers]);

  React.useEffect(() => {
    void loadInvites(invPage);
  }, [invPage, loadInvites]);

  // Role catalog (best-effort — only needed by the edit dialog).
  React.useEffect(() => {
    axios
      .get<{ roles: OrgMemberRole[] }>(`${projectURL}/roles`)
      .then((r) => setRoleCatalog(r.data.roles || []))
      .catch(() => {});
  }, [projectURL]);

  async function addMemberSubmit() {
    if (!addEmail.trim()) return;
    setAddSaving(true);
    try {
      await axios.post(`${orgURL}/members`, { email: addEmail.trim(), orgRole: addTier });
      setAddEmail("");
      setAddTier("member");
      enqueueSnackbar(t("organizations.memberAdded", { defaultValue: "Member added" }), { variant: "success" });
      await loadMembers(page, pageSize, debouncedSearch);
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setAddSaving(false);
    }
  }

  async function inviteSubmit() {
    if (!inviteEmail.trim()) return;
    setInviteSaving(true);
    try {
      await axios.post(`${orgURL}/invites`, { email: inviteEmail.trim(), orgRole: inviteTier });
      setInviteEmail("");
      setInviteTier("member");
      enqueueSnackbar(t("organizations.inviteSent", { defaultValue: "Invitation sent" }), { variant: "success" });
      await loadInvites(invPage);
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setInviteSaving(false);
    }
  }

  async function revokeInvite(id: string) {
    setRevokingId(id);
    try {
      await axios.delete(`${orgURL}/invites/${id}`);
      await loadInvites(invPage);
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setRevokingId(null);
    }
  }

  function openEditMember(m: OrgMember) {
    setEditMember(m);
    setEditTier(m.orgRole);
    setEditRoleIds(m.roles ? m.roles.map((r) => r.id) : []);
  }

  async function saveMember() {
    if (!editMember) return;
    setEditSaving(true);
    try {
      const base = `${orgURL}/members/${editMember.userId}`;
      if (editTier !== editMember.orgRole) {
        await axios.patch(base, { orgRole: editTier });
      }
      const curIds = [...(editMember.roles ?? []).map((r) => r.id)].sort();
      const newIds = [...editRoleIds].sort();
      const rolesChanged = curIds.length !== newIds.length || curIds.some((id, i) => id !== newIds[i]);
      if (rolesChanged) {
        await axios.put(`${base}/roles`, { roleIds: editRoleIds });
      }
      enqueueSnackbar(t("organizations.memberUpdated", { defaultValue: "Member updated" }), { variant: "success" });
      setEditMember(null);
      await loadMembers(page, pageSize, debouncedSearch);
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setEditSaving(false);
    }
  }

  async function confirmRemove() {
    if (!removeTarget) return;
    setRemoveSaving(true);
    try {
      await axios.delete(`${orgURL}/members/${removeTarget.userId}`);
      enqueueSnackbar(t("organizations.memberRemoved", { defaultValue: "Member removed" }), { variant: "success" });
      setRemoveTarget(null);
      // If we just emptied the last row of a non-first page, step back.
      const nextPage = members.length === 1 && page > 0 ? page - 1 : page;
      setPage(nextPage);
      await loadMembers(nextPage, pageSize, debouncedSearch);
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setRemoveSaving(false);
    }
  }

  async function confirmSuspend() {
    if (!suspendTarget) return;
    const isSuspending = suspendTarget.status === "active";
    const nextStatus = isSuspending ? "disabled" : "active";
    setSuspendSaving(true);
    try {
      await axios.patch(`${orgURL}/members/${suspendTarget.userId}/status`, { status: nextStatus });
      enqueueSnackbar(
        isSuspending
          ? t("orgMembers.suspend", { defaultValue: "Suspend" })
          : t("orgMembers.reactivate", { defaultValue: "Reactivate" }),
        { variant: "success" },
      );
      setSuspendTarget(null);
      await loadMembers(page, pageSize, debouncedSearch);
    } catch (e: unknown) {
      if ((e as { response?: { status?: number } })?.response?.status === 409) {
        enqueueSnackbar(t("orgMembers.lastOwnerError", { defaultValue: "Cannot suspend the organization's only owner." }), {
          variant: "error",
        });
      } else {
        enqueueSnackbar(errText(e), { variant: "error" });
      }
    } finally {
      setSuspendSaving(false);
    }
  }

  return (
    <Box>
      <Breadcrumbs sx={{ mb: 1 }}>
        <Link component="button" type="button" variant="body2" underline="hover" color="inherit" onClick={onBack}>
          {t("organizations.title", { defaultValue: "Organizations" })}
        </Link>
        <Typography variant="body2" color="text.primary">
          {org.name}
        </Typography>
      </Breadcrumbs>

      <PageHeader title={`${org.name} — ${t("organizations.membersTitle", { defaultValue: "Members" })}`} mb={2} />

      {!isActive && (
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {t("organizations.archivedReadOnly", { defaultValue: "This organization is archived — members are read-only." })}
        </Typography>
      )}

      <Stack spacing={3}>
        {/* Members */}
        <Box>
          <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
            <Typography variant="subtitle2">{t("organizations.membersTitle", { defaultValue: "Members" })}</Typography>
            <TextField
              size="small"
              placeholder={t("organizations.searchEmail", { defaultValue: "Search email…" })}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              sx={{ minWidth: 240 }}
            />
          </Stack>

          <TableContainer component={Paper} variant="outlined" sx={{ borderRadius: 2 }}>
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
                {membersLoading ? (
                  <TableRow>
                    <TableCell colSpan={5} align="center" sx={{ py: 3 }}>
                      <CircularProgress size={20} />
                    </TableCell>
                  </TableRow>
                ) : members.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5}>
                      <Typography variant="body2" color="text.secondary">
                        {t("organizations.noMembers", { defaultValue: "No members." })}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  members.map((m) => (
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
                      <TableCell>
                        {m.status === "disabled" ? (
                          <Chip
                            size="small"
                            label={t("orgMembers.statusDisabled", { defaultValue: "Suspended" })}
                            color="warning"
                          />
                        ) : (
                          m.status
                        )}
                      </TableCell>
                      <TableCell align="right">
                        {isActive && (
                          <Stack direction="row" spacing={0.5} justifyContent="flex-end">
                            <Tooltip title={t("organizations.editMember", { defaultValue: "Edit member" })}>
                              <IconButton size="small" onClick={() => openEditMember(m)}>
                                <SquarePen size={15} />
                              </IconButton>
                            </Tooltip>
                            <Tooltip
                              title={
                                m.status === "disabled"
                                  ? t("orgMembers.reactivate", { defaultValue: "Reactivate" })
                                  : t("orgMembers.suspend", { defaultValue: "Suspend" })
                              }
                            >
                              <IconButton
                                size="small"
                                color={m.status === "disabled" ? "success" : "warning"}
                                onClick={() => setSuspendTarget(m)}
                              >
                                {m.status === "disabled" ? <UserCheck size={15} /> : <Ban size={15} />}
                              </IconButton>
                            </Tooltip>
                            <Tooltip title={t("organizations.removeMember", { defaultValue: "Remove member" })}>
                              <IconButton size="small" color="error" onClick={() => setRemoveTarget(m)}>
                                <Trash2 size={15} />
                              </IconButton>
                            </Tooltip>
                          </Stack>
                        )}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
            <TablePagination
              component="div"
              count={membersTotal}
              page={page}
              onPageChange={(_, p) => setPage(p)}
              rowsPerPage={pageSize}
              onRowsPerPageChange={(e) => {
                setPageSize(parseInt(e.target.value, 10));
                setPage(0);
              }}
              rowsPerPageOptions={[10, 25, 50]}
            />
          </TableContainer>
        </Box>

        {/* Add existing user */}
        {isActive && (
          <Box>
            <Typography variant="subtitle2" gutterBottom>
              {t("organizations.addMemberTitle", { defaultValue: "Add existing user" })}
            </Typography>
            <Stack direction="row" spacing={1} alignItems="center" sx={{ maxWidth: 560 }}>
              <TextField
                size="small"
                fullWidth
                placeholder={t("organizations.addMemberEmail", { defaultValue: "user@example.com" })}
                value={addEmail}
                onChange={(e) => setAddEmail(e.target.value)}
              />
              <TextField select size="small" value={addTier} onChange={(e) => setAddTier(e.target.value)} sx={{ minWidth: 120 }}>
                {TIERS.map((tier) => (
                  <MenuItem key={tier} value={tier}>
                    {tier}
                  </MenuItem>
                ))}
              </TextField>
              <Button variant="outlined" onClick={() => void addMemberSubmit()} disabled={addSaving || !addEmail.trim()}>
                {t("organizations.add", { defaultValue: "Add" })}
              </Button>
            </Stack>
            <Typography variant="caption" color="text.secondary">
              {t("organizations.addMemberHelp", {
                defaultValue: "The user must already belong to this app. To bring in a new email, send an invitation below.",
              })}
            </Typography>
          </Box>
        )}

        {/* Invitations */}
        {isActive && (
          <Box>
            <Typography variant="subtitle2" gutterBottom>
              {t("organizations.invitesTitle", { defaultValue: "Pending invitations" })}
            </Typography>
            {invites.length === 0 ? (
              <Typography variant="body2" color="text.secondary">
                {t("organizations.noInvites", { defaultValue: "No pending invitations." })}
              </Typography>
            ) : (
              <TableContainer component={Paper} variant="outlined" sx={{ borderRadius: 2 }}>
                <Table size="small">
                  <TableBody>
                    {invites.map((inv) => (
                      <TableRow key={inv.id}>
                        <TableCell>{inv.email}</TableCell>
                        <TableCell>{inv.orgRole}</TableCell>
                        <TableCell align="right">
                          <Button size="small" color="error" onClick={() => void revokeInvite(inv.id)} disabled={revokingId === inv.id}>
                            {t("organizations.revoke", { defaultValue: "Revoke" })}
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                <TablePagination
                  component="div"
                  count={invitesTotal}
                  page={invPage}
                  onPageChange={(_, p) => setInvPage(p)}
                  rowsPerPage={invPageSize}
                  rowsPerPageOptions={[invPageSize]}
                />
              </TableContainer>
            )}
            <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 1, maxWidth: 560 }}>
              <TextField
                size="small"
                fullWidth
                placeholder={t("organizations.inviteEmail", { defaultValue: "invite@example.com" })}
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
              />
              <TextField select size="small" value={inviteTier} onChange={(e) => setInviteTier(e.target.value)} sx={{ minWidth: 120 }}>
                {TIERS.map((tier) => (
                  <MenuItem key={tier} value={tier}>
                    {tier}
                  </MenuItem>
                ))}
              </TextField>
              <Button variant="outlined" onClick={() => void inviteSubmit()} disabled={inviteSaving || !inviteEmail.trim()}>
                {t("organizations.invite", { defaultValue: "Invite" })}
              </Button>
            </Stack>
          </Box>
        )}
      </Stack>

      {/* Edit member dialog (tier + project roles) */}
      <Dialog open={!!editMember} onClose={() => setEditMember(null)} fullWidth maxWidth="xs">
        <DialogTitle>
          {t("organizations.editMemberTitle", { defaultValue: "Edit member" })}
          {editMember ? ` — ${editMember.email || editMember.userId}` : ""}
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
              {TIERS.map((tier) => (
                <MenuItem key={tier} value={tier}>
                  {tier}
                </MenuItem>
              ))}
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
                            setEditRoleIds((prev) => (e.target.checked ? [...prev, r.id] : prev.filter((id) => id !== r.id)))
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
          <Button onClick={() => setEditMember(null)} disabled={editSaving}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button variant="contained" onClick={() => void saveMember()} disabled={editSaving}>
            {t("common.save", { defaultValue: "Save" })}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Remove member confirm dialog */}
      <Dialog open={!!removeTarget} onClose={() => setRemoveTarget(null)} fullWidth maxWidth="xs">
        <DialogTitle>{t("organizations.removeMemberTitle", { defaultValue: "Remove member" })}</DialogTitle>
        <DialogContent>
          <Typography variant="body2">
            {t("organizations.removeMemberConfirm", {
              defaultValue: "Remove {{email}} from {{org}}? They lose access to this organization.",
              email: removeTarget?.email || removeTarget?.userId,
              org: org.name,
            })}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRemoveTarget(null)} disabled={removeSaving}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button color="error" variant="contained" onClick={() => void confirmRemove()} disabled={removeSaving}>
            {t("organizations.remove", { defaultValue: "Remove" })}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Suspend / reactivate member confirm dialog */}
      <Dialog open={!!suspendTarget} onClose={() => setSuspendTarget(null)} fullWidth maxWidth="xs">
        <DialogTitle>
          {suspendTarget?.status === "disabled"
            ? t("orgMembers.reactivate", { defaultValue: "Reactivate" })
            : t("orgMembers.suspend", { defaultValue: "Suspend" })}
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2">
            {suspendTarget?.status === "disabled"
              ? `${t("orgMembers.reactivate", { defaultValue: "Reactivate" })} ${suspendTarget?.email || suspendTarget?.userId}?`
              : t("orgMembers.suspendConfirm", {
                  defaultValue: "Suspend this member? They lose organization access until reactivated.",
                })}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSuspendTarget(null)} disabled={suspendSaving}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button
            color={suspendTarget?.status === "disabled" ? "success" : "warning"}
            variant="contained"
            onClick={() => void confirmSuspend()}
            disabled={suspendSaving}
          >
            {suspendTarget?.status === "disabled"
              ? t("orgMembers.reactivate", { defaultValue: "Reactivate" })
              : t("orgMembers.suspend", { defaultValue: "Suspend" })}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
