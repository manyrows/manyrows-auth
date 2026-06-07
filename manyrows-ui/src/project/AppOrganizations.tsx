import * as React from "react";
import axios from "axios";
import { useSnackbar } from "notistack";
import { useTranslation } from "react-i18next";
import {
  Alert,
  Box,
  Button,
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
import { Archive, ArchiveRestore, SquarePen, Users } from "lucide-react";
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

interface OrgMember {
  userId: string;
  email: string;
  orgRole: string;
  status: string;
}

function fmtDate(d?: string): string {
  if (!d) return "-";
  const date = new Date(d);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleDateString();
}

export default function AppOrganizations({ project, appId }: Props) {
  const { enqueueSnackbar } = useSnackbar();
  const { t } = useTranslation();

  const appsBaseURL = `/admin/workspace/${project.workspaceId}/projects/${project.id}/apps`;
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
      enqueueSnackbar(t("apps.appUpdated", { defaultValue: "App updated" }), { variant: "success" });
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setSavingEnabled(false);
    }
  }

  async function openMembers(org: OrgRow) {
    setMembersOrg(org);
    setMembers([]);
    setMembersOpen(true);
    setMembersLoading(true);
    try {
      const res = await axios.get<{ members: OrgMember[] }>(`${appURL}/organizations/${org.id}/members`);
      setMembers(res.data.members || []);
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setMembersLoading(false);
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
                      "Let end-users belong to organizations (tenants) within this app. A consuming app can't create organizations until this is on. Default off.",
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
        </Box>

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
      <Dialog open={membersOpen} onClose={() => setMembersOpen(false)} fullWidth maxWidth="sm">
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
                  <TableCell>{t("organizations.col.role", { defaultValue: "Role" })}</TableCell>
                  <TableCell>{t("organizations.col.status", { defaultValue: "Status" })}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {members.map((m) => (
                  <TableRow key={m.userId}>
                    <TableCell>{m.email || m.userId}</TableCell>
                    <TableCell>{m.orgRole}</TableCell>
                    <TableCell>{m.status}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setMembersOpen(false)}>{t("common.close", { defaultValue: "Close" })}</Button>
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
              defaultValue: 'Archive "{{name}}"? Members lose access; this can be reversed by the consuming app.',
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
    </Box>
  );
}
