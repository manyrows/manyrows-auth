import * as React from "react";
import axios from "axios";
import { useTranslation } from "react-i18next";
import { useSnackbar } from "notistack";
import { Link as RouterLink, useNavigate } from "react-router-dom";
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Divider,
  IconButton,
  InputAdornment,
  Paper,
  Stack,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  Tabs,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { ArrowLeft, Edit3, Search, Trash2 } from "lucide-react";
import Loader from "../Loader.tsx";
import PageHeader from "../components/PageHeader.tsx";
import { extractApiError } from "../lib/apiError.ts";
import type { Workspace } from "../core.ts";
import PoolUserFields from "./PoolUserFields.tsx";

// Single-source pool detail page. Replaces the old drill-down dialog
// in UserPools.tsx: clicking a pool row now navigates here so admins
// can see meta, apps using the pool, and manage user fields without
// stacking on top of the pools list.
type Pool = {
  id: string;
  workspaceId: string;
  name: string;
  createdAt: string;
  updatedAt: string;
  appCount: number;
  userCount: number;
};

type PoolApp = {
  id: string;
  projectId: string;
  projectName: string;
  type: string;
  enabled: boolean;
  displayName: string;
  memberCount: number;
};

type PoolUserRow = {
  id: string;
  email: string;
  enabled: boolean;
  apps: { id: string; name: string; projectId: string }[];
};

interface Props {
  workspace: Workspace;
  poolId: string;
  tab: "overview" | "users" | "fields";
}

const labelSx = {
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase" as const,
  letterSpacing: "0.14em",
  fontSize: 10,
  fontWeight: 500,
  color: "text.disabled" as const,
};

export default function PoolDetail({ workspace, poolId, tab }: Props) {
  const { t } = useTranslation();
  const { enqueueSnackbar } = useSnackbar();
  const navigate = useNavigate();

  const [pool, setPool] = React.useState<Pool | null>(null);
  const [apps, setApps] = React.useState<PoolApp[] | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [err, setErr] = React.useState<string | null>(null);

  // Users tab: server-paginated, lazily loaded when the tab is opened.
  const [users, setUsers] = React.useState<PoolUserRow[] | null>(null);
  const [usersTotal, setUsersTotal] = React.useState(0);
  const [usersLoading, setUsersLoading] = React.useState(false);
  const [usersErr, setUsersErr] = React.useState<string | null>(null);
  const [userSearch, setUserSearch] = React.useState("");
  const [debouncedSearch, setDebouncedSearch] = React.useState("");
  const [page, setPage] = React.useState(0);
  const [pageSize, setPageSize] = React.useState(25);
  // Bumped to force a users refetch after a delete/purge (a nonce, so
  // it doesn't reintroduce the self-retriggering-dep effect bug).
  const [reloadUsers, setReloadUsers] = React.useState(0);
  const [deleteUser, setDeleteUser] = React.useState<PoolUserRow | null>(null);
  const [deletingUser, setDeletingUser] = React.useState(false);
  const [purgeOpen, setPurgeOpen] = React.useState(false);
  const [purging, setPurging] = React.useState(false);

  // Rename + delete dialogs (kept consistent with UserPools list-page UX).
  const [renameOpen, setRenameOpen] = React.useState(false);
  const [renameName, setRenameName] = React.useState("");
  const [renameSaving, setRenameSaving] = React.useState(false);
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [deleteSaving, setDeleteSaving] = React.useState(false);

  const poolsUrl = `/admin/workspace/${workspace.id}/userPools`;
  const backTo = `/app/workspace/${workspace.id}/userPools`;

  const load = React.useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      // No single-pool GET endpoint yet — list and filter locally.
      const [poolsRes, appsRes] = await Promise.all([
        axios.get<{ pools: Pool[] }>(poolsUrl),
        axios.get<{ apps: PoolApp[] }>(`${poolsUrl}/${poolId}/apps`),
      ]);
      const target = (poolsRes.data?.pools ?? []).find((p) => p.id === poolId) ?? null;
      setPool(target);
      setApps(appsRes.data?.apps ?? []);
    } catch (e) {
      setErr(extractApiError(e, t("userPools.detail.loadFailed", { defaultValue: "Could not load pool." })));
    } finally {
      setLoading(false);
    }
  }, [poolsUrl, poolId, t]);

  React.useEffect(() => { void load(); }, [load]);

  // Debounce the search box; reset to page 0 whenever the query settles
  // so the page slice and the pager stay coherent.
  React.useEffect(() => {
    const id = setTimeout(() => {
      setDebouncedSearch(userSearch.trim());
      setPage(0);
    }, 300);
    return () => clearTimeout(id);
  }, [userSearch]);

  // Load the pool's accounts when the Users tab is open — server-side
  // paginated + filtered. Keyed on identity + page/search inputs;
  // deliberately NOT on users/usersLoading (setUsersLoading(true) below
  // would otherwise mutate a dep, tear the effect down mid-flight via
  // the `alive` cleanup, and drop the in-flight response).
  React.useEffect(() => {
    if (tab !== "users") return;
    let alive = true;
    setUsersLoading(true);
    setUsersErr(null);
    axios
      .get<{ accounts: Array<{ id: string; email: string; enabled?: boolean; apps?: { id: string; name: string; projectId: string }[] }>; total: number }>(
        `/admin/workspace/${workspace.id}/accounts`,
        { params: { poolId, page, pageSize, ...(debouncedSearch ? { email: debouncedSearch } : {}) } },
      )
      .then((res) => {
        if (!alive) return;
        setUsers(
          (res.data?.accounts ?? []).map((a) => ({
            id: a.id,
            email: a.email,
            enabled: a.enabled !== false,
            apps: a.apps ?? [],
          })),
        );
        setUsersTotal(typeof res.data?.total === "number" ? res.data.total : 0);
      })
      .catch((e) => {
        if (alive) setUsersErr(extractApiError(e, t("userPools.detail.usersLoadFailed", { defaultValue: "Could not load pool users." })));
      })
      .finally(() => {
        if (alive) setUsersLoading(false);
      });
    return () => { alive = false; };
  }, [tab, workspace.id, poolId, page, pageSize, debouncedSearch, reloadUsers, t]);

  const confirmDeleteUser = async () => {
    if (!deleteUser) return;
    setDeletingUser(true);
    try {
      await axios.delete(`/admin/workspace/${workspace.id}/userPools/${poolId}/users/${deleteUser.id}`);
      enqueueSnackbar(t("userPools.detail.userDeleted", { defaultValue: "User deleted." }), { variant: "success" });
      setDeleteUser(null);
      // If this was the last row on the last page, step back a page.
      setPage((p) => ((users ?? []).length === 1 && p > 0 ? p - 1 : p));
      setReloadUsers((n) => n + 1);
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("userPools.detail.userDeleteFailed", { defaultValue: "Could not delete user." })), { variant: "error" });
    } finally {
      setDeletingUser(false);
    }
  };

  const confirmPurgeOrphans = async () => {
    setPurging(true);
    try {
      const res = await axios.delete<{ deleted?: number }>(`/admin/workspace/${workspace.id}/userPools/${poolId}/orphan-users`);
      const n = res.data?.deleted ?? 0;
      enqueueSnackbar(
        t("userPools.detail.orphansPurged", { count: n, defaultValue: "Deleted {{count}} users with no apps." }),
        { variant: "success" },
      );
      setPurgeOpen(false);
      setPage(0);
      setReloadUsers((n) => n + 1);
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("userPools.detail.orphansPurgeFailed", { defaultValue: "Could not delete users." })), { variant: "error" });
    } finally {
      setPurging(false);
    }
  };

  const openRename = () => {
    if (!pool) return;
    setRenameName(pool.name);
    setRenameOpen(true);
  };
  const closeRename = () => {
    if (renameSaving) return;
    setRenameOpen(false);
  };
  const submitRename = async () => {
    if (!pool) return;
    const name = renameName.trim();
    if (!name || name === pool.name) {
      closeRename();
      return;
    }
    setRenameSaving(true);
    try {
      await axios.patch(`${poolsUrl}/${pool.id}`, { name });
      enqueueSnackbar(t("userPools.renamed", { defaultValue: "Pool renamed." }), { variant: "success" });
      setRenameOpen(false);
      void load();
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("userPools.renameFailed", { defaultValue: "Could not rename pool." })), { variant: "error" });
    } finally {
      setRenameSaving(false);
    }
  };

  const openDelete = () => {
    if (!pool || pool.appCount > 0) return;
    setDeleteOpen(true);
  };
  const closeDelete = () => {
    if (deleteSaving) return;
    setDeleteOpen(false);
  };
  const submitDelete = async () => {
    if (!pool) return;
    setDeleteSaving(true);
    try {
      await axios.delete(`${poolsUrl}/${pool.id}`);
      enqueueSnackbar(t("userPools.deleted", { defaultValue: "Pool deleted." }), { variant: "success" });
      navigate(backTo);
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("userPools.deleteFailed", { defaultValue: "Could not delete pool." })), { variant: "error" });
      setDeleteSaving(false);
    }
  };

  if (loading) return <Loader />;

  if (!pool) {
    return (
      <Stack spacing={2}>
        <Button
          component={RouterLink}
          to={backTo}
          startIcon={<ArrowLeft size={14} strokeWidth={1.75} />}
          size="small"
          sx={{ alignSelf: "flex-start", textTransform: "none" }}
        >
          {t("userPools.detail.back", { defaultValue: "All pools" })}
        </Button>
        <Alert severity="error">
          {err ?? t("userPools.detail.notFound", { defaultValue: "Pool not found." })}
        </Alert>
      </Stack>
    );
  }

  const tabBase = `/app/workspace/${workspace.id}/userPools/${pool.id}`;

  return (
    <Box>
      <Stack spacing={2.5}>
        <Button
          component={RouterLink}
          to={backTo}
          startIcon={<ArrowLeft size={14} strokeWidth={1.75} />}
          size="small"
          sx={{ alignSelf: "flex-start", textTransform: "none", color: "text.secondary" }}
        >
          {t("userPools.detail.back", { defaultValue: "All pools" })}
        </Button>

        <PageHeader
          title={pool.name}
          subtitle={t("userPools.detail.subtitle", {
            defaultValue: "Identity boundary. Apps pointing here share users.",
          })}
          mb={0}
          action={
            <>
              <Button
                size="small"
                variant="outlined"
                startIcon={<Edit3 size={14} strokeWidth={1.75} />}
                onClick={openRename}
                sx={{ borderRadius: 2, textTransform: "none" }}
              >
                {t("userPools.rename", { defaultValue: "Rename" })}
              </Button>
              <Button
                size="small"
                variant="outlined"
                color="error"
                startIcon={<Trash2 size={14} strokeWidth={1.75} />}
                onClick={openDelete}
                disabled={pool.appCount > 0}
                sx={{ borderRadius: 2, textTransform: "none" }}
                title={pool.appCount > 0
                  ? t("userPools.deleteBlocked", { defaultValue: "Remove or repoint apps using this pool first" })
                  : undefined}
              >
                {t("userPools.delete", { defaultValue: "Delete" })}
              </Button>
            </>
          }
        />

        {err && <Alert severity="error">{err}</Alert>}

        <Tabs
          value={tab}
          onChange={(_, v) =>
            navigate(
              v === "fields"
                ? `${tabBase}/fields`
                : v === "users"
                  ? `${tabBase}/poolUsers`
                  : tabBase,
            )
          }
          sx={{ borderBottom: "1px solid", borderColor: "divider" }}
        >
          <Tab
            label={t("userPools.detail.tab.overview", { defaultValue: "Overview" })}
            value="overview"
          />
          <Tab
            label={t("userPools.detail.tab.users", { defaultValue: "Users" })}
            value="users"
          />
          <Tab
            label={t("userPools.detail.tab.fields", { defaultValue: "User fields" })}
            value="fields"
          />
        </Tabs>

        {tab === "overview" ? (
          <Stack spacing={2.5}>
            {/* Meta row */}
            <Stack direction="row" spacing={4}>
              <Stack spacing={0.25}>
                <Typography sx={labelSx}>{t("userPools.detail.metaId", { defaultValue: "ID" })}</Typography>
                <Typography variant="body2" sx={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
                  {pool.id}
                </Typography>
              </Stack>
              <Stack spacing={0.25}>
                <Typography sx={labelSx}>{t("userPools.detail.metaUsers", { defaultValue: "Users" })}</Typography>
                <Typography variant="body2">{pool.userCount}</Typography>
              </Stack>
              <Stack spacing={0.25}>
                <Typography sx={labelSx}>{t("userPools.detail.metaApps", { defaultValue: "Apps" })}</Typography>
                <Typography variant="body2">{pool.appCount}</Typography>
              </Stack>
            </Stack>

            <Divider />

            <Stack spacing={0.75}>
              <Typography sx={labelSx}>
                {t("userPools.detail.appsUsing", { defaultValue: "Apps using this pool" })}
              </Typography>
              {apps && apps.length === 0 && (
                <Typography variant="body2" color="text.secondary">
                  {t("userPools.detail.noApps", {
                    defaultValue: "No apps point at this pool. Safe to delete, or repoint a new app here to start using it.",
                  })}
                </Typography>
              )}
              {apps && apps.length > 0 && (
                <Stack spacing={0.5}>
                  {apps.map((a) => (
                    <RouterLink
                      key={a.id}
                      to={`/app/workspace/${workspace.id}/projects/${a.projectId}/apps/${a.id}`}
                      style={{ textDecoration: "none", color: "inherit" }}
                    >
                      <Box
                        sx={{
                          display: "flex",
                          alignItems: "center",
                          gap: 1,
                          px: 1.25,
                          py: 0.75,
                          borderRadius: 1.5,
                          border: "1px solid",
                          borderColor: "divider",
                          "&:hover": { bgcolor: "action.hover", borderColor: "primary.main" },
                        }}
                      >
                        <Typography sx={{ fontSize: 13, fontWeight: 500, flex: 1, minWidth: 0 }} noWrap>
                          {a.displayName}
                        </Typography>
                        <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "var(--font-mono)" }}>
                          {t("userPools.detail.memberCount", { count: a.memberCount, defaultValue: "{{count}} members" })}
                        </Typography>
                        {!a.enabled && (
                          <Chip
                            label={t("userPools.detail.appDisabled", { defaultValue: "disabled" })}
                            size="small"
                            variant="outlined"
                            sx={{ height: 18, fontSize: 10, borderColor: "error.main", color: "error.main" }}
                          />
                        )}
                      </Box>
                    </RouterLink>
                  ))}
                </Stack>
              )}
            </Stack>
          </Stack>
        ) : tab === "users" ? (
          <Stack spacing={2}>
            {usersErr && <Alert severity="error">{usersErr}</Alert>}
            <Stack direction="row" spacing={1.5} alignItems="center" sx={{ flexWrap: "wrap" }}>
              <TextField
                size="small"
                placeholder={t("userPools.detail.usersSearch", { defaultValue: "Search by email..." })}
                value={userSearch}
                onChange={(e) => setUserSearch(e.target.value)}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <Search size={14} strokeWidth={1.75} />
                    </InputAdornment>
                  ),
                }}
                sx={{ flex: 1, minWidth: 220, maxWidth: 360 }}
              />
              <Button
                size="small"
                variant="outlined"
                color="error"
                startIcon={<Trash2 size={14} strokeWidth={1.75} />}
                onClick={() => setPurgeOpen(true)}
                sx={{ borderRadius: 2, textTransform: "none", flexShrink: 0 }}
              >
                {t("userPools.detail.purgeOrphans", { defaultValue: "Delete users with no apps" })}
              </Button>
            </Stack>
            {usersLoading && users === null ? (
              <Loader />
            ) : usersErr ? null : usersTotal === 0 ? (
              <Typography variant="body2" color="text.secondary">
                {debouncedSearch
                  ? t("userPools.detail.noUserMatch", { defaultValue: "No users match your search." })
                  : t("userPools.detail.noUsers", { defaultValue: "No users in this pool yet." })}
              </Typography>
            ) : (
              <>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 600, fontSize: 12 }}>
                        {t("userPools.detail.colEmail", { defaultValue: "Email" })}
                      </TableCell>
                      <TableCell sx={{ fontWeight: 600, fontSize: 12 }}>
                        {t("userPools.detail.colApps", { defaultValue: "Apps" })}
                      </TableCell>
                      <TableCell sx={{ fontWeight: 600, fontSize: 12 }}>
                        {t("userPools.detail.colStatus", { defaultValue: "Status" })}
                      </TableCell>
                      <TableCell sx={{ width: 48 }} aria-label={t("common.actions")} />
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {(users ?? []).map((u) => (
                      <TableRow key={u.id}>
                        <TableCell>
                          <Typography variant="body2">{u.email}</Typography>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                            {u.apps.length > 0 ? (
                              u.apps.map((a) => (
                                <Chip
                                  key={a.id}
                                  label={a.name}
                                  size="small"
                                  clickable
                                  onClick={() =>
                                    navigate(
                                      `/app/workspace/${workspace.id}/projects/${a.projectId}/apps/${a.id}/members?email=${encodeURIComponent(u.email)}`,
                                    )
                                  }
                                  sx={{ height: 20, fontSize: 11 }}
                                />
                              ))
                            ) : (
                              <Typography variant="caption" color="text.secondary">
                                {t("userPools.detail.noAppMemberships", { defaultValue: "no app memberships" })}
                              </Typography>
                            )}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Chip
                            size="small"
                            label={
                              u.enabled
                                ? t("userPools.detail.statusEnabled", { defaultValue: "Enabled" })
                                : t("userPools.detail.statusDisabled", { defaultValue: "Disabled" })
                            }
                            variant={u.enabled ? "filled" : "outlined"}
                            sx={{
                              height: 20,
                              fontSize: 11,
                              ...(u.enabled
                                ? { bgcolor: "success.main", color: "#fff" }
                                : { borderColor: "error.main", color: "error.main" }),
                            }}
                          />
                        </TableCell>
                        <TableCell align="right" sx={{ width: 48 }}>
                          <Tooltip
                            title={
                              u.apps.length > 0
                                ? t("userPools.detail.deleteBlocked", { defaultValue: "Remove from all apps first" })
                                : t("userPools.detail.deleteUser", { defaultValue: "Delete user from pool" })
                            }
                          >
                            <span>
                              <IconButton
                                size="small"
                                color="error"
                                disabled={u.apps.length > 0 || deletingUser}
                                onClick={() => setDeleteUser(u)}
                              >
                                <Trash2 size={15} strokeWidth={1.75} />
                              </IconButton>
                            </span>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
              <TablePagination
                component="div"
                count={usersTotal}
                page={page}
                onPageChange={(_, p) => setPage(p)}
                rowsPerPage={pageSize}
                onRowsPerPageChange={(e) => {
                  setPageSize(parseInt(e.target.value, 10));
                  setPage(0);
                }}
                rowsPerPageOptions={[25, 50, 100]}
              />
              </>
            )}
          </Stack>
        ) : (
          <PoolUserFields workspaceId={workspace.id} poolId={pool.id} embedded />
        )}
      </Stack>

      {/* Rename */}
      <Dialog open={renameOpen} onClose={closeRename} fullWidth maxWidth="xs">
        <DialogTitle>{t("userPools.dialog.renameTitle", { defaultValue: "Rename pool" })}</DialogTitle>
        <Box
          component="form"
          onSubmit={(e) => {
            e.preventDefault();
            if (!renameSaving) void submitRename();
          }}
        >
          <DialogContent>
            <TextField
              autoFocus
              fullWidth
              size="small"
              label={t("userPools.dialog.nameLabel", { defaultValue: "Name" })}
              value={renameName}
              onChange={(e) => setRenameName(e.target.value)}
              disabled={renameSaving}
            />
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button onClick={closeRename} disabled={renameSaving}>
              {t("common.cancel", { defaultValue: "Cancel" })}
            </Button>
            <Button
              type="submit"
              variant="contained"
              disableElevation
              disabled={renameSaving || renameName.trim() === ""}
            >
              {t("common.save", { defaultValue: "Save" })}
            </Button>
          </DialogActions>
        </Box>
      </Dialog>

      {/* Delete */}
      <Dialog open={deleteOpen} onClose={closeDelete} fullWidth maxWidth="xs">
        <DialogTitle>{t("userPools.dialog.deleteTitle", { defaultValue: "Delete pool?" })}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t("userPools.dialog.deleteConfirm", {
              defaultValue: "This permanently removes \"{{name}}\" and every user in it. Apps must be repointed or deleted first.",
              name: pool.name,
            })}
          </DialogContentText>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={closeDelete} disabled={deleteSaving}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button
            color="error"
            variant="contained"
            disableElevation
            onClick={() => void submitDelete()}
            disabled={deleteSaving}
          >
            {t("common.delete", { defaultValue: "Delete" })}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete pool user */}
      <Dialog open={!!deleteUser} onClose={() => !deletingUser && setDeleteUser(null)} fullWidth maxWidth="xs">
        <DialogTitle>{t("userPools.detail.deleteUserTitle", { defaultValue: "Delete user?" })}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t("userPools.detail.deleteUserConfirm", {
              defaultValue: "Permanently deletes \"{{email}}\" and all of their data (roles, permissions, identities, sessions, custom fields). This cannot be undone.",
              email: deleteUser?.email ?? "",
            })}
          </DialogContentText>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setDeleteUser(null)} disabled={deletingUser}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button
            color="error"
            variant="contained"
            disableElevation
            onClick={() => void confirmDeleteUser()}
            disabled={deletingUser}
          >
            {t("common.delete", { defaultValue: "Delete" })}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Purge orphan users (no app memberships) */}
      <Dialog open={purgeOpen} onClose={() => !purging && setPurgeOpen(false)} fullWidth maxWidth="xs">
        <DialogTitle>{t("userPools.detail.purgeOrphansTitle", { defaultValue: "Delete all users with no apps?" })}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t("userPools.detail.purgeOrphansConfirm", {
              defaultValue: "Permanently deletes every user in this pool that belongs to no app, with all of their data. Users who are members of any app are not affected. This cannot be undone.",
            })}
          </DialogContentText>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setPurgeOpen(false)} disabled={purging}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button
            color="error"
            variant="contained"
            disableElevation
            onClick={() => void confirmPurgeOrphans()}
            disabled={purging}
          >
            {t("userPools.detail.purgeOrphansAction", { defaultValue: "Delete users" })}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
