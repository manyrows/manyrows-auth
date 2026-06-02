import * as React from "react";
import axios from "axios";
import { useTranslation } from "react-i18next";
import { useSnackbar } from "notistack";
import { useNavigate } from "react-router-dom";
import {
  Alert,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  IconButton,
  Paper,
  Stack,
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
import { Plus, Trash2, Edit3, Boxes, RefreshCw } from "lucide-react";
import Loader from "../Loader.tsx";
import EmptyState from "../components/EmptyState.tsx";
import PageHeader from "../components/PageHeader.tsx";
import { extractApiError } from "../lib/apiError.ts";
import type { Workspace } from "../core.ts";

// UserPool is the identity boundary every app points at. The default
// is one pool per app (auto-created on app create), but two related
// apps can share a pool so a single user identity covers both - the
// "internal dashboard + marketing site" SSO case.
type Pool = {
  id: string;
  workspaceId: string;
  name: string;
  createdAt: string;
  updatedAt: string;
  appCount: number;
  userCount: number;
};

export default function UserPools({ workspace }: { workspace: Workspace }) {
  const { t } = useTranslation();
  const { enqueueSnackbar } = useSnackbar();
  const navigate = useNavigate();

  const [pools, setPools] = React.useState<Pool[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [err, setErr] = React.useState<string | null>(null);

  // Create dialog
  const [createOpen, setCreateOpen] = React.useState(false);
  const [createName, setCreateName] = React.useState("");
  const [createSaving, setCreateSaving] = React.useState(false);

  // Rename dialog
  const [renameTarget, setRenameTarget] = React.useState<Pool | null>(null);
  const [renameName, setRenameName] = React.useState("");
  const [renameSaving, setRenameSaving] = React.useState(false);

  // Delete confirm
  const [deleteTarget, setDeleteTarget] = React.useState<Pool | null>(null);
  const [deleteSaving, setDeleteSaving] = React.useState(false);

  const baseUrl = `/admin/workspace/${workspace.id}/userPools`;

  const load = React.useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      const res = await axios.get<{ pools: Pool[] }>(baseUrl);
      setPools(res.data?.pools ?? []);
    } catch (e) {
      setErr(extractApiError(e, t("userPools.loadFailed", { defaultValue: "Failed to load pools." })));
    } finally {
      setLoading(false);
    }
  }, [baseUrl, t]);

  React.useEffect(() => { void load(); }, [load]);

  const openCreate = () => {
    setCreateName("");
    setCreateOpen(true);
  };
  const closeCreate = () => {
    if (createSaving) return;
    setCreateOpen(false);
  };

  const submitCreate = async () => {
    const name = createName.trim();
    if (!name) return;
    setCreateSaving(true);
    try {
      await axios.post(baseUrl, { name });
      enqueueSnackbar(t("userPools.created", { defaultValue: "Pool created." }), { variant: "success" });
      setCreateOpen(false);
      void load();
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("userPools.createFailed", { defaultValue: "Could not create pool." })), { variant: "error" });
    } finally {
      setCreateSaving(false);
    }
  };

  const openRename = (p: Pool) => {
    setRenameTarget(p);
    setRenameName(p.name);
  };
  const closeRename = () => {
    if (renameSaving) return;
    setRenameTarget(null);
  };

  const submitRename = async () => {
    if (!renameTarget) return;
    const name = renameName.trim();
    if (!name || name === renameTarget.name) {
      closeRename();
      return;
    }
    setRenameSaving(true);
    try {
      await axios.patch(`${baseUrl}/${renameTarget.id}`, { name });
      enqueueSnackbar(t("userPools.renamed", { defaultValue: "Pool renamed." }), { variant: "success" });
      setRenameTarget(null);
      void load();
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("userPools.renameFailed", { defaultValue: "Could not rename pool." })), { variant: "error" });
    } finally {
      setRenameSaving(false);
    }
  };

  const openDetail = (p: Pool) => {
    navigate(`/app/workspace/${workspace.id}/userPools/${p.id}`);
  };

  const openDelete = (p: Pool) => setDeleteTarget(p);
  const closeDelete = () => {
    if (deleteSaving) return;
    setDeleteTarget(null);
  };

  const submitDelete = async () => {
    if (!deleteTarget) return;
    setDeleteSaving(true);
    try {
      await axios.delete(`${baseUrl}/${deleteTarget.id}`);
      enqueueSnackbar(t("userPools.deleted", { defaultValue: "Pool deleted." }), { variant: "success" });
      setDeleteTarget(null);
      void load();
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("userPools.deleteFailed", { defaultValue: "Could not delete pool." })), { variant: "error" });
    } finally {
      setDeleteSaving(false);
    }
  };

  if (loading) return <Loader />;

  return (
    <Box>
      <Stack spacing={3}>
        <PageHeader
          title={t("userPools.title", { defaultValue: "User pools" })}
          subtitle={t("userPools.subtitle", {
            defaultValue:
              "Identity boundaries. Apps pointing at the same pool share users - the basis for SSO between related apps.",
          })}
          mb={0}
          action={
            <>
              <Tooltip title={t("common.refresh", { defaultValue: "Refresh" })}>
                <span>
                  <IconButton size="small" onClick={() => void load()}>
                    <RefreshCw size={14} strokeWidth={2} />
                  </IconButton>
                </span>
              </Tooltip>
              <Button
                size="small"
                variant="contained"
                disableElevation
                startIcon={<Plus size={14} strokeWidth={2} />}
                onClick={openCreate}
              >
                {t("userPools.new", { defaultValue: "New pool" })}
              </Button>
            </>
          }
        />

        {err && <Alert severity="error">{err}</Alert>}

        {pools.length === 0 ? (
          <EmptyState
            icon={<Boxes size={18} strokeWidth={1.75} />}
            title={t("userPools.none", { defaultValue: "No pools yet." })}
            description={t("userPools.noneDesc", {
              defaultValue:
                "Pools are usually auto-created on app create. Make one here when you want two apps to share users before either exists.",
            })}
            action={
              <Button
                size="small"
                variant="contained"
                disableElevation
                startIcon={<Plus size={14} strokeWidth={2} />}
                onClick={openCreate}
              >
                {t("userPools.createFirst", { defaultValue: "Create first pool" })}
              </Button>
            }
          />
        ) : (
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>{t("userPools.col.name", { defaultValue: "Name" })}</TableCell>
                  <TableCell align="right">{t("userPools.col.apps", { defaultValue: "Apps" })}</TableCell>
                  <TableCell align="right">{t("userPools.col.users", { defaultValue: "Users" })}</TableCell>
                  <TableCell align="right" />
                </TableRow>
              </TableHead>
              <TableBody>
                {pools.map((p) => (
                  <TableRow
                    key={p.id}
                    hover
                    onClick={() => openDetail(p)}
                    sx={{ cursor: "pointer" }}
                  >
                    <TableCell>
                      <Typography sx={{ fontSize: 13, fontWeight: 600 }}>{p.name}</Typography>
                      <Typography sx={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "text.secondary" }}>
                        {p.id}
                      </Typography>
                    </TableCell>
                    <TableCell align="right">
                      <Typography sx={{ fontSize: 13 }}>{p.appCount}</Typography>
                    </TableCell>
                    <TableCell align="right">
                      <Typography sx={{ fontSize: 13 }}>{p.userCount}</Typography>
                    </TableCell>
                    <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                      <Stack direction="row" spacing={0.5} justifyContent="flex-end">
                        <Tooltip title={t("userPools.rename", { defaultValue: "Rename" })}>
                          <IconButton size="small" onClick={() => openRename(p)}>
                            <Edit3 size={14} strokeWidth={1.75} />
                          </IconButton>
                        </Tooltip>
                        <Tooltip
                          title={
                            p.appCount > 0
                              ? t("userPools.deleteBlocked", { defaultValue: "Remove or repoint apps using this pool first" })
                              : t("userPools.delete", { defaultValue: "Delete" })
                          }
                        >
                          <span>
                            <IconButton
                              size="small"
                              onClick={() => openDelete(p)}
                              disabled={p.appCount > 0}
                              sx={{ color: p.appCount > 0 ? undefined : "error.main" }}
                            >
                              <Trash2 size={14} strokeWidth={1.75} />
                            </IconButton>
                          </span>
                        </Tooltip>
                      </Stack>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Stack>

      {/* Create */}
      <Dialog open={createOpen} onClose={closeCreate} fullWidth maxWidth="xs">
        <DialogTitle>{t("userPools.dialog.createTitle", { defaultValue: "New user pool" })}</DialogTitle>
        <Box
          component="form"
          onSubmit={(e) => {
            e.preventDefault();
            if (!createSaving) void submitCreate();
          }}
        >
          <DialogContent>
            <TextField
              autoFocus
              fullWidth
              size="small"
              label={t("userPools.dialog.nameLabel", { defaultValue: "Name" })}
              value={createName}
              onChange={(e) => setCreateName(e.target.value)}
              disabled={createSaving}
              helperText={t("userPools.dialog.nameHelp", {
                defaultValue: "Shown only to admins. Apps point at the pool by ID.",
              })}
            />
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button onClick={closeCreate} disabled={createSaving}>
              {t("common.cancel", { defaultValue: "Cancel" })}
            </Button>
            <Button
              type="submit"
              variant="contained"
              disableElevation
              disabled={createSaving || createName.trim() === ""}
            >
              {t("common.create", { defaultValue: "Create" })}
            </Button>
          </DialogActions>
        </Box>
      </Dialog>

      {/* Rename */}
      <Dialog open={!!renameTarget} onClose={closeRename} fullWidth maxWidth="xs">
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
      <Dialog open={!!deleteTarget} onClose={closeDelete} fullWidth maxWidth="xs">
        <DialogTitle>{t("userPools.dialog.deleteTitle", { defaultValue: "Delete pool?" })}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t("userPools.dialog.deleteConfirm", {
              defaultValue: "This permanently removes \"{{name}}\" and every user in it. Apps must be repointed or deleted first.",
              name: deleteTarget?.name,
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
    </Box>
  );
}
