import * as React from "react";
import axios from "axios";
import type { Product, Permission, Role, Workspace } from "../core.ts";
import { extractApiError } from "../lib/apiError.ts";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControlLabel,
  IconButton,
  Paper,
  Stack,
  TextField,
  Tooltip,
  Typography,
  Chip,
} from "@mui/material";
import PageHeader from "../components/PageHeader.tsx";
import StatusChip from "../components/StatusChip.tsx";
import { useSnackbar } from "notistack";
import { useTranslation, Trans } from "react-i18next";

import { Plus, Save, SquarePen, Settings, SquareCheck, SquareMinus, Shield, Trash2, TriangleAlert, Copy, CopyPlus } from "lucide-react";

const tc = { code: <code />, b: <b />, strong: <strong /> };

type TFunc = (key: string, opts?: Record<string, unknown>) => string;

/** ===== Types ===== */

interface Props {
  project: Product;
  workspace: Workspace;
}

/** ===== API helpers (match your mounted /admin routes) ===== */

function rolesBase(project: Product) {
  return `/admin/workspace/${project.workspaceId}/products/${project.id}/roles`;
}

function permissionsBase(project: Product) {
  return `/admin/workspace/${project.workspaceId}/products/${project.id}/permissions`;
}

async function getRoles(project: Product): Promise<Role[]> {
  const r = await axios.get(rolesBase(project));
  const raw = r.data?.roles ?? r.data ?? [];
  return Array.isArray(raw) ? (raw as Role[]) : [];
}

async function createRole(project: Product, body: Pick<Role, "name" | "slug">): Promise<Role> {
  const r = await axios.post<Role>(rolesBase(project), body);
  return r.data;
}

async function updateRole(
  project: Product,
  roleId: string,
  body: Partial<Pick<Role, "name" | "slug">>,
): Promise<Role> {
  const r = await axios.patch<Role>(`${rolesBase(project)}/${roleId}`, body);
  return r.data;
}

async function deleteRole(project: Product, roleId: string): Promise<void> {
  // Requires backend endpoint:
  // DELETE /admin/workspace/{workspaceId}/products/{productId}/roles/{roleId}
  await axios.delete(`${rolesBase(project)}/${roleId}`);
}

async function getPermissions(project: Product): Promise<Permission[]> {
  const r = await axios.get(permissionsBase(project));
  return r.data.permissions;
}

async function patchRolePermissions(project: Product, roleId: string, permissionIds: string[]): Promise<void> {
  await axios.patch(`${rolesBase(project)}/${roleId}/permissions`, { permissionIds });
}

/** ===== Shared UI helpers ===== */

function normalizeSlugInput(s: string): string {
  return s
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "_")
    .replace(/[^a-z0-9_]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function titleCase(s: string): string {
  const t = (s || "").trim();
  if (!t) return "";
  return t.charAt(0).toUpperCase() + t.slice(1);
}

/** ===== Dialog: Create role ===== */

function CreateRoleDialog(props: {
  open: boolean;
  onClose: () => void;
  onSave: (vals: Pick<Role, "name" | "slug">) => void | Promise<void>;
  t: TFunc;
}) {
  const { open, onClose, onSave, t } = props;
  const [name, setName] = React.useState("");
  const [slug, setSlug] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);

  React.useEffect(() => {
    if (!open) return;
    setName("");
    setSlug("");
    setSubmitting(false);
  }, [open]);

  const canSave = name.trim().length > 0 && slug.trim().length > 0;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSave || submitting) return;
    setSubmitting(true);
    try {
      await onSave({ name: titleCase(name.trim()), slug: normalizeSlugInput(slug) });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>{t("roles.dialog.createTitle")}</DialogTitle>
      <Box component="form" onSubmit={handleSubmit}>
        <DialogContent sx={{ pt: 1 }}>
          <Stack spacing={2}>
            <TextField
              label={t("roles.dialog.roleName")}
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
              fullWidth
              placeholder={t("roles.dialog.roleNamePlaceholder")}
              helperText={t("roles.dialog.roleNameHelper")}
            />
            <TextField
              label={t("roles.dialog.slug")}
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              helperText={t("roles.dialog.slugHelper")}
              fullWidth
              placeholder={t("roles.dialog.slugPlaceholder")}
              inputProps={{ spellCheck: false }}
            />
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2.5 }}>
          <Button onClick={onClose} color="inherit" sx={{ textTransform: "none" }}>
            {t("roles.dialog.cancel")}
          </Button>
          <Button type="submit" variant="contained" disabled={!canSave || submitting} sx={{ textTransform: "none" }}>
            {t("roles.dialog.create")}
          </Button>
        </DialogActions>
      </Box>
    </Dialog>
  );
}

/** ===== Dialog: Edit role ===== */

function EditRoleDialog(props: {
  open: boolean;
  role: Role | null;
  onClose: () => void;
  onSave: (vals: Pick<Role, "name" | "slug">) => void | Promise<void>;
  t: TFunc;
}) {
  const { open, role, onClose, onSave, t } = props;

  const [name, setName] = React.useState("");
  const [slug, setSlug] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);

  const roleId = role?.id;
  const roleName = role?.name;
  const roleSlug = role?.slug;
  React.useEffect(() => {
    if (!open || !role) return;
    setName(role.name ?? "");
    setSlug(role.slug ?? "");
    setSubmitting(false);
  }, [open, roleId, roleName, roleSlug]);

  const canSave = name.trim().length > 0 && slug.trim().length > 0;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSave || submitting) return;
    setSubmitting(true);
    try {
      await onSave({ name: titleCase(name.trim()), slug: normalizeSlugInput(slug) });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>{t("roles.dialog.editTitle")}</DialogTitle>
      <Box component="form" onSubmit={handleSubmit}>
        <DialogContent sx={{ pt: 1 }}>
          <Stack spacing={2}>
            <TextField label={t("roles.dialog.roleName")} value={name} onChange={(e) => setName(e.target.value)} autoFocus fullWidth />
            <TextField
              label={t("roles.dialog.slug")}
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              helperText={t("roles.dialog.slugHelper")}
              fullWidth
              inputProps={{ spellCheck: false }}
            />
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2.5 }}>
          <Button onClick={onClose} color="inherit" sx={{ textTransform: "none" }}>
            {t("roles.dialog.cancel")}
          </Button>
          <Button type="submit" variant="contained" disabled={!canSave || submitting} sx={{ textTransform: "none" }}>
            {t("roles.dialog.save")}
          </Button>
        </DialogActions>
      </Box>
    </Dialog>
  );
}

/** ===== Dialog: Edit role permissions ===== */

function RolePermissionsDialog(props: {
  open: boolean;
  role: Role | null;
  allPermissions: Permission[];
  selectedIds: Set<string>;
  onClose: () => void;
  onToggle: (permissionId: string) => void;
  onSelectAll: () => void;
  onDeselectAll: () => void;
  onSave: () => void;
  saving: boolean;
  disabled?: boolean;
  disabledReason?: string;
  t: TFunc;
}) {
  const {
    open,
    role,
    allPermissions,
    selectedIds,
    onClose,
    onToggle,
    onSelectAll,
    onDeselectAll,
    onSave,
    saving,
    disabled,
    disabledReason,
    t,
  } = props;

  const safePermissions = Array.isArray(allPermissions) ? allPermissions : [];

  const groupedPermissions = React.useMemo(() => {
    const map = new Map<string, Permission[]>();
    for (const p of safePermissions) {
      const group = p.group ?? "General";
      if (!map.has(group)) map.set(group, []);
      map.get(group)!.push(p);
    }
    for (const list of map.values()) {
      list.sort((a, b) => (a.name ?? "").localeCompare(b.name ?? ""));
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [safePermissions]);

  const total = safePermissions.length;
  const selectedCount = selectedIds.size;

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle >
        <Stack direction="row" spacing={1} alignItems="center">
          <Shield size={14} strokeWidth={1.75} />
          <Box sx={{ minWidth: 0 }}>
            <Typography noWrap>
              {role?.name ? t("roles.permDialog.title", { name: role.name }) : t("roles.permDialog.titleFallback")}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {t("roles.permDialog.subtitle")}
            </Typography>
          </Box>
          <Box sx={{ flex: 1 }} />
          <Chip
            size="small"
            variant="outlined"
            label={t("roles.permDialog.selectedCount", { selected: selectedCount, total })}
            sx={{ borderRadius: 2, bgcolor: "action.hover" }}
          />
        </Stack>
      </DialogTitle>

      <DialogContent sx={{ pt: 1 }}>
        <Stack spacing={1.5}>
          {disabled ? (
            <Alert severity="warning">
              {disabledReason || t("roles.permDialog.editDisabled")}
            </Alert>
          ) : (
            <Alert severity="info">
              {t("roles.permDialog.info")}
            </Alert>
          )}

          <Stack direction={{ xs: "column", sm: "row" }} spacing={1} alignItems={{ xs: "stretch", sm: "center" }}>
            <Button
              size="small"
              variant="outlined"
              startIcon={<SquareCheck size={14} strokeWidth={1.75} />}
              onClick={onSelectAll}
              disabled={disabled || total === 0}
              sx={{ borderRadius: 2, textTransform: "none" }}
            >
              {t("roles.permDialog.selectAll")}
            </Button>
            <Button
              size="small"
              variant="outlined"
              startIcon={<SquareMinus size={14} strokeWidth={1.75} />}
              onClick={onDeselectAll}
              disabled={disabled || total === 0}
              sx={{ borderRadius: 2, textTransform: "none" }}
            >
              {t("roles.permDialog.deselectAll")}
            </Button>
            <Box sx={{ flex: 1 }} />
            <Typography
              variant="body2"
              color="text.secondary"
            ><Trans i18nKey="roles.permDialog.saveNote" components={tc} /></Typography>
          </Stack>

          <Divider />

          {total === 0 ? (
            <Alert severity="warning">
              {t("roles.permDialog.noPermissions")}
            </Alert>
          ) : (
            <Stack spacing={2}>
              {groupedPermissions.map(([group, perms]) => (
                <Paper key={group} variant="outlined" sx={{ borderRadius: 2, p: 1.75, opacity: disabled ? 0.6 : 1 }}>
                  <Stack spacing={1}>
                    <Typography
                      sx={{
                        fontFamily: "var(--font-mono)",
                        textTransform: "uppercase",
                        letterSpacing: "0.14em",
                        fontSize: 10,
                        fontWeight: 500,
                        color: "text.disabled",
                        px: 0.5,
                      }}
                    >
                      {group}
                    </Typography>

                    <Stack spacing={0.25}>
                      {perms.map((p) => {
                        const checked = selectedIds.has(p.id);
                        return (
                          <FormControlLabel
                            key={p.id}
                            sx={{
                              borderRadius: 1,
                              px: 1,
                              py: 0.75,
                              mx: 0,
                              "&:hover": { bgcolor: "action.hover" },
                              alignItems: "flex-start",
                            }}
                            control={<Checkbox checked={checked} onChange={() => onToggle(p.id)} disabled={disabled} />}
                            label={
                              <Stack spacing={0.25} sx={{ py: 0.25 }}>
                                <Typography variant="body2">
                                  {p.name}
                                </Typography>
                                <Typography
                                  variant="caption"
                                  color="text.secondary"
                                  sx={{ fontFamily: "var(--font-mono)" }}
                                >
                                  {p.slug}
                                </Typography>
                              </Stack>
                            }
                          />
                        );
                      })}
                    </Stack>
                  </Stack>
                </Paper>
              ))}
            </Stack>
          )}
        </Stack>
      </DialogContent>

      <DialogActions sx={{ px: 3, pb: 2.5 }}>
        <Button onClick={onClose} color="inherit" sx={{ textTransform: "none" }}>
          {t("roles.permDialog.close")}
        </Button>
        <Button
          variant="contained"
          startIcon={saving ? <CircularProgress size={16} /> : <Save size={14} strokeWidth={1.75} />}
          onClick={onSave}
          disabled={disabled || saving || total === 0}
          sx={{ borderRadius: 2, textTransform: "none" }}
        >
          {saving ? t("roles.permDialog.saving") : t("roles.permDialog.savePermissions")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/** ===== Dialog: Duplicate role confirm ===== */

function DuplicateRoleDialog(props: {
  open: boolean;
  role: Role | null;
  onClose: () => void;
  onConfirm: () => void;
  duplicating: boolean;
  t: TFunc;
}) {
  const { open, role, onClose, onConfirm, duplicating, t } = props;

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>
        <Stack direction="row" spacing={1} alignItems="center">
          <CopyPlus size={14} strokeWidth={1.75} />
          <Typography>{t("roles.dupDialog.title")}</Typography>
        </Stack>
      </DialogTitle>
      <DialogContent sx={{ pt: 1 }}>
        <Stack spacing={1.5}>
          <Typography variant="body2">
            {role?.name
              ? <Trans i18nKey="roles.dupDialog.description" values={{ name: role.name }} components={tc} />
              : <Trans i18nKey="roles.dupDialog.descriptionFallback" components={tc} />}
          </Typography>

          <Paper variant="outlined" sx={{ borderRadius: 2, p: 1.5, bgcolor: "action.hover" }}>
            <Stack spacing={1}>
              <Box>
                <Typography variant="caption" color="text.secondary">
                  {t("roles.dupDialog.newNameLabel")}
                </Typography>
                <Typography variant="body2" fontWeight={500}>
                  {t("roles.dupDialog.newName", { name: role?.name ?? "" })}
                </Typography>
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">
                  {t("roles.dupDialog.newSlugLabel")}
                </Typography>
                <Typography variant="body2" sx={{ fontFamily: "var(--font-mono)" }}>
                  {t("roles.dupDialog.newSlug", { slug: role?.slug ?? "" })}
                </Typography>
              </Box>
            </Stack>
          </Paper>

          <Typography variant="body2" color="text.secondary">
            {t("roles.dupDialog.renameHint")}
          </Typography>
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2.5 }}>
        <Button onClick={onClose} color="inherit" disabled={duplicating} sx={{ textTransform: "none" }}>
          {t("roles.dupDialog.cancel")}
        </Button>
        <Button
          onClick={onConfirm}
          variant="contained"
          disableElevation
          startIcon={duplicating ? <CircularProgress size={16} /> : <CopyPlus size={14} strokeWidth={1.75} />}
          disabled={duplicating || !role}
          sx={{ textTransform: "none", borderRadius: 2 }}
        >
          {duplicating ? t("roles.dupDialog.duplicating") : t("roles.dupDialog.duplicate")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/** ===== Dialog: Delete role confirm ===== */

function DeleteRoleDialog(props: {
  open: boolean;
  role: Role | null;
  onClose: () => void;
  onConfirm: () => void;
  deleting: boolean;
  disabled?: boolean;
  disabledReason?: string;
  t: TFunc;
}) {
  const { open, role, onClose, onConfirm, deleting, disabled, disabledReason, t } = props;

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle >
        <Stack direction="row" spacing={1} alignItems="center">
          <TriangleAlert size={14} strokeWidth={1.75} />
          <Typography>{t("roles.delDialog.title")}</Typography>
        </Stack>
      </DialogTitle>
      <DialogContent sx={{ pt: 1 }}>
        <Stack spacing={1.25}>
          {disabled ? (
            <Alert severity="warning">
              {disabledReason || t("roles.delDialog.editDisabled")}
            </Alert>
          ) : (
            <Alert
              severity="warning"
             
            >
              {role?.name
                ? <Trans i18nKey="roles.delDialog.warning" values={{ name: role.name }} components={tc} />
                : <Trans i18nKey="roles.delDialog.warningFallback" components={tc} />}
            </Alert>
          )}

          <Typography variant="body2" color="text.secondary">
            {t("roles.delDialog.memberNote")}
          </Typography>

          <Paper
            variant="outlined"
            sx={{ borderRadius: 2, p: 1.25, bgcolor: "action.hover", opacity: disabled ? 0.7 : 1 }}
          >
            <Stack spacing={0.75}>
              <Box>
                <Typography variant="caption" color="text.secondary" >
                  {t("roles.delDialog.slugLabel")}
                </Typography>
                <Typography sx={{ fontFamily: "var(--font-mono)" }}>{role?.slug ?? "-"}</Typography>
              </Box>

              <Box>
                <Typography variant="caption" color="text.secondary" >
                  {t("roles.delDialog.idLabel")}
                </Typography>
                <Typography sx={{ fontFamily: "var(--font-mono)" }}>{role?.id ?? "-"}</Typography>
              </Box>
            </Stack>
          </Paper>
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2.5 }}>
        <Button onClick={onClose} color="inherit" disabled={deleting} sx={{ textTransform: "none" }}>
          {t("roles.delDialog.cancel")}
        </Button>
        <Button
          onClick={onConfirm}
          variant="contained"
          color="error"
          disableElevation
          startIcon={deleting ? <CircularProgress size={16} /> : <Trash2 size={14} strokeWidth={1.75} />}
          disabled={deleting || !role || !!disabled}
          sx={{ textTransform: "none", borderRadius: 2 }}
        >
          {deleting ? t("roles.delDialog.deleting") : t("roles.delDialog.delete")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/** ===== Main page ===== */

export default function Roles({ project }: Props) {
  const { enqueueSnackbar } = useSnackbar();
  const { t } = useTranslation();

  const [loading, setLoading] = React.useState(true);
  const [err, setErr] = React.useState<string | null>(null);

  const [roles, setRoles] = React.useState<Role[]>([]);
  const [permissions, setPermissions] = React.useState<Permission[]>([]);

  const [createOpen, setCreateOpen] = React.useState(false);

  const [editOpen, setEditOpen] = React.useState(false);
  const [editingRole, setEditingRole] = React.useState<Role | null>(null);

  const [permOpen, setPermOpen] = React.useState(false);
  const [permRole, setPermRole] = React.useState<Role | null>(null);

  // delete
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [deletingRole, setDeletingRole] = React.useState<Role | null>(null);
  const [deleting, setDeleting] = React.useState(false);

  // local editing state: roleId -> selected permission ids (used by dialog)
  const [selectedByRole, setSelectedByRole] = React.useState<Record<string, Set<string>>>({});

  const [savingPermissions, setSavingPermissions] = React.useState<Record<string, boolean>>({});

  const copy = React.useCallback(
    async (text: string, okMsg: string) => {
      try {
        await navigator.clipboard.writeText(text);
        enqueueSnackbar(okMsg, { variant: "success" });
      } catch {
        enqueueSnackbar(t("roles.copyFailed"), { variant: "error" });
      }
    },
    [enqueueSnackbar, t],
  );

  const refresh = React.useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      const [r, p] = await Promise.all([getRoles(project), getPermissions(project)]);
      setRoles(r);
      setPermissions(p);

      const next: Record<string, Set<string>> = {};
      for (const role of r) {
        const perms = Array.isArray(role.permissions) ? role.permissions : [];
        next[role.id] = new Set<string>(perms.map((pp) => pp.id));
      }
      setSelectedByRole(next);
    } catch (e) {
      setErr(extractApiError(e, "Failed to load roles/permissions"));
    } finally {
      setLoading(false);
    }
  }, [project]);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  const rolesCount = roles.length;

  const handleCreateRole = async (vals: Pick<Role, "name" | "slug">) => {
    setErr(null);
    try {
      await createRole(project, vals);
      setCreateOpen(false);
      enqueueSnackbar(t("roles.roleCreated"), { variant: "success" });
      await refresh();
    } catch (e) {
      setErr(extractApiError(e, t("roles.failedToCreate")));
    }
  };

  const openEditRole = (role: Role) => {
    setEditingRole(role);
    setEditOpen(true);
  };

  const handleUpdateRole = async (vals: Pick<Role, "name" | "slug">) => {
    if (!editingRole) return;

    setErr(null);
    try {
      await updateRole(project, editingRole.id, vals);
      setEditOpen(false);
      setEditingRole(null);
      enqueueSnackbar(t("roles.roleUpdated"), { variant: "success" });
      await refresh();
    } catch (e) {
      setErr(extractApiError(e, t("roles.failedToUpdate")));
    }
  };

  const [duplicating, setDuplicating] = React.useState<string | null>(null);
  const [duplicateOpen, setDuplicateOpen] = React.useState(false);
  const [duplicateTarget, setDuplicateTarget] = React.useState<Role | null>(null);

  const openDuplicateRole = (role: Role) => {
    setDuplicateTarget(role);
    setDuplicateOpen(true);
  };

  const closeDuplicateRole = () => {
    if (duplicating) return;
    setDuplicateOpen(false);
    setDuplicateTarget(null);
  };

  const confirmDuplicateRole = async () => {
    if (!duplicateTarget) return;
    await duplicateRole(duplicateTarget);
    setDuplicateOpen(false);
    setDuplicateTarget(null);
  };

  const duplicateRole = async (role: Role) => {
    setErr(null);
    setDuplicating(role.id);
    try {
      const newName = `${role.name} (Copy)`;
      let newSlug = `${role.slug}_copy`;

      const existingSlugs = new Set(roles.map((r) => r.slug));
      let counter = 1;
      while (existingSlugs.has(newSlug)) {
        counter++;
        newSlug = `${role.slug}_copy_${counter}`;
      }

      const newRole = await createRole(project, { name: newName, slug: newSlug });

      const originalPermIds = selectedByRole[role.id] ?? new Set<string>();
      if (originalPermIds.size > 0) {
        await patchRolePermissions(project, newRole.id, [...originalPermIds]);
      }

      enqueueSnackbar(t("roles.roleDuplicatedAs", { name: newName }), { variant: "success" });
      await refresh();
    } catch (e) {
      setErr(extractApiError(e, t("roles.failedToCreate")));
    } finally {
      setDuplicating(null);
    }
  };

  const openPermissions = (role: Role) => {
    setPermRole(role);
    setPermOpen(true);
  };

  const closePermissions = () => {
    setPermOpen(false);
    setPermRole(null);
  };

  const togglePermission = (roleId: string, permId: string) => {
    setSelectedByRole((prev) => {
      const cur = prev[roleId] ? new Set(prev[roleId]) : new Set<string>();
      if (cur.has(permId)) cur.delete(permId);
      else cur.add(permId);
      return { ...prev, [roleId]: cur };
    });
  };

  const selectAllPermissions = (roleId: string) => {
    setSelectedByRole((prev) => {
      const all = new Set<string>((Array.isArray(permissions) ? permissions : []).map((p) => p.id));
      return { ...prev, [roleId]: all };
    });
  };

  const deselectAllPermissions = (roleId: string) => {
    setSelectedByRole((prev) => ({ ...prev, [roleId]: new Set<string>() }));
  };

  const savePermissions = async (roleId: string) => {
    setErr(null);
    setSavingPermissions((m) => ({ ...m, [roleId]: true }));
    try {
      const selected = selectedByRole[roleId] ?? new Set<string>();
      await patchRolePermissions(project, roleId, [...selected]);
      enqueueSnackbar(t("roles.permissionsSaved"), { variant: "success" });
      await refresh();
      closePermissions();
    } catch (e) {
      setErr(extractApiError(e, t("roles.failedToSavePermissions")));
    } finally {
      setSavingPermissions((m) => ({ ...m, [roleId]: false }));
    }
  };

  const openDeleteRole = (role: Role) => {
    setErr(null);
    setDeletingRole(role);
    setDeleteOpen(true);
  };

  const closeDeleteRole = () => {
    if (deleting) return;
    setDeleteOpen(false);
    setDeletingRole(null);
  };

  const confirmDeleteRole = async () => {
    if (!deletingRole || deleting) return;

    setErr(null);
    setDeleting(true);
    try {
      await deleteRole(project, deletingRole.id);
      enqueueSnackbar(t("roles.roleDeleted"), { variant: "success" });
      closeDeleteRole();
      await refresh();
    } catch (e) {
      setErr(extractApiError(e, t("roles.failedToDelete")));
    } finally {
      setDeleting(false);
    }
  };

  const permissionCount = Array.isArray(permissions) ? permissions.length : 0;

  return (
    <Box>
      <Box>
        <PageHeader
          title={t("roles.title")}
          subtitle={t("roles.description")}
          mb={0}
          action={
            <>
              <Chip
                size="small"
                variant="outlined"
                icon={<Shield size={14} strokeWidth={1.75} />}
                label={t("roles.chipLabelWithPerms", { roles: t("roles.chipLabelUnlimited", { count: rolesCount }), perms: permissionCount })}
              />
              <Button
                disableElevation
                size="small"
                variant="contained"
                startIcon={<Plus size={14} strokeWidth={1.75} />}
                onClick={() => setCreateOpen(true)}
              >
                {t("roles.newRole")}
              </Button>
            </>
          }
        />
        <Divider sx={{ mt: 3 }} />
        <Box sx={{ py: { xs: 2, sm: 2.5 } }}>
          {err ? (
            <Alert severity="error" sx={{ borderRadius: 2, mb: 2 }}>
              {err}
            </Alert>
          ) : null}

          {loading ? (
            <Stack direction="row" spacing={1.5} alignItems="center">
              <CircularProgress size={18} />
              <Typography variant="body2" color="text.secondary">
                {t("roles.loading")}
              </Typography>
            </Stack>
          ) : roles.length === 0 ? (
            <Paper variant="outlined" sx={{ borderRadius: 3, p: 3, textAlign: "center" }}>
              <Box
                sx={{
                  width: 56,
                  height: 56,
                  borderRadius: 3,
                  bgcolor: "action.selected",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  mx: "auto",
                  mb: 2,
                }}
              >
                <Box component="span" sx={{ color: "primary.main" }}><Shield size={28} strokeWidth={1.75} /></Box>
              </Box>
              <Typography sx={{ fontSize: 17, fontWeight: 600, letterSpacing: "-0.005em", mb: 1 }}>
                {t("roles.emptyState.title")}
              </Typography>
              <Typography
                variant="body2"
                color="text.secondary"
                sx={{ mb: 2, maxWidth: 400, mx: "auto" }}
              ><Trans i18nKey="roles.emptyState.description" components={tc} /></Typography>
              <Stack spacing={1} sx={{ mb: 2.5, maxWidth: 320, mx: "auto", textAlign: "left" }}>
                <Typography
                  variant="body2"
                  color="text.secondary"
                ><Trans i18nKey="roles.emptyState.step1" components={tc} /></Typography>
                <Typography
                  variant="body2"
                  color="text.secondary"
                ><Trans i18nKey="roles.emptyState.step2" components={tc} /></Typography>
                <Typography
                  variant="body2"
                  color="text.secondary"
                ><Trans i18nKey="roles.emptyState.step3" components={tc} /></Typography>
              </Stack>
              <Button
                variant="contained"
                startIcon={<Plus size={14} strokeWidth={1.75} />}
                onClick={() => setCreateOpen(true)}
                sx={{ borderRadius: 2, textTransform: "none" }}
              >
                {t("roles.createFirst")}
              </Button>
            </Paper>
          ) : (
            <Stack spacing={1.5}>
              {roles
                .slice()
                .sort((a, b) => (a.name ?? "").localeCompare(b.name ?? ""))
                .map((role) => {
                  const selected = selectedByRole[role.id] ?? new Set<string>();
                  const canEditPerms = permissionCount > 0;

                  // Get first few permission names for preview
                  const assignedPerms = Array.isArray(permissions)
                    ? permissions.filter((p) => selected.has(p.id))
                    : [];
                  const previewPerms = assignedPerms.slice(0, 4);
                  const moreCount = assignedPerms.length - previewPerms.length;

                  return (
                    <Paper
                      key={role.id}
                      variant="outlined"
                      sx={{
                        borderRadius: 2.5,
                        overflow: "hidden",
                        transition: "border-color 140ms ease",
                        "&:hover": { borderColor: "primary.main" },
                      }}
                    >
                      {/* Header row */}
                      <Box
                        sx={{
                          px: 2,
                          py: 1.5,
                          bgcolor: "action.hover",
                          borderBottom: "1px solid",
                          borderColor: "divider",
                        }}
                      >
                        <Stack direction="row" spacing={1.5} alignItems="center">
                          <Box
                            sx={{
                              width: 36,
                              height: 36,
                              borderRadius: 1.5,
                              bgcolor: "action.selected",
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "center",
                              flexShrink: 0,
                            }}
                          >
                            <Box component="span" sx={{ color: "primary.main" }}><Shield size={20} strokeWidth={1.75} /></Box>
                          </Box>

                          <Box sx={{ flex: 1, minWidth: 0 }}>
                            <Stack direction="row" spacing={1} alignItems="center">
                              <Typography sx={{ fontSize: 15, fontWeight: 600, letterSpacing: "-0.005em" }} noWrap>
                                {role.name}
                              </Typography>
                              <StatusChip label={role.slug} uppercase={false} />
                            </Stack>
                          </Box>

                          <StatusChip
                            size="md"
                            label={selected.size === 1
                              ? t("roles.permissionSingular", { count: selected.size })
                              : t("roles.permissionPlural", { count: selected.size })}
                            severity={selected.size > 0 ? "success" : "muted"}
                          />
                        </Stack>
                      </Box>

                      {/* Body */}
                      <Box sx={{ px: 2, py: 1.5 }}>
                        <Stack spacing={1.5}>
                          {/* Permission preview */}
                          {selected.size > 0 ? (
                            <Box>
                              <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.75 }}>
                                {t("roles.assignedPermissions")}
                              </Typography>
                              <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                                {previewPerms.map((p) => (
                                  <StatusChip key={p.id} size="md" label={p.slug} uppercase={false} />
                                ))}
                                {moreCount > 0 && (
                                  <StatusChip
                                    size="md"
                                    label={t("roles.morePermissions", { count: moreCount })}
                                    uppercase={false}
                                    severity="muted"
                                  />
                                )}
                              </Stack>
                            </Box>
                          ) : (
                            <Typography variant="body2" color="text.secondary" sx={{ fontStyle: "italic" }}>
                              {t("roles.noPermissionsAssigned")}
                            </Typography>
                          )}

                          {/* Actions row */}
                          <Stack
                            direction="row"
                            spacing={1}
                            alignItems="center"
                            sx={{ pt: 0.5, borderTop: "1px solid", borderColor: "divider" }}
                          >
                            <Button
                              size="small"
                              variant="outlined"
                              startIcon={<Settings size={14} strokeWidth={1.75} />}
                              onClick={() => openPermissions(role)}
                              disabled={!canEditPerms}
                              sx={{ borderRadius: 1.5, textTransform: "none", fontSize: 13 }}
                            >
                              {t("roles.editPermissions")}
                            </Button>

                            <Button
                              size="small"
                              variant="text"
                              startIcon={<SquarePen size={14} strokeWidth={1.75} />}
                              onClick={() => openEditRole(role)}
                              sx={{ borderRadius: 1.5, textTransform: "none", fontSize: 13, color: "text.secondary" }}
                            >
                              {t("roles.rename")}
                            </Button>

                            <Box sx={{ flex: 1 }} />

                            <Tooltip title={t("roles.duplicateRole")}>
                              <span>
                                <IconButton
                                  size="small"
                                  onClick={() => openDuplicateRole(role)}
                                  disabled={!!duplicating}
                                >
                                  {duplicating === role.id ? (
                                    <CircularProgress size={16} />
                                  ) : (
                                    <CopyPlus size={14} strokeWidth={1.75} />
                                  )}
                                </IconButton>
                              </span>
                            </Tooltip>

                            <Tooltip title={t("roles.copyRoleId")}>
                              <IconButton size="small" onClick={() => void copy(role.id, t("roles.roleIdCopied"))}>
                                <Copy size={14} strokeWidth={1.75} />
                              </IconButton>
                            </Tooltip>

                            <Tooltip title={t("roles.deleteRole")}>
                              <span>
                                <IconButton
                                  size="small"
                                  onClick={() => openDeleteRole(role)}
                                  disabled={loading}
                                  sx={{ color: "error.main" }}
                                >
                                  <Trash2 size={14} strokeWidth={1.75} />
                                </IconButton>
                              </span>
                            </Tooltip>
                          </Stack>
                        </Stack>
                      </Box>
                    </Paper>
                  );
                })}
            </Stack>
          )}

          {!loading ? (
            <>
              <Divider sx={{ my: 2 }} />
              <Typography variant="body2" color="text.secondary">
                {t("roles.tipFinal")}
              </Typography>
            </>
          ) : null}
        </Box>
      </Box>

      <CreateRoleDialog open={createOpen} onClose={() => setCreateOpen(false)} onSave={handleCreateRole} t={t} />

      <EditRoleDialog
        open={editOpen}
        role={editingRole}
        onClose={() => {
          setEditOpen(false);
          setEditingRole(null);
        }}
        onSave={handleUpdateRole}
        t={t}
      />

      <RolePermissionsDialog
        open={permOpen}
        role={permRole}
        allPermissions={Array.isArray(permissions) ? permissions : []}
        selectedIds={permRole ? selectedByRole[permRole.id] ?? new Set<string>() : new Set<string>()}
        onClose={closePermissions}
        onToggle={(permissionId) => {
          if (!permRole) return;
          togglePermission(permRole.id, permissionId);
        }}
        onSelectAll={() => {
          if (!permRole) return;
          selectAllPermissions(permRole.id);
        }}
        onDeselectAll={() => {
          if (!permRole) return;
          deselectAllPermissions(permRole.id);
        }}
        onSave={() => {
          if (!permRole) return;
          savePermissions(permRole.id);
        }}
        saving={permRole ? savingPermissions[permRole.id] : false}
        disabled={false}
        disabledReason={undefined}
        t={t}
      />

      <DeleteRoleDialog
        open={deleteOpen}
        role={deletingRole}
        onClose={closeDeleteRole}
        onConfirm={confirmDeleteRole}
        deleting={deleting}
        disabled={false}
        disabledReason={undefined}
        t={t}
      />

      <DuplicateRoleDialog
        open={duplicateOpen}
        role={duplicateTarget}
        onClose={closeDuplicateRole}
        onConfirm={confirmDuplicateRole}
        duplicating={!!duplicating}
        t={t}
      />
    </Box>
  );
}
