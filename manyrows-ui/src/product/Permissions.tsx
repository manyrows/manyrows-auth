import * as React from "react";
import axios from "axios";
import type { Permission, Product, Workspace } from "../core.ts";
import { extractApiError } from "../lib/apiError.ts";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  IconButton,
  Paper,
  Stack,
  TextField,
  Tooltip,
  Typography,
  Chip,
} from "@mui/material";
import { Copy, Lock, Plus, SquarePen, Trash2 } from "lucide-react";
import Eyebrow from "../components/Eyebrow.tsx";
import PageHeader from "../components/PageHeader.tsx";
import { useTranslation } from "react-i18next";

type TFunc = (key: string, opts?: Record<string, unknown>) => string;

/** ========= Types ========= */

interface Props {
  project: Product;
  workspace: Workspace;
}

interface PermissionsResponse {
  permissions: Permission[];
}

/** ========= API (mounted /admin routes) ========= */

// /admin/workspace/{workspaceId}/products/{productId}/permissions
function permissionsBase(project: Product) {
  return `/admin/workspace/${project.workspaceId}/products/${project.id}/permissions`;
}

async function getPermissions(project: Product): Promise<Permission[]> {
  const r = await axios.get<PermissionsResponse>(permissionsBase(project));
  return r.data.permissions;
}

async function createPermission(
  project: Product,
  body: Pick<Permission, "name" | "slug">,
): Promise<Permission> {
  const r = await axios.post<Permission>(permissionsBase(project), body);
  return r.data;
}

async function updatePermission(
  project: Product,
  permissionId: string,
  body: Partial<Pick<Permission, "name" | "slug">>,
): Promise<Permission> {
  const r = await axios.patch<Permission>(`${permissionsBase(project)}/${permissionId}`, body);
  return r.data;
}

// Derive group from slug prefix (e.g., "orders:read" -> "Orders")
function deriveGroupFromSlug(slug: string): string {
  const idx = slug.indexOf(":");
  if (idx > 0) {
    const prefix = slug.slice(0, idx);
    return prefix.charAt(0).toUpperCase() + prefix.slice(1);
  }
  return "General";
}

async function deletePermission(project: Product, permissionId: string): Promise<void> {
  await axios.delete(`${permissionsBase(project)}/${permissionId}`);
}

/** ========= UI helpers ========= */

function normalizeSlugInput(s: string): string {
  return (s || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "_")
    .replace(/[^a-z0-9:_-]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function titleCase(s: string): string {
  const t = (s || "").trim();
  if (!t) return "";
  return t.charAt(0).toUpperCase() + t.slice(1);
}

function PermissionDialog({
                            open,
                            mode,
                            initial,
                            onClose,
                            onSave,
                            disabled,
                            disabledReason,
                            t,
                          }: {
  open: boolean;
  mode: "create" | "edit";
  initial?: Partial<Permission>;
  onClose: () => void;
  onSave: (vals: Pick<Permission, "name" | "slug">) => void | Promise<void>;
  disabled?: boolean;
  disabledReason?: string;
  t: TFunc;
}) {
  const [name, setName] = React.useState("");
  const [slug, setSlug] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);

  React.useEffect(() => {
    if (!open) return;
    setName(initial?.name ?? "");
    setSlug(initial?.slug ?? "");
    setSubmitting(false);
  }, [open, initial?.id]);

  const canSave = !disabled && name.trim().length > 0 && slug.trim().length > 0;

  // Preview the derived group
  const derivedGroup = slug.trim() ? deriveGroupFromSlug(normalizeSlugInput(slug)) : "";

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSave || submitting) return;
    setSubmitting(true);
    try {
      await onSave({
        name: titleCase(name.trim()),
        slug: normalizeSlugInput(slug),
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>
        {mode === "create" ? t("permissions.dialog.createTitle") : t("permissions.dialog.editTitle")}
      </DialogTitle>

      <Box component="form" onSubmit={handleSubmit}>
        <DialogContent sx={{ pt: 1 }}>
          <Stack spacing={2}>
            {disabled ? (
              <Alert severity="warning">
                {disabledReason || t("permissions.dialog.editDisabled")}
              </Alert>
            ) : null}

            <TextField
              label={t("permissions.dialog.name")}
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
              fullWidth
              placeholder={t("permissions.dialog.namePlaceholder")}
              helperText={t("permissions.dialog.nameHelper")}
              disabled={!!disabled}
            />
            <TextField
              label={t("permissions.dialog.slug")}
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              helperText={
                derivedGroup
                  ? t("permissions.dialog.slugHelperWithGroup", { group: derivedGroup })
                  : t("permissions.dialog.slugHelper")
              }
              fullWidth
              placeholder={t("permissions.dialog.slugPlaceholder")}
              inputProps={{ spellCheck: false }}
              disabled={!!disabled}
            />

            {derivedGroup && (
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mt: -0.5 }}>
                <Typography variant="caption" color="text.secondary">
                  {t("permissions.dialog.group")}
                </Typography>
                <Chip
                  size="small"
                  label={derivedGroup}
                  sx={{
                    height: 20,
                    fontSize: 11,
                    bgcolor: "action.selected",
                    color: "primary.main",
                  }}
                />
              </Box>
            )}
          </Stack>
        </DialogContent>

        <DialogActions sx={{ px: 3, pb: 2.5 }}>
          <Button onClick={onClose} color="inherit" sx={{ textTransform: "none" }}>
            {t("permissions.dialog.cancel")}
          </Button>
          <Button type="submit" variant="contained" disabled={!canSave || submitting} sx={{ textTransform: "none" }}>
            {t("permissions.dialog.save")}
          </Button>
        </DialogActions>
      </Box>
    </Dialog>
  );
}

function DeletePermissionDialog({
                                  open,
                                  permission,
                                  onClose,
                                  onConfirm,
                                  deleting,
                                  disabled,
                                  disabledReason,
                                  t,
                                }: {
  open: boolean;
  permission: Permission | null;
  deleting: boolean;
  onClose: () => void;
  onConfirm: () => void;
  disabled?: boolean;
  disabledReason?: string;
  t: TFunc;
}) {
  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="xs">
      <DialogTitle>{t("permissions.dialog.deleteTitle")}</DialogTitle>
      <DialogContent sx={{ pt: 1 }}>
        {disabled ? (
          <Alert severity="warning">
            {disabledReason || t("permissions.dialog.editDisabled")}
          </Alert>
        ) : (
          <Alert severity="warning" icon={<Lock size={14} strokeWidth={1.75} />}>
            {permission
              ? t("permissions.dialog.deleteWarning", { name: permission.name })
              : t("permissions.dialog.deleteWarningGeneric")}
          </Alert>
        )}

        {permission?.id ? (
          <Paper variant="outlined" sx={{ borderRadius: 2, p: 1.25, mt: 1.5, bgcolor: "action.hover" }}>
            <Typography variant="caption" color="text.secondary">
              {t("permissions.dialog.slug")}
            </Typography>
            <Typography sx={{ fontFamily: "var(--font-mono)" }}>{permission.slug}</Typography>
          </Paper>
        ) : null}
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2.5 }}>
        <Button onClick={onClose} color="inherit" sx={{ textTransform: "none" }}>
          {t("permissions.dialog.cancel")}
        </Button>
        <Button
          onClick={onConfirm}
          variant="contained"
          color="error"
          disabled={!permission || deleting || !!disabled}
          startIcon={deleting ? <CircularProgress size={16} /> : <Trash2 size={14} strokeWidth={1.75} />}
          sx={{ textTransform: "none", borderRadius: 2 }}
        >
          {deleting ? t("permissions.dialog.deleting") : t("permissions.delete")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export default function Permissions({ project }: Props) {
  const { t } = useTranslation();

  const [loading, setLoading] = React.useState(true);
  const [err, setErr] = React.useState<string | null>(null);

  const [permissions, setPermissions] = React.useState<Permission[]>([]);

  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [dialogMode, setDialogMode] = React.useState<"create" | "edit">("create");
  const [editing, setEditing] = React.useState<Permission | null>(null);

  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [deleting, setDeleting] = React.useState(false);
  const [deletingPerm, setDeletingPerm] = React.useState<Permission | null>(null);

  const refresh = React.useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      const next = await getPermissions(project);
      setPermissions(next ?? []);
    } catch (e) {
      setErr(extractApiError(e, t("permissions.failedToLoad")));
    } finally {
      setLoading(false);
    }
  }, [project]);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  const permissionCount = permissions.length;

  const openCreate = () => {
    setDialogMode("create");
    setEditing(null);
    setDialogOpen(true);
  };

  const openEdit = (p: Permission) => {
    setDialogMode("edit");
    setEditing(p);
    setDialogOpen(true);
  };

  const handleSave = async (vals: Pick<Permission, "name" | "slug">) => {
    setErr(null);

    try {
      if (dialogMode === "create") {
        await createPermission(project, vals);
      } else if (editing) {
        await updatePermission(project, editing.id, vals);
      }
      setDialogOpen(false);
      setEditing(null);
      await refresh();
    } catch (e) {
      setErr(extractApiError(e, t("permissions.failedToSave")));
    }
  };

  const askDelete = (p: Permission) => {
    // allow delete even if over limit
    setDeletingPerm(p);
    setDeleteOpen(true);
  };

  const handleDelete = async () => {
    if (!deletingPerm) return;
    // allow delete even if over limit

    setDeleting(true);
    setErr(null);
    try {
      await deletePermission(project, deletingPerm.id);
      setDeleteOpen(false);
      setDeletingPerm(null);
      await refresh();
    } catch (e) {
      setErr(extractApiError(e, t("permissions.failedToDelete")));
    } finally {
      setDeleting(false);
    }
  };

  const copyTextSilent = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // ignore
    }
  };

  const grouped = React.useMemo(() => {
    const map = new Map<string, Permission[]>();
    for (const p of permissions) {
      // Derive group from slug prefix instead of using stored group field
      const group = deriveGroupFromSlug(p.slug);
      if (!map.has(group)) map.set(group, []);
      map.get(group)!.push(p);
    }
    for (const list of map.values()) {
      list.sort((a, b) => (a.slug || "").localeCompare(b.slug || ""));
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [permissions]);

  return (
    <Box>
      <Box>
        <PageHeader
          title={t("permissions.title")}
          subtitle={t("permissions.description")}
          mb={0}
          action={
            <>
              <Chip
                size="small"
                variant="outlined"
                label={t("permissions.countLabel", { count: permissionCount })}
              />
              <Button
                disableElevation
                size="small"
                variant="contained"
                startIcon={<Plus size={14} strokeWidth={1.75} />}
                onClick={openCreate}
              >
                {t("permissions.newPermission")}
              </Button>
            </>
          }
        />
        <Divider sx={{ mt: 3 }} />

        {/* Body */}
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
                {t("permissions.loading")}
              </Typography>
            </Stack>
          ) : grouped.length === 0 ? (
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
                <Box component="span" sx={{ color: "primary.main" }}><Lock size={28} strokeWidth={1.75} /></Box>
              </Box>
              <Typography sx={{ fontSize: 17, fontWeight: 600, letterSpacing: "-0.005em", mb: 1 }}>
                {t("permissions.noPermissionsYet")}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, maxWidth: 420, mx: "auto" }}>
                {t("permissions.noPermissionsDesc")}
                <code style={{ margin: "0 4px" }}>orders:read</code> {t("permissions.or")}
                <code style={{ margin: "0 4px" }}>users:delete</code>{t("permissions.noPermissionsDesc2")}
              </Typography>
              <Paper variant="outlined" sx={{ borderRadius: 2, p: 2, mb: 2.5, maxWidth: 360, mx: "auto", bgcolor: "action.hover" }}>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1, textAlign: "left" }}>
                  {t("permissions.examplePermissions")}
                </Typography>
                <Stack spacing={0.5} sx={{ textAlign: "left" }}>
                  <Typography variant="body2" sx={{ fontFamily: "var(--font-mono)" }}>orders:read</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "var(--font-mono)" }}>orders:write</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "var(--font-mono)" }}>users:manage</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "var(--font-mono)" }}>billing:view</Typography>
                </Stack>
              </Paper>
              <Button
                variant="contained"
                startIcon={<Plus size={14} strokeWidth={1.75} />}
                onClick={openCreate}
                sx={{ borderRadius: 2, textTransform: "none" }}
              >
                {t("permissions.createFirst")}
              </Button>
            </Paper>
          ) : (
            <Stack spacing={3}>
              {grouped.map(([group, perms]) => (
                <Box key={group}>
                  {/* Group header */}
                  <Box
                    sx={{
                      display: "flex",
                      alignItems: "center",
                      gap: 1.5,
                      mb: 1.5,
                      pb: 1,
                      borderBottom: "1px solid",
                      borderColor: "divider",
                    }}
                  >
                    <Box
                      sx={{
                        width: 4,
                        height: 4,
                        borderRadius: "50%",
                        bgcolor: "primary.main",
                        flexShrink: 0,
                      }}
                    />
                    <Eyebrow>{group}</Eyebrow>
                    <Chip
                      size="small"
                      label={perms.length}
                      variant="outlined"
                      sx={{
                        height: 18,
                        fontSize: 10,
                        fontWeight: 500,
                        fontFamily: "var(--font-mono)",
                        color: "text.disabled",
                      }}
                    />
                  </Box>

                  {/* Permission list - compact table-like layout */}
                  <Paper variant="outlined" sx={{ borderRadius: 2, overflow: "hidden" }}>
                    {perms.map((p, idx) => (
                      <Box
                        key={p.id}
                        sx={{
                          display: "flex",
                          alignItems: "center",
                          gap: 2,
                          px: 2,
                          py: 1.25,
                          borderBottom: idx < perms.length - 1 ? "1px solid" : "none",
                          borderColor: "divider",
                          transition: "background-color 100ms",
                          "&:hover": { bgcolor: "action.hover" },
                        }}
                      >
                        {/* Name */}
                        <Typography variant="body2" fontWeight={500} sx={{ minWidth: 140, flex: "0 0 auto" }} noWrap>
                          {p.name}
                        </Typography>

                        {/* Slug chip */}
                        <Chip
                          size="small"
                          label={p.slug}
                          onClick={() => void copyTextSilent(p.slug)}
                          variant="outlined"
                          sx={{
                            height: 22,
                            fontSize: 11.5,
                            fontFamily: "var(--font-mono)",
                            cursor: "pointer",
                            "&:hover": { bgcolor: "action.hover" },
                            "& .MuiChip-label": { px: 1.25 },
                          }}
                        />

                        <Box sx={{ flex: 1 }} />

                        {/* Actions */}
                        <Stack direction="row" spacing={0.5}>
                          <Tooltip title={t("permissions.copySlug")}>
                            <IconButton size="small" onClick={() => void copyTextSilent(p.slug)}>
                              <Copy size={16} strokeWidth={1.75} />
                            </IconButton>
                          </Tooltip>

                          <Tooltip title={t("permissions.edit")}>
                            <span>
                              <IconButton size="small" onClick={() => openEdit(p)}>
                                <SquarePen size={16} strokeWidth={1.75} />
                              </IconButton>
                            </span>
                          </Tooltip>

                          <Tooltip title={t("permissions.delete")}>
                            <span>
                              <IconButton
                                size="small"
                                onClick={() => askDelete(p)}
                                disabled={loading}
                                sx={{ color: "error.main" }}
                              >
                                <Trash2 size={16} strokeWidth={1.75} />
                              </IconButton>
                            </span>
                          </Tooltip>
                        </Stack>
                      </Box>
                    ))}
                  </Paper>
                </Box>
              ))}
            </Stack>
          )}

          {!loading ? (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
              {t("permissions.tip")}
            </Typography>
          ) : null}
        </Box>
      </Box>

      <PermissionDialog
        open={dialogOpen}
        mode={dialogMode}
        initial={editing ?? undefined}
        onClose={() => setDialogOpen(false)}
        onSave={handleSave}
        disabled={false}
        disabledReason={undefined}
        t={t}
      />

      <DeletePermissionDialog
        open={deleteOpen}
        permission={deletingPerm}
        deleting={deleting}
        onClose={() => setDeleteOpen(false)}
        onConfirm={handleDelete}
        disabled={false}
        disabledReason={undefined}
        t={t}
      />
    </Box>
  );
}
