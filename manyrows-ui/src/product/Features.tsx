import * as React from "react";
import { apiJson } from "../lib/api.ts";
import { useSnackbar } from "notistack";
import { useTranslation, Trans } from "react-i18next";

type TFunc = (key: string, opts?: Record<string, unknown>) => string;
import type { App, FeatureFlag, FeatureFlagOverride, Product, Workspace } from "../core.ts";
import { appTypeLabel } from "../core.ts";
import { extractApiError } from "../lib/apiError.ts";
import { appTypeColors, alpha } from "../colors.ts";
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
  Divider,
  FormControlLabel,
  IconButton,
  InputAdornment,
  LinearProgress,
  ListItemIcon,
  ListItemText,
  Menu,
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
import { Ban, CircleCheck, Download, Flag, Lightbulb, Plus, RefreshCw, Save, Search, SquarePen, Trash2, X } from "lucide-react";
import PageHeader from "../components/PageHeader.tsx";
const tc = { code: <code />, b: <b />, strong: <strong /> };

interface Props {
  project: Product;
  workspace: Workspace;
  appId?: string;
}

type Scope = "server" | "client";

// Some server versions return `visibility` instead of `scope`. Treat both as
// possible inputs when normalizing into the local Scope union.
type FlagWire = FeatureFlag & { visibility?: string };

function normalize(s: string): string {
  return (s || "").trim().toLowerCase();
}

function isValidKey(key: string): boolean {
  return /^[a-z][a-z0-9_]*$/.test(key);
}

function fmtDate(d: string | number | Date | null | undefined): string {
  if (!d) return "-";
  const date = d instanceof Date ? d : new Date(d);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString();
}

function isProdApp(app: App | null | undefined): boolean {
  if (!app) return false;
  return app.type === "prod";
}

function normalizeScope(v: unknown): Scope {
  const s = normalize(String(v ?? ""));
  return s === "client" ? "client" : "server";
}

function flagScope(flag: FeatureFlag): Scope {
  const f = flag as FlagWire;
  return normalizeScope(f.scope ?? f.visibility);
}

function scopeLabel(v: Scope, t: TFunc): string {
  return v === "client" ? t("features.scope.client") : t("features.scope.server");
}

function scopeHelp(v: Scope, t: TFunc): string {
  return v === "client"
    ? t("features.scope.clientHelp")
    : t("features.scope.serverHelp");
}

function downloadFile(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function escapeCsvField(value: string): string {
  if (value.includes(",") || value.includes('"') || value.includes("\n")) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

export default function Features({ project, appId: fixedAppId }: Props) {
  const { t } = useTranslation();
  const { enqueueSnackbar } = useSnackbar();

  const base = `/admin/workspace/${project.workspaceId}/products/${project.id}`;

  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const [flags, setFlags] = React.useState<FeatureFlag[]>([]);
  // IMPORTANT: apps are displayed exactly as returned from the API (no sorting)
  const [apps, setApps] = React.useState<App[]>([]);
  const [overrides, setOverrides] = React.useState<FeatureFlagOverride[]>([]);
  const [roles, setRoles] = React.useState<{ id: string; name: string; slug: string }[]>([]);

  // Keep as string (not null) so MUI select behaves predictably.
  const [selectedAppId, setSelectedAppId] = React.useState<string>(fixedAppId || "");

  React.useEffect(() => {
    if (fixedAppId) setSelectedAppId(fixedAppId);
  }, [fixedAppId]);

  const selectedApp = React.useMemo(
    () => apps.find((e) => e.id === selectedAppId) || null,
    [apps, selectedAppId],
  );

  // Prod confirm dialog state (same behavior as config keys page)
  const [prodConfirmOpen, setProdConfirmOpen] = React.useState(false);
  const [pendingAppId, setPendingAppId] = React.useState<string>("");

  // Per-flag saving state (for optimistic toggle)
  const [savingFlagIds, setSavingFlagIds] = React.useState<Set<string>>(new Set());

  // dialogs
  const [createOpen, setCreateOpen] = React.useState(false);
  const [editOpen, setEditOpen] = React.useState(false);
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [killSwitchOpen, setKillSwitchOpen] = React.useState(false);
  const [enableAllOpen, setEnableAllOpen] = React.useState(false);

  const [createKey, setCreateKey] = React.useState("");
  const [createDesc, setCreateDesc] = React.useState("");
  const [createDefaultEnabled, setCreateDefaultEnabled] = React.useState(false);
  const [createScope, setCreateScope] = React.useState<Scope>("server");

  const [selected, setSelected] = React.useState<FeatureFlag | null>(null);
  const [editDesc, setEditDesc] = React.useState("");
  const [editDefaultEnabled, setEditDefaultEnabled] = React.useState(false);
  const [editStatus, setEditStatus] = React.useState<"active" | "archived">("active");
  const [editScope, setEditScope] = React.useState<Scope>("server");

  // Search
  const [searchQuery, setSearchQuery] = React.useState("");

  // Export menu
  const [exportAnchorEl, setExportAnchorEl] = React.useState<null | HTMLElement>(null);
  const exportMenuOpen = Boolean(exportAnchorEl);

  function handleExportCsv() {
    setExportAnchorEl(null);
    const appNames = apps.map((e) => appTypeLabel(e));
    const header = ["Key", "Description", "Scope", "DefaultEnabled", "Status", ...appNames];
    const rows: string[][] = [];

    for (const flag of flags) {
      const scope = flagScope(flag);
      const row: string[] = [
        flag.key,
        flag.description || "",
        scope,
        String(flag.defaultEnabled),
        flag.status || "",
      ];
      for (const app of apps) {
        const k = `${flag.id}::${app.id}`;
        const override = overrideByKey.get(k);
        const enabled = override ? override.enabled : flag.defaultEnabled;
        row.push(String(enabled));
      }
      rows.push(row);
    }

    const csv = [header.map(escapeCsvField).join(","), ...rows.map((r) => r.map(escapeCsvField).join(","))].join("\n");
    downloadFile(csv, `feature-flags-${project.id}.csv`, "text/csv;charset=utf-8");
  }

  function handleExportJson() {
    setExportAnchorEl(null);
    const result = {
      features: flags.map((flag) => {
        const scope = flagScope(flag);
        const byApp: Record<string, boolean> = {};
        for (const app of apps) {
          const k = `${flag.id}::${app.id}`;
          const override = overrideByKey.get(k);
          byApp[appTypeLabel(app)] = override ? override.enabled : flag.defaultEnabled;
        }
        return {
          key: flag.key,
          description: flag.description || null,
          scope,
          defaultEnabled: flag.defaultEnabled,
          status: flag.status,
          apps: byApp,
        };
      }),
    };
    downloadFile(JSON.stringify(result, null, 2), `feature-flags-${project.id}.json`, "application/json");
  }

  // Role targeting dialog
  const [roleDialogOpen, setRoleDialogOpen] = React.useState(false);
  const [roleDialogFlag, setRoleDialogFlag] = React.useState<FeatureFlag | null>(null);
  const [roleDialogApp, setRoleDialogApp] = React.useState<App | null>(null);
  const [roleDialogSelected, setRoleDialogSelected] = React.useState<Set<string>>(new Set());
  const [roleDialogSaving, setRoleDialogSaving] = React.useState(false);

  function openRoleDialog(flag: FeatureFlag, app: App) {
    const override = overrides.find((o) => o.featureFlagId === flag.id && o.appId === app.id);
    setRoleDialogFlag(flag);
    setRoleDialogApp(app);
    setRoleDialogSelected(new Set(override?.roleIds ?? []));
    setRoleDialogOpen(true);
  }

  async function saveRoleTargeting() {
    if (!roleDialogFlag || !roleDialogApp) return;
    setRoleDialogSaving(true);
    try {
      const override = overrides.find((o) => o.featureFlagId === roleDialogFlag.id && o.appId === roleDialogApp.id);
      const enabled = override?.enabled ?? roleDialogFlag.defaultEnabled;
      await apiJson(`${base}/featureFlags/${roleDialogFlag.id}/apps/${roleDialogApp.id}`, {
        method: "PUT",
        data: { enabled, status: "active", roleIds: [...roleDialogSelected] },
      });
      // Refresh overrides
      const overrideRes = await apiJson<{ featureFlagOverrides: FeatureFlagOverride[] }>(
        `${base}/featureFlags/apps`,
      );
      setOverrides(overrideRes.featureFlagOverrides || []);
      setRoleDialogOpen(false);
      enqueueSnackbar(t("features.roleTargeting.saved"), { variant: "success" });
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("features.roleTargeting.saveFailed")), { variant: "error" });
    } finally {
      setRoleDialogSaving(false);
    }
  }

  function cellKey(flagId: string, appId: string) {
    return `${flagId}::${appId}`;
  }

  const overrideByKey = React.useMemo(() => {
    const m = new Map<string, FeatureFlagOverride>();
    overrides.forEach((o) => m.set(`${o.featureFlagId}::${o.appId}`, o));
    return m;
  }, [overrides]);

  function effectiveEnabled(flag: FeatureFlag, app: App): boolean {
    const o = overrideByKey.get(cellKey(flag.id, app.id));
    return o ? o.enabled : flag.defaultEnabled;
  }

  async function handleToggle(flag: FeatureFlag, app: App, enabled: boolean) {
    // Snapshot for revert
    const prevOverrides = overrides;

    // Optimistic update
    setOverrides((prev) => {
      const existing = prev.find((o) => o.featureFlagId === flag.id && o.appId === app.id);
      if (existing) {
        return prev.map((o) => (o === existing ? { ...o, enabled } : o));
      }
      return [...prev, { featureFlagId: flag.id, appId: app.id, enabled, status: "active" } as FeatureFlagOverride];
    });

    setSavingFlagIds((prev) => { const next = new Set(prev); next.add(flag.id); return next; });

    try {
      await apiJson(`${base}/featureFlags/${flag.id}/apps/${app.id}`, {
        method: "PUT",
        data: { enabled, status: "active", roleIds: overrideByKey.get(cellKey(flag.id, app.id))?.roleIds ?? [] },
      });

      enqueueSnackbar(t("features.snackbar.toggled"), { variant: "success" });

      // Refresh from server to ensure consistency
      const overrideRes = await apiJson<{ featureFlagOverrides: FeatureFlagOverride[] }>(
        `${base}/featureFlags/apps`,
      );
      setOverrides(overrideRes.featureFlagOverrides || []);
    } catch (e) {
      // Revert optimistic update
      setOverrides(prevOverrides);
      enqueueSnackbar(extractApiError(e, t("features.snackbar.toggleFailed")), { variant: "error" });
    } finally {
      setSavingFlagIds((prev) => { const next = new Set(prev); next.delete(flag.id); return next; });
    }
  }

  function applyEnvSwitch(nextAppId: string) {
    setSelectedAppId(nextAppId);
  }

  function requestEnvSwitch(nextAppId: string) {
    if (!nextAppId || nextAppId === selectedAppId) return;

    const nextApp = apps.find((e) => e.id === nextAppId) || null;
    if (isProdApp(nextApp)) {
      setPendingAppId(nextAppId);
      setProdConfirmOpen(true);
      return;
    }

    applyEnvSwitch(nextAppId);
  }

  function confirmProdSwitch() {
    const next = pendingAppId;
    setProdConfirmOpen(false);
    setPendingAppId("");
    if (!next) return;
    applyEnvSwitch(next);
    enqueueSnackbar(t("features.snackbar.switchedToProd"), { variant: "info" });
  }

  function cancelProdSwitch() {
    setProdConfirmOpen(false);
    setPendingAppId("");
    enqueueSnackbar(t("features.snackbar.cancelledProdSwitch"), { variant: "info" });
  }

  const pendingApp = React.useMemo(() => {
    return apps.find((e) => e.id === pendingAppId) || null;
  }, [apps, pendingAppId]);

  const flagsCount = flags.length;

  async function refreshAll() {
    setLoading(true);
    setError(null);
    try {
      const [envRes, flagRes, overrideRes, rolesRes] = await Promise.all([
        apiJson<{ apps: App[] }>(`${base}/apps`),
        apiJson<{ featureFlags: FeatureFlag[] }>(`${base}/featureFlags`),
        apiJson<{ featureFlagOverrides: FeatureFlagOverride[] }>(
          `${base}/featureFlags/apps`,
        ),
        apiJson<{ roles: { id: string; name: string; slug: string }[] }>(`${base}/roles`).catch(() => ({ roles: [] })),
      ]);

      const nextApps = envRes.apps || [];
      const nextFlags = flagRes.featureFlags || [];
      const nextOverrides = overrideRes.featureFlagOverrides || [];

      // Back-compat: if older deployments still send visibility, map it.
      (nextFlags as FlagWire[]).forEach((f) => {
        if (!f) return;
        if (f.scope === undefined || f.scope === null || f.scope === "") {
          if (f.visibility !== undefined && f.visibility !== null && f.visibility !== "") {
            f.scope = f.visibility;
          } else {
            f.scope = "server";
          }
        }
      });

      setApps(nextApps);
      setFlags(nextFlags);
      setOverrides(nextOverrides);
      setRoles(rolesRes.roles || []);

      // Ensure selected app stays valid (preserve API order; default to first returned app)
      setSelectedAppId((prev) => {
        if (fixedAppId) return fixedAppId;
        if (prev && nextApps.some((e) => e.id === prev)) return prev;
        return nextApps.length > 0 ? nextApps[0].id : "";
      });
    } catch (e) {
      const msg = extractApiError(e, t("features.snackbar.loadFailed"));
      setError(msg);
      enqueueSnackbar(msg, { variant: "error" });
    } finally {
      setLoading(false);
    }
  }

  React.useEffect(() => {
    void refreshAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [project.id]);

  async function handleCreate() {
    setSaving(true);
    setError(null);
    try {
      const k = createKey.trim();
      if (!isValidKey(k)) throw new Error(t("features.snackbar.invalidKey"));

      await apiJson(`${base}/featureFlags`, {
        method: "POST",
        data: {
          key: k,
          description: createDesc.trim() || null,
          scope: createScope,
          defaultEnabled: createDefaultEnabled,
          status: "active",
        },
      });

      setCreateOpen(false);
      setCreateKey("");
      setCreateDesc("");
      setCreateDefaultEnabled(false);
      setCreateScope("server");

      enqueueSnackbar(t("features.snackbar.created"), { variant: "success" });
      await refreshAll();
    } catch (e) {
      const msg = extractApiError(e, t("features.snackbar.createFailed"));
      setError(msg);
      enqueueSnackbar(msg, { variant: "error" });
    } finally {
      setSaving(false);
    }
  }

  async function handleEditSave() {
    if (!selected) return;

    setSaving(true);
    setError(null);
    try {
      await apiJson(`${base}/featureFlags/${selected.id}`, {
        method: "PATCH",
        data: {
          description: editDesc.trim() || null,
          scope: editScope,
          defaultEnabled: editDefaultEnabled,
          status: editStatus,
        },
      });

      setEditOpen(false);
      setSelected(null);

      enqueueSnackbar(t("features.snackbar.updated"), { variant: "success" });
      await refreshAll();
    } catch (e) {
      const msg = extractApiError(e, t("features.snackbar.updateFailed"));
      setError(msg);
      enqueueSnackbar(msg, { variant: "error" });
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    if (!selected) return;

    setSaving(true);
    setError(null);
    try {
      await apiJson(`${base}/featureFlags/${selected.id}`, { method: "DELETE" });
      setDeleteOpen(false);
      setSelected(null);

      enqueueSnackbar(t("features.snackbar.deleted"), { variant: "success" });
      await refreshAll();
    } catch (e) {
      const msg = extractApiError(e, t("features.snackbar.deleteFailed"));
      setError(msg);
      enqueueSnackbar(msg, { variant: "error" });
    } finally {
      setSaving(false);
    }
  }

  const hasApps = apps.length > 0;

  const filteredFlags = React.useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return flags;
    return flags.filter(f =>
      f.key.toLowerCase().includes(q) ||
      (f.description || "").toLowerCase().includes(q)
    );
  }, [flags, searchQuery]);

  // Count how many apps have a flag enabled (for overview)
  function countEnabledApps(flag: FeatureFlag): number {
    let count = 0;
    for (const app of apps) {
      const k = cellKey(flag.id, app.id);
      const override = overrideByKey.get(k);
      const enabled = override ? override.enabled : flag.defaultEnabled;
      if (enabled) count++;
    }
    return count;
  }

  // Apply the same enabled state to a flag across ALL apps, settling every
  // request so one failure doesn't abort the rest mid-way (which would leave a
  // half-applied state). Returns how many apps failed.
  async function applyFlagToAllApps(flagId: string, enabled: boolean): Promise<number> {
    const results = await Promise.allSettled(
      apps.map((app) =>
        apiJson(`${base}/featureFlags/${flagId}/apps/${app.id}`, {
          method: "PUT",
          data: { enabled, status: "active" },
        }),
      ),
    );
    return results.filter((r) => r.status === "rejected").length;
  }

  // Kill switch: disable a flag across ALL apps
  async function handleKillSwitch() {
    const flag = selected;
    if (!flag) return;

    setSaving(true);
    setError(null);
    try {
      const failed = await applyFlagToAllApps(flag.id, false);
      setKillSwitchOpen(false);
      setSelected(null);
      await refreshAll();
      if (failed > 0) {
        const msg = t("features.snackbar.killSwitchPartial", {
          defaultValue: "Disabled on {{ok}} of {{total}} apps; {{failed}} failed",
          ok: apps.length - failed,
          total: apps.length,
          failed,
        });
        setError(msg);
        enqueueSnackbar(msg, { variant: "error" });
      } else {
        enqueueSnackbar(t("features.snackbar.killSwitchActivated", { key: flag.key }), { variant: "warning" });
      }
    } catch (e) {
      const msg = extractApiError(e, t("features.snackbar.killSwitchFailed"));
      setError(msg);
      enqueueSnackbar(msg, { variant: "error" });
    } finally {
      setSaving(false);
    }
  }

  // Enable a flag across ALL apps
  async function handleEnableAll() {
    const flag = selected;
    if (!flag) return;

    setSaving(true);
    setError(null);
    try {
      const failed = await applyFlagToAllApps(flag.id, true);
      setEnableAllOpen(false);
      setSelected(null);
      await refreshAll();
      if (failed > 0) {
        const msg = t("features.snackbar.enableAllPartial", {
          defaultValue: "Enabled on {{ok}} of {{total}} apps; {{failed}} failed",
          ok: apps.length - failed,
          total: apps.length,
          failed,
        });
        setError(msg);
        enqueueSnackbar(msg, { variant: "error" });
      } else {
        enqueueSnackbar(t("features.snackbar.enabledAll", { key: flag.key }), { variant: "success" });
      }
    } catch (e) {
      const msg = extractApiError(e, t("features.snackbar.enableAllFailed"));
      setError(msg);
      enqueueSnackbar(msg, { variant: "error" });
    } finally {
      setSaving(false);
    }
  }

  return (
    <Box>
      <Stack spacing={2.5}>
        <PageHeader
          title={t("features.title")}
          mb={0}
          action={
            <>
              <Chip
                size="small"
                variant="outlined"
                label={t("features.flagsCount", { current: flagsCount.toLocaleString() })}
                sx={{ fontFamily: "var(--font-mono)" }}
              />
              <Tooltip title={t("features.refresh")}>
                <span>
                  <IconButton onClick={() => void refreshAll()} disabled={loading || saving} size="small">
                    <RefreshCw size={14} strokeWidth={1.75} />
                  </IconButton>
                </span>
              </Tooltip>
              <Button
                size="small"
                variant="outlined"
                startIcon={<Download size={14} strokeWidth={1.75} />}
                onClick={(e) => setExportAnchorEl(e.currentTarget)}
                disabled={loading || flags.length === 0}
              >
                {t("features.export")}
              </Button>
              <Menu
                anchorEl={exportAnchorEl}
                open={exportMenuOpen}
                onClose={() => setExportAnchorEl(null)}
              >
                <MenuItem onClick={handleExportCsv}>
                  <ListItemIcon><Download size={14} strokeWidth={1.75} /></ListItemIcon>
                  <ListItemText>{t("features.exportCsv")}</ListItemText>
                </MenuItem>
                <MenuItem onClick={handleExportJson}>
                  <ListItemIcon><Download size={14} strokeWidth={1.75} /></ListItemIcon>
                  <ListItemText>{t("features.exportJson")}</ListItemText>
                </MenuItem>
              </Menu>
              <Button
                variant="contained"
                disableElevation
                size="small"
                startIcon={<Plus size={14} strokeWidth={1.75} />}
                onClick={() => setCreateOpen(true)}
                disabled={loading || saving}
              >
                {t("features.newFlag")}
              </Button>
            </>
          }
        />

        {/* ✅ Explanation (kept compact, lives "somewhere on this page") */}
        <Alert severity="info" variant="outlined">
          <Stack spacing={0.75}>
            <Typography variant="body2" >
              {t("features.info.title")}
            </Typography>
            <Typography variant="body2" color="text.secondary"><Trans i18nKey="features.info.description" components={tc} /></Typography>
            <Typography variant="body2" color="text.secondary"><Trans i18nKey="features.info.scope" components={tc} /></Typography>
          </Stack>
        </Alert>

        <Divider />

        {(loading || saving) && <LinearProgress />}

        {error && (
          <Alert severity="error" onClose={() => setError(null)}>
            {error}
          </Alert>
        )}

        {loading ? null : !hasApps ? (
          <Alert severity="info">
            {t("features.noApps")}
          </Alert>
        ) : (
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1} alignItems={{ xs: "stretch", sm: "center" }}>
            {!fixedAppId && (
              <TextField
                size="small"
                select
                label={t("features.app")}
                value={selectedAppId}
                onChange={(e) => requestEnvSwitch(e.target.value)}
                disabled={!hasApps || loading || saving}
                sx={{ minWidth: 280 }}
              >
                {apps.map((app) => (
                  <MenuItem key={app.id} value={app.id}>
                    {appTypeLabel(app)}
                  </MenuItem>
                ))}
              </TextField>
            )}

            {flags.length > 0 && (
              <TextField
                size="small"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={t("features.searchPlaceholder")}
                sx={{ minWidth: 220 }}
                slotProps={{
                  input: {
                    startAdornment: (
                      <InputAdornment position="start">
                        <Search size={14} strokeWidth={1.75} />
                      </InputAdornment>
                    ),
                    endAdornment: searchQuery ? (
                      <InputAdornment position="end">
                        <IconButton size="small" onClick={() => setSearchQuery("")}>
                          <X size={14} strokeWidth={1.75} />
                        </IconButton>
                      </InputAdornment>
                    ) : undefined,
                  },
                }}
              />
            )}
          </Stack>
        )}

        {loading ? null : !selectedAppId ? (
          <Alert severity="info">{t("features.selectApp")}</Alert>
        ) : flags.length === 0 && !searchQuery ? (
          <Box
            sx={{
              border: "1px solid",
              borderColor: "divider",
              borderRadius: 2.5,
              p: 4,
              textAlign: "center",
              bgcolor: "action.hover",
            }}
          >
            <Box
              sx={{
                width: 56,
                height: 56,
                borderRadius: 2,
                bgcolor: "action.selected",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                mx: "auto",
                mb: 2,
              }}
            >
              <Box component="span" sx={{ color: "primary.main" }}><Flag size={28} strokeWidth={1.75} /></Box>
            </Box>
            <Typography sx={{ fontSize: 17, fontWeight: 600, letterSpacing: "-0.005em", mb: 1 }}>
              {t("features.empty.title")}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3, maxWidth: 400, mx: "auto" }}>
              {t("features.empty.description")}
            </Typography>
            <Stack spacing={1.5} sx={{ maxWidth: 320, mx: "auto", mb: 3, textAlign: "left" }}>
              <Stack direction="row" spacing={1.5} alignItems="flex-start">
                <Box component="span" sx={{ color: "text.secondary", mt: 0.25 }}><Lightbulb size={18} strokeWidth={1.75} /></Box>
                <Typography variant="body2" color="text.secondary"><Trans i18nKey="features.empty.tip1" components={tc} /></Typography>
              </Stack>
              <Stack direction="row" spacing={1.5} alignItems="flex-start">
                <Box component="span" sx={{ color: "text.secondary", mt: 0.25 }}><Lightbulb size={18} strokeWidth={1.75} /></Box>
                <Typography variant="body2" color="text.secondary">
                  {t("features.empty.tip2")}
                </Typography>
              </Stack>
              <Stack direction="row" spacing={1.5} alignItems="flex-start">
                <Box component="span" sx={{ color: "text.secondary", mt: 0.25 }}><Lightbulb size={18} strokeWidth={1.75} /></Box>
                <Typography variant="body2" color="text.secondary">
                  {t("features.empty.tip3")}
                </Typography>
              </Stack>
            </Stack>
            <Button
              variant="contained"
              disableElevation
              startIcon={<Plus size={14} strokeWidth={1.75} />}
              onClick={() => setCreateOpen(true)}
              sx={{ borderRadius: 2, textTransform: "none" }}
            >
              {t("features.empty.createFirst")}
            </Button>
          </Box>
        ) : filteredFlags.length === 0 ? (
          <Alert severity="info">{t("features.noSearchResults")}</Alert>
        ) : (
          <TableContainer component={Paper} variant="outlined" sx={{ borderRadius: 2, overflowX: "auto" }}>
            <Table size="small" stickyHeader>
              <TableHead>
                <TableRow>
                  <TableCell sx={{ width: 320, minWidth: 260 }}>
                    <Typography variant="subtitle2">{t("features.table.key")}</Typography>
                  </TableCell>

                  <TableCell sx={{ width: 160, minWidth: 140 }}>
                    <Typography variant="subtitle2">{t("features.table.scope")}</Typography>
                  </TableCell>

                  <TableCell sx={{ minWidth: 320 }}>
                    <Typography variant="subtitle2">{t("features.table.description")}</Typography>
                  </TableCell>

                  <TableCell align="center" sx={{ width: 220, whiteSpace: "nowrap" }}>
                    <Typography variant="subtitle2">
                      {selectedApp ? t("features.table.enabledApp", { app: appTypeLabel(selectedApp) }) : t("features.table.enabled")}
                    </Typography>
                  </TableCell>

                  <TableCell align="right" sx={{ width: 240, whiteSpace: "nowrap" }}>
                    <Typography variant="subtitle2">{t("features.table.actions")}</Typography>
                  </TableCell>
                </TableRow>
              </TableHead>

              <TableBody>
                {filteredFlags.map((flag) => {
                  const archived = normalize(flag.status) === "archived";
                  if (!selectedApp) return null;
                  const app = selectedApp;

                  const enabled = effectiveEnabled(flag, app);

                  const rowEditDisabled = saving || loading || archived || !selectedAppId || savingFlagIds.has(flag.id);

                  const scope = flagScope(flag);

                  return (
                    <TableRow key={flag.id} hover sx={{ opacity: archived ? 0.6 : 1 }}>
                      <TableCell sx={{ width: 320, minWidth: 260, maxWidth: 420 }}>
                        <Stack spacing={0.4} sx={{ minWidth: 0 }}>
                          <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0 }}>
                            <Typography
                              sx={{
                                fontFamily: "var(--font-mono)",
                                fontSize: 12.5,
                                fontWeight: 500,
                                minWidth: 0,
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                whiteSpace: "nowrap",
                              }}
                            >
                              {flag.key}
                            </Typography>
                            {archived && (
                              <Chip
                                size="small"
                                label={t("features.archived")}
                                variant="outlined"
                                sx={{
                                  height: 18,
                                  fontSize: 9.5,
                                  fontFamily: "var(--font-mono)",
                                  textTransform: "uppercase",
                                  letterSpacing: "0.08em",
                                  fontWeight: 600,
                                  color: "text.disabled",
                                }}
                              />
                            )}
                          </Stack>

                          <Typography
                            sx={{
                              display: "block",
                              mt: 0.25,
                              fontFamily: "var(--font-mono)",
                              fontSize: 10.5,
                              color: "text.disabled",
                            }}
                          >
                            {t("features.updated", { date: fmtDate(flag.updatedAt) })}
                          </Typography>
                        </Stack>
                      </TableCell>

                      <TableCell sx={{ width: 160, minWidth: 140 }}>
                        <Tooltip title={scopeHelp(scope, t)}>
                          <Chip
                            size="small"
                            variant="outlined"
                            label={scopeLabel(scope, t)}
                            sx={{
                              height: 20,
                              fontSize: 10,
                              fontFamily: "var(--font-mono)",
                              textTransform: "uppercase",
                              letterSpacing: "0.08em",
                              fontWeight: 600,
                              color: "text.secondary",
                            }}
                          />
                        </Tooltip>
                      </TableCell>

                      <TableCell sx={{ minWidth: 320, maxWidth: 520 }}>
                        {flag.description ? (
                          <Typography
                            variant="body2"
                            color="text.secondary"
                            sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                          >
                            {flag.description}
                          </Typography>
                        ) : (
                          <Typography variant="body2" color="text.disabled">
                            -
                          </Typography>
                        )}
                      </TableCell>

                      <TableCell align="center">
                        <Stack spacing={0.25} alignItems="center">
                          <Stack direction="row" spacing={0.75} alignItems="center" justifyContent="center">
                            <Switch
                              size="small"
                              checked={enabled}
                              disabled={rowEditDisabled}
                              onChange={(_, v) => void handleToggle(flag, app, v)}
                            />
                            {savingFlagIds.has(flag.id) && <CircularProgress size={14} />}
                          </Stack>
                          {roles.length > 0 && (
                            <Chip
                              size="small"
                              variant="outlined"
                              clickable
                              onClick={() => openRoleDialog(flag, app)}
                              label={(() => {
                                const o = overrideByKey.get(cellKey(flag.id, app.id));
                                const rids = o?.roleIds ?? [];
                                return rids.length === 0 ? t("features.roleTargeting.allUsers") : t("features.roleTargeting.roleCount", { count: rids.length });
                              })()}
                              sx={{
                                height: 18,
                                fontSize: 10,
                                fontFamily: "var(--font-mono)",
                                color: "text.secondary",
                              }}
                            />
                          )}
                        </Stack>
                      </TableCell>

                      <TableCell align="right">
                        <Stack direction="row" spacing={0.5} justifyContent="flex-end" alignItems="center">
                          {/* App status indicator */}
                          {(() => {
                            const enabledCount = countEnabledApps(flag);
                            const totalApps = apps.length;
                            const allEnabled = enabledCount === totalApps;
                            const noneEnabled = enabledCount === 0;
                            return (
                              <Tooltip title={t("features.appStatusTooltip", { count: enabledCount, total: totalApps })}>
                                <Chip
                                  size="small"
                                  variant="outlined"
                                  icon={allEnabled ? <CircleCheck size={14} strokeWidth={1.75} /> : noneEnabled ? <Ban size={14} strokeWidth={1.75} /> : undefined}
                                  label={`${enabledCount}/${totalApps}`}
                                  sx={{
                                    fontFamily: "var(--font-mono)",
                                    fontSize: 11,
                                    fontWeight: 600,
                                    height: 22,
                                    borderColor: allEnabled
                                      ? "success.main"
                                      : noneEnabled
                                      ? "error.main"
                                      : "warning.main",
                                    color: allEnabled
                                      ? "success.main"
                                      : noneEnabled
                                      ? "error.main"
                                      : "warning.main",
                                    "& .MuiChip-icon": {
                                      fontSize: 12,
                                      color: "inherit",
                                    },
                                  }}
                                />
                              </Tooltip>
                            );
                          })()}

                          <Divider orientation="vertical" flexItem sx={{ mx: 0.5 }} />

                          {/* Kill switch */}
                          <Tooltip title={t("features.killSwitchTooltip")}>
                            <span>
                              <IconButton
                                size="small"
                                disabled={saving || loading || archived}
                                onClick={() => {
                                  setSelected(flag);
                                  setKillSwitchOpen(true);
                                }}
                                sx={{
                                  color: "error.main",
                                  "&:hover": { bgcolor: alpha(appTypeColors.prod, 0.08) },
                                }}
                              >
                                <Ban size={14} strokeWidth={1.75} />
                              </IconButton>
                            </span>
                          </Tooltip>

                          {/* Enable all */}
                          <Tooltip title={t("features.enableAllTooltip")}>
                            <span>
                              <IconButton
                                size="small"
                                disabled={saving || loading || archived}
                                onClick={() => {
                                  setSelected(flag);
                                  setEnableAllOpen(true);
                                }}
                                sx={{
                                  color: "success.main",
                                  "&:hover": { bgcolor: alpha(appTypeColors.dev, 0.08) },
                                }}
                              >
                                <CircleCheck size={14} strokeWidth={1.75} />
                              </IconButton>
                            </span>
                          </Tooltip>

                          <Tooltip title={t("features.editTooltip")}>
                            <span>
                              <IconButton
                                size="small"
                                disabled={saving || loading}
                                onClick={() => {
                                  setSelected(flag);
                                  setEditDesc(flag.description || "");
                                  setEditDefaultEnabled(flag.defaultEnabled);
                                  setEditStatus(flag.status === "archived" ? "archived" : "active");
                                  setEditScope(flagScope(flag));
                                  setEditOpen(true);
                                }}
                              >
                                <SquarePen size={14} strokeWidth={1.75} />
                              </IconButton>
                            </span>
                          </Tooltip>

                          <Tooltip title={t("features.deleteTooltip")}>
                            <span>
                              <IconButton
                                size="small"
                                disabled={saving || loading}
                                onClick={() => {
                                  setSelected(flag);
                                  setDeleteOpen(true);
                                }}
                              >
                                <Trash2 size={14} strokeWidth={1.75} />
                              </IconButton>
                            </span>
                          </Tooltip>
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

      {/* PROD confirm dialog */}
      <Dialog open={prodConfirmOpen} onClose={cancelProdSwitch} maxWidth="xs" fullWidth>
        <DialogTitle>{t("features.prodConfirm.title")}</DialogTitle>
        <DialogContent>
          <Stack spacing={1}>
            <Typography variant="body2" color="text.secondary"><Trans i18nKey="features.prodConfirm.description" values={{ app: appTypeLabel(pendingApp) || "Production" }} components={tc} /></Typography>
            <Alert severity="warning">{t("features.prodConfirm.warning")}</Alert>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={cancelProdSwitch}>{t("features.prodConfirm.cancel")}</Button>
          <Button variant="contained" color="warning" onClick={confirmProdSwitch}>
            {t("features.prodConfirm.confirm")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Create dialog */}
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>{t("features.dialog.createTitle")}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label={t("features.dialog.keyLabel")}
              value={createKey}
              onChange={(e) => setCreateKey(e.target.value)}
              error={!!createKey && !isValidKey(createKey.trim())}
              helperText={t("features.dialog.keyHelper")}
              autoFocus
              disabled={saving}
            />

            <TextField
              size="small"
              select
              label={t("features.dialog.scopeLabel")}
              value={createScope}
              onChange={(e) => setCreateScope(normalizeScope(e.target.value))}
              disabled={saving}
              helperText={scopeHelp(createScope, t)}
            >
              <MenuItem value="server">{t("features.scope.server")}</MenuItem>
              <MenuItem value="client">{t("features.scope.client")}</MenuItem>
            </TextField>

            <TextField
              label={t("features.dialog.descriptionLabel")}
              value={createDesc}
              onChange={(e) => setCreateDesc(e.target.value)}
              multiline
              minRows={2}
              disabled={saving}
            />
            <FormControlLabel
              control={
                <Switch
                  checked={createDefaultEnabled}
                  onChange={(_, v) => setCreateDefaultEnabled(v)}
                  disabled={saving}
                />
              }
              label={t("features.dialog.defaultEnabled")}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)} startIcon={<X size={14} strokeWidth={1.75} />} disabled={saving}>
            {t("features.dialog.cancel")}
          </Button>
          <Button
            variant="contained"
            onClick={() => void handleCreate()}
            disabled={saving}
            startIcon={saving ? <CircularProgress size={18} /> : <Plus size={14} strokeWidth={1.75} />}
          >
            {t("features.dialog.create")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit dialog */}
      <Dialog open={editOpen} onClose={() => setEditOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>{t("features.dialog.editTitle")}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label={t("features.dialog.keyLabel")} value={selected?.key || ""} disabled />

            <TextField
              size="small"
              select
              label={t("features.dialog.scopeLabel")}
              value={editScope}
              onChange={(e) => setEditScope(normalizeScope(e.target.value))}
              disabled={saving}
              helperText={scopeHelp(editScope, t)}
            >
              <MenuItem value="server">{t("features.scope.server")}</MenuItem>
              <MenuItem value="client">{t("features.scope.client")}</MenuItem>
            </TextField>

            <TextField
              label={t("features.dialog.descriptionLabel")}
              value={editDesc}
              onChange={(e) => setEditDesc(e.target.value)}
              multiline
              minRows={2}
              disabled={saving}
            />

            <FormControlLabel
              control={
                <Switch
                  checked={editDefaultEnabled}
                  onChange={(_, v) => setEditDefaultEnabled(v)}
                  disabled={saving}
                />
              }
              label={t("features.dialog.defaultEnabled")}
            />

            <Stack direction="row" spacing={1} alignItems="center">
              <Typography variant="body2" color="text.secondary">
                {t("features.dialog.status")}
              </Typography>
              <Chip
                size="small"
                label={editStatus === "archived" ? t("features.dialog.statusArchived") : t("features.dialog.statusActive")}
                variant="outlined"
                color={editStatus === "archived" ? "default" : "success"}
              />
              <Button
                size="small"
                onClick={() => setEditStatus(editStatus === "active" ? "archived" : "active")}
                disabled={saving}
              >
                {t("features.dialog.toggle")}
              </Button>
            </Stack>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditOpen(false)} startIcon={<X size={14} strokeWidth={1.75} />} disabled={saving}>
            {t("features.dialog.cancel")}
          </Button>
          <Button
            variant="contained"
            onClick={() => void handleEditSave()}
            disabled={saving}
            startIcon={saving ? <CircularProgress size={18} /> : <Save size={14} strokeWidth={1.75} />}
          >
            {t("features.dialog.save")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete dialog */}
      <Dialog open={deleteOpen} onClose={() => setDeleteOpen(false)} fullWidth maxWidth="xs">
        <DialogTitle>{t("features.dialog.deleteTitle")}</DialogTitle>
        <DialogContent>
          <Typography variant="body2"><Trans i18nKey="features.dialog.deleteConfirm" values={{ key: selected?.key }} components={tc} /></Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteOpen(false)} startIcon={<X size={14} strokeWidth={1.75} />} disabled={saving}>
            {t("features.dialog.cancel")}
          </Button>
          <Button
            color="warning"
            variant="contained"
            onClick={() => void handleDelete()}
            disabled={saving}
            startIcon={saving ? <CircularProgress size={18} /> : <Trash2 size={14} strokeWidth={1.75} />}
          >
            {t("features.dialog.delete")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Kill Switch dialog */}
      <Dialog open={killSwitchOpen} onClose={() => setKillSwitchOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle sx={{ bgcolor: alpha(appTypeColors.prod, 0.08), color: "error.main" }}>
          <Stack direction="row" spacing={1} alignItems="center">
            <Ban size={14} strokeWidth={1.75} />
            <span>{t("features.dialog.killSwitchTitle")}</span>
          </Stack>
        </DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 2 }}>
            <Alert severity="error" variant="filled">
              <Trans i18nKey="features.dialog.killSwitchWarning" values={{ count: apps.length }} components={tc} />
            </Alert>

            <Typography variant="body2"><Trans i18nKey="features.dialog.killSwitchDescription" values={{ key: selected?.key }} components={tc} /></Typography>

            <Box sx={{ bgcolor: alpha(appTypeColors.prod, 0.04), borderRadius: 2, p: 2 }}>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                <b>{t("features.dialog.affectedApps")}</b>
              </Typography>
              <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap>
                {apps.map((app) => (
                  <Chip
                    key={app.id}
                    size="small"
                    label={appTypeLabel(app)}
                    variant="outlined"
                    sx={{
                      borderColor: isProdApp(app) ? "error.main" : "divider",
                      color: isProdApp(app) ? "error.main" : "text.secondary",
                    }}
                  />
                ))}
              </Stack>
            </Box>

            <Typography variant="body2" color="text.secondary">
              {t("features.dialog.killSwitchHelp")}
            </Typography>
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setKillSwitchOpen(false)} disabled={saving}>
            {t("features.dialog.cancel")}
          </Button>
          <Button
            color="error"
            variant="contained"
            onClick={() => void handleKillSwitch()}
            disabled={saving}
            startIcon={saving ? <CircularProgress size={18} /> : <Ban size={14} strokeWidth={1.75} />}
          >
            {t("features.dialog.disableEverywhere")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Enable All dialog */}
      <Dialog open={enableAllOpen} onClose={() => setEnableAllOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle sx={{ bgcolor: alpha(appTypeColors.dev, 0.08), color: "success.main" }}>
          <Stack direction="row" spacing={1} alignItems="center">
            <CircleCheck size={14} strokeWidth={1.75} />
            <span>{t("features.dialog.enableAllTitle")}</span>
          </Stack>
        </DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 2 }}>
            <Alert severity="warning" variant="filled">
              <Trans i18nKey="features.dialog.enableAllWarning" values={{ count: apps.length }} components={tc} />
            </Alert>

            <Typography variant="body2"><Trans i18nKey="features.dialog.enableAllDescription" values={{ key: selected?.key }} components={tc} /></Typography>

            <Box sx={{ bgcolor: alpha(appTypeColors.dev, 0.04), borderRadius: 2, p: 2 }}>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                <b>{t("features.dialog.affectedApps")}</b>
              </Typography>
              <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap>
                {apps.map((app) => (
                  <Chip
                    key={app.id}
                    size="small"
                    label={appTypeLabel(app)}
                    variant="outlined"
                    sx={{
                      borderColor: isProdApp(app) ? "error.main" : "divider",
                      color: isProdApp(app) ? "error.main" : "text.secondary",
                    }}
                  />
                ))}
              </Stack>
            </Box>

            <Typography variant="body2" color="text.secondary">
              {t("features.dialog.enableAllHelp")}
            </Typography>
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setEnableAllOpen(false)} disabled={saving}>
            {t("features.dialog.cancel")}
          </Button>
          <Button
            color="success"
            variant="contained"
            onClick={() => void handleEnableAll()}
            disabled={saving}
            startIcon={saving ? <CircularProgress size={18} /> : <CircleCheck size={14} strokeWidth={1.75} />}
          >
            {t("features.dialog.enableEverywhere")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Role targeting dialog */}
      <Dialog open={roleDialogOpen} onClose={() => setRoleDialogOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>{t("features.roleTargeting.title")}</DialogTitle>
        <DialogContent>
          <Stack spacing={1.5} sx={{ pt: 1 }}>
            <Typography variant="body2" color="text.secondary">
              {t("features.roleTargeting.description")}
            </Typography>
            {roles.map((role) => (
              <FormControlLabel
                key={role.id}
                control={
                  <Checkbox
                    size="small"
                    checked={roleDialogSelected.has(role.id)}
                    onChange={() => {
                      setRoleDialogSelected((prev) => {
                        const next = new Set(prev);
                        if (next.has(role.id)) next.delete(role.id); else next.add(role.id);
                        return next;
                      });
                    }}
                    disabled={roleDialogSaving}
                  />
                }
                label={<Typography variant="body2">{role.name} <Typography component="span" variant="caption" color="text.secondary">({role.slug})</Typography></Typography>}
              />
            ))}
            {roleDialogSelected.size > 0 && (
              <Button size="small" onClick={() => setRoleDialogSelected(new Set())} sx={{ textTransform: "none", fontSize: 12, alignSelf: "flex-start" }}>
                {t("features.roleTargeting.clearAll")}
              </Button>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRoleDialogOpen(false)} disabled={roleDialogSaving}>{t("features.dialog.cancel")}</Button>
          <Button variant="contained" disableElevation onClick={() => void saveRoleTargeting()} disabled={roleDialogSaving}>
            {roleDialogSaving ? <CircularProgress size={16} /> : t("features.dialog.save")}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
