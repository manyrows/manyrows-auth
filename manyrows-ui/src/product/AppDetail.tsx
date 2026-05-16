import * as React from "react";
import axios from "axios";
import { appDisplayName, type Product, type Workspace } from "../core.ts";
import { extractApiError } from "../lib/apiError.ts";
import { useSnackbar } from "notistack";
import { useTranslation } from "react-i18next";
import { Link as RouterLink, useNavigate } from "react-router-dom";
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
  DialogContentText,
  FormControl,
  FormControlLabel,
  IconButton,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  Switch,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { Copy, Save, SquarePen, Trash2, TriangleAlert } from "lucide-react";
import Loader from "../Loader.tsx";
import PageHeader from "../components/PageHeader.tsx";

type App = {
  id: string;
  workspaceId: string;
  productId: string;
  type: string;
  name: string;
  description?: string;
  createdAt: string;
  updatedAt: string;
  enabled: boolean;
  allowRegistration: boolean;
  defaultRoleId?: string;
  allowedEmailDomains?: string[];
  primaryAuthMethod: "password" | "code" | "none";
  authMethodGoogle: boolean;
  googleOAuthClientId?: string;
  googleOAuthRedirectUri?: string;
  hasGoogleClientSecret?: boolean;
  require2fa: boolean;
  appUrl?: string;
  authDomain?: string;
  userPoolId?: string;
  sessionTtlMinutes?: number | null;
  idleTimeoutMinutes?: number | null;
  rememberMeTtlMinutes?: number | null;
  accessTokenTtlMinutes?: number | null;
  maxSessionsPerUser?: number | null;
};

type WorkspacePool = {
  id: string;
  workspaceId: string;
  name: string;
  appCount: number;
  userCount: number;
};

const errText = extractApiError;

interface Props {
  project: Product;
  workspace: Workspace;
  appId: string;
  onAppUpdated?: (app: { name: string; enabled: boolean; type?: string }) => void;
}

export default function AppDetail({ project, workspace, appId, onAppUpdated }: Props) {
  const { enqueueSnackbar } = useSnackbar();
  const { t } = useTranslation();
  const nav = useNavigate();
  const [loading, setLoading] = React.useState(true);
  const [app, setApp] = React.useState<App | null>(null);

  // Edit state
  const [editing, setEditing] = React.useState(false);
  const [editDescription, setEditDescription] = React.useState("");
  const [editEnabled, setEditEnabled] = React.useState(false);
  const [editAppUrl, setEditAppUrl] = React.useState("");
  const [editAuthDomain, setEditAuthDomain] = React.useState("");
  const [saving, setSaving] = React.useState(false);

  const trimmedEditUrl = editAppUrl.trim();
  // App URL is required (matches the create-time validation): invite
  // emails / password resets / OAuth redirects all reference it, and
  // there's no sensible fallback. Soft URL-shape check before
  // round-tripping to the server.
  const editUrlMissing = trimmedEditUrl.length === 0;
  const editUrlInvalid =
    !editUrlMissing && !/^https?:\/\/[^\s]+$/i.test(trimmedEditUrl);

  const appsBaseURL = `/admin/workspace/${project.workspaceId}/products/${project.id}/apps`;
  const backURL = `/app/workspace/${workspace.id}/products/${project.id}/home`;

  const [type, setType] = React.useState("");

  // Pool repoint state. Pools are workspace-scoped, so we load the
  // whole workspace list once when the user opens the picker, not on
  // every render of AppDetail.
  const [pools, setPools] = React.useState<WorkspacePool[]>([]);
  const [repointOpen, setRepointOpen] = React.useState(false);
  const [repointTargetId, setRepointTargetId] = React.useState<string>("");
  const [repointSaving, setRepointSaving] = React.useState(false);
  const [repointErr, setRepointErr] = React.useState<string | null>(null);
  // Resolves the current pool's display name from the pool list. Loaded
  // lazily; falls back to the bare ID when the list hasn't arrived yet.
  const currentPool = React.useMemo(
    () => (app?.userPoolId ? pools.find((p) => p.id === app.userPoolId) ?? null : null),
    [app?.userPoolId, pools],
  );

  function populateForm(a: App) {
    setEditDescription(a.description || "");
    setEditEnabled(!!a.enabled);
    setEditAppUrl(a.appUrl || "");
    setEditAuthDomain(a.authDomain || "");
  }

  // Load workspace pools so the AppDetail can resolve the current
  // pool's display name and so the repoint dialog has options ready.
  React.useEffect(() => {
    let alive = true;
    axios
      .get<{ pools: WorkspacePool[] }>(`/admin/workspace/${workspace.id}/userPools`)
      .then((res) => {
        if (!alive) return;
        setPools(res.data?.pools ?? []);
      })
      .catch(() => {
        if (alive) setPools([]);
      });
    return () => { alive = false; };
  }, [workspace.id]);

  const openRepoint = () => {
    setRepointTargetId("");
    setRepointErr(null);
    setRepointOpen(true);
  };
  const closeRepoint = () => {
    if (repointSaving) return;
    setRepointOpen(false);
  };

  const submitRepoint = async () => {
    if (!app || !repointTargetId || repointTargetId === app.userPoolId) {
      closeRepoint();
      return;
    }
    setRepointSaving(true);
    setRepointErr(null);
    try {
      await axios.post(`${appsBaseURL}/${appId}/userPool`, { userPoolId: repointTargetId });
      const next = await axios.get<App>(`${appsBaseURL}/${appId}/`);
      setApp(next.data);
      enqueueSnackbar(t("apps.repointSuccess", { defaultValue: "App repointed at new pool." }), { variant: "success" });
      setRepointOpen(false);
    } catch (e) {
      setRepointErr(extractApiError(e, t("apps.repointFailed", { defaultValue: "Could not repoint app." })));
    } finally {
      setRepointSaving(false);
    }
  };

  React.useEffect(() => {
    let alive = true;
    setLoading(true);

    axios.get<App>(`${appsBaseURL}/${appId}/`)
      .then((appRes) => {
        if (!alive) return;
        const a = appRes.data;
        setApp(a);
        setType(a.type || "");
        populateForm(a);
        setLoading(false);
      })
      .catch((e) => {
        if (!alive) return;
        setLoading(false);
        enqueueSnackbar(errText(e), { variant: "error" });
        nav(backURL);
      });

    return () => { alive = false; };
  }, [appId, appsBaseURL]);

  async function save() {
    if (!app) return;

    if (editUrlMissing || editUrlInvalid) {
      enqueueSnackbar(
        t("apps.detail.appUrlRequired", {
          defaultValue: "App URL is required and must start with http:// or https://",
        }),
        { variant: "error" },
      );
      return;
    }

    setSaving(true);
    try {
      // Strip an accidental scheme/path the operator may have pasted in;
      // the server stores bare hostname and prepends https:// itself.
      const trimmedAuthDomain = editAuthDomain
        .trim()
        .replace(/^https?:\/\//, "")
        .replace(/\/+$/, "");
      const patchBody = {
        description: editDescription.trim() || null,
        enabled: editEnabled,
        appUrl: trimmedEditUrl,
        authDomain: trimmedAuthDomain,
      };
      const patchRes = await axios.patch<App>(`${appsBaseURL}/${app.id}/`, patchBody);

      setApp(patchRes.data);
      populateForm(patchRes.data);
      setEditing(false);
      // App display name is computed from product + env type; no
      // freeform name to surface back to the parent. Pass the parent
      // a stable shape so it can refetch / re-render if it wants.
      onAppUpdated?.({ name: appDisplayName(patchRes.data), enabled: patchRes.data.enabled ?? true, type: patchRes.data.type });
      enqueueSnackbar(t("apps.appUpdated"), { variant: "success" });
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setSaving(false);
    }
  }

  function openEdit() {
    if (!app) return;
    populateForm(app);
    setEditing(true);
  }

  function cancelEdit() {
    if (!app) return;
    populateForm(app);
    setEditing(false);
  }

  // ----- Delete -----
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [deleteConfirm, setDeleteConfirm] = React.useState("");
  const [deleting, setDeleting] = React.useState(false);

  async function confirmDelete() {
    if (!app) return;
    setDeleting(true);
    try {
      await axios.delete(`${appsBaseURL}/${app.id}`);
      enqueueSnackbar(t("apps.dialog.deleted", { defaultValue: "App deleted" }), { variant: "success" });
      nav(backURL);
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setDeleting(false);
    }
  }

  if (loading) return <Loader />;
  if (!app) return null;

  return (
    <Box>
      <Stack spacing={2.5} sx={{ maxWidth: 720 }}>
        {!editing ? (
          /* ---- Read-only view ---- */
          <Stack spacing={2.5}>
            <PageHeader
              title={t("app.nav.settings", { defaultValue: "App Settings" })}
              mb={0}
              action={
                <Stack direction="row" spacing={1} sx={{ flexShrink: 0 }}>
                <Button
                  size="small"
                  startIcon={<SquarePen size={14} strokeWidth={1.75} />}
                  onClick={openEdit}
                  variant="outlined"
                >
                  {t("apps.edit", { defaultValue: "Edit" })}
                </Button>
                <Button
                  size="small"
                  color="error"
                  startIcon={<Trash2 size={14} strokeWidth={1.75} />}
                  onClick={() => { setDeleteConfirm(""); setDeleteOpen(true); }}
                  variant="outlined"
                >
                  {t("apps.dialog.delete", { defaultValue: "Delete" })}
                </Button>
                </Stack>
              }
            />

            <Box
              sx={{
                border: "1px solid",
                borderColor: "divider",
                borderRadius: 2,
                bgcolor: "background.paper",
                px: { xs: 2, sm: 2.5 },
                py: 1,
              }}
            >
              <Stack spacing={0}>
                <DetailRow label={t("apps.dialog.nameLabel")} value={appDisplayName(app)} />
                <DetailRow
                  label={t("apps.dialog.description", { defaultValue: "Description" })}
                  value={app.description || "-"}
                />
                <DetailRow label={t("apps.dialog.type")} value={
                  <Chip
                    size="small"
                    label={
                      type === "prod" ? t("apps.type.production")
                        : type === "staging" ? t("apps.type.staging")
                        : type === "dev" ? t("apps.type.development")
                        : type || "-"
                    }
                    variant="outlined"
                    sx={{
                      height: 20,
                      fontSize: 10.5,
                      ...(type === "prod" && {
                        borderColor: "error.main",
                        color: "error.main",
                      }),
                    }}
                  />
                } />
                <DetailRow
                  label={t("apps.detail.status", { defaultValue: "Status" })}
                  value={
                    <Chip
                      size="small"
                      label={app.enabled ? t("apps.enabled") : t("apps.disabled")}
                      variant="outlined"
                      sx={{
                        height: 20,
                        fontSize: 10.5,
                        ...(app.enabled && {
                          borderColor: "success.main",
                          color: "success.main",
                        }),
                      }}
                    />
                  }
                />
                <DetailRow label={t("apps.detail.appUrl", { defaultValue: "App URL" })} value={app.appUrl || "-"} />
                <DetailRow label={t("apps.detail.authDomain", { defaultValue: "Auth domain" })} value={app.authDomain || "-"} />
                <DetailRow
                  label={t("apps.detail.userPool", { defaultValue: "User pool" })}
                  value={
                    <Stack direction="row" spacing={1} alignItems="center">
                      {app.userPoolId ? (
                        <RouterLink
                          to={`/app/workspace/${workspace.id}/userPools/${app.userPoolId}`}
                          style={{ textDecoration: "none" }}
                        >
                          <Typography
                            sx={{
                              fontSize: 13,
                              color: "primary.main",
                              "&:hover": { textDecoration: "underline" },
                            }}
                          >
                            {currentPool?.name ?? app.userPoolId}
                          </Typography>
                        </RouterLink>
                      ) : (
                        <Typography sx={{ fontSize: 13 }}>-</Typography>
                      )}
                      {currentPool && (
                        <Typography sx={{ fontSize: 11.5, color: "text.secondary" }}>
                          ({currentPool.appCount} {currentPool.appCount === 1 ? "app" : "apps"})
                        </Typography>
                      )}
                      <Button size="small" variant="text" onClick={openRepoint} sx={{ ml: 0.5 }}>
                        {t("apps.detail.changePool", { defaultValue: "Change" })}
                      </Button>
                    </Stack>
                  }
                />
                <DetailRow
                  label="App ID"
                  value={
                    <Stack direction="row" spacing={0.5} alignItems="center">
                      <Typography sx={{ fontFamily: "var(--font-mono)", fontSize: 12.5, color: "text.secondary", wordBreak: "break-all" }}>
                        {app.id}
                      </Typography>
                      <Tooltip title="Copy App ID">
                        <IconButton
                          size="small"
                          onClick={() => {
                            navigator.clipboard.writeText(app.id).then(
                              () => enqueueSnackbar("App ID copied", { variant: "success" }),
                              () => enqueueSnackbar("Copy failed", { variant: "error" }),
                            );
                          }}
                          sx={{ color: "text.secondary" }}
                        >
                          <Copy size={12} strokeWidth={1.75} />
                        </IconButton>
                      </Tooltip>
                    </Stack>
                  }
                />
              </Stack>
            </Box>
          </Stack>
        ) : (
          /* ---- Edit form ---- */
          <Stack spacing={2.5}>
            <Typography
              sx={{
                display: "inline-flex",
                alignItems: "center",
                gap: 1,
                fontFamily: "var(--font-mono)",
                textTransform: "uppercase",
                letterSpacing: "0.16em",
                fontSize: 10.5,
                fontWeight: 500,
                color: "text.disabled",
              }}
            >
              <Box component="span" sx={{ width: 4, height: 4, borderRadius: "50%", bgcolor: "primary.main" }} />
              {t("apps.dialog.editTitle")}
            </Typography>

              <TextField
                label={t("apps.dialog.description", { defaultValue: "Description" })}
                size="small"
                value={editDescription}
                onChange={(e) => setEditDescription(e.target.value)}
                fullWidth
                disabled={saving}
                multiline
                minRows={2}
                maxRows={6}
              />

              <TextField
                label={t("apps.detail.appUrl", { defaultValue: "App URL" })}
                size="small"
                value={editAppUrl}
                onChange={(e) => setEditAppUrl(e.target.value)}
                fullWidth
                disabled={saving}
                placeholder="https://myapp.com"
                error={editUrlMissing || editUrlInvalid}
                helperText={
                  editUrlMissing
                    ? t("apps.detail.appUrlMissing", {
                        defaultValue: "App URL is required",
                      })
                    : editUrlInvalid
                      ? t("wizard.appUrl.invalid", {
                          defaultValue: "Must start with http:// or https://",
                        })
                      : t("apps.detail.appUrlDesc", {
                          defaultValue: "Used in emails such as password reset and invite links",
                        })
                }
              />

              <TextField
                label={t("apps.detail.authDomain", { defaultValue: "Auth domain (optional)" })}
                size="small"
                value={editAuthDomain}
                onChange={(e) => setEditAuthDomain(e.target.value)}
                fullWidth
                disabled={saving}
                placeholder="auth.myapp.com"
                helperText={t("apps.detail.authDomainDesc", {
                  defaultValue: "Custom hostname for OAuth callbacks and AppKit's API base. Bare hostname only (no scheme, no path). CNAME this to the ManyRows install. Leave blank to use the install's default base URL. If you set this, also set the Cookie domain to the registrable parent (e.g. auth.drumkingdom.com → drumkingdom.com) under Security → Session transport → enable cookies → Cookie domain, or session cookies stay scoped to the auth subdomain.",
                })}
              />

              <FormControlLabel
                control={
                  <Switch
                    checked={editEnabled}
                    onChange={(e) => setEditEnabled(e.target.checked)}
                    disabled={saving}
                  />
                }
                label={
                  <Stack>
                    <Typography variant="body2" sx={{ fontWeight: 500 }}>
                      {editEnabled ? t("apps.enabled") : t("apps.disabled")}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {t("apps.dialog.enabledDesc")}
                    </Typography>
                  </Stack>
                }
                sx={{ alignItems: "flex-start", ml: 0 }}
              />

              <Stack direction="row" spacing={1.5} justifyContent="flex-end">
                <Button
                  onClick={cancelEdit}
                  disabled={saving}
                  sx={{ borderRadius: 2, textTransform: "none" }}
                >
                  {t("apps.dialog.cancel")}
                </Button>
                <Button
                  variant="contained"
                  disableElevation
                  onClick={save}
                  disabled={editUrlMissing || editUrlInvalid || saving}
                  startIcon={saving ? <CircularProgress size={16} /> : <Save size={14} strokeWidth={1.75} />}
                  sx={{ borderRadius: 2, textTransform: "none" }}
                >
                  {saving ? t("apps.dialog.saving") : t("apps.dialog.save")}
                </Button>
              </Stack>
          </Stack>
        )}
      </Stack>

      {/* Delete confirm dialog */}
      <Dialog open={deleteOpen} onClose={() => setDeleteOpen(false)} fullWidth maxWidth="xs">
        <DialogTitle>{t("apps.dialog.deleteTitle", { defaultValue: "Delete App" })}</DialogTitle>
        <Box
          component="form"
          onSubmit={(e) => {
            e.preventDefault();
            if (deleteConfirm.trim() === appDisplayName(app)) void confirmDelete();
          }}
        >
          <DialogContent sx={{ pt: 1 }}>
            <Stack spacing={1.5}>
              <Alert severity="warning" icon={<TriangleAlert size={16} strokeWidth={1.75} />}>
                {t("apps.dialog.deleteWarning", { defaultValue: "This will permanently delete this app. This action cannot be undone." })}
              </Alert>
              <Typography variant="body2" color="text.secondary">
                {t("apps.dialog.typeToConfirm", { name: appDisplayName(app), defaultValue: `Type "${appDisplayName(app)}" to confirm.` })}
              </Typography>
              <TextField
                size="small"
                autoFocus
                value={deleteConfirm}
                onChange={(e) => setDeleteConfirm(e.target.value)}
                placeholder={appDisplayName(app)}
                disabled={deleting}
              />
            </Stack>
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button onClick={() => setDeleteOpen(false)} disabled={deleting}>
              {t("apps.dialog.cancel")}
            </Button>
            <Button
              type="submit"
              variant="contained"
              color="error"
              disableElevation
              disabled={deleteConfirm.trim() !== appDisplayName(app) || deleting}
            >
              {deleting ? t("apps.dialog.deleting", { defaultValue: "Deleting..." }) : t("apps.dialog.delete", { defaultValue: "Delete" })}
            </Button>
          </DialogActions>
        </Box>
      </Dialog>

      {/*
        Repoint dialog. The server refuses when the app has any
        members (would orphan them in the old pool); we surface that
        with the conflict-error string returned by the API. Once a
        merge-on-repoint wizard lands this becomes the entry point.
      */}
      <Dialog open={repointOpen} onClose={closeRepoint} fullWidth maxWidth="xs">
        <DialogTitle>{t("apps.dialog.repointTitle", { defaultValue: "Change user pool" })}</DialogTitle>
        <DialogContent>
          <Stack spacing={2}>
            <DialogContentText>
              {t("apps.dialog.repointHelp", {
                defaultValue:
                  "Moves this app to a different identity pool. Only allowed while the app has zero members - otherwise members would be left in the old pool.",
              })}
            </DialogContentText>
            {repointErr && <Alert severity="error">{repointErr}</Alert>}
            <FormControl size="small" fullWidth>
              <InputLabel id="repoint-pool-label">
                {t("apps.dialog.repointPickLabel", { defaultValue: "Target pool" })}
              </InputLabel>
              <Select
                labelId="repoint-pool-label"
                label={t("apps.dialog.repointPickLabel", { defaultValue: "Target pool" })}
                value={repointTargetId}
                onChange={(e) => setRepointTargetId(String(e.target.value))}
                disabled={repointSaving}
              >
                {pools
                  .filter((p) => p.id !== app?.userPoolId)
                  .map((p) => (
                    <MenuItem key={p.id} value={p.id}>
                      {p.name}
                      <Typography component="span" sx={{ ml: 1, color: "text.secondary", fontSize: 12 }}>
                        ({p.appCount} {p.appCount === 1 ? "app" : "apps"}, {p.userCount} {p.userCount === 1 ? "user" : "users"})
                      </Typography>
                    </MenuItem>
                  ))}
              </Select>
            </FormControl>
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={closeRepoint} disabled={repointSaving}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button
            variant="contained"
            disableElevation
            onClick={() => void submitRepoint()}
            disabled={
              repointSaving ||
              !repointTargetId ||
              repointTargetId === app?.userPoolId
            }
          >
            {repointSaving
              ? t("apps.dialog.repointing", { defaultValue: "Moving..." })
              : t("apps.dialog.repoint", { defaultValue: "Move app" })}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

function DetailRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <Stack
      direction="row"
      spacing={2}
      alignItems="baseline"
      sx={{
        py: 0.75,
        borderBottom: "1px solid",
        borderColor: "divider",
        "&:last-of-type": { borderBottom: 0 },
      }}
    >
      <Typography
        sx={{
          fontSize: 11,
          color: "text.disabled",
          fontWeight: 600,
          letterSpacing: "0.08em",
          textTransform: "uppercase",
          minWidth: 160,
          flexShrink: 0,
        }}
      >
        {label}
      </Typography>
      {typeof value === "string" ? (
        <Typography sx={{ fontSize: 13.5 }}>{value || "-"}</Typography>
      ) : (
        value
      )}
    </Stack>
  );
}
