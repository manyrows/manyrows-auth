import * as React from "react";
import axios from "axios";
import { appDisplayName, type Project, type Workspace } from "../core.ts";
import { extractApiError } from "../lib/apiError.ts";
import { useSnackbar } from "notistack";
import { useTranslation } from "react-i18next";
import { useNavigate, Link as RouterLink } from "react-router-dom";
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
  Stack,
  Switch,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { Copy, Save, SquarePen, Trash2, TriangleAlert, Lock, ChevronRight } from "lucide-react";
import Loader from "../Loader.tsx";
import PageHeader from "../components/PageHeader.tsx";

type App = {
  id: string;
  workspaceId: string;
  projectId: string;
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

const errText = extractApiError;

interface Props {
  project: Project;
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
  const [saving, setSaving] = React.useState(false);

  const trimmedEditUrl = editAppUrl.trim();
  // App URL is required (matches the create-time validation): invite
  // emails / password resets / OAuth redirects all reference it, and
  // there's no sensible fallback. Soft URL-shape check before
  // round-tripping to the server.
  const editUrlMissing = trimmedEditUrl.length === 0;
  const editUrlInvalid =
    !editUrlMissing && !/^https?:\/\/[^\s]+$/i.test(trimmedEditUrl);

  const appsBaseURL = `/admin/workspace/${project.workspaceId}/projects/${project.id}/apps`;
  const backURL = `/app/workspace/${workspace.id}/projects/${project.id}/home`;
  // UI route base for this environment — used by the next-steps shortcuts.
  const appBasePath = `/app/workspace/${workspace.id}/projects/${project.id}/apps/${appId}`;

  const [type, setType] = React.useState("");

  function populateForm(a: App) {
    setEditDescription(a.description || "");
    setEditEnabled(!!a.enabled);
    setEditAppUrl(a.appUrl || "");
  }

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
      const patchBody = {
        description: editDescription.trim() || null,
        enabled: editEnabled,
        appUrl: trimmedEditUrl,
      };
      const patchRes = await axios.patch<App>(`${appsBaseURL}/${app.id}/`, patchBody);

      setApp(patchRes.data);
      populateForm(patchRes.data);
      setEditing(false);
      // App display name is computed from project + env type; no
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
              title={t("app.nav.summary", { defaultValue: "App Summary" })}
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
                <DetailRow
                  label={t("apps.detail.appId", { defaultValue: "App ID" })}
                  value={
                    <Stack direction="row" spacing={0.5} alignItems="center">
                      <Typography sx={{ fontFamily: "var(--font-mono)", fontSize: 12.5, color: "text.secondary", wordBreak: "break-all" }}>
                        {app.id}
                      </Typography>
                      <Tooltip title={t("apps.copyAppId", { defaultValue: "Copy App ID" })}>
                        <IconButton
                          size="small"
                          onClick={() => {
                            navigator.clipboard.writeText(app.id).then(
                              () => enqueueSnackbar(t("apps.idCopied", { defaultValue: "App ID copied" }), { variant: "success" }),
                              () => enqueueSnackbar(t("apps.copyFailed", { defaultValue: "Copy failed" }), { variant: "error" }),
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

            {/* Next steps — point newcomers at the main thing they'll
                do in an environment: turn on sign-in. */}
            <Box>
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
                  mb: 1.5,
                }}
              >
                <Box component="span" sx={{ width: 4, height: 4, borderRadius: "50%", bgcolor: "primary.main" }} />
                {t("apps.detail.nextStepsTitle", { defaultValue: "Next steps" })}
              </Typography>
              <Box
                sx={{
                  display: "grid",
                  gap: 1.5,
                  gridTemplateColumns: { xs: "1fr", sm: "repeat(2, 1fr)" },
                }}
              >
                <HintCard
                  to={`${appBasePath}/auth-methods`}
                  icon={<Lock size={18} strokeWidth={1.75} />}
                  title={t("apps.detail.setupAuthTitle", { defaultValue: "Manage auth, sessions and users" })}
                  desc={t("apps.detail.setupAuthDesc", {
                    defaultValue: "Add sign-in and user accounts — only if your app needs them.",
                  })}
                  badge={t("apps.detail.optional", { defaultValue: "Optional" })}
                />
              </Box>
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

    </Box>
  );
}

// Clickable shortcut card — mirrors the schema-overview card language
// (rounded icon tile, trailing chevron, hover lift).
function HintCard({
  to,
  icon,
  title,
  desc,
  badge,
}: {
  to: string;
  icon: React.ReactNode;
  title: string;
  desc: string;
  badge?: string;
}) {
  return (
    <Box
      component={RouterLink}
      to={to}
      sx={{
        display: "block",
        textDecoration: "none",
        color: "inherit",
        border: "1px solid",
        borderColor: "divider",
        borderRadius: 2,
        p: 2,
        bgcolor: "background.paper",
        transition: "box-shadow 160ms ease, border-color 160ms ease, transform 160ms ease",
        "&:hover": {
          borderColor: "text.disabled",
          boxShadow: "0 1px 3px rgba(13,10,8,0.06), 0 10px 28px rgba(13,10,8,0.08)",
          transform: "translateY(-1px)",
        },
      }}
    >
      <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
        <Box
          sx={{
            width: 36,
            height: 36,
            borderRadius: "10px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            bgcolor: "action.hover",
            color: "text.secondary",
          }}
        >
          {icon}
        </Box>
        <ChevronRight size={16} strokeWidth={1.75} style={{ opacity: 0.4 }} />
      </Box>
      <Stack direction="row" spacing={0.75} alignItems="center">
        <Typography sx={{ fontSize: 14.5, fontWeight: 600 }}>{title}</Typography>
        {badge && (
          <Chip
            size="small"
            label={badge}
            variant="outlined"
            sx={{ height: 18, fontSize: 9.5, "& .MuiChip-label": { px: 0.75 } }}
          />
        )}
      </Stack>
      <Typography sx={{ fontSize: 13, color: "text.secondary", mt: 0.5 }}>{desc}</Typography>
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
