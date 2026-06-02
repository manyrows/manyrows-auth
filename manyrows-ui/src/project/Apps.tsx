import * as React from "react";
import type { AppType, Project, Workspace } from "../core.ts";
import { appTypeLabel } from "../core.ts";
import axios from "axios";
import { extractApiError } from "../lib/apiError.ts";
import { useSnackbar } from "notistack";
import { useTranslation } from "react-i18next";
import { Link as RouterLink, useNavigate } from "react-router-dom";

import {
  Alert,
  Box,
  Button,
  CircularProgress,
  IconButton,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  FormHelperText,
  InputLabel,
  Select,
  MenuItem,
} from "@mui/material";
import PageHeader from "../components/PageHeader.tsx";
import EmptyState from "../components/EmptyState.tsx";
import StatusChip from "../components/StatusChip.tsx";
import { Layers, Plus, RefreshCw } from "lucide-react";

type App = {
  id: string;
  workspaceId: string;
  projectId: string;
  type: AppType | string;
  // projectName is the parent project's name, returned by the server
  // on every app row. The visible app label is composed from it and
  // the env type; the freeform apps.name column is gone.
  projectName: string;
  userPoolId?: string;
  userPoolName?: string;
  description?: string;
  enabled: boolean;
};

type TFunc = (key: string, opts?: Record<string, unknown>) => string;

function appDisplayName(a: App, t: TFunc): string {
  if (!a.projectName) return t("apps.unnamedApp");
  switch (a.type) {
    case "prod":
      return a.projectName;
    case "staging":
      return `${a.projectName} (Staging)`;
    case "dev":
      return `${a.projectName} (Dev)`;
    default:
      return a.projectName;
  }
}

interface Props {
  project: Project;
  workspace: Workspace;
}

export default function Apps({ project, workspace }: Props) {
  const { enqueueSnackbar } = useSnackbar();
  const { t } = useTranslation();
  const nav = useNavigate();

  const workspaceId = project.workspaceId;
  const projectId = project.id;

  const appsBasePath = React.useMemo(() => {
    if (!workspaceId) return "";
    return `/admin/workspace/${workspaceId}/projects/${projectId}/apps`;
  }, [workspaceId, projectId]);

  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [apps, setApps] = React.useState<App[]>([]);

  const load = React.useCallback(async () => {
    if (!workspaceId) {
      setError(t("apps.missingWorkspaceId"));
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await axios.get<{ apps: App[] }>(`${appsBasePath}/`);
      setApps(res.data?.apps ?? []);
    } catch (e) {
      setError(extractApiError(e, t("apps.failedToLoad")));
    } finally {
      setLoading(false);
    }
  }, [workspaceId, appsBasePath, t]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const openAppDetail = React.useCallback((app: App) => {
    nav(`/app/workspace/${workspace.id}/projects/${project.id}/apps/${app.id}`);
  }, [nav, workspace.id, project.id]);

  // ----- Create Dialog -----
  // Each app is an environment of the parent project (prod | staging |
  // dev). The display name comes from project + env type, so the form
  // has no freeform name input - just env, App URL, primary sign-in
  // method, and the optional shared-pool picker.
  type AuthMethod = "password" | "code" | "magicLink" | "none";
  const [createOpen, setCreateOpen] = React.useState(false);
  const [createType, setCreateType] = React.useState<AppType>("dev");
  const [createAppUrl, setCreateAppUrl] = React.useState("");
  const [createPrimaryAuth, setCreatePrimaryAuth] = React.useState<AuthMethod>("password");
  // User-pool picker. Default ("new") mints a fresh 1:1 pool on create;
  // "existing" lets the admin point this app at a pool another app
  // already uses, giving the two apps shared identity (SSO).
  const [createPoolMode, setCreatePoolMode] = React.useState<"new" | "existing">("new");
  const [createPoolId, setCreatePoolId] = React.useState<string>("");
  type WorkspacePool = { id: string; name: string; appCount: number; userCount: number };
  const [workspacePools, setWorkspacePools] = React.useState<WorkspacePool[]>([]);

  // Load the workspace's existing pools the first time the create
  // dialog opens. Cheap, and lets the "use existing" dropdown have
  // options ready without an extra round-trip while the user is mid-fill.
  React.useEffect(() => {
    if (!createOpen || !workspaceId) return;
    let alive = true;
    axios
      .get(`/admin/workspace/${workspaceId}/userPools`)
      .then((res) => {
        if (!alive) return;
        const list = (res.data?.pools ?? []) as WorkspacePool[];
        setWorkspacePools(list);
      })
      .catch(() => {
        if (alive) setWorkspacePools([]);
      });
    return () => { alive = false; };
  }, [createOpen, workspaceId]);

  const trimmedCreateUrl = createAppUrl.trim();
  const createUrlInvalid =
    trimmedCreateUrl !== "" && !/^https?:\/\/[^\s]+$/i.test(trimmedCreateUrl);
  // When sharing an existing pool, the user must actually pick one.
  const poolSelectionValid = createPoolMode === "new" || createPoolId !== "";

  // The server enforces unique (project_id, type); reflect it in the
  // dropdown so the admin sees which envs are still available instead
  // of hitting a 409 mid-create.
  const takenTypes = React.useMemo(() => {
    const s = new Set<string>();
    for (const a of apps) s.add(a.type);
    return s;
  }, [apps]);
  const allEnvs: AppType[] = React.useMemo(() => ["dev", "staging", "prod"], []);
  const firstAvailableEnv = React.useMemo(
    () => allEnvs.find((t) => !takenTypes.has(t)),
    [allEnvs, takenTypes],
  );
  const allEnvsTaken = !firstAvailableEnv;

  const canCreate =
    !allEnvsTaken &&
    !takenTypes.has(createType) &&
    trimmedCreateUrl !== "" &&
    !createUrlInvalid &&
    poolSelectionValid;

  const openCreate = () => {
    // Default the type to the first env that doesn't already exist
    // for this project, so the form opens in a valid state.
    setCreateType(firstAvailableEnv ?? "dev");
    setCreateAppUrl("");
    setCreatePrimaryAuth("password");
    setCreatePoolMode("new");
    setCreatePoolId("");
    setCreateOpen(true);
  };

  const closeCreate = () => setCreateOpen(false);

  const createApp = async () => {
    if (!workspaceId) return;
    if (!canCreate) return;

    setSaving(true);
    try {
      await axios.post<App>(`${appsBasePath}/`, {
        type: createType,
        enabled: true,
        appUrl: trimmedCreateUrl,
        primaryAuthMethod: createPrimaryAuth,
        userPoolId: createPoolMode === "existing" ? createPoolId : undefined,
      });
      // Refetch rather than optimistically inserting res.data: the create
      // response is the raw row, without the join-populated projectName /
      // userPoolName, so an optimistic insert renders "(unnamed app)" until
      // the next load.
      await load();
      enqueueSnackbar(t("apps.appCreated"), { variant: "success" });
      closeCreate();
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("apps.failedToCreate")), { variant: "error" });
    } finally {
      setSaving(false);
    }
  };

  // Open dialog is meaningful only while at least one env type is
  // free. Once all three exist for this project the only path forward
  // is opening an existing app, not creating a new one.
  const disableCreateUI = saving || !workspaceId || allEnvsTaken;

  return (
    <Box>
      <Stack spacing={3}>
        <PageHeader
          title={t("apps.title", { defaultValue: "Apps" })}
          mb={0}
          action={
            <>
              <Tooltip title={t("apps.refresh", { defaultValue: "Refresh" })}>
                <span>
                  <IconButton size="small" onClick={() => void load()} disabled={loading || saving}>
                    {loading ? <CircularProgress size={16} /> : <RefreshCw size={14} strokeWidth={2} />}
                  </IconButton>
                </span>
              </Tooltip>
              <Button
                size="small"
                disableElevation
                variant="contained"
                startIcon={<Plus size={14} strokeWidth={2} />}
                onClick={openCreate}
                disabled={disableCreateUI}
              >
                {t("apps.new", { defaultValue: "New app" })}
              </Button>
            </>
          }
        />

        {error && <Alert severity="error">{error}</Alert>}

        {/* App table */}
        {apps.length > 0 ? (
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>{t("apps.dialog.nameLabel")}</TableCell>
                  <TableCell>{t("apps.id", { defaultValue: "App ID" })}</TableCell>
                  <TableCell>{t("apps.dialog.type")}</TableCell>
                  <TableCell>{t("apps.col.userPool", { defaultValue: "User pool" })}</TableCell>
                  <TableCell>{t("apps.detail.status", { defaultValue: "Status" })}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {apps.map((app) => {
                  const typeLabel = appTypeLabel(app);
                  return (
                    <TableRow
                      key={app.id}
                      hover
                      onClick={() => openAppDetail(app)}
                      sx={{ cursor: "pointer" }}
                    >
                      <TableCell>
                        <Typography sx={{ fontSize: 13, fontWeight: 600 }}>
                          {appDisplayName(app, t)}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography
                          sx={{
                            fontSize: 11.5,
                            fontFamily: "var(--font-mono)",
                            color: "text.secondary",
                          }}
                        >
                          {app.id}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <StatusChip
                          label={typeLabel}
                          severity={
                            app.type === "prod" ? "error"
                              : app.type === "staging" ? "warning"
                              : app.type === "dev" ? "success"
                              : "neutral"
                          }
                        />
                      </TableCell>
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        {app.userPoolName ? (
                          <RouterLink
                            to={`/app/workspace/${workspace.id}/userPools`}
                            style={{ color: "inherit", textDecoration: "none" }}
                          >
                            <Typography
                              sx={{
                                fontSize: 12.5,
                                color: "primary.main",
                                "&:hover": { textDecoration: "underline" },
                              }}
                            >
                              {app.userPoolName}
                            </Typography>
                          </RouterLink>
                        ) : (
                          <Typography sx={{ fontSize: 12.5, color: "text.disabled" }}>-</Typography>
                        )}
                      </TableCell>
                      <TableCell>
                        <StatusChip
                          label={app.enabled ? t("apps.enabled", { defaultValue: "Enabled" }) : t("apps.disabled", { defaultValue: "Disabled" })}
                          severity={app.enabled ? "success" : "neutral"}
                        />
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        ) : !loading ? (
          <EmptyState
            icon={<Layers size={18} strokeWidth={1.75} />}
            title={t("apps.none", { defaultValue: "No apps yet." })}
            description={t("apps.noneDesc", { defaultValue: "An app is a sign-in surface - usually one per environment (prod, staging, dev)." })}
            action={
              <Button
                size="small"
                variant="contained"
                startIcon={<Plus size={14} strokeWidth={2} />}
                onClick={openCreate}
                disabled={disableCreateUI}
                disableElevation
              >
                {t("apps.createFirst", { defaultValue: "Create first app" })}
              </Button>
            }
          />
        ) : null}
      </Stack>

      {/* Create Dialog */}
      <Dialog open={createOpen} onClose={closeCreate} fullWidth maxWidth="sm">
        <DialogTitle>{t("apps.dialog.newTitle", { defaultValue: "New app" })}</DialogTitle>
        <Box
          component="form"
          onSubmit={(e) => {
            e.preventDefault();
            if (canCreate && !saving) void createApp();
          }}
        >
          <DialogContent sx={{ pt: 1 }}>
            <Stack spacing={2.25} sx={{ mt: 1 }}>
              <FormControl size="small" fullWidth>
                <InputLabel id="app-type-label">
                  {t("wizard.appEnv.label", { defaultValue: "Environment" })}
                </InputLabel>
                <Select
                  labelId="app-type-label"
                  label={t("wizard.appEnv.label", { defaultValue: "Environment" })}
                  value={createType}
                  onChange={(e) => setCreateType(e.target.value as AppType)}
                  disabled={saving}
                  autoFocus
                >
                  <MenuItem value="dev" disabled={takenTypes.has("dev")}>
                    {t("apps.type.development", { defaultValue: "Development" })}
                    {takenTypes.has("dev") && (
                      <Typography component="span" sx={{ ml: 1, color: "text.disabled", fontSize: 12 }}>
                        {t("apps.alreadyExists")}
                      </Typography>
                    )}
                  </MenuItem>
                  <MenuItem value="staging" disabled={takenTypes.has("staging")}>
                    {t("apps.type.staging", { defaultValue: "Staging" })}
                    {takenTypes.has("staging") && (
                      <Typography component="span" sx={{ ml: 1, color: "text.disabled", fontSize: 12 }}>
                        {t("apps.alreadyExists")}
                      </Typography>
                    )}
                  </MenuItem>
                  <MenuItem value="prod" disabled={takenTypes.has("prod")}>
                    {t("apps.type.production", { defaultValue: "Production" })}
                    {takenTypes.has("prod") && (
                      <Typography component="span" sx={{ ml: 1, color: "text.disabled", fontSize: 12 }}>
                        {t("apps.alreadyExists")}
                      </Typography>
                    )}
                  </MenuItem>
                </Select>
                <FormHelperText>
                  {t("wizard.appEnv.help", {
                    defaultValue:
                      "Each project has up to one app per environment (prod, staging, dev). The display name comes from the project + this environment.",
                  })}
                </FormHelperText>
              </FormControl>
              <TextField
                size="small"
                label={t("wizard.appUrl.label", { defaultValue: "App URL" })}
                placeholder="https://myapp.com"
                value={createAppUrl}
                onChange={(e) => setCreateAppUrl(e.target.value)}
                disabled={saving}
                error={createUrlInvalid}
                helperText={
                  createUrlInvalid
                    ? t("wizard.appUrl.invalid", {
                        defaultValue: "Must start with http:// or https://",
                      })
                    : t("wizard.appUrl.help", {
                        defaultValue:
                          "Where end-users access your app. Used for invite emails, password-reset links, and OAuth redirects.",
                      })
                }
              />
              <FormControl size="small" fullWidth>
                <InputLabel id="app-pam-label">
                  {t("wizard.primaryAuth.label", { defaultValue: "Primary sign-in method" })}
                </InputLabel>
                <Select
                  labelId="app-pam-label"
                  label={t("wizard.primaryAuth.label", { defaultValue: "Primary sign-in method" })}
                  value={createPrimaryAuth}
                  onChange={(e) => setCreatePrimaryAuth(e.target.value as AuthMethod)}
                  disabled={saving}
                >
                  <MenuItem value="password">{t("apps.authMethod.password")}</MenuItem>
                  <MenuItem value="code">{t("apps.authMethod.code")}</MenuItem>
                  <MenuItem value="magicLink">{t("apps.authMethod.magicLink")}</MenuItem>
                  <MenuItem value="none">{t("apps.authMethod.none")}</MenuItem>
                </Select>
                <FormHelperText>
                  {t("wizard.primaryAuth.help", {
                    defaultValue:
                      "How end-users sign in by default. You can change this and add OAuth providers (Google, Apple, etc.) later.",
                  })}
                </FormHelperText>
              </FormControl>

              <FormControl size="small" fullWidth>
                <InputLabel id="app-pool-mode-label">
                  {t("wizard.userPool.label", { defaultValue: "User pool" })}
                </InputLabel>
                <Select
                  labelId="app-pool-mode-label"
                  label={t("wizard.userPool.label", { defaultValue: "User pool" })}
                  value={createPoolMode}
                  onChange={(e) => {
                    const v = e.target.value as "new" | "existing";
                    setCreatePoolMode(v);
                    if (v === "new") setCreatePoolId("");
                  }}
                  disabled={saving}
                >
                  <MenuItem value="new">
                    {t("wizard.userPool.optionNew", { defaultValue: "New pool (isolated users)" })}
                  </MenuItem>
                  <MenuItem value="existing" disabled={workspacePools.length === 0}>
                    {t("wizard.userPool.optionExisting", { defaultValue: "Share users with an existing pool" })}
                  </MenuItem>
                </Select>
                <FormHelperText>
                  {createPoolMode === "new"
                    ? t("wizard.userPool.helpNew", {
                        defaultValue: "Default. Users created in this app do not exist in any other app.",
                      })
                    : t("wizard.userPool.helpExisting", {
                        defaultValue: "Apps sharing a pool share users (SSO). Pick a pool another app already uses.",
                      })}
                </FormHelperText>
              </FormControl>

              {createPoolMode === "existing" && (
                <FormControl size="small" fullWidth>
                  <InputLabel id="app-pool-pick-label">
                    {t("wizard.userPool.pickLabel", { defaultValue: "Pool" })}
                  </InputLabel>
                  <Select
                    labelId="app-pool-pick-label"
                    label={t("wizard.userPool.pickLabel", { defaultValue: "Pool" })}
                    value={createPoolId}
                    onChange={(e) => setCreatePoolId(String(e.target.value))}
                    disabled={saving}
                  >
                    {workspacePools.map((p) => (
                      <MenuItem key={p.id} value={p.id}>
                        {p.name}
                        <Typography component="span" sx={{ ml: 1, color: "text.secondary", fontSize: 12 }}>
                          {t("apps.poolCounts", { apps: p.appCount, users: p.userCount })}
                        </Typography>
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              )}
            </Stack>
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button onClick={closeCreate} disabled={saving}>
              {t("apps.dialog.cancel")}
            </Button>
            <Button type="submit" variant="contained" disableElevation disabled={!canCreate || saving}>
              {t("apps.dialog.create")}
            </Button>
          </DialogActions>
        </Box>
      </Dialog>
    </Box>
  );
}
