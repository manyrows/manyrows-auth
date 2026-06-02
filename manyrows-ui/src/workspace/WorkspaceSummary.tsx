import * as React from "react";
import axios from "axios";
import { extractApiError } from "../lib/apiError.ts";
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  Paper,
  Snackbar,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import PageHeader from "../components/PageHeader.tsx";
import Eyebrow from "../components/Eyebrow.tsx";
import StatusChip from "../components/StatusChip.tsx";
import { BadgeCheck, Plus, Rocket, Code, Folder } from "lucide-react";
import { useTranslation } from "react-i18next";

import type { AppType, Project, Workspace } from "../core.ts";
import { appDisplayName, appTypeLabel } from "../core.ts";
import { useNavigate } from "react-router-dom";
import { useApp } from "../App.tsx";
import QuickStartWizard from "./QuickStartWizard.tsx";
import SetupChecklist from "./SetupChecklist.tsx";

interface Props {
  workspace: Workspace;
}

// AppLite is the slice of an app row this page actually needs to
// render the per-project nav list. Only the workspace summary fetches
// these; the broader admin App type lives in core.ts.
type AppLite = {
  id: string;
  // projectName + type drive the computed display name; the freeform
  // apps.name column was dropped server-side, so we read these and
  // hand them to appDisplayName().
  projectName?: string;
  enabled: boolean;
  appId: string;
  type?: AppType | string;
};

function roleLabel(role: string, t: (key: string) => string): string {
  if (!role) return t("role.member");
  const r = role.toLowerCase();
  if (r === "owner") return t("role.owner");
  if (r === "admin") return t("role.admin");
  return t("role.member");
}

export default function WorkspaceSummary(props: Props) {
  const { t } = useTranslation();
  const { workspace } = props;
  const navigate = useNavigate();
  const app = useApp();

  const projects = workspace.projects ?? [];
  const projectCount = projects.length;

  // Local override for the dismiss timestamp - the workspace prop
  // comes from the parent and won't update without a refetch, so we
  // mirror the dismiss state here to hide the card immediately on
  // click. The next page load picks up the persisted value.
  const [dismissedLocally, setDismissedLocally] = React.useState(false);
  const checklistDismissed = dismissedLocally || !!workspace.setupChecklistDismissedAt;

  const [wizardOpen, setWizardOpen] = React.useState(false);

  // Apps per project - fetched in parallel on mount and whenever the
  // project list changes. Cached as a Record<projectId, AppLite[]> so
  // the render stays a flat lookup. Best-effort: failed per-project
  // fetches just leave the project's app list empty (the project row
  // still navigates).
  const [projectApps, setProjectApps] = React.useState<Record<string, AppLite[]>>({});
  React.useEffect(() => {
    if (projectCount === 0) {
      setProjectApps({});
      return;
    }
    let alive = true;
    (async () => {
      const entries = await Promise.all(
        projects.map(async (p) => {
          try {
            const res = await axios.get<{ apps?: AppLite[] } | AppLite[]>(
              `/admin/workspace/${workspace.id}/projects/${p.id}/apps/`,
            );
            const data = res.data;
            const list: AppLite[] = Array.isArray(data) ? data : (data?.apps ?? []);
            return [p.id, list] as const;
          } catch {
            return [p.id, [] as AppLite[]] as const;
          }
        }),
      );
      if (!alive) return;
      const map: Record<string, AppLite[]> = {};
      for (const [pid, list] of entries) map[pid] = list;
      setProjectApps(map);
    })();
    return () => { alive = false; };
    // We re-fetch only when the set of project IDs changes - name
    // edits don't need a refetch, and refetching on every project
    // identity change (e.g. parent re-render) would burn requests.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workspace.id, projects.map((p) => p.id).join(",")]);

  // ----- Create-project dialog (used once at least one project exists;
  // the QuickStartWizard handles first-time onboarding via the empty
  // state above). Mirrors the lift-from Projects.tsx flow that used to
  // live on a dedicated /projects page. -----
  const [createOpen, setCreateOpen] = React.useState(false);
  const [createName, setCreateName] = React.useState("");
  const [createBusy, setCreateBusy] = React.useState(false);
  const [createErr, setCreateErr] = React.useState<string | null>(null);

  const [toastOpen, setToastOpen] = React.useState(false);
  const [toastMsg, setToastMsg] = React.useState("");
  const [toastSeverity, setToastSeverity] = React.useState<"success" | "error">("success");

  const handleWizardComplete = async (projectId: string) => {
    setWizardOpen(false);
    await app.refreshAppData();
    navigate(`/app/workspace/${workspace.id}/projects/${projectId}`);
  };

  const showToast = (msg: string, severity: "success" | "error" = "success") => {
    setToastMsg(msg);
    setToastSeverity(severity);
    setToastOpen(true);
  };

  const openCreate = () => {
    setCreateName("");
    setCreateErr(null);
    setCreateOpen(true);
  };

  const canCreate = createName.trim() !== "";

  const doCreate = async () => {
    if (createBusy) return;
    const name = createName.trim();
    if (!name) {
      setCreateErr(t("projects.nameRequired"));
      return;
    }
    setCreateBusy(true);
    setCreateErr(null);
    try {
      const res = await axios.post<Project>(
        `/admin/workspace/${workspace.id}/projects`,
        { name },
      );
      const created = res.data;
      setCreateOpen(false);
      await app.refreshAppData();
      showToast(t("projects.projectCreated"), "success");
      if (created?.id) {
        navigate(`/app/workspace/${workspace.id}/projects/${created.id}`);
      }
    } catch (e) {
      setCreateErr(extractApiError(e, t("projects.failedToCreate")));
      showToast(t("projects.failedToCreate"), "error");
    } finally {
      setCreateBusy(false);
    }
  };

  const onCreateKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== "Enter") return;
    if (e.shiftKey || e.altKey || e.ctrlKey || e.metaKey) return;
    if (!canCreate) return;
    e.preventDefault();
    void doCreate();
  };

  return (
    <Stack spacing={3.5}>
      <PageHeader
        title={workspace.name}
        meta={
          <>
            <Typography
              sx={{
                fontSize: 12.5,
                color: "text.secondary",
                fontFamily: "var(--font-mono)",
                borderBottom: "1px dashed",
                borderColor: "divider",
                pb: "2px",
              }}
            >
              /{workspace.slug}
            </Typography>
            <Chip
              size="small"
              icon={<BadgeCheck size={10} strokeWidth={1.75} />}
              label={roleLabel(workspace.role, t)}
              variant="outlined"
              sx={{ fontWeight: 600, fontSize: 10.5, height: 22 }}
            />
          </>
        }
      />

      {/* First-boot setup checklist - Stripe-style "complete your
          setup" card. Auto-hides when every item is done or after
          dismiss. */}
      {!checklistDismissed && (
        <SetupChecklist
          workspace={workspace}
          onDismissed={() => setDismissedLocally(true)}
        />
      )}

      {/* Get started - first-time empty state. Launches the full
          QuickStartWizard which handles project + app + first
          user in one ceremony. */}
      {projectCount === 0 && (
        <Paper
          variant="outlined"
          sx={{
            p: 3.5,
            borderRadius: 2.5,
            borderStyle: "dashed",
            borderColor: "primary.main",
            position: "relative",
            overflow: "hidden",
            "&::before": {
              content: '""',
              position: "absolute",
              inset: 0,
              background: "linear-gradient(135deg, rgba(74,25,66,0.04) 0%, rgba(217,111,58,0.025) 100%)",
              pointerEvents: "none",
            },
          }}
        >
          <Stack spacing={2} sx={{ position: "relative" }}>
            <Stack direction="row" spacing={2.5} alignItems="center">
              <Box
                sx={{
                  width: 52,
                  height: 52,
                  borderRadius: 2,
                  bgcolor: "primary.main",
                  color: "primary.contrastText",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  flexShrink: 0,
                }}
              >
                <Rocket size={22} strokeWidth={1.5} />
              </Box>
              <Box sx={{ flex: 1, minWidth: 0 }}>
                <Typography
                  sx={{ fontSize: 16, fontWeight: 650, letterSpacing: "-0.01em", mb: 0.25 }}
                >
                  {t("wizard.getStarted.title")}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {t("wizard.getStarted.description")}
                </Typography>
              </Box>
            </Stack>
            <Button
              variant="contained"
              disableElevation
              onClick={() => setWizardOpen(true)}
              sx={{ alignSelf: "flex-start" }}
            >
              {t("wizard.getStarted.button")}
            </Button>
          </Stack>
        </Paper>
      )}

      <QuickStartWizard
        open={wizardOpen}
        onClose={() => setWizardOpen(false)}
        workspace={workspace}
        onComplete={handleWizardComplete}
      />

      {/* Projects section - list + create. Replaces the standalone
          /projects page; the side menu no longer surfaces it
          separately. */}
      {projectCount > 0 && (
        <Box>
          <Divider sx={{ mb: 2.5 }} />
          <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1.5 }}>
            <Stack direction="row" alignItems="baseline" spacing={1}>
              <Eyebrow>
                {t("workspace.summary.projects")}
              </Eyebrow>
              <Typography
                sx={{
                  fontSize: 11,
                  fontFamily: "var(--font-mono)",
                  color: "text.disabled",
                }}
              >
                {projectCount}
              </Typography>
            </Stack>
            <Button
              size="small"
              variant="contained"
              disableElevation
              startIcon={<Plus size={14} strokeWidth={2} />}
              onClick={openCreate}
            >
              {t("projects.newProject")}
            </Button>
          </Stack>
          <Stack spacing={1.5}>
            {projects.map((p) => {
              const apps = projectApps[p.id] ?? [];
              return (
                <Paper
                  key={p.id}
                  variant="outlined"
                  sx={{ borderRadius: 2, overflow: "hidden" }}
                >
                  <Box
                    role="button"
                    tabIndex={0}
                    onClick={() => navigate(`/app/workspace/${workspace.id}/projects/${p.id}`)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        navigate(`/app/workspace/${workspace.id}/projects/${p.id}`);
                      }
                    }}
                    sx={{
                      display: "flex",
                      alignItems: "center",
                      gap: 1.25,
                      px: 2,
                      py: 1.25,
                      cursor: "pointer",
                      "&:hover": { bgcolor: "action.hover" },
                      borderBottom: apps.length > 0 ? "1px solid" : "none",
                      borderColor: "divider",
                    }}
                  >
                    <Box sx={{ color: "text.secondary", display: "inline-flex" }}>
                      <Folder size={14} strokeWidth={1.75} />
                    </Box>
                    <Typography sx={{ fontSize: 14, fontWeight: 600, flex: 1, minWidth: 0 }} noWrap>
                      {p.name}
                    </Typography>
                    <Typography sx={{ fontSize: 12, color: "text.disabled" }}>
                      {t("workspace.summary.appCount", { count: apps.length, defaultValue: "{{count}} apps" })}
                    </Typography>
                  </Box>
                  {apps.length > 0 && (
                    <Stack divider={<Box sx={{ borderTop: "1px solid", borderColor: "divider" }} />}>
                      {apps.map((a) => (
                        <Box
                          key={a.id}
                          role="button"
                          tabIndex={0}
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/app/workspace/${workspace.id}/projects/${p.id}/apps/${a.id}`);
                          }}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" || e.key === " ") {
                              e.preventDefault();
                              e.stopPropagation();
                              navigate(`/app/workspace/${workspace.id}/projects/${p.id}/apps/${a.id}`);
                            }
                          }}
                          sx={{
                            display: "flex",
                            alignItems: "center",
                            gap: 1.25,
                            px: 2,
                            py: 0.85,
                            pl: 4.5,
                            cursor: "pointer",
                            "&:hover": { bgcolor: "action.hover" },
                          }}
                        >
                          <Box sx={{ color: a.enabled ? "primary.main" : "text.disabled", display: "inline-flex" }}>
                            <Code size={12} strokeWidth={1.75} />
                          </Box>
                          <Typography
                            sx={{
                              fontFamily: "var(--font-mono)",
                              textTransform: "uppercase",
                              letterSpacing: "0.14em",
                              fontSize: 10,
                              fontWeight: 500,
                              color: "text.disabled",
                              flexShrink: 0,
                            }}
                          >
                            {t("workspace.summary.app", { defaultValue: "App" })}
                          </Typography>
                          <Typography sx={{ fontSize: 13, minWidth: 0 }} noWrap>
                            {appDisplayName(a)}
                          </Typography>
                          {a.type && (
                            <StatusChip
                              size="xs"
                              label={appTypeLabel(a)}
                              severity={
                                a.type === "prod" ? "error"
                                  : a.type === "staging" ? "warning"
                                  : a.type === "dev" ? "success"
                                  : "neutral"
                              }
                            />
                          )}
                          <Box sx={{ flex: 1 }} />
                          {!a.enabled && (
                            <Typography sx={{ fontSize: 11, color: "text.disabled" }}>
                              {t("apps.disabled", { defaultValue: "Disabled" })}
                            </Typography>
                          )}
                        </Box>
                      ))}
                    </Stack>
                  )}
                </Paper>
              );
            })}
          </Stack>
        </Box>
      )}

      <Dialog open={createOpen} onClose={() => !createBusy && setCreateOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>{t("projects.createProject")}</DialogTitle>
        <DialogContent onKeyDown={onCreateKeyDown}>
          <Stack spacing={2} sx={{ mt: 1 }}>
            {createErr && <Alert severity="error">{createErr}</Alert>}
            <TextField
              label={t("field.name")}
              value={createName}
              onChange={(e) => setCreateName(e.target.value)}
              autoFocus
              fullWidth
              disabled={createBusy}
            />
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setCreateOpen(false)} disabled={createBusy} sx={{ textTransform: "none" }}>
            {t("common.cancel")}
          </Button>
          <Button
            onClick={doCreate}
            variant="contained"
            disableElevation
            disabled={createBusy || !canCreate}
            sx={{ textTransform: "none", borderRadius: 2 }}
          >
            {t("common.create")}
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar
        open={toastOpen}
        autoHideDuration={2500}
        onClose={() => setToastOpen(false)}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
      >
        <Alert severity={toastSeverity} onClose={() => setToastOpen(false)}>
          {toastMsg}
        </Alert>
      </Snackbar>
    </Stack>
  );
}
