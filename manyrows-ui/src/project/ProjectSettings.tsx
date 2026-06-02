import * as React from "react";
import type {Project} from "../core.ts";
import axios from "axios";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import PageHeader from "../components/PageHeader.tsx";
import { useNavigate } from "react-router-dom";
import { useSnackbar } from "notistack";
import {useApp} from "../App.tsx";
import { useTranslation } from "react-i18next";

type TFunc = (key: string, opts?: Record<string, unknown>) => string;

interface Props {
  project: Project;
  onUpdated?: (project: Project) => void;
}

const MAX_NAME = 80;

async function updateProject(
  workspaceId: string,
  projectId: string,
  body: { name: string },
): Promise<Project> {
  return axios
    .put(`/admin/workspace/${workspaceId}/projects/${projectId}`, body)
    .then((r) => r.data)
    .catch((err) => Promise.reject(err));
}

function getErrMessage(err: unknown, t: TFunc): string {
  const errObj = (err ?? {}) as { response?: { status?: number; data?: unknown } };
  const status = errObj.response?.status;
  const data = errObj.response?.data;

  if (typeof data === "string" && data.trim().length > 0) return data;
  if (status === 400) return t("projectSettings.error.badRequest");
  if (status === 401) return t("projectSettings.error.notSignedIn");
  if (status === 403) return t("projectSettings.error.noPermission");
  if (status === 404) return t("projectSettings.error.notFound");
  return t("projectSettings.error.generic");
}

export default function ProjectSettings(props: Props) {
  const { project, onUpdated } = props;
  const app = useApp();
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { enqueueSnackbar } = useSnackbar();

  const [name, setName] = React.useState(project.name ?? "");

  const [touched, setTouched] = React.useState(false);
  const [saved, setSaved] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [errorText, setErrorText] = React.useState<string | null>(null);

  React.useEffect(() => {
    setName(project.name ?? "");
    setTouched(false);
    setSaved(false);
    setSaving(false);
    setErrorText(null);
  }, [project.id]);

  const nameTrim = name.trim();

  const nameError =
    touched && (nameTrim.length === 0 || nameTrim.length > MAX_NAME);

  const isDirty = nameTrim !== (project.name ?? "").trim();

  const canSave = !saving && !nameError && isDirty;

  const onChangeName = (v: string) => {
    setName(v);
    setTouched(true);
    setSaved(false);
    setErrorText(null);
  };

  const onReset = () => {
    setName(project.name ?? "");
    setTouched(false);
    setSaved(false);
    setErrorText(null);
  };

  // ----- Delete -----
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [deleteConfirm, setDeleteConfirm] = React.useState("");
  const [deleting, setDeleting] = React.useState(false);

  React.useEffect(() => {
    setDeleteOpen(false);
    setDeleteConfirm("");
    setDeleting(false);
  }, [project.id]);

  const confirmDelete = async () => {
    setDeleting(true);
    try {
      await axios.delete(`/admin/workspace/${project.workspaceId}/projects/${project.id}`);
      enqueueSnackbar(
        t("projectSettings.deleted", { defaultValue: "Project deleted" }),
        { variant: "success" },
      );
      // Hop out of the project subtree first, then refresh sidebar
      // counts. Doing the navigate before the refresh avoids a flash
      // of "this project no longer exists" content.
      navigate(`/app/workspace/${project.workspaceId}`);
      app.refreshAppData();
    } catch (err) {
      enqueueSnackbar(getErrMessage(err, t), { variant: "error" });
      setDeleting(false);
    }
  };

  const onSave = async () => {
    setTouched(true);
    setSaved(false);
    setErrorText(null);

    if (!canSave) return;

    setSaving(true);
    try {
      const updated = await updateProject(project.workspaceId, project.id, { name: nameTrim });

      setSaved(true);
      onUpdated?.(updated);
      app.refreshAppData()
    } catch (err) {
      setErrorText(getErrMessage(err, t));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Box>
      <Stack spacing={2} sx={{ maxWidth: 820 }}>
        <PageHeader
          title={t("projectSettings.title")}
          mb={1}
        />

        <Stack spacing={2}>
          <Box>
            <Typography
              sx={{
                fontFamily: "var(--font-mono)",
                textTransform: "uppercase",
                letterSpacing: "0.14em",
                fontSize: 10,
                fontWeight: 500,
                color: "text.disabled",
              }}
            >
              {t("projectSettings.projectId")}
            </Typography>
            <Typography
              variant="body2"
              sx={{ fontFamily: "var(--font-mono)" }}
            >
              {project.id}
            </Typography>
          </Box>

          <Divider />

          <TextField
            label={t("projectSettings.name")}
            value={name}
            onChange={(e) => onChangeName(e.target.value)}
            fullWidth
            size="small"
            error={nameError}
            helperText={
              nameError
                ? nameTrim.length === 0
                  ? t("projectSettings.nameRequired")
                  : t("projectSettings.nameTooLong", { max: MAX_NAME })
                : " "
            }
            inputProps={{ maxLength: MAX_NAME }}
            disabled={saving}
          />

          {errorText && (
            <Alert severity="error">{errorText}</Alert>
          )}

          {saved && !errorText && (
            <Alert severity="success">{t("projectSettings.saved")}</Alert>
          )}

          <Stack direction="row" spacing={1} justifyContent="flex-end">
            <Button onClick={onReset} disabled={!isDirty || saving} sx={{ textTransform: "none" }}>
              {t("projectSettings.reset")}
            </Button>
            <Button
              variant="contained"
              disableElevation
              onClick={onSave}
              disabled={!canSave}
              sx={{ textTransform: "none" }}
            >
              {saving ? t("projectSettings.saving") : t("projectSettings.saveChanges")}
            </Button>
          </Stack>
        </Stack>

        <Card variant="outlined" sx={{ borderRadius: 2, borderColor: "error.main", borderStyle: "dashed" }}>
          <CardContent sx={{ p: 2.5 }}>
            <Stack spacing={1.5}>
              <Typography
                sx={{
                  fontFamily: "var(--font-mono)",
                  textTransform: "uppercase",
                  letterSpacing: "0.14em",
                  fontSize: 10,
                  fontWeight: 600,
                  color: "error.main",
                }}
              >
                {t("projectSettings.dangerZone", { defaultValue: "Danger zone" })}
              </Typography>
              <Stack direction={{ xs: "column", sm: "row" }} spacing={2} alignItems={{ sm: "center" }} justifyContent="space-between">
                <Box>
                  <Typography variant="body2" sx={{ fontWeight: 500 }}>
                    {t("projectSettings.deleteTitle", { defaultValue: "Delete this project" })}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {t("projectSettings.deleteHint", { defaultValue: "Removes the project, its apps, and all associated data. This cannot be undone." })}
                  </Typography>
                </Box>
                <Button
                  color="error"
                  variant="outlined"
                  onClick={() => { setDeleteConfirm(""); setDeleteOpen(true); }}
                  sx={{ flexShrink: 0 }}
                >
                  {t("projectSettings.deleteButton", { defaultValue: "Delete project…" })}
                </Button>
              </Stack>
            </Stack>
          </CardContent>
        </Card>
      </Stack>

      <Dialog open={deleteOpen} onClose={() => !deleting && setDeleteOpen(false)} fullWidth maxWidth="xs">
        <DialogTitle>
          {t("projectSettings.deleteDialogTitle", { defaultValue: "Delete project" })}
        </DialogTitle>
        <Box
          component="form"
          onSubmit={(e) => {
            e.preventDefault();
            if (deleteConfirm.trim() === project.name) void confirmDelete();
          }}
        >
          <DialogContent sx={{ pt: 1 }}>
            <Stack spacing={1.5}>
              <Alert severity="warning">
                {t("projectSettings.deleteWarning", { defaultValue: "This permanently deletes the project, its apps, users, and roles. This action cannot be undone." })}
              </Alert>
              <Typography variant="body2" color="text.secondary">
                {t("projectSettings.deleteTypeToConfirm", { name: project.name, defaultValue: `Type "${project.name}" to confirm.` })}
              </Typography>
              <TextField
                size="small"
                autoFocus
                value={deleteConfirm}
                onChange={(e) => setDeleteConfirm(e.target.value)}
                placeholder={project.name}
                disabled={deleting}
              />
            </Stack>
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button onClick={() => setDeleteOpen(false)} disabled={deleting}>
              {t("projectSettings.cancel", { defaultValue: "Cancel" })}
            </Button>
            <Button
              type="submit"
              variant="contained"
              color="error"
              disableElevation
              disabled={deleteConfirm.trim() !== project.name || deleting}
            >
              {deleting
                ? t("projectSettings.deleting", { defaultValue: "Deleting…" })
                : t("projectSettings.deleteConfirm", { defaultValue: "Delete" })}
            </Button>
          </DialogActions>
        </Box>
      </Dialog>
    </Box>
  );
}
