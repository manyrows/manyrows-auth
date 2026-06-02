import * as React from "react";
import type { Workspace } from "../core.ts";
import axios from "axios";
import {
  Alert,
  Box,
  Button,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import PageHeader from "../components/PageHeader.tsx";
import { useApp } from "../App.tsx";
import { useSnackbar } from "notistack";
import { useTranslation } from "react-i18next";

interface Props {
  workspace: Workspace;
  onUpdated?: (workspace: Workspace) => void; // optional: let parent refresh state
}

const MAX_NAME = 80;
const MAX_SLUG = 80;

async function updateWorkspace(
  workspaceId: string,
  body: { name: string; slug: string },
): Promise<Workspace> {
  return axios
    .post(`/admin/workspace/${workspaceId}`, body)
    .then((r) => r.data)
    .catch((err) => Promise.reject(err));
}

function getErrMessage(err: unknown, t: (key: string) => string): string {
  const errObj = (err ?? {}) as { response?: { status?: number; data?: unknown } };
  const status = errObj.response?.status;
  const data = errObj.response?.data;

  if (typeof data === "string" && data.trim().length > 0) return data;
  if (status === 409) return t("error.slugInUse");
  if (status === 400) return t("error.invalidFields");
  if (status === 401) return t("error.notSignedIn");
  if (status === 403) return t("error.noPermission");
  if (status === 404) return t("error.workspaceNotFound");
  return t("error.generic");
}

// WorkspaceSettings is now the "General" workspace settings page -
// the inner tab strip is gone. Team / Email are top-level entries in
// the WorkspaceSideMenu (and reachable via /team and /emailSettings),
// no longer hidden inside this page.
export default function WorkspaceSettings(props: Props) {
  const { workspace, onUpdated } = props;
  const app = useApp();
  const { enqueueSnackbar } = useSnackbar();
  const { t } = useTranslation();

  return (
    <Box>
      <Stack spacing={2} sx={{ maxWidth: 820 }}>
        <PageHeader
          title={t("settings.pageTitle", { defaultValue: "Settings" })}
          mb={0}
        />

        <GeneralTabContent
          workspace={workspace}
          onUpdated={onUpdated}
          app={app}
          enqueueSnackbar={enqueueSnackbar}
          t={t}
        />
      </Stack>
    </Box>
  );
}

// Extracted General tab body - same form fields as before (workspace
// name + slug, cookie domain). Pulled out so the parent can swap in
// EmailSettings for the Email tab without juggling two render paths
// inside the main component.
function GeneralTabContent({
  workspace,
  onUpdated,
  app,
  enqueueSnackbar,
  t,
}: {
  workspace: Workspace;
  onUpdated?: (workspace: Workspace) => void;
  app: ReturnType<typeof useApp>;
  enqueueSnackbar: ReturnType<typeof useSnackbar>["enqueueSnackbar"];
  t: ReturnType<typeof useTranslation>["t"];
}) {
  const [name, setName] = React.useState(workspace.name ?? "");
  const [slug, setSlug] = React.useState(workspace.slug ?? "");

  const [touched, setTouched] = React.useState(false);
  const [saved, setSaved] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [errorText, setErrorText] = React.useState<string | null>(null);

  React.useEffect(() => {
    setName(workspace.name ?? "");
    setSlug(workspace.slug ?? "");
    setTouched(false);
    setSaved(false);
    setSaving(false);
    setErrorText(null);
  }, [workspace.id]);

  const nameTrim = name.trim();
  const slugTrim = slug.trim();

  const nameError =
    touched && (nameTrim.length === 0 || nameTrim.length > MAX_NAME);
  const slugError =
    touched && (slugTrim.length === 0 || slugTrim.length > MAX_SLUG);

  const isDirty =
    nameTrim !== (workspace.name ?? "").trim() ||
    slugTrim !== (workspace.slug ?? "").trim();

  const canSave = !saving && !nameError && !slugError && isDirty;

  const onChangeName = (v: string) => {
    setName(v);
    setTouched(true);
    setSaved(false);
    setErrorText(null);
  };

  const onChangeSlug = (v: string) => {
    setSlug(v);
    setTouched(true);
    setSaved(false);
    setErrorText(null);
  };

  const onReset = () => {
    setName(workspace.name ?? "");
    setSlug(workspace.slug ?? "");
    setTouched(false);
    setSaved(false);
    setErrorText(null);
  };

  const onSave = async () => {
    setTouched(true);
    setSaved(false);
    setErrorText(null);

    if (!canSave) return;

    setSaving(true);
    try {
      const updated = await updateWorkspace(workspace.id, {
        name: nameTrim,
        slug: slugTrim,
      });

      setSaved(true);
      enqueueSnackbar(t("settings.workspaceUpdated"), { variant: "success" });

      onUpdated?.(updated);
      app.refreshAppData();
    } catch (err) {
      const msg = getErrMessage(err, t);
      setErrorText(msg);
      enqueueSnackbar(msg, { variant: "error" });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Stack spacing={3.5} sx={{ maxWidth: 680 }}>
      <Stack spacing={2}>
        <Box>
          <Typography
            sx={{
              display: "inline-flex",
              alignItems: "center",
              gap: 1,
              fontFamily: "var(--font-mono)",
              textTransform: "uppercase",
              letterSpacing: "0.14em",
              fontSize: 10,
              fontWeight: 500,
              color: "text.disabled",
              mb: 0.75,
            }}
          >
            {t("settings.identityEyebrow")}
          </Typography>
          <Typography sx={{ fontSize: 15, fontWeight: 600, letterSpacing: "-0.005em" }}>
            {t("settings.nameAndSlug")}
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, maxWidth: 620 }}>
            {t("settings.slugPropagates")}
          </Typography>
        </Box>

        <TextField
          label={t("settings.nameLabel")}
          value={name}
          onChange={(e) => onChangeName(e.target.value)}
          fullWidth
          size="small"
          error={nameError}
          helperText={
            nameError
              ? nameTrim.length === 0
                ? t("settings.nameRequired")
                : t("settings.nameTooLong", { max: MAX_NAME })
              : " "
          }
          inputProps={{ maxLength: MAX_NAME }}
          disabled={saving}
        />

        <TextField
          label={t("settings.slugLabel")}
          value={slug}
          onChange={(e) => onChangeSlug(e.target.value)}
          fullWidth
          size="small"
          error={slugError}
          helperText={
            slugError
              ? slugTrim.length === 0
                ? t("settings.slugRequired")
                : t("settings.slugTooLong", { max: MAX_SLUG })
              : " "
          }
          inputProps={{ maxLength: MAX_SLUG }}
          disabled={saving}
        />

        {errorText && (
          <Alert severity="error">{errorText}</Alert>
        )}

        {saved && !errorText && (
          <Alert severity="success">{t("settings.saved")}</Alert>
        )}

        <Stack direction="row" spacing={1} justifyContent="flex-end">
          <Button onClick={onReset} disabled={!isDirty || saving} sx={{ textTransform: "none" }}>
            {t("settings.reset")}
          </Button>
          <Button
            variant="contained"
            disableElevation
            onClick={onSave}
            disabled={!canSave}
            sx={{ textTransform: "none" }}
          >
            {saving ? t("settings.saving") : t("settings.saveChanges")}
          </Button>
        </Stack>
      </Stack>
    </Stack>
  );
}
