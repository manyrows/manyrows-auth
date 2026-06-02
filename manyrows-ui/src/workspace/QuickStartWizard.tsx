import * as React from "react";
import axios from "axios";
import { extractApiError } from "../lib/apiError.ts";
import {
  Alert,
  Button,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  FormHelperText,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  TextField,
} from "@mui/material";
import { useTranslation } from "react-i18next";

import type { Workspace } from "../core.ts";

interface Props {
  open: boolean;
  onClose: () => void;
  workspace: Workspace;
  onComplete: (projectId: string) => void;
}

type AppEnv = "dev" | "staging" | "prod";
type AuthMethod = "password" | "code" | "magicLink" | "none";

// QuickStartWizard - minimum config to make a working app on first
// run. The project is the user-named entity; each app under it is an
// environment (prod / staging / dev) whose display name is derived,
// not entered. Everything else (OAuth, branding, password policy,
// session TTL, etc.) lives behind sensible defaults and gets edited
// later in the dedicated tabs.
export default function QuickStartWizard({ open, onClose, workspace, onComplete }: Props) {
  const { t } = useTranslation();
  const basePath = `/admin/workspace/${workspace.id}`;

  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const [projectName, setProjectName] = React.useState("");
  const [appEnv, setAppEnv] = React.useState<AppEnv>("dev");
  const [appUrl, setAppUrl] = React.useState("");
  const [primaryAuth, setPrimaryAuth] = React.useState<AuthMethod>("password");

  // Reset on every open so a half-finished previous run doesn't leak in.
  React.useEffect(() => {
    if (!open) return;
    setProjectName("");
    setAppEnv("dev");
    setAppUrl("");
    setPrimaryAuth("password");
    setError(null);
  }, [open]);

  const handleClose = (_event: unknown, reason?: string) => {
    if (loading && (reason === "backdropClick" || reason === "escapeKeyDown")) return;
    onClose();
  };

  const trimmedName = projectName.trim();
  const trimmedUrl = appUrl.trim();
  const urlInvalid = trimmedUrl !== "" && !isLikelyURL(trimmedUrl);
  const canCreate =
    !loading && trimmedName.length > 0 && trimmedUrl.length > 0 && !urlInvalid;

  const handleCreate = async () => {
    if (!canCreate) return;

    setLoading(true);
    setError(null);
    try {
      // 1. Project carries the user-chosen name. The app under it
      //    inherits identity from this label (display name is
      //    composed from project + env type at read time).
      const projectRes = await axios.post<{ id: string }>(`${basePath}/projects`, {
        name: trimmedName,
      });
      const projectId = projectRes.data.id;

      // 2. App - no name field anymore. type + appUrl +
      //    primaryAuthMethod is the whole create payload.
      await axios.post(`${basePath}/projects/${projectId}/apps/`, {
        type: appEnv,
        enabled: true,
        appUrl: trimmedUrl,
        primaryAuthMethod: primaryAuth,
      });

      onComplete(projectId);
    } catch (e) {
      setError(extractApiError(e, t("wizard.error.projectFailed")));
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onClose={handleClose} fullWidth maxWidth="sm">
      <DialogTitle>{t("wizard.title", { defaultValue: "Quick setup" })}</DialogTitle>
      <DialogContent>
        <Stack spacing={2.25} sx={{ mt: 1 }}>
          {error && (
            <Alert severity="error" onClose={() => setError(null)}>
              {typeof error === "string" ? error : t("error.generic")}
            </Alert>
          )}

          <TextField
            label={t("wizard.projectName.label", { defaultValue: "Project name" })}
            placeholder="My Project"
            value={projectName}
            onChange={(e) => setProjectName(e.target.value)}
            autoFocus
            fullWidth
            size="small"
            disabled={loading}
            helperText={t("wizard.projectName.help", {
              defaultValue: "The project this belongs to. Each environment - prod, staging, dev - is a separate app under it.",
            })}
          />

          <FormControl size="small" fullWidth disabled={loading}>
            <InputLabel id="wizard-env-label">
              {t("wizard.appEnv.label", { defaultValue: "Environment" })}
            </InputLabel>
            <Select
              labelId="wizard-env-label"
              label={t("wizard.appEnv.label", { defaultValue: "Environment" })}
              value={appEnv}
              onChange={(e) => setAppEnv(e.target.value as AppEnv)}
            >
              <MenuItem value="dev">Development</MenuItem>
              <MenuItem value="staging">Staging</MenuItem>
              <MenuItem value="prod">Production</MenuItem>
            </Select>
            <FormHelperText>
              {t("wizard.appEnv.help", {
                defaultValue:
                  "Add the other environments later - prod / staging / dev share roles, permissions, config keys, and feature flags under one project.",
              })}
            </FormHelperText>
          </FormControl>

          <TextField
            label={t("wizard.appUrl.label", { defaultValue: "App URL" })}
            placeholder="https://myapp.com"
            value={appUrl}
            onChange={(e) => setAppUrl(e.target.value)}
            fullWidth
            size="small"
            disabled={loading}
            error={urlInvalid}
            helperText={
              urlInvalid
                ? t("wizard.appUrl.invalid", {
                    defaultValue: "Must start with http:// or https://",
                  })
                : t("wizard.appUrl.help", {
                    defaultValue:
                      "Where end-users access your app. Used for invite emails, password-reset links, and OAuth redirects.",
                  })
            }
          />

          <FormControl size="small" fullWidth disabled={loading}>
            <InputLabel id="wizard-pam-label">
              {t("wizard.primaryAuth.label", { defaultValue: "Primary sign-in method" })}
            </InputLabel>
            <Select
              labelId="wizard-pam-label"
              label={t("wizard.primaryAuth.label", { defaultValue: "Primary sign-in method" })}
              value={primaryAuth}
              onChange={(e) => setPrimaryAuth(e.target.value as AuthMethod)}
            >
              <MenuItem value="password">Email + password</MenuItem>
              <MenuItem value="code">Email code (OTP)</MenuItem>
              <MenuItem value="magicLink">Magic link</MenuItem>
              <MenuItem value="none">No email form (OAuth only)</MenuItem>
            </Select>
            <FormHelperText>
              {t("wizard.primaryAuth.help", {
                defaultValue:
                  "How end-users sign in by default. You can change this and add OAuth providers (Google, Apple, etc.) later.",
              })}
            </FormHelperText>
          </FormControl>
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} disabled={loading}>
          {t("common.cancel", { defaultValue: "Cancel" })}
        </Button>
        <Button
          variant="contained"
          disableElevation
          onClick={handleCreate}
          disabled={!canCreate}
          startIcon={loading ? <CircularProgress size={16} color="inherit" /> : undefined}
        >
          {loading
            ? t("wizard.creating", { defaultValue: "Creating…" })
            : t("wizard.finish", { defaultValue: "Create app" })}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// isLikelyURL is a soft guard for the App URL field - the server has
// the authoritative validation. Just catches the obvious "missing
// scheme" case so the user sees the error before round-tripping.
function isLikelyURL(s: string): boolean {
  return /^https?:\/\/[^\s]+$/i.test(s);
}
