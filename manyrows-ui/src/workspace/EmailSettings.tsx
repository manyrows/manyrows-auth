import * as React from "react";
import axios from "axios";
import { extractApiError } from "../lib/apiError.ts";
import {
  Alert,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Divider,
  FormControlLabel,
  Stack,
  Switch,
  TextField,
  Typography,
} from "@mui/material";
import { Send, Trash2 } from "lucide-react";
import PageHeader from "../components/PageHeader.tsx";
import { useSnackbar } from "notistack";
import { useTranslation } from "react-i18next";
import { useApp } from "../App.tsx";

interface Props {
  workspaceId: string;
}

interface SMTPData {
  configured: boolean;
  enabled: boolean;
  host: string;
  port: number;
  username: string;
  hasPassword: boolean;
  fromEmail: string;
  fromName: string;
  // System-level transport metadata. Tells the operator whether a
  // global transport (env-configured) is already delivering admin
  // emails without any per-workspace setup.
  systemProvider: "console" | "smtp" | "cloudmailin" | "";
  systemFromEmail: string;
}

export default function EmailSettings({ workspaceId }: Props) {
  const { enqueueSnackbar } = useSnackbar();
  const { t } = useTranslation();
  const { refreshAppData } = useApp();

  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [testing, setTesting] = React.useState(false);
  const [errorText, setErrorText] = React.useState<string | null>(null);

  const [enabled, setEnabled] = React.useState(false);
  const [host, setHost] = React.useState("");
  const [port, setPort] = React.useState(587);
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [fromEmail, setFromEmail] = React.useState("");
  const [fromName, setFromName] = React.useState("");
  const [hasPassword, setHasPassword] = React.useState(false);
  const [configured, setConfigured] = React.useState(false);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = React.useState(false);
  const [systemProvider, setSystemProvider] = React.useState<SMTPData["systemProvider"]>("");
  const [systemFromEmail, setSystemFromEmail] = React.useState("");

  const load = React.useCallback(async () => {
    try {
      const res = await axios.get<SMTPData>(
        `/admin/workspace/${workspaceId}/smtp`,
      );
      const d = res.data;
      setConfigured(d.configured);
      setSystemProvider(d.systemProvider ?? "");
      setSystemFromEmail(d.systemFromEmail ?? "");
      if (d.configured) {
        setEnabled(d.enabled);
        setHost(d.host);
        setPort(d.port);
        setUsername(d.username);
        setHasPassword(d.hasPassword);
        setFromEmail(d.fromEmail);
        setFromName(d.fromName);
      }
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, [workspaceId]);

  React.useEffect(() => {
    load();
  }, [load]);

  const onSave = async () => {
    setErrorText(null);
    if (!host.trim()) {
      setErrorText(t("smtp.hostRequired"));
      return;
    }
    if (!fromEmail.trim()) {
      setErrorText(t("smtp.fromEmailRequired"));
      return;
    }

    setSaving(true);
    try {
      const body: {
        enabled: boolean;
        host: string;
        port: number;
        username: string;
        fromEmail: string;
        fromName: string;
        password?: string;
      } = {
        enabled,
        host: host.trim(),
        port: port || 587,
        username: username.trim(),
        fromEmail: fromEmail.trim(),
        fromName: fromName.trim(),
      };
      if (password) {
        body.password = password;
      }
      await axios.post(`/admin/workspace/${workspaceId}/smtp`, body);
      setConfigured(true);
      setHasPassword(hasPassword || !!password);
      setPassword("");
      enqueueSnackbar(t("smtp.saved"), { variant: "success" });
    } catch (e) {
      setErrorText(extractApiError(e, t("error.generic")));
    } finally {
      setSaving(false);
    }
  };

  const onDelete = async () => {
    setDeleteConfirmOpen(false);
    try {
      await axios.delete(`/admin/workspace/${workspaceId}/smtp`);
      setConfigured(false);
      setEnabled(false);
      setHost("");
      setPort(587);
      setUsername("");
      setPassword("");
      setFromEmail("");
      setFromName("");
      setHasPassword(false);
      setErrorText(null);
      enqueueSnackbar(t("smtp.deleted"), { variant: "success" });
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("error.generic")), { variant: "error" });
    }
  };

  const onSendTest = async () => {
    setTesting(true);
    try {
      const res = await axios.post(
        `/admin/workspace/${workspaceId}/smtp/test`,
      );
      enqueueSnackbar(t("smtp.testSent", { email: res.data.sentTo }), {
        variant: "success",
      });
      // The handler stamped setup_test_email_sent_at on the workspace
      // row. Refresh appData so the home-page setup checklist picks
      // it up without a manual reload.
      refreshAppData();
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("smtp.testFailed")), { variant: "error" });
    } finally {
      setTesting(false);
    }
  };

  if (loading) return null;

  // Pick the right banner for the active system transport. The form
  // below stays usable as an override in every case - the banner is
  // purely informational so the operator knows whether they actually
  // need to fill it in.
  const renderSystemStatus = () => {
    if (!systemProvider) return null;

    // "console" is the warning case (nothing's delivering); every
    // other transport (SMTP / env-configured outbound) is the same
    // success-with-from-line message from the operator's POV.
    if (systemProvider !== "console") {
      const severity = !systemFromEmail
        ? "warning"
        : systemProvider === "smtp"
          ? "info"
          : "success";
      return (
        <Alert severity={severity}>
          {t("smtp.system.active.body", {
            defaultValue:
              "Outbound mail is being delivered automatically - system-level credentials are configured. The form below overrides per-workspace.",
          })}
          {systemFromEmail ? (
            <>
              {" "}
              {t("smtp.system.fromEmail", { defaultValue: "From:" })}{" "}
              <code>{systemFromEmail}</code>
            </>
          ) : (
            <>
              {" - "}
              <strong>
                {t("smtp.system.fromMissing", {
                  defaultValue:
                    "MANYROWS_FROM_EMAIL is not set; the server will refuse to send outbound mail until you configure a sender on your own domain.",
                })}
              </strong>
            </>
          )}
        </Alert>
      );
    }

    // console - nothing's actually delivering mail.
    return (
      <Alert severity="warning">
        <strong>{t("smtp.system.console.title", { defaultValue: "No outbound email transport is configured." })}</strong>
        {" "}
        {t("smtp.system.console.body", {
          defaultValue:
            "Sign-in and admin emails are being logged to stdout instead of delivered. Set MANYROWS_SMTP_* env vars or fill in the SMTP form below.",
        })}
      </Alert>
    );
  };

  return (
    <Box>
      <Stack spacing={3} sx={{ maxWidth: 680 }}>
        <PageHeader
          title={t("smtp.title")}
          subtitle={t("smtp.description")}
        />

        {renderSystemStatus()}

        <Stack spacing={2.5}>
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
              {t("smtp.customEyebrow")}
            </Typography>
            <Typography sx={{ fontSize: 15, fontWeight: 600, letterSpacing: "-0.005em" }}>
              {t("smtp.outboundTransport")}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, maxWidth: 620 }}>
              {t("smtp.relayDescription")}
            </Typography>
          </Box>

          <FormControlLabel
            control={
              <Switch
                checked={enabled}
                onChange={(e) => setEnabled(e.target.checked)}
                disabled={saving}
              />
            }
            label={t("smtp.enabled")}
          />

          <Divider />

          <Stack direction="row" spacing={2}>
            <TextField
              label={t("smtp.host")}
              value={host}
              onChange={(e) => setHost(e.target.value)}
              fullWidth
              size="small"
              placeholder={t("smtp.hostPlaceholder", "smtp.example.com")}
              disabled={saving}

            />
            <TextField
              label={t("smtp.port")}
              value={port}
              onChange={(e) =>
                setPort(parseInt(e.target.value, 10) || 587)
              }
              size="small"
              type="number"
              disabled={saving}
              sx={{ width: 120, flexShrink: 0 }}
            />
          </Stack>

          <Stack direction="row" spacing={2}>
            <TextField
              label={t("smtp.username")}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              fullWidth
              size="small"
              disabled={saving}

            />
            <TextField
              label={t("smtp.password")}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              fullWidth
              size="small"
              type="password"
              placeholder={
                hasPassword ? t("smtp.passwordPlaceholder") : ""
              }
              disabled={saving}

            />
          </Stack>

          <Divider />

          <Stack direction="row" spacing={2}>
            <TextField
              label={t("smtp.fromEmail")}
              value={fromEmail}
              onChange={(e) => setFromEmail(e.target.value)}
              fullWidth
              size="small"
              placeholder={t("smtp.fromEmailPlaceholder", "no-reply@yourdomain.com")}
              disabled={saving}

            />
            <TextField
              label={t("smtp.fromName")}
              value={fromName}
              onChange={(e) => setFromName(e.target.value)}
              fullWidth
              size="small"
              placeholder={t("smtp.fromNamePlaceholder", "Your Workspace Name")}
              disabled={saving}

            />
          </Stack>

          {errorText && (
            <Alert severity="error">{errorText}</Alert>
          )}

          <Stack direction="row" spacing={1} justifyContent="flex-end">
            {configured && (
              <Button
                color="error"
                startIcon={<Trash2 size={14} strokeWidth={1.75} />}
                onClick={() => setDeleteConfirmOpen(true)}
                disabled={saving}
                sx={{ mr: "auto", textTransform: "none" }}
              >
                {t("smtp.delete")}
              </Button>
            )}
            {/* Test button is always available when *something* can
                deliver - system transport (env-configured) or
                workspace SMTP. Hidden only when systemProvider is
                "console" and no workspace SMTP is set, since there's
                nothing for the test to do. */}
            {(systemProvider !== "console" || configured) && (
              <Button
                startIcon={<Send size={14} strokeWidth={1.75} />}
                onClick={onSendTest}
                disabled={saving || testing}
                sx={{ textTransform: "none" }}
              >
                {testing
                  ? t("smtp.sendTest") + "..."
                  : t("smtp.sendTest")}
              </Button>
            )}
            <Button
              variant="contained"
              disableElevation
              onClick={onSave}
              disabled={saving}
              sx={{ textTransform: "none" }}
            >
              {saving ? t("smtp.saving") : t("smtp.save")}
            </Button>
          </Stack>
        </Stack>
      </Stack>

      {/* Delete SMTP confirmation dialog */}
      <Dialog open={deleteConfirmOpen} onClose={() => setDeleteConfirmOpen(false)}>
        <DialogTitle>{t("smtp.confirmDeleteTitle")}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t("smtp.deleteConfirm")}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteConfirmOpen(false)}>
            {t("common.cancel")}
          </Button>
          <Button color="error" variant="contained" onClick={onDelete}>
            {t("common.remove")}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
