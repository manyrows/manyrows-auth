import * as React from "react";
import { useApp } from "../App.tsx";
import { isSafeRedirectURL } from "../core.ts";
import axios from "axios";
import QRCode from "qrcode";
import {
  Alert,
  Avatar,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  IconButton,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { BadgeCheck, Lock, Mail, SquarePen } from "lucide-react";
import Eyebrow from "../components/Eyebrow.tsx";
import { useTranslation } from "react-i18next";

function QRCodeImg({ data, size }: { data: string; size: number }) {
  const { t } = useTranslation();
  const [src, setSrc] = React.useState<string | null>(null);
  React.useEffect(() => {
    let cancelled = false;
    QRCode.toDataURL(data, { width: size, margin: 1 }).then((url) => {
      if (!cancelled) setSrc(url);
    });
    return () => { cancelled = true; };
  }, [data, size]);
  if (!src) return null;
  return (
    <Box sx={{ textAlign: "center", py: 1 }}>
      <Box
        component="img"
        src={src}
        alt={t("profile.totp.qrAlt")}
        sx={{ width: size, height: size, borderRadius: 2 }}
      />
    </Box>
  );
}

function initials(acc: { name?: string; email?: string } | null | undefined) {
  const name = (acc?.name || "").trim();
  const email = (acc?.email || "").trim();

  const src =
    name ||
    (email.includes("@") ? email.split("@")[0] : email) ||
    "U";

  const parts = src.split(/[.\s_-]+/).filter(Boolean);
  const a = (parts[0]?.[0] ?? "U").toUpperCase();
  const b = (parts[1]?.[0] ?? "").toUpperCase();
  return (a + b).slice(0, 2);
}

function FieldRow(props: {
  label: string;
  value?: string | null;
  icon: React.ReactNode;
  onEdit?: () => void;
  right?: React.ReactNode;
}) {
  const { label, value, icon, onEdit, right } = props;
  const { t } = useTranslation();

  return (
    <Stack spacing={0.75}>
      <Stack direction="row" alignItems="center" spacing={1}>
        <Box
          sx={{
            width: 34,
            display: "grid",
            placeItems: "center",
            color: "text.secondary",
          }}
        >
          {icon}
        </Box>
        <Eyebrow>{label}</Eyebrow>
        <Box sx={{ flex: 1 }} />

        {right}

        {onEdit && (
          <Tooltip title={t("profile.edit")}>
                <span>
            <IconButton size="small" onClick={onEdit} aria-label={t("profile.edit")}>
              <SquarePen size={14} strokeWidth={1.75} />
            </IconButton>
                </span>
          </Tooltip>
        )}
      </Stack>

      <Typography
        variant="body1"
        sx={{
          wordBreak: "break-word",
          pl: 4.25,
        }}
      >
        {value && value.trim().length > 0 ? value : "\u2014"}
      </Typography>
    </Stack>
  );
}

type PostJSONResult = {
  ok: boolean;
  status: number;
  redirected?: boolean;
  message?: string;
};

async function postJSON(path: string, body: unknown): Promise<PostJSONResult> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });

  // If backend logs you out and redirects, fetch won't navigate; do it manually.
  if (res.redirected && res.url) {
    if (isSafeRedirectURL(res.url)) {
      window.location.href = res.url;
    }
    return { ok: false, redirected: true, status: res.status };
  }

  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try {
      const t = await res.text();
      if (t && t.trim().length > 0) msg = t;
    } catch {}
    return { ok: false, status: res.status, message: msg };
  }

  return { ok: true, status: res.status };
}

export default function Profile() {
  const { t } = useTranslation();
  const app = useApp();
  const acc = app.appData.account;

  // dialogs
  const [nameOpen, setNameOpen] = React.useState(false);
  const [emailOpen, setEmailOpen] = React.useState(false);

  // form values
  const [name, setName] = React.useState("");
  const [newEmail, setNewEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [otpCode, setOtpCode] = React.useState("");

  // per-dialog state
  const [nameSaving, setNameSaving] = React.useState(false);
  const [emailSaving, setEmailSaving] = React.useState(false);
  const [emailStep, setEmailStep] = React.useState<"request" | "verify">("request");

  const [nameError, setNameError] = React.useState<string | null>(null);
  const [emailError, setEmailError] = React.useState<string | null>(null);

  // ----- TOTP state -----
  const [totpSetupOpen, setTotpSetupOpen] = React.useState(false);
  const [totpSetupStep, setTotpSetupStep] = React.useState<"loading" | "scan" | "backupCodes">("loading");
  const [totpSecret, setTotpSecret] = React.useState("");
  const [totpUri, setTotpUri] = React.useState("");
  const [totpConfirmCode, setTotpConfirmCode] = React.useState("");
  const [totpBackupCodes, setTotpBackupCodes] = React.useState<string[]>([]);
  const [totpSaving, setTotpSaving] = React.useState(false);
  const [totpError, setTotpError] = React.useState<string | null>(null);

  const [totpDisableOpen, setTotpDisableOpen] = React.useState(false);
  const [totpDisablePassword, setTotpDisablePassword] = React.useState("");
  const [totpDisableSaving, setTotpDisableSaving] = React.useState(false);
  const [totpDisableError, setTotpDisableError] = React.useState<string | null>(null);

  const [totpRegenOpen, setTotpRegenOpen] = React.useState(false);
  const [totpRegenPassword, setTotpRegenPassword] = React.useState("");
  const [totpRegenSaving, setTotpRegenSaving] = React.useState(false);
  const [totpRegenError, setTotpRegenError] = React.useState<string | null>(null);
  const [totpRegenCodes, setTotpRegenCodes] = React.useState<string[]>([]);
  const [totpRegenStep, setTotpRegenStep] = React.useState<"password" | "codes">("password");

  const openNameDialog = () => {
    setNameError(null);
    setName(acc?.name ?? "");
    setNameOpen(true);
  };
  const closeNameDialog = () => {
    if (nameSaving) return;
    setNameOpen(false);
  };

  const openEmailDialog = () => {
    setEmailError(null);
    setNewEmail("");
    setPassword("");
    setOtpCode("");
    setEmailStep("request");
    setEmailOpen(true);
  };
  const closeEmailDialog = () => {
    if (emailSaving) return;
    setEmailOpen(false);
  };

  const saveName = async () => {
    setNameError(null);

    const v = name.trim();
    if (!v) {
      setNameError(t("profile.nameRequired"));
      return;
    }

    const cur = (acc?.name ?? "").trim();
    if (v === cur) {
      setNameOpen(false);
      return;
    }

    setNameSaving(true);
    try {
      const out = await postJSON("/admin/profile/name", { name: v });
      if (!out.ok) {
        if (out.redirected) return;
        setNameError(out.message ?? t("profile.couldNotUpdateName"));
        return;
      }
      setNameOpen(false);
      app.refreshAppData();
    } finally {
      setNameSaving(false);
    }
  };

  const requestEmailChange = async () => {
    setEmailError(null);

    const email = newEmail.trim().toLowerCase();
    const pw = password.trim();

    if (!email) {
      setEmailError(t("profile.newEmailRequired"));
      return;
    }
    if (!pw) {
      setEmailError(t("profile.passwordRequired"));
      return;
    }
    if (email === (acc?.email ?? "").toLowerCase()) {
      setEmailError(t("profile.newEmailMustDiffer"));
      return;
    }

    setEmailSaving(true);
    try {
      const out = await postJSON("/admin/profile/email/change", {
        newEmail: email,
        password: pw,
      });
      if (!out.ok) {
        if (out.redirected) return;
        setEmailError(out.message ?? t("profile.couldNotRequestChange"));
        return;
      }
      setEmailStep("verify");
    } finally {
      setEmailSaving(false);
    }
  };

  const verifyEmailChange = async () => {
    setEmailError(null);

    const code = otpCode.trim();
    if (!code || code.length !== 6) {
      setEmailError(t("profile.enterCode"));
      return;
    }

    setEmailSaving(true);
    try {
      const out = await postJSON("/admin/profile/email/verify", { code });
      if (!out.ok) {
        if (out.redirected) return;
        setEmailError(out.message ?? t("profile.invalidCode"));
        return;
      }
      setEmailOpen(false);
      app.refreshAppData();
    } finally {
      setEmailSaving(false);
    }
  };

  // ----- TOTP Setup -----
  const openTotpSetup = async () => {
    setTotpError(null);
    setTotpConfirmCode("");
    setTotpBackupCodes([]);
    setTotpSetupStep("loading");
    setTotpSetupOpen(true);

    try {
      const res = await axios.post("/admin/totp/setup");
      setTotpSecret(res.data.secret);
      setTotpUri(res.data.uri);
      setTotpSetupStep("scan");
    } catch {
      setTotpError(t("profile.totp.setupFailed"));
      setTotpSetupStep("scan");
    }
  };

  const closeTotpSetup = () => {
    if (totpSaving) return;
    setTotpSetupOpen(false);
    // If we just showed backup codes, refresh to update the account state
    if (totpSetupStep === "backupCodes") {
      app.refreshAppData();
    }
  };

  const confirmTotpSetup = async () => {
    setTotpError(null);
    const code = totpConfirmCode.trim();
    if (code.length !== 6) {
      setTotpError(t("profile.totp.enterCode"));
      return;
    }

    setTotpSaving(true);
    try {
      const res = await axios.post("/admin/totp/enable", { code });
      setTotpBackupCodes(res.data.backupCodes || []);
      setTotpSetupStep("backupCodes");
    } catch (e) {
      if (axios.isAxiosError(e) && e.response?.status === 401) {
        setTotpError(t("profile.totp.invalidCode"));
      } else {
        setTotpError(t("profile.totp.enableFailed"));
      }
    } finally {
      setTotpSaving(false);
    }
  };

  // ----- TOTP Disable -----
  const openTotpDisable = () => {
    setTotpDisableError(null);
    setTotpDisablePassword("");
    setTotpDisableOpen(true);
  };

  const closeTotpDisable = () => {
    if (totpDisableSaving) return;
    setTotpDisableOpen(false);
  };

  const confirmTotpDisable = async () => {
    setTotpDisableError(null);
    const pw = totpDisablePassword.trim();
    if (!pw) {
      setTotpDisableError(t("profile.passwordRequired"));
      return;
    }

    setTotpDisableSaving(true);
    try {
      await axios.post("/admin/totp/disable", { password: pw });
      setTotpDisableOpen(false);
      app.refreshAppData();
    } catch (e) {
      if (axios.isAxiosError(e) && e.response?.status === 401) {
        setTotpDisableError(t("auth.invalidCredentials"));
      } else {
        setTotpDisableError(t("profile.totp.disableFailed"));
      }
    } finally {
      setTotpDisableSaving(false);
    }
  };

  // ----- TOTP Regenerate Backup Codes -----
  const openTotpRegen = () => {
    setTotpRegenError(null);
    setTotpRegenPassword("");
    setTotpRegenCodes([]);
    setTotpRegenStep("password");
    setTotpRegenOpen(true);
  };

  const closeTotpRegen = () => {
    if (totpRegenSaving) return;
    setTotpRegenOpen(false);
  };

  const confirmTotpRegen = async () => {
    setTotpRegenError(null);
    const pw = totpRegenPassword.trim();
    if (!pw) {
      setTotpRegenError(t("profile.passwordRequired"));
      return;
    }

    setTotpRegenSaving(true);
    try {
      const res = await axios.post("/admin/totp/backup-codes", { password: pw });
      setTotpRegenCodes(res.data.backupCodes || []);
      setTotpRegenStep("codes");
    } catch (e) {
      if (axios.isAxiosError(e) && e.response?.status === 401) {
        setTotpRegenError(t("auth.invalidCredentials"));
      } else {
        setTotpRegenError(t("profile.totp.regenFailed"));
      }
    } finally {
      setTotpRegenSaving(false);
    }
  };

  const totpEnabled = !!acc?.totpEnabled;

  return (
    <Box sx={{ p: { xs: 2, sm: 3 }, bgcolor: "background.paper", minHeight: "calc(100vh - 52px)" }}>
      <Stack spacing={3} sx={{ maxWidth: 920 }}>
        {/* Header */}
        <Stack direction="row" spacing={2.5} alignItems="center">
          <Avatar
            variant="rounded"
            sx={{
              width: 52,
              height: 52,
              borderRadius: 1.75,
              bgcolor: "primary.main",
              color: "primary.contrastText",
              fontSize: 16,
              fontWeight: 700,
              letterSpacing: "0.02em",
            }}
          >
            {initials(acc)}
          </Avatar>

          <Box sx={{ minWidth: 0, flex: 1 }}>
            <Eyebrow dot sx={{ mb: 1 }}>{t("profile.account")}</Eyebrow>
            <Typography
              sx={{
                fontFamily: "var(--font-serif)",
                fontSize: 32,
                fontWeight: 500,
                letterSpacing: "-0.025em",
                lineHeight: 1.15,
                fontOpticalSizing: "auto",
                pb: "2px",
              }}
            >
              {t("profile.header")}
            </Typography>
            <Typography
              sx={{
                fontSize: 13,
                color: "text.secondary",
                mt: 0.5,
                fontFamily: "var(--font-mono)",
              }}
            >
              {acc?.email ?? "\u2014"}
            </Typography>
          </Box>
        </Stack>

        {/* Main card */}
        <Card variant="outlined" sx={{ overflow: "hidden" }}>
          <Box
            sx={{
              px: 2.25,
              py: 1.75,
              bgcolor: "action.disabledBackground",
              borderBottom: "1px solid",
              borderColor: "divider",
            }}
          >
            <Typography>
              {t("profile.accountDetails")}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {t("profile.manageIdentity")}
            </Typography>
          </Box>

          <CardContent sx={{ p: 2.25 }}>
            <Stack spacing={2.25}>
              <FieldRow
                label={t("auth.email")}
                value={acc?.email}
                icon={<Mail size={14} strokeWidth={1.75} />}
                onEdit={openEmailDialog}
              />
              <Divider />

              <FieldRow
                label={t("profile.name")}
                value={acc?.name}
                icon={<BadgeCheck size={14} strokeWidth={1.75} />}
                onEdit={openNameDialog}
              />
            </Stack>
          </CardContent>
        </Card>

        {/* Security card (TOTP) */}
        <Card variant="outlined" sx={{ overflow: "hidden" }}>
          <Box
            sx={{
              px: 2.25,
              py: 1.75,
              bgcolor: "action.disabledBackground",
              borderBottom: "1px solid",
              borderColor: "divider",
            }}
          >
            <Typography>
              {t("profile.totp.securityTitle")}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {t("profile.totp.securityDescription")}
            </Typography>
          </Box>

          <CardContent sx={{ p: 2.25 }}>
            <Stack spacing={2.25}>
              <FieldRow
                label={t("profile.totp.label")}
                value={totpEnabled ? t("profile.totp.enabled") : t("profile.totp.disabled")}
                icon={<Lock size={14} strokeWidth={1.75} />}
                right={
                  totpEnabled ? (
                    <Chip
                      size="small"
                      label={t("profile.totp.enabled")}
                      variant="outlined"
                      sx={{
                        fontFamily: "var(--font-mono)",
                        textTransform: "uppercase",
                        letterSpacing: "0.08em",
                        fontSize: 10,
                        fontWeight: 600,
                        borderColor: "success.main",
                        color: "success.main",
                      }}
                    />
                  ) : undefined
                }
              />

              <Stack direction="row" spacing={1} sx={{ pl: 4.25 }}>
                {!totpEnabled ? (
                  <Button
                    variant="contained"
                    size="small"
                    onClick={openTotpSetup}
                   
                  >
                    {t("profile.totp.setup")}
                  </Button>
                ) : (
                  <>
                    <Button
                      variant="outlined"
                      size="small"
                      onClick={openTotpRegen}
                     
                    >
                      {t("profile.totp.regenerateBackupCodes")}
                    </Button>
                    <Button
                      variant="outlined"
                      size="small"
                      color="error"
                      onClick={openTotpDisable}
                     
                    >
                      {t("profile.totp.disable")}
                    </Button>
                  </>
                )}
              </Stack>
            </Stack>
          </CardContent>
        </Card>

      </Stack>

      {/* ------------------------------ Name dialog ----------------------------- */}
      <Dialog
        open={nameOpen}
        onClose={closeNameDialog}
        fullWidth
        maxWidth="sm"
       
      >
        <DialogTitle>{t("profile.updateName")}</DialogTitle>
        <DialogContent>
          <Stack spacing={1.25} sx={{ pt: 1 }}>
            <TextField
              label={t("profile.name")}
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
              fullWidth
              disabled={nameSaving}
            />
            {nameError && (
              <Alert severity="error">
                {nameError}
              </Alert>
            )}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
          <Button
            onClick={closeNameDialog}
            disabled={nameSaving}
           
          >
            {t("common.cancel")}
          </Button>
          <Button
            variant="contained"
            onClick={saveName}
            disabled={nameSaving}
           
            startIcon={nameSaving ? <CircularProgress size={16} /> : undefined}
          >
            {t("common.save")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* ------------------------------ Email dialog ----------------------------- */}
      <Dialog
        open={emailOpen}
        onClose={closeEmailDialog}
        fullWidth
        maxWidth="sm"
       
      >
        <DialogTitle>
          {emailStep === "request" ? t("profile.changeEmail") : t("profile.verifyNewEmail")}
        </DialogTitle>
        <DialogContent>
          {emailStep === "request" ? (
            <Stack spacing={1.25} sx={{ pt: 1 }}>
              <Typography variant="body2" color="text.secondary">
                {t("profile.changeEmailDescription")}
              </Typography>
              <TextField
                label={t("profile.newEmail")}
                type="email"
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                autoFocus
                fullWidth
                disabled={emailSaving}
              />
              <TextField
                label={t("profile.currentPassword")}
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                fullWidth
                disabled={emailSaving}
              />
              {emailError && (
                <Alert severity="error">
                  {emailError}
                </Alert>
              )}
            </Stack>
          ) : (
            <Stack spacing={1.25} sx={{ pt: 1 }}>
              <Typography variant="body2" color="text.secondary">
                {t("profile.codeSentTo")} <strong>{newEmail}</strong>. {t("profile.enterCodeToConfirm")}
              </Typography>
              <TextField
                label={t("profile.verificationCode")}
                value={otpCode}
                onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                autoFocus
                fullWidth
                disabled={emailSaving}
                inputProps={{ maxLength: 6, inputMode: "numeric" }}
              />
              {emailError && (
                <Alert severity="error">
                  {emailError}
                </Alert>
              )}
            </Stack>
          )}
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
          <Button
            onClick={closeEmailDialog}
            disabled={emailSaving}
           
          >
            {t("common.cancel")}
          </Button>
          {emailStep === "request" ? (
            <Button
              variant="contained"
              onClick={requestEmailChange}
              disabled={emailSaving}
             
              startIcon={emailSaving ? <CircularProgress size={16} /> : undefined}
            >
              {t("auth.forgot.sendCode")}
            </Button>
          ) : (
            <Button
              variant="contained"
              onClick={verifyEmailChange}
              disabled={emailSaving}
             
              startIcon={emailSaving ? <CircularProgress size={16} /> : undefined}
            >
              {t("profile.verify")}
            </Button>
          )}
        </DialogActions>
      </Dialog>

      {/* ------------------------------ TOTP Setup dialog ----------------------------- */}
      <Dialog
        open={totpSetupOpen}
        onClose={closeTotpSetup}
        fullWidth
        maxWidth="sm"
       
      >
        <DialogTitle>{t("profile.totp.setupTitle")}</DialogTitle>
        <DialogContent>
          {totpSetupStep === "loading" && (
            <Box sx={{ display: "flex", justifyContent: "center", py: 4 }}>
              <CircularProgress />
            </Box>
          )}

          {totpSetupStep === "scan" && (
            <Stack spacing={2} sx={{ pt: 1 }}>
              <Typography variant="body2" color="text.secondary">
                {t("profile.totp.scanDescription")}
              </Typography>

              {totpUri && <QRCodeImg data={totpUri} size={200} />}

              <Typography variant="body2" color="text.secondary">
                {t("profile.totp.manualEntry")}
              </Typography>
              <TextField
                value={totpSecret}
                fullWidth
                size="small"
                slotProps={{ input: { readOnly: true, sx: { fontFamily: "var(--font-mono)", letterSpacing: 2 } } }}
                onClick={(e) => (e.target as HTMLInputElement).select()}
              />

              <Divider />

              <Typography variant="body2" color="text.secondary">
                {t("profile.totp.confirmDescription")}
              </Typography>
              <TextField
                label={t("profile.totp.confirmCode")}
                value={totpConfirmCode}
                onChange={(e) => {
                  setTotpConfirmCode(e.target.value.replace(/\D/g, "").slice(0, 6));
                  if (totpError) setTotpError(null);
                }}
                autoFocus={false}
                fullWidth
                inputProps={{ maxLength: 6, inputMode: "numeric" }}
              />

              {totpError && (
                <Alert severity="error">
                  {totpError}
                </Alert>
              )}
            </Stack>
          )}

          {totpSetupStep === "backupCodes" && (
            <Stack spacing={2} sx={{ pt: 1 }}>
              <Alert severity="warning">
                {t("profile.totp.backupCodesWarning")}
              </Alert>

              <Box
                sx={{
                  p: 2,
                  borderRadius: 2,
                  bgcolor: "action.disabledBackground",
                  border: "1px solid",
                  borderColor: "divider",
                  userSelect: "all",
                }}
              >
                <Stack spacing={0.5} alignItems="center">
                  {totpBackupCodes.map((code, i) => (
                    <Typography
                      key={i}
                      variant="body2"
                      sx={{
                        fontFamily: "var(--font-mono)",
                        fontSize: "1.1rem",
                        letterSpacing: 1.5,
                      }}
                    >
                      {code}
                    </Typography>
                  ))}
                </Stack>
              </Box>

              <Button
                variant="outlined"
                size="small"
                sx={{ borderRadius: 2, alignSelf: "center" }}
                onClick={() => {
                  navigator.clipboard.writeText(totpBackupCodes.join("\n"));
                }}
              >
                {t("profile.totp.copyBackupCodes")}
              </Button>
            </Stack>
          )}
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
          {totpSetupStep === "scan" && (
            <>
              <Button onClick={closeTotpSetup} disabled={totpSaving}>
                {t("common.cancel")}
              </Button>
              <Button
                variant="contained"
                onClick={confirmTotpSetup}
                disabled={totpSaving || totpConfirmCode.length !== 6}
               
                startIcon={totpSaving ? <CircularProgress size={16} /> : undefined}
              >
                {t("profile.totp.enable")}
              </Button>
            </>
          )}
          {totpSetupStep === "backupCodes" && (
            <Button variant="contained" onClick={closeTotpSetup}>
              {t("profile.totp.done")}
            </Button>
          )}
        </DialogActions>
      </Dialog>

      {/* ------------------------------ TOTP Disable dialog ----------------------------- */}
      <Dialog
        open={totpDisableOpen}
        onClose={closeTotpDisable}
        fullWidth
        maxWidth="sm"
       
      >
        <DialogTitle>{t("profile.totp.disableTitle")}</DialogTitle>
        <DialogContent>
          <Stack spacing={1.25} sx={{ pt: 1 }}>
            <Typography variant="body2" color="text.secondary">
              {t("profile.totp.disableDescription")}
            </Typography>
            <TextField
              label={t("profile.currentPassword")}
              type="password"
              value={totpDisablePassword}
              onChange={(e) => {
                setTotpDisablePassword(e.target.value);
                if (totpDisableError) setTotpDisableError(null);
              }}
              autoFocus
              fullWidth
              disabled={totpDisableSaving}
            />
            {totpDisableError && (
              <Alert severity="error">
                {totpDisableError}
              </Alert>
            )}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
          <Button onClick={closeTotpDisable} disabled={totpDisableSaving}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="contained"
            color="error"
            onClick={confirmTotpDisable}
            disabled={totpDisableSaving || !totpDisablePassword.trim()}
           
            startIcon={totpDisableSaving ? <CircularProgress size={16} /> : undefined}
          >
            {t("profile.totp.disable")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* ------------------------------ Regenerate Backup Codes dialog ----------------------------- */}
      <Dialog
        open={totpRegenOpen}
        onClose={closeTotpRegen}
        fullWidth
        maxWidth="sm"
       
      >
        <DialogTitle>{t("profile.totp.regenTitle")}</DialogTitle>
        <DialogContent>
          {totpRegenStep === "password" ? (
            <Stack spacing={1.25} sx={{ pt: 1 }}>
              <Typography variant="body2" color="text.secondary">
                {t("profile.totp.regenDescription")}
              </Typography>
              <TextField
                label={t("profile.currentPassword")}
                type="password"
                value={totpRegenPassword}
                onChange={(e) => {
                  setTotpRegenPassword(e.target.value);
                  if (totpRegenError) setTotpRegenError(null);
                }}
                autoFocus
                fullWidth
                disabled={totpRegenSaving}
              />
              {totpRegenError && (
                <Alert severity="error">
                  {totpRegenError}
                </Alert>
              )}
            </Stack>
          ) : (
            <Stack spacing={2} sx={{ pt: 1 }}>
              <Alert severity="warning">
                {t("profile.totp.backupCodesWarning")}
              </Alert>

              <Box
                sx={{
                  p: 2,
                  borderRadius: 2,
                  bgcolor: "action.disabledBackground",
                  border: "1px solid",
                  borderColor: "divider",
                  userSelect: "all",
                }}
              >
                <Stack spacing={0.5} alignItems="center">
                  {totpRegenCodes.map((code, i) => (
                    <Typography
                      key={i}
                      variant="body2"
                      sx={{
                        fontFamily: "var(--font-mono)",
                        fontSize: "1.1rem",
                        letterSpacing: 1.5,
                      }}
                    >
                      {code}
                    </Typography>
                  ))}
                </Stack>
              </Box>

              <Button
                variant="outlined"
                size="small"
                sx={{ borderRadius: 2, alignSelf: "center" }}
                onClick={() => {
                  navigator.clipboard.writeText(totpRegenCodes.join("\n"));
                }}
              >
                {t("profile.totp.copyBackupCodes")}
              </Button>
            </Stack>
          )}
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
          {totpRegenStep === "password" ? (
            <>
              <Button onClick={closeTotpRegen} disabled={totpRegenSaving}>
                {t("common.cancel")}
              </Button>
              <Button
                variant="contained"
                onClick={confirmTotpRegen}
                disabled={totpRegenSaving || !totpRegenPassword.trim()}
               
                startIcon={totpRegenSaving ? <CircularProgress size={16} /> : undefined}
              >
                {t("profile.totp.regenerate")}
              </Button>
            </>
          ) : (
            <Button variant="contained" onClick={closeTotpRegen}>
              {t("profile.totp.done")}
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </Box>
  );
}
