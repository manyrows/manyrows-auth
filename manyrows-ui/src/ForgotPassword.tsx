// ForgotPassword.tsx
import * as React from "react";
import axios, { AxiosError } from "axios";
import {
  Box,
  Button,
  Card,
  CardActions,
  CardContent,
  CircularProgress,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { Send, SquarePen } from "lucide-react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import AuthShell from "./components/AuthShell";
import Turnstile, { useTurnstileSiteKey, type TurnstileHandle } from "./components/Turnstile";

const minAdminPasswordLen = 10;

function normalizeEmail(v: string): string {
  return (v || "").trim().toLowerCase();
}

function normalizeCode(v: string): string {
  return (v || "").trim().replace(/\s+/g, "");
}

function isDigits(s: string): boolean {
  if (!s) return false;
  for (const ch of s) if (ch < "0" || ch > "9") return false;
  return true;
}

function validateEmail(v: string): boolean {
  const s = normalizeEmail(v);
  return s.length >= 3 && s.includes("@") && s.includes(".");
}

function sanitizeErrorMsg(msg: string): string {
  const clean = msg.replace(/<[^>]*>/g, "");
  return clean.length > 200 ? clean.slice(0, 200) + "\u2026" : clean;
}

type AuthErrorBody = {
  issues?: { message?: string }[];
  message?: string;
  error?: string;
};

function pickErrorMessage(err: AxiosError<AuthErrorBody | string | undefined>, t: (key: string) => string, fallbackKey: string): string {
  if (err.response?.status === 401) return t("auth.forgot.invalidCode");
  if (err.response?.status === 429) return t("auth.forgot.tooManyAttempts");
  const d = err.response?.data;
  if (d && typeof d === "object") {
    if (Array.isArray(d.issues) && d.issues.length > 0) {
      const msg = d.issues[0].message;
      if (typeof msg === "string" && msg.trim()) return sanitizeErrorMsg(msg.trim());
    }
    if (typeof d.message === "string" && d.message.trim()) return sanitizeErrorMsg(d.message.trim());
    if (typeof d.error === "string" && d.error !== "validation" && d.error.trim()) return sanitizeErrorMsg(d.error.trim());
  }
  if (typeof d === "string" && d.trim()) return sanitizeErrorMsg(d.trim());
  return t(fallbackKey);
}

type Step = "request" | "sent" | "resetting" | "done";

interface Props {
  onSuccess: () => void;
}

export default function ForgotPassword(props: Props) {
  const { t } = useTranslation();
  const [step, setStep] = React.useState<Step>("request");
  const [loading, setLoading] = React.useState(false);

  const [email, setEmail] = React.useState("");
  const [code, setCode] = React.useState("");
  const [newPassword, setNewPassword] = React.useState("");

  const [infoMsg, setInfoMsg] = React.useState<string>("");
  const [errMsg, setErrMsg] = React.useState<string>("");

  const [editingEmail, setEditingEmail] = React.useState<boolean>(true);

  // Cloudflare Turnstile (bot challenge on the initial "send code" request)
  const [turnstileToken, setTurnstileToken] = React.useState("");
  const turnstileRef = React.useRef<TurnstileHandle>(null);
  const { siteKey: turnstileSiteKey } = useTurnstileSiteKey();

  const emailRef = React.useRef<HTMLInputElement>(null);
  const codeRef = React.useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    window.setTimeout(() => emailRef.current?.focus(), 50);
  }, []);

  const emailNorm = React.useMemo(() => normalizeEmail(email), [email]);
  const emailOk = React.useMemo(() => validateEmail(emailNorm), [emailNorm]);

  const codeNorm = React.useMemo(() => normalizeCode(code), [code]);
  const codeOk = React.useMemo(() => codeNorm.length === 6 && isDigits(codeNorm), [codeNorm]);

  const pwTrimmed = newPassword.trim();
  const pwOk = React.useMemo(() => pwTrimmed.length >= minAdminPasswordLen, [pwTrimmed]);

  // Turnstile token only required when the operator has Turnstile
  // configured (site key published). Otherwise the widget never
  // renders and there's no token to wait for.
  const canSend = emailOk && (!turnstileSiteKey || !!turnstileToken) && !loading;
  const canReset = emailOk && codeOk && pwOk && !loading;

  const showResetFields = step === "sent" || step === "resetting" || step === "done";
  const showSendButton = step === "request" && editingEmail; // ✅ hide after code sent

  const sendCode = async () => {
    if (!canSend) return;

    setErrMsg("");
    setInfoMsg("");
    setLoading(true);
    try {
      await axios.post("/admin/auth/forgot", { email: emailNorm, turnstileToken });

      setStep("sent");
      setInfoMsg(t("auth.forgot.codeSent"));

      setEditingEmail(false);
      setCode("");
      setNewPassword("");

      window.setTimeout(() => codeRef.current?.focus(), 50);
    } catch (e) {
      const err = e as AxiosError<any>;
      setErrMsg(pickErrorMessage(err, t, "auth.forgot.couldNotSend"));
      // Turnstile tokens are single-use; refresh on failure so the user can retry.
      setTurnstileToken("");
      turnstileRef.current?.reset();
    } finally {
      setLoading(false);
    }
  };

  const resetPassword = async () => {
    if (!canReset) return;

    setErrMsg("");
    setInfoMsg("");
    setLoading(true);
    setStep("resetting");
    try {
      await axios.post("/admin/auth/reset", {
        email: emailNorm,
        code: codeNorm,
        password: pwTrimmed,
      });

      setStep("done");
      setInfoMsg(t("auth.forgot.passwordUpdated"));

      props.onSuccess();
    } catch (e) {
      const err = e as AxiosError<any>;
      setErrMsg(pickErrorMessage(err, t, "auth.forgot.resetFailed"));
      setStep("sent");
      window.setTimeout(() => codeRef.current?.focus(), 50);
    } finally {
      setLoading(false);
    }
  };

  const startEditEmail = () => {
    setErrMsg("");
    setInfoMsg("");
    setEditingEmail(true);
    setStep("request");
    setCode("");
    setNewPassword("");
    window.setTimeout(() => emailRef.current?.focus(), 50);
  };

  return (
    <AuthShell>
      <Card
        elevation={0}
        sx={{
          borderRadius: 2.5,
          border: "1px solid",
          borderColor: "divider",
          bgcolor: "background.paper",
          overflow: "hidden",
        }}
      >
        <CardContent sx={{ p: { xs: 3, sm: 4 } }}>
            <Stack spacing={2.25}>
              <Stack spacing={0.5}>
                <Typography
                  sx={{
                    fontFamily: "var(--font-sans)",
                    fontSize: 34,
                    fontWeight: 500,
                    letterSpacing: "-0.025em",
                    lineHeight: 1.15,
                    fontOpticalSizing: "auto",
                    pb: "2px",
                  }}
                >
                  {t("auth.forgot.title")}
                </Typography>
                <Typography variant="body1" color="text.secondary">
                  {t("auth.forgot.description")}
                </Typography>
              </Stack>

              {editingEmail ? (
                <TextField
                  inputRef={emailRef}
                  label={t("auth.email")}
                  placeholder={t("auth.emailPlaceholder")}
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    if (errMsg) setErrMsg("");
                    if (infoMsg) setInfoMsg("");
                  }}
                  autoComplete="email"
                  fullWidth
                  disabled={loading}
                  error={email.length > 0 && !emailOk}
                  helperText={
                    email.length === 0
                      ? t("auth.forgot.emailHelper")
                      : !emailOk
                        ? t("auth.emailInvalid")
                        : t("auth.forgot.willSendCode")
                  }
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      if (emailOk) sendCode();
                    }
                  }}
                />
              ) : (
                <Box
                  sx={{
                    border: "1px solid",
                    borderColor: "divider",
                    borderRadius: 2.5,
                    p: 1.5,
                    bgcolor: "background.paper",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 1.5,
                  }}
                >
                  <Box sx={{ minWidth: 0 }}>
                    <Typography variant="caption" color="text.secondary">
                      {t("auth.email")}
                    </Typography>
                    <Typography variant="body2" sx={{ fontWeight: 600, wordBreak: "break-all" }}>
                      {emailNorm || "-"}
                    </Typography>
                  </Box>

                  <Button
                    variant="text"
                    size="small"
                    onClick={startEditEmail}
                    disabled={loading}
                    startIcon={<SquarePen size={14} strokeWidth={1.75} />}
                   
                  >
                    {t("common.change")}
                  </Button>
                </Box>
              )}

              {infoMsg ? (
                <Box
                  sx={{
                    borderRadius: 2.5,
                    border: "1px solid",
                    borderColor: "divider",
                    bgcolor: "rgba(2,132,199,0.06)",
                    px: 1.75,
                    py: 1.25,
                  }}
                >
                  <Typography variant="body2">{infoMsg}</Typography>
                </Box>
              ) : null}

              {errMsg ? (
                <Box
                  sx={{
                    borderRadius: 2.5,
                    border: "1px solid",
                    borderColor: "error.main",
                    bgcolor: "rgba(211,47,47,0.08)",
                    px: 1.75,
                    py: 1.25,
                  }}
                >
                  <Typography variant="body2" sx={{ color: "error.main" }}>
                    {errMsg}
                  </Typography>
                </Box>
              ) : null}

              {showResetFields ? (
                <Stack spacing={2}>
                  <TextField
                    inputRef={codeRef}
                    label={t("auth.forgot.verificationCode")}
                    placeholder={t("auth.forgot.codePlaceholder")}
                    value={code}
                    onChange={(e) => {
                      setCode(e.target.value);
                      if (errMsg) setErrMsg("");
                      if (infoMsg) setInfoMsg("");
                    }}
                    fullWidth
                    disabled={loading}
                    autoComplete="one-time-code"
                    inputProps={{ inputMode: "numeric", maxLength: 6 }}
                    error={code.length > 0 && !codeOk}
                    helperText={t("auth.forgot.codeHelper")}
                  />

                  <TextField
                    label={t("auth.forgot.newPassword")}
                    type="password"
                    value={newPassword}
                    onChange={(e) => {
                      setNewPassword(e.target.value);
                      if (errMsg) setErrMsg("");
                      if (infoMsg) setInfoMsg("");
                    }}
                    fullWidth
                    disabled={loading}
                    autoComplete="new-password"
                    error={newPassword.length > 0 && !pwOk}
                    helperText={
                      newPassword.length === 0
                        ? t("auth.forgot.minChars", { count: minAdminPasswordLen })
                        : !pwOk
                          ? t("auth.forgot.passwordTooShort", { count: minAdminPasswordLen })
                          : t("auth.register.passwordValid")
                    }
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        resetPassword();
                      }
                    }}
                  />

                  <Button
                    variant="contained"
                    disabled={!canReset}
                    onClick={resetPassword}
                    sx={{ borderRadius: 2.5 }}
                    endIcon={loading ? <CircularProgress size={18} color="inherit" /> : undefined}
                  >
                    {step === "resetting" ? t("auth.forgot.resetting") : t("auth.forgot.resetPassword")}
                  </Button>
                </Stack>
              ) : (
                <Typography variant="body2" color="text.secondary">
                  {t("auth.forgot.enterEmailFirst")}
                </Typography>
              )}

              <Typography variant="caption" color="text.secondary">
                {t("auth.forgot.rememberedPassword")}{" "}
                <Link to="/app/login" style={{ color: "inherit" }}>
                  {t("auth.forgot.backToSignIn")}
                </Link>
                .
              </Typography>
            </Stack>
          </CardContent>

          {showSendButton ? (
            <CardActions sx={{ px: { xs: 3, sm: 4 }, pb: { xs: 3, sm: 4 }, flexDirection: "column", gap: 2, alignItems: "stretch" }}>
              {turnstileSiteKey && (
                <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 1 }}>
                  <Typography variant="caption" color="text.secondary">
                    {t("auth.turnstilePrompt")}
                  </Typography>
                  <Turnstile
                    key="forgot"
                    ref={turnstileRef}
                    siteKey={turnstileSiteKey}
                    onVerify={setTurnstileToken}
                    onExpire={() => setTurnstileToken("")}
                    onError={() => setTurnstileToken("")}
                  />
                </Box>
              )}
              <Button
                variant="contained"
                fullWidth
                disabled={!canSend}
                onClick={sendCode}
                sx={{ borderRadius: 2.5 }}
                startIcon={<Send size={14} strokeWidth={1.75} />}
                endIcon={loading ? <CircularProgress size={18} color="inherit" /> : undefined}
              >
                {loading ? t("auth.forgot.sendingCode") : t("auth.forgot.sendCode")}
            </Button>
          </CardActions>
        ) : null}
      </Card>
    </AuthShell>
  );
}
