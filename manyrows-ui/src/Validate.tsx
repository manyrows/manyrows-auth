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
import { MailCheck } from "lucide-react";
import type { Account } from "./core.ts";
import { useTranslation } from "react-i18next";
import AuthShell from "./components/AuthShell";

type TFunc = (key: string, opts?: Record<string, unknown>) => string;

interface Props {
  onSuccess: () => void;
  account: Account;
}

function normalizeEmail(v: string): string {
  return (v || "").trim().toLowerCase();
}

function normalizeCode(v: string): string {
  // keep digits only, so "123 456" or "123-456" works
  return (v || "").trim().replace(/[^\d]/g, "");
}

function sanitizeErrorMsg(msg: string): string {
  const clean = msg.replace(/<[^>]*>/g, "");
  return clean.length > 200 ? clean.slice(0, 200) + "\u2026" : clean;
}

type ValidateApiBody = {
  issues?: { message?: string }[];
  message?: string;
  error?: string;
};

function pickErrorMessage(err: AxiosError<ValidateApiBody | string | undefined>, fallback: string, t: TFunc): string {
  const status = err.response?.status;

  if (status === 401) return t("validate.error.invalidCode");
  if (status === 429) return t("validate.error.tooManyAttempts");
  if (status === 400) return t("validate.error.invalidFormat");

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
  return fallback;
}

export default function Validate(props: Props) {
  const { account, onSuccess } = props;
  const { t } = useTranslation();

  const email = React.useMemo(() => normalizeEmail(account?.email || ""), [account?.email]);

  const [step, setStep] = React.useState<"intro" | "sent" | "verifying" | "done">("intro");
  const [loading, setLoading] = React.useState(false);

  const [code, setCode] = React.useState("");
  const [errMsg, setErrMsg] = React.useState<string>("");

  const codeRef = React.useRef<HTMLInputElement>(null);

  const codeNorm = React.useMemo(() => normalizeCode(code), [code]);
  const codeOk = React.useMemo(() => codeNorm.length === 6, [codeNorm]);
  const canVerify = codeOk && !loading;

  const focusCodeSoon = React.useCallback(() => {
    window.setTimeout(() => codeRef.current?.focus(), 50);
  }, []);

  const send = React.useCallback(async () => {
    if (loading) return;

    if (!email) {
      setErrMsg(t("validate.error.missingEmail"));
      return;
    }

    setErrMsg("");
    setLoading(true);
    try {
      // Server uses logged-in account; body is ignored (safe to omit)
      await axios.post("/admin/auth/validate");

      setStep("sent");
      focusCodeSoon();
    } catch (e) {
      const err = e as AxiosError<any>;
      setErrMsg(pickErrorMessage(err, t("validate.error.sendFailed"), t));
    } finally {
      setLoading(false);
    }
  }, [email, focusCodeSoon, loading, t]);

  const verify = React.useCallback(async () => {
    if (!canVerify) return;

    setErrMsg("");
    setLoading(true);
    setStep("verifying");
    try {
      // Server verifies code for logged-in account; do not send email
      await axios.post("/admin/auth/verify", { code: codeNorm });

      setStep("done");
      onSuccess();
    } catch (e) {
      const err = e as AxiosError<any>;
      setErrMsg(pickErrorMessage(err, t("validate.error.verifyFailed"), t));
      setStep("sent");
      focusCodeSoon();
    } finally {
      setLoading(false);
    }
  }, [canVerify, codeNorm, focusCodeSoon, onSuccess, t]);

  const onChangeCode = (v: string) => {
    // keep raw input in state, but we’ll normalize for validation
    setCode(v);
    if (errMsg) setErrMsg("");
  };

  const isSent = step === "sent" || step === "verifying";
  const isDone = step === "done";

  return (
    <AuthShell>
      <Box sx={{ display: "flex", justifyContent: "center", mb: 2 }}>
        <Stack direction="row" spacing={1} alignItems="center" sx={{ color: "text.disabled" }}>
          <MailCheck size={14} strokeWidth={1.75} />
          <Typography
            sx={{
              fontFamily: "var(--font-mono)",
              textTransform: "uppercase",
              letterSpacing: "0.16em",
              fontSize: 10,
              fontWeight: 500,
            }}
          >
            {t("validate.title")}
          </Typography>
        </Stack>
      </Box>
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
            <Stack spacing={2}>
              <Stack spacing={0.5}>
                <Typography
                  sx={{
                    fontFamily: "var(--font-serif)",
                    fontSize: 28,
                    fontWeight: 500,
                    letterSpacing: "-0.025em",
                    lineHeight: 1.15,
                    fontOpticalSizing: "auto",
                    pb: "2px",
                  }}
                >
                  {t("validate.heading")}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {t("validate.description")}
                </Typography>
              </Stack>

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
                    {t("validate.email")}
                  </Typography>
                  <Typography variant="body2" sx={{ fontWeight: 600, wordBreak: "break-all" }}>
                    {email || "-"}
                  </Typography>
                </Box>
              </Box>

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

              {isSent ? (
                <Stack spacing={1.5}>
                  <TextField
                    inputRef={codeRef}
                    label={t("validate.codeLabel")}
                    placeholder={t("validate.codePlaceholder")}
                    value={code}
                    onChange={(e) => onChangeCode(e.target.value)}
                    fullWidth
                    disabled={loading}
                    autoComplete="one-time-code"
                    inputProps={{
                      inputMode: "numeric",
                      pattern: "[0-9]*",
                      maxLength: 8, // allow spaces/dashes; normalized anyway
                    }}
                    helperText={t("validate.codeHelper")}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        verify();
                      }
                    }}
                  />

                  <Stack direction={{ xs: "column", sm: "row" }} spacing={1} justifyContent="space-between">
                    <Button
                      variant="contained"
                      disabled={!canVerify}
                      onClick={verify}
                      sx={{ borderRadius: 2.5 }}
                      endIcon={loading ? <CircularProgress size={18} color="inherit" /> : undefined}
                    >
                      {step === "verifying" ? t("validate.verifying") : t("validate.verify")}
                    </Button>
                  </Stack>
                </Stack>
              ) : (
                <Typography variant="body2" color="text.secondary">
                  {t("validate.sendPrompt")}
                </Typography>
              )}
            </Stack>
          </CardContent>

          <CardActions sx={{ px: { xs: 2.5, sm: 3 }, pb: { xs: 2.5, sm: 3 } }}>
            {isSent ? (
              <Button variant="outlined" fullWidth disabled sx={{ borderRadius: 2.5 }}>
                {t("validate.codeSent")}
              </Button>
            ) : (
              <Button
                variant="contained"
                fullWidth
                disabled={loading || !email}
                onClick={send}
                sx={{ borderRadius: 2.5 }}
                endIcon={loading ? <CircularProgress size={18} color="inherit" /> : undefined}
              >
                {loading ? t("validate.sending") : isDone ? t("validate.verified") : t("validate.sendCode")}
            </Button>
          )}
        </CardActions>
      </Card>
    </AuthShell>
  );
}
