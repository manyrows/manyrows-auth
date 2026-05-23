// Register.tsx
import {
  Alert,
  Box,
  Button,
  Card,
  CardActions,
  CardContent,
  CircularProgress,
  Collapse,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { UserPlus } from "lucide-react";
import axios, { AxiosError } from "axios";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, Navigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import AuthShell from "./components/AuthShell";
import Turnstile, { useTurnstileSiteKey, type TurnstileHandle } from "./components/Turnstile";
import { useAdminAuthConfig, resetAdminAuthConfigCache } from "./hooks/useAdminAuthConfig";

const LAST_EMAIL_KEY = "manyrows:lastEmail";

function normalizeEmail(v: string): string {
  return (v || "").trim().toLowerCase();
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

function pickErrorMessage(err: AxiosError<AuthErrorBody | string | undefined>, t: (key: string) => string): string {
  if (err.response?.status === 409) return t("auth.register.alreadyRegistered");
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
  return t("auth.register.failed");
}

interface Props {
  onSuccess: () => void;
}

export default function Register(props: Props) {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [errMsg, setErrMsg] = useState<string>("");

  // Cloudflare Turnstile (bot challenge on register)
  const [turnstileToken, setTurnstileToken] = useState("");
  const turnstileRef = useRef<TurnstileHandle>(null);
  const { siteKey: turnstileSiteKey } = useTurnstileSiteKey();
  const authCfg = useAdminAuthConfig();

  const emailRef = useRef<HTMLInputElement>(null);
  const passRef = useRef<HTMLInputElement>(null);

  // Registration is closed once the first admin has been claimed.
  // Redirect direct-link visitors back to login so the page doesn't
  // dangle as a dead-end (the backend would 403 the POST anyway).
  // Wait until authCfg has loaded before deciding.
  const registrationClosed = !!authCfg && !authCfg.needsFirstAdmin;

  useEffect(() => {
    try {
      const saved = localStorage.getItem(LAST_EMAIL_KEY);
      if (saved) setEmail(saved);
    } catch {
      // ignore
    }
    window.setTimeout(() => emailRef.current?.focus(), 50);
  }, []);

  // These hooks must run unconditionally on every render — keep them above the
  // early return below, or React throws "rendered fewer hooks than expected"
  // when registrationClosed flips after authCfg loads.
  const emailTrimmed = normalizeEmail(email);
  const emailOk = useMemo(() => validateEmail(emailTrimmed), [emailTrimmed]);

  const pwTrimmed = password.trim();
  const pwOk = useMemo(() => pwTrimmed.length >= 10, [pwTrimmed]);

  if (registrationClosed) {
    return <Navigate to="/app/login" replace />;
  }

  // Only require a Turnstile token when the operator has Turnstile
  // configured - when site key isn't published the widget never
  // renders, so we can't (and shouldn't) wait for a token.
  const canSubmit = emailOk && pwOk && (!turnstileSiteKey || !!turnstileToken) && !loading;

  const submit = async () => {
    if (!canSubmit) return;

    setErrMsg("");
    setLoading(true);
    try {
      await axios.post("/admin/auth/register", {
        email: emailTrimmed,
        password: pwTrimmed,
        turnstileToken,
      });

      try {
        localStorage.setItem(LAST_EMAIL_KEY, emailTrimmed);
      } catch {
        // ignore
      }

      // Force /admin/auth/config to refetch - the just-registered
      // account flipped needsFirstAdmin to false. Without this the
      // banner / first-boot register-default would linger across
      // a logout-then-revisit cycle.
      resetAdminAuthConfigCache();

      props.onSuccess();
    } catch (e) {
      const err = e as AxiosError<any>;
      setErrMsg(pickErrorMessage(err, t));
      // Turnstile tokens are single-use; refresh on failure so the user can retry.
      setTurnstileToken("");
      turnstileRef.current?.reset();
    } finally {
      setLoading(false);
    }
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
            <Collapse in={!!errMsg} timeout={180} unmountOnExit>
              <Alert severity="error" sx={{ borderRadius: 2.5, mb: 2.25 }} onClose={() => setErrMsg("")}>
                {errMsg}
              </Alert>
            </Collapse>

            {/* ✅ Real form for autofill + Enter submit */}
            <Box
              component="form"
              onSubmit={(e) => {
                e.preventDefault();
                submit();
              }}
              noValidate
            >
              <Stack spacing={2.25}>
                <Stack spacing={0.5}>
                  <Typography
                    sx={{
                      fontFamily: "var(--font-serif)",
                      fontSize: 34,
                      fontWeight: 500,
                      letterSpacing: "-0.025em",
                      lineHeight: 1.15,
                      fontOpticalSizing: "auto",
                      pb: "2px",
                    }}
                  >
                    {t("auth.register.title")}
                  </Typography>
                </Stack>

                {authCfg?.needsFirstAdmin && (
                  <Box sx={{marginBottom:4}}>
                  <Alert severity="info" sx={{ borderRadius: 2.5 }}>
                    {t("auth.register.firstAdmin", {
                      defaultValue:
                        "First time here - whoever registers next becomes the super admin for this install.",
                    })}
                  </Alert>
                  </Box>
                )}

                <TextField
                  inputRef={emailRef}
                  label={t("auth.email")}
                  placeholder={t("auth.emailPlaceholder")}
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    if (errMsg) setErrMsg("");
                  }}
                  autoComplete="email"
                  fullWidth
                  disabled={loading}
                  error={email.length > 0 && !emailOk}
                  helperText={
                    email.length === 0
                      ? t("auth.register.emailHelper")
                      : !emailOk
                        ? t("auth.emailInvalid")
                        : t("auth.register.emailValid")
                  }
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      passRef.current?.focus();
                    }
                  }}
                />

                <TextField
                  inputRef={passRef}
                  label={t("auth.password")}
                  type="password"
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (errMsg) setErrMsg("");
                  }}
                  autoComplete="new-password"
                  fullWidth
                  disabled={loading}
                  error={password.length > 0 && !pwOk}
                  helperText={
                    password.length === 0
                      ? t("auth.register.passwordHelper")
                      : !pwOk
                        ? t("auth.register.passwordTooShort")
                        : t("auth.register.passwordValid")
                  }
                />

                {!authCfg?.needsFirstAdmin && (
                  // First-admin install: no other accounts exist yet,
                  // so a "sign in" link would dead-end.
                  <Typography variant="caption" color="text.secondary">
                    {t("auth.register.hasAccount")}{" "}
                    <Link to="/app/login" style={{ color: "inherit" }}>
                      {t("auth.signIn")}
                    </Link>
                    .
                  </Typography>
                )}

                {turnstileSiteKey && (
                  <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 1 }}>
                    <Typography variant="caption" color="text.secondary">
                      Let us know you are human
                    </Typography>
                    <Turnstile
                      key="register"
                      ref={turnstileRef}
                      siteKey={turnstileSiteKey}
                      onVerify={setTurnstileToken}
                      onExpire={() => setTurnstileToken("")}
                      onError={() => setTurnstileToken("")}
                    />
                  </Box>
                )}

                {/* Keep inside form so Enter submits naturally */}
                <Button
                  type="submit"
                  variant="contained"
                  size="large"
                  fullWidth
                  disabled={!canSubmit}
                  sx={{ py: 1.2, borderRadius: 2.5 }}
                  startIcon={<UserPlus size={14} strokeWidth={1.75} />}
                  endIcon={loading ? <CircularProgress size={18} color="inherit" /> : undefined}
                >
                  {loading ? t("auth.register.submitting") : t("auth.register.submit")}
                </Button>
              </Stack>
            </Box>
        </CardContent>

        {/* No longer needed for the submit button, but leaving structure intact */}
        <CardActions sx={{ display: "none" }} />
      </Card>

      <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 2, textAlign: "center" }}>
        {t("auth.register.termsPrefix", { defaultValue: "By continuing, you agree to the" })}{" "}
        <a
          href="https://manyrows.com/legal"
          target="_blank"
          rel="noopener noreferrer"
          style={{ color: "inherit", textDecoration: "underline" }}
        >
          {t("auth.register.termsLink", { defaultValue: "terms" })}
        </a>
        .
      </Typography>
    </AuthShell>
  );
}
