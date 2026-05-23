// Login.tsx
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
import { ArrowLeft, Lock, LogIn } from "lucide-react";
import axios, { AxiosError } from "axios";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import AuthShell from "./components/AuthShell";
import Turnstile, { useTurnstileSiteKey, type TurnstileHandle } from "./components/Turnstile";
import { useAdminAuthConfig } from "./hooks/useAdminAuthConfig";
import LanguagePicker from "./components/LanguagePicker";

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
  if (err.response?.status === 401) return t("auth.invalidCredentials");
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
  return t("auth.loginFailed");
}

interface Props {
  onSuccess: () => void;
}

export default function Login(props: Props) {
  const { t } = useTranslation();
  const authCfg = useAdminAuthConfig();
  // Public sign-up is open only until the first admin is claimed;
  // additional admins arrive via invite. Hide the "Create account"
  // link once that's happened so we don't dangle a dead-end action.
  const showRegisterLink = !!authCfg && authCfg.needsFirstAdmin;
  const [loading, setLoading] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [errMsg, setErrMsg] = useState<string>("");

  // TOTP step
  const [totpStep, setTotpStep] = useState(false);
  const [challengeToken, setChallengeToken] = useState("");
  const [totpCode, setTotpCode] = useState("");

  // Cloudflare Turnstile (bot challenge on login)
  const [turnstileToken, setTurnstileToken] = useState("");
  const turnstileRef = useRef<TurnstileHandle>(null);
  const { siteKey: turnstileSiteKey } = useTurnstileSiteKey();

  const emailRef = useRef<HTMLInputElement>(null);
  const passRef = useRef<HTMLInputElement>(null);
  const totpRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    try {
      const saved = localStorage.getItem(LAST_EMAIL_KEY);
      if (saved) setEmail(saved);
    } catch {
      // ignore
    }
    window.setTimeout(() => emailRef.current?.focus(), 50);
  }, []);

  useEffect(() => {
    if (totpStep) {
      window.setTimeout(() => totpRef.current?.focus(), 50);
    }
  }, [totpStep]);

  const emailTrimmed = normalizeEmail(email);
  const emailOk = useMemo(() => validateEmail(emailTrimmed), [emailTrimmed]);

  const pwTrimmed = password.trim();
  const pwOk = useMemo(() => pwTrimmed.length > 0, [pwTrimmed]);

  // Only require a Turnstile token when the operator has Turnstile
  // configured - when site key isn't published the widget never
  // renders, so we can't (and shouldn't) wait for a token.
  const canSubmit = emailOk && pwOk && (!turnstileSiteKey || !!turnstileToken) && !loading;
  const canSubmitTotp = totpCode.trim().length >= 6 && !loading;

  const submit = async () => {
    if (!canSubmit) return;

    setErrMsg("");
    setLoading(true);
    try {
      const res = await axios.post("/admin/auth/login", {
        email: emailTrimmed,
        password: pwTrimmed,
        turnstileToken,
      });

      try {
        localStorage.setItem(LAST_EMAIL_KEY, emailTrimmed);
      } catch {
        // ignore
      }

      // Check if TOTP is required
      if (res.data?.totpRequired && res.data?.challengeToken) {
        setChallengeToken(res.data.challengeToken);
        setTotpCode("");
        setTotpStep(true);
        return;
      }

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

  const submitTotp = async () => {
    if (!canSubmitTotp) return;

    setErrMsg("");
    setLoading(true);
    try {
      await axios.post("/admin/auth/totp/verify", {
        challengeToken,
        code: totpCode.trim(),
      });
      props.onSuccess();
    } catch (e) {
      const err = e as AxiosError<any>;
      if (err.response?.status === 401) {
        const msg = err.response?.data?.message;
        if (msg && typeof msg === "string" && msg.includes("expired")) {
          setErrMsg(t("auth.totp.challengeExpired"));
        } else {
          setErrMsg(t("auth.totp.invalidCode"));
        }
      } else {
        setErrMsg(pickErrorMessage(err, t));
      }
    } finally {
      setLoading(false);
    }
  };

  const backToLogin = () => {
    setTotpStep(false);
    setChallengeToken("");
    setTotpCode("");
    setErrMsg("");
  };

  return (
    <AuthShell>
      <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 1.5 }}>
        <LanguagePicker />
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
            <Collapse in={!!errMsg} timeout={180} unmountOnExit>
              <Alert severity="error" sx={{ borderRadius: 2.5, mb: 2.25 }} onClose={() => setErrMsg("")}>
                {errMsg}
              </Alert>
            </Collapse>

            {!totpStep ? (
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
                      {t("auth.signIn")}
                    </Typography>
                  </Stack>

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
                        ? t("auth.emailHelper")
                        : !emailOk
                          ? t("auth.emailInvalid")
                          : t("auth.emailPressEnter")
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
                    autoComplete="current-password"
                    fullWidth
                    disabled={loading}
                  />

                  <Stack spacing={0.5}>
                    <Typography variant="caption" color="text.secondary">
                      <Link to="/app/forgot" style={{ color: "inherit" }}>
                        {t("auth.forgotPassword")}
                      </Link>
                    </Typography>

                    {showRegisterLink && (
                      <Typography variant="caption" color="text.secondary">
                        {t("auth.noAccount")}{" "}
                        <Link to="/app/register" style={{ color: "inherit" }}>
                          {t("auth.createAccount")}
                        </Link>
                        .
                      </Typography>
                    )}
                  </Stack>

                  {turnstileSiteKey && (
                    <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 1 }}>
                      <Typography variant="caption" color="text.secondary">
                        {t("auth.turnstilePrompt")}
                      </Typography>
                      <Turnstile
                        key="login"
                        ref={turnstileRef}
                        siteKey={turnstileSiteKey}
                        onVerify={setTurnstileToken}
                        onExpire={() => setTurnstileToken("")}
                        onError={() => setTurnstileToken("")}
                      />
                    </Box>
                  )}

                  <Button
                    type="submit"
                    variant="contained"
                    size="large"
                    fullWidth
                    disabled={!canSubmit}
                    sx={{ py: 1.2, borderRadius: 2.5 }}
                    startIcon={<LogIn size={14} strokeWidth={1.75} />}
                    endIcon={loading ? <CircularProgress size={18} color="inherit" /> : undefined}
                  >
                    {loading ? t("auth.signingIn") : t("auth.signIn")}
                  </Button>
                </Stack>
              </Box>
            ) : (
              /* ---- TOTP verification step ---- */
              <Box
                component="form"
                onSubmit={(e) => {
                  e.preventDefault();
                  submitTotp();
                }}
                noValidate
              >
                <Stack spacing={2.25}>
                  <Stack spacing={0.5}>
                    <Typography
                      sx={{
                        fontFamily: "var(--font-serif)",
                        fontSize: 30,
                        fontWeight: 500,
                        letterSpacing: "-0.025em",
                        lineHeight: 1.15,
                        fontOpticalSizing: "auto",
                        pb: "2px",
                      }}
                    >
                      {t("auth.totp.title")}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {t("auth.totp.description")}
                    </Typography>
                  </Stack>

                  <TextField
                    inputRef={totpRef}
                    label={t("auth.totp.code")}
                    placeholder="000000"
                    value={totpCode}
                    onChange={(e) => {
                      setTotpCode(e.target.value.replace(/[^a-zA-Z0-9]/g, "").slice(0, 8));
                      if (errMsg) setErrMsg("");
                    }}
                    autoComplete="one-time-code"
                    fullWidth
                    disabled={loading}
                    inputProps={{ inputMode: "numeric", maxLength: 8 }}
                    helperText={t("auth.totp.codeHelper")}
                  />

                  <Button
                    type="submit"
                    variant="contained"
                    size="large"
                    fullWidth
                    disabled={!canSubmitTotp}
                    sx={{ py: 1.2, borderRadius: 2.5 }}
                    startIcon={<Lock size={14} strokeWidth={1.75} />}
                    endIcon={loading ? <CircularProgress size={18} color="inherit" /> : undefined}
                  >
                    {loading ? t("auth.totp.verifying") : t("auth.totp.verify")}
                  </Button>

                  <Button
                    variant="text"
                    size="small"
                    onClick={backToLogin}
                    disabled={loading}
                    startIcon={<ArrowLeft size={14} strokeWidth={1.75} />}
                    sx={{ alignSelf: "flex-start" }}
                  >
                    {t("auth.totp.backToLogin")}
                  </Button>
                </Stack>
              </Box>
            )}
        </CardContent>

        <CardActions sx={{ display: "none" }} />
      </Card>
    </AuthShell>
  );
}
