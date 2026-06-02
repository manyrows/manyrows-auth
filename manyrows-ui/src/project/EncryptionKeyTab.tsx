import * as React from "react";
import axios from "axios";
import { useSnackbar } from "notistack";
import { extractApiError } from "../lib/apiError.ts";
import {
  Alert,
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
  Paper,
  Stack,
  Step,
  StepContent,
  StepLabel,
  Stepper,
  TextField,
  Typography,
} from "@mui/material";
import { Check, Copy, KeyRound, Save } from "lucide-react";
import { useTranslation } from "react-i18next";
import { codeTheme } from "../colors.ts";

type TFunc = (key: string, opts?: Record<string, unknown>) => string;

interface Props {
  workspaceId: string;
  onSaved?: () => void;
}

type PublicKeyRecord = {
  id: string;
  createdAt: string;
  publicKeyJwk: JsonWebKey;
  fingerprint: string;
};

type WorkspaceKeyResponse = {
  key: PublicKeyRecord | null;
};

const mono = 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Monaco, Consolas, monospace';

function CodeBlock({ title, code, lang, t }: { title?: string; code: string; lang?: string; t: TFunc }) {
  const [copied, setCopied] = React.useState(false);

  const copy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <Box
      sx={{
        borderRadius: 2.5,
        overflow: "hidden",
        border: "1px solid rgba(0,0,0,0.08)",
        bgcolor: codeTheme.bg,
      }}
    >
      {title && (
        <Stack
          direction="row"
          justifyContent="space-between"
          alignItems="center"
          sx={{
            px: 2,
            py: 1,
            borderBottom: "1px solid rgba(255,255,255,0.06)",
            bgcolor: "rgba(0,0,0,0.2)",
          }}
        >
          <Stack direction="row" spacing={1} alignItems="center">
            <Typography sx={{ fontSize: 12, color: "rgba(255,255,255,0.5)", fontWeight: 500 }}>
              {title}
            </Typography>
            {lang && (
              <Chip
                label={lang}
                size="small"
                sx={{
                  height: 18,
                  bgcolor: "rgba(255,255,255,0.08)",
                  color: "rgba(255,255,255,0.6)",
                  "& .MuiChip-label": { px: 1, fontSize: 10, fontWeight: 600 },
                }}
              />
            )}
          </Stack>
          <Button
            size="small"
            onClick={copy}
            sx={{
              minWidth: 0,
              px: 1,
              color: copied ? "rgb(134, 239, 172)" : "rgba(255,255,255,0.5)",
              fontSize: 11,
              "&:hover": { bgcolor: "rgba(255,255,255,0.05)" },
            }}
            startIcon={
              copied ? (
                <Check size={14} strokeWidth={1.75} />
              ) : (
                <Copy size={14} strokeWidth={1.75} />
              )
            }
          >
            {copied ? t("common.copied") : t("common.copy")}
          </Button>
        </Stack>
      )}
      <Box
        component="pre"
        sx={{
          m: 0,
          p: 2,
          fontSize: 13,
          lineHeight: 1.6,
          fontFamily: mono,
          color: codeTheme.text,
          overflow: "auto",
          "&::-webkit-scrollbar": { height: 6 },
          "&::-webkit-scrollbar-thumb": { bgcolor: "rgba(255,255,255,0.1)", borderRadius: 3 },
        }}
      >
        {code}
      </Box>
    </Box>
  );
}

function assertWebCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error("WebCrypto not available in this browser context");
  return subtle;
}

function utf8Bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const subtle = assertWebCrypto();
  const digest = await subtle.digest("SHA-256", bytes as BufferSource);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) {
    hex += arr[i].toString(16).padStart(2, "0");
  }
  return hex;
}

function canonicalizePublicJwk(jwk: JsonWebKey): string {
  const obj: Record<string, unknown> = {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
  };
  const keys = Object.keys(obj).sort();
  const sorted: Record<string, unknown> = {};
  for (const k of keys) sorted[k] = obj[k];
  return JSON.stringify(sorted);
}

function shortFingerprint(hex: string): string {
  if (!hex) return "-";
  if (hex.length <= 28) return hex;
  return `${hex.slice(0, 14)}…${hex.slice(-14)}`;
}

async function generateEcdhP256Keypair(): Promise<{
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
  fingerprintHex: string;
}> {
  const subtle = assertWebCrypto();
  const keyPair = await subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"]
  );
  const publicJwk = (await subtle.exportKey("jwk", keyPair.publicKey)) as JsonWebKey;
  const privateJwk = (await subtle.exportKey("jwk", keyPair.privateKey)) as JsonWebKey;
  const canon = canonicalizePublicJwk(publicJwk);
  const fingerprintHex = await sha256Hex(utf8Bytes(canon));
  return { publicJwk, privateJwk, fingerprintHex };
}

const ENVELOPE_SHAPE = `{
  "v": 1,
  "alg": "ECDH-P256+HKDF-SHA256+AES-256-GCM",
  "fingerprintSha256": "abc123...",
  "ephemeralPublicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "ivB64": "...",
  "ciphertextB64": "..."
}`;

function SdkPointers({ t }: { t: TFunc }) {
  return (
    <Card>
      <CardContent>
        <Stack spacing={2}>
          <Box>
            <Typography variant="h6">{t("encryption.sdk.title")}</Typography>
            <Typography variant="body2" color="text.secondary">
              {t("encryption.sdk.description")}
            </Typography>
          </Box>

          <Alert severity="info">
            <b>{t("encryption.sdk.scheme")}</b>
            <br />
            {t("encryption.sdk.schemeDescription")}
          </Alert>

          <Box>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>
              {t("encryption.sdk.envelopeFormat")}
            </Typography>
            <CodeBlock title={t("encryption.sdk.envelopeStructure")} lang="json" code={ENVELOPE_SHAPE} t={t} />
          </Box>

          <Box>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>
              {t("encryption.sdk.helpers")}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              {t("encryption.sdk.helpersNote")}
            </Typography>
            <Typography variant="body2" color="text.secondary" component="div">
              <Box component="ul" sx={{ m: 0, pl: 3 }}>
                <li>
                  <b>Go</b> -{" "}
                  <a href="https://github.com/manyrows/manyrows-go" target="_blank" rel="noreferrer">
                    github.com/manyrows/manyrows-go
                  </a>
                  {" · "}
                  <code>secrets.Decrypt(envelope, privateKeyJSON)</code>
                  {" "}
                  <span style={{ opacity: 0.7 }}>(go get)</span>
                </li>
                <li>
                  <b>Node / TypeScript</b> -{" "}
                  <a href="https://github.com/manyrows/manyrows-node" target="_blank" rel="noreferrer">
                    github.com/manyrows/manyrows-node
                  </a>
                  {" · "}
                  <code>decryptSecret(envelope, privateKeyJwk)</code>
                </li>
                <li>
                  <b>Python</b> -{" "}
                  <a href="https://github.com/manyrows/manyrows-python" target="_blank" rel="noreferrer">
                    github.com/manyrows/manyrows-python
                  </a>
                  {" · "}
                  <code>decrypt_secret(envelope, private_key_jwk)</code>
                </li>
                <li>
                  <b>Java</b> -{" "}
                  <a href="https://github.com/manyrows/manyrows-java" target="_blank" rel="noreferrer">
                    github.com/manyrows/manyrows-java
                  </a>
                  {" · "}
                  <code>Secrets.decryptSecret(envelope, privateKeyJwkJson)</code>
                </li>
              </Box>
            </Typography>
          </Box>

          <Alert severity="warning">{t("encryption.sdk.securityReminder")}</Alert>
        </Stack>
      </CardContent>
    </Card>
  );
}

export default function EncryptionKeyTab({ workspaceId, onSaved }: Props) {
  const { enqueueSnackbar } = useSnackbar();
  const { t } = useTranslation();

  const [saving, setSaving] = React.useState(false);
  const [generating, setGenerating] = React.useState(false);

  const [activeKey, setActiveKey] = React.useState<PublicKeyRecord | null>(null);

  const [generatedPublicJwk, setGeneratedPublicJwk] = React.useState<JsonWebKey | null>(null);
  const [generatedPrivateJwk, setGeneratedPrivateJwk] = React.useState<JsonWebKey | null>(null);
  const [generatedFingerprintHex, setGeneratedFingerprintHex] = React.useState("");
  const [generatedCreatedAt, setGeneratedCreatedAt] = React.useState("");

  const [showPrivateDialog, setShowPrivateDialog] = React.useState(false);
  const [privateCopied, setPrivateCopied] = React.useState(false);
  const [savedThisSession, setSavedThisSession] = React.useState(false);

  const [activeStep, setActiveStep] = React.useState(0);

  const saveButtonRef = React.useRef<HTMLButtonElement | null>(null);

  async function load() {
    try {
      const res = await axios.get<WorkspaceKeyResponse>(
        `/admin/workspace/${workspaceId}/encryption-key`
      );
      setActiveKey(res.data.key);
    } catch {
      setActiveKey(null);
    }
  }

  React.useEffect(() => {
    void load();
  }, [workspaceId]);

  const hasActive = !!activeKey;
  const hasGenerated = !!generatedPublicJwk && !!generatedPrivateJwk;

  React.useEffect(() => {
    if (hasActive && !hasGenerated && !savedThisSession) {
      setActiveStep(3);
      return;
    }
    if (savedThisSession) {
      setActiveStep(3);
      return;
    }
    if (!hasGenerated) {
      setActiveStep(0);
      return;
    }
    if (!privateCopied) {
      setActiveStep(1);
      return;
    }
    setActiveStep(2);
  }, [hasActive, hasGenerated, privateCopied, savedThisSession]);

  async function generateKeypair() {
    setGenerating(true);
    try {
      const { publicJwk, privateJwk, fingerprintHex } = await generateEcdhP256Keypair();
      setGeneratedPublicJwk(publicJwk);
      setGeneratedPrivateJwk(privateJwk);
      setGeneratedFingerprintHex(fingerprintHex);
      setGeneratedCreatedAt(new Date().toISOString());
      setPrivateCopied(false);
      setSavedThisSession(false);
      setShowPrivateDialog(true);
      enqueueSnackbar(t("encryption.snackbar.generated"), { variant: "success" });
    } catch (err) {
      enqueueSnackbar(extractApiError(err, t("encryption.snackbar.generateFailed")), { variant: "error" });
    } finally {
      setGenerating(false);
    }
  }

  function privateKeyCopyText(): string {
    if (!generatedPrivateJwk) return "";
    return JSON.stringify({ privateKeyJwk: generatedPrivateJwk }, null, 2);
  }

  async function copyPrivateKey() {
    const text = privateKeyCopyText();
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setPrivateCopied(true);
      setShowPrivateDialog(false);
      enqueueSnackbar(t("encryption.snackbar.copied"), { variant: "success" });
      setTimeout(() => {
        saveButtonRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
      }, 150);
    } catch {
      enqueueSnackbar(t("encryption.snackbar.clipboardBlocked"), { variant: "warning" });
    }
  }

  async function savePublicKey() {
    if (!generatedPublicJwk || !privateCopied) return;
    setSaving(true);
    try {
      await axios.post(`/admin/workspace/${workspaceId}/encryption-key`, {
        publicKeyJwk: generatedPublicJwk,
        fingerprintSha256: generatedFingerprintHex,
      });
      enqueueSnackbar(t("encryption.snackbar.saved"), { variant: "success" });
      setSavedThisSession(true);
      setGeneratedPublicJwk(null);
      setGeneratedPrivateJwk(null);
      setGeneratedFingerprintHex("");
      setGeneratedCreatedAt("");
      setPrivateCopied(false);
      await load();
      onSaved?.();
    } catch {
      enqueueSnackbar(t("encryption.snackbar.saveFailed"), { variant: "error" });
    } finally {
      setSaving(false);
    }
  }

  function resetFlow() {
    setGeneratedPublicJwk(null);
    setGeneratedPrivateJwk(null);
    setGeneratedFingerprintHex("");
    setGeneratedCreatedAt("");
    setPrivateCopied(false);
    setSavedThisSession(false);
    setShowPrivateDialog(false);
    setActiveStep(0);
  }

  const steps = [
    {
      label: t("encryption.step1.label"),
      description: t("encryption.step1.description"),
      content: (
        <Stack spacing={1}>
          <Button
            variant="contained"
            onClick={generateKeypair}
            disabled={generating || saving}
            startIcon={generating ? <CircularProgress size={18} /> : <KeyRound size={14} strokeWidth={1.75} />}
            sx={{ alignSelf: "flex-start" }}
          >
            {t("encryption.step1.button")}
          </Button>
          {hasGenerated && (
            <Alert severity="success">
              {t("encryption.step1.success", { fingerprint: shortFingerprint(generatedFingerprintHex) })}
            </Alert>
          )}
        </Stack>
      ),
      canContinue: hasGenerated,
    },
    {
      label: t("encryption.step2.label"),
      description: t("encryption.step2.description"),
      content: (
        <Stack spacing={1}>
          <Button
            variant={privateCopied ? "contained" : "outlined"}
            color={privateCopied ? "success" : "primary"}
            onClick={() => setShowPrivateDialog(true)}
            disabled={!hasGenerated}
            startIcon={<Copy size={14} strokeWidth={1.75} />}
            sx={{ alignSelf: "flex-start" }}
          >
            {privateCopied ? t("encryption.step2.copied") : t("encryption.step2.view")}
          </Button>
          {!privateCopied && hasGenerated && (
            <Alert severity="warning">{t("encryption.step2.required")}</Alert>
          )}
        </Stack>
      ),
      canContinue: privateCopied,
    },
    {
      label: t("encryption.step3.label"),
      description: t("encryption.step3.description"),
      content: (
        <Stack spacing={1}>
          <Button
            ref={saveButtonRef}
            variant="contained"
            onClick={savePublicKey}
            disabled={!hasGenerated || !privateCopied || saving || generating}
            startIcon={saving ? <CircularProgress size={18} /> : <Save size={14} strokeWidth={1.75} />}
            sx={{
              alignSelf: "flex-start",
              boxShadow: privateCopied ? (theme) => `0 0 0 3px ${theme.palette.primary.main}33` : undefined,
            }}
          >
            {t("encryption.step3.button")}
          </Button>
          {hasActive && !hasGenerated && (
            <Alert severity="success">
              {t("encryption.step3.active")}
              <br />
              {t("encryption.dialog.fingerprint")} <code>{shortFingerprint(activeKey?.fingerprint || "")}</code>
            </Alert>
          )}
        </Stack>
      ),
      canContinue: false,
    },
  ];

  return (
    <Box>
      <Stack spacing={2}>
        <Stack direction="row" spacing={1} alignItems="center">
          <Box>
            <Typography variant="h6">{t("encryption.title")}</Typography>
          </Box>
        </Stack>

        <Alert severity="info">
          {t("encryption.intro")}
          <br />
          <br />
          <b>{t("encryption.trustModel")}</b>
        </Alert>

        <Card>
          <CardContent>
            <Typography>{t("encryption.setup")}</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              {t("encryption.setupDescription")}
            </Typography>

            <Box sx={{ maxWidth: 720 }}>
              <Stepper activeStep={activeStep} orientation="vertical">
                {steps.map((step, index) => (
                  <Step key={step.label}>
                    <StepLabel
                      optional={
                        index === 2 ? (
                          <Typography variant="caption">
                            {hasActive && !hasGenerated ? t("encryption.alreadyConfigured") : t("encryption.finalStep")}
                          </Typography>
                        ) : null
                      }
                    >
                      {step.label}
                    </StepLabel>
                    <StepContent>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        {step.description}
                      </Typography>
                      {step.content}
                      <Box sx={{ mb: 2 }}>
                        <Button
                          variant="contained"
                          onClick={() => setActiveStep((s) => Math.min(s + 1, 3))}
                          sx={{ mt: 1, mr: 1 }}
                          disabled={
                            (index === 0 && !steps[0].canContinue) ||
                            (index === 1 && !steps[1].canContinue) ||
                            index === 2
                          }
                        >
                          {t("encryption.continue")}
                        </Button>
                        <Button
                          disabled={index === 0}
                          onClick={() => setActiveStep((s) => Math.max(s - 1, 0))}
                          sx={{ mt: 1, mr: 1 }}
                        >
                          {t("encryption.back")}
                        </Button>
                      </Box>
                    </StepContent>
                  </Step>
                ))}
              </Stepper>

              {activeStep === 3 && (
                <Paper square elevation={0} sx={{ p: 2, mt: 1, borderRadius: 2 }}>
                  <Stack spacing={1}>
                    <Typography>{t("encryption.complete.title")}</Typography>
                    <Typography variant="body2" color="text.secondary">
                      {t("encryption.complete.description")}
                    </Typography>
                    {hasActive && (
                      <Typography variant="body2">
                        {t("encryption.dialog.fingerprint")} <code>{shortFingerprint(activeKey?.fingerprint || "")}</code>
                      </Typography>
                    )}
                    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                      <Button onClick={resetFlow} sx={{ mt: 1, mr: 1 }}>
                        {t("encryption.startOver")}
                      </Button>
                      <Button onClick={load} sx={{ mt: 1, mr: 1 }}>
                        {t("encryption.refresh")}
                      </Button>
                    </Stack>
                    <Alert severity="warning" sx={{ mt: 1 }}>
                      {t("encryption.rotateWarning")}
                    </Alert>
                  </Stack>
                </Paper>
              )}
            </Box>
          </CardContent>
        </Card>

        <SdkPointers t={t} />
      </Stack>

      <Dialog open={showPrivateDialog} onClose={() => setShowPrivateDialog(false)} fullWidth maxWidth="md">
        <DialogTitle>{t("encryption.dialog.title")}</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>
            {t("encryption.dialog.warning")}
          </Alert>

          <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
            <Typography sx={{ mb: 1 }}>{t("encryption.dialog.metadata")}</Typography>
            <Typography variant="body2" color="text.secondary">
              {t("encryption.dialog.metadataNote")}
            </Typography>
            <Stack spacing={0.5} sx={{ mt: 1 }}>
              <Typography variant="body2">
                <b>{t("encryption.dialog.fingerprint")}</b>{" "}
                <code>{shortFingerprint(generatedFingerprintHex)}</code>
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {t("encryption.dialog.created")} {generatedCreatedAt || "-"}
              </Typography>
            </Stack>
          </Paper>

          <Typography sx={{ mb: 0.5 }}>{t("encryption.dialog.privateKey")}</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            {t("encryption.dialog.privateKeyNote")}
          </Typography>

          <TextField
            value={privateKeyCopyText()}
            multiline
            minRows={12}
            fullWidth
            slotProps={{ input: { readOnly: true } }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowPrivateDialog(false)}>{t("encryption.dialog.close")}</Button>
          <Button
            onClick={copyPrivateKey}
            startIcon={<Copy size={14} strokeWidth={1.75} />}
            variant={privateCopied ? "contained" : "outlined"}
            color={privateCopied ? "success" : "primary"}
            disabled={!hasGenerated}
          >
            {privateCopied ? t("common.copied") : t("encryption.dialog.copy")}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
