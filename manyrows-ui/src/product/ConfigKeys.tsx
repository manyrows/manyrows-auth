import * as React from "react";
import axios from "axios";
import { extractApiError } from "../lib/apiError.ts";
import { useSnackbar } from "notistack";
import { useTranslation, Trans } from "react-i18next";

type TFunc = (key: string, opts?: Record<string, unknown>) => string;
import type { ConfigExposure, ConfigKey, ConfigValue, ConfigValueType, App, Product, Workspace } from "../core.ts";
import { appTypeLabel } from "../core.ts";
import { alpha } from "../colors.ts";
import EncryptionKeyTab from "./EncryptionKeyTab.tsx";
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Collapse,
  Divider,
  FormControlLabel,
  IconButton,
  InputAdornment,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Paper,
  Stack,
  Switch,
  Tab,
  Tabs,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { CircleCheck, Copy, Download, Lightbulb, Plus, RefreshCw, Save, Search, Settings, Trash2, TriangleAlert, X } from "lucide-react";
import PageHeader from "../components/PageHeader.tsx";
import StatusChip from "../components/StatusChip.tsx";
const tc = { code: <code />, b: <b />, strong: <strong /> };

function isValidKey(k: string): boolean {
  const s = (k || "").trim();
  if (!s) return false;
  // allow letters, numbers, underscore, dash, dot
  return /^[A-Za-z0-9_.-]+$/.test(s);
}

function deriveGroupFromKey(key: string): string {
  // Group by prefix before first underscore, e.g. "STRIPE_PUBLIC_KEY" -> "Stripe"
  const idx = key.indexOf("_");
  if (idx > 0) {
    const prefix = key.slice(0, idx);
    // Title case: STRIPE -> Stripe
    return prefix.charAt(0).toUpperCase() + prefix.slice(1).toLowerCase();
  }
  // If key has dots, use first segment: "api.base.url" -> "Api"
  const dotIdx = key.indexOf(".");
  if (dotIdx > 0) {
    const prefix = key.slice(0, dotIdx);
    return prefix.charAt(0).toUpperCase() + prefix.slice(1).toLowerCase();
  }
  return "General";
}

function groupConfigKeys(keys: ConfigKey[]): Map<string, ConfigKey[]> {
  const groups = new Map<string, ConfigKey[]>();
  for (const k of keys) {
    const group = deriveGroupFromKey(k.key);
    if (!groups.has(group)) {
      groups.set(group, []);
    }
    groups.get(group)!.push(k);
  }
  // Sort groups alphabetically, but put "General" last
  const sorted = new Map<string, ConfigKey[]>();
  const sortedKeys = [...groups.keys()].sort((a, b) => {
    if (a === "General") return 1;
    if (b === "General") return -1;
    return a.localeCompare(b);
  });
  for (const gk of sortedKeys) {
    sorted.set(gk, groups.get(gk)!);
  }
  return sorted;
}

function getValueTypes(t: TFunc): Array<{ value: ConfigValueType; label: string; hint: string }> {
  return [
    { value: "string", label: t("configKeys.valueType.string"), hint: t("configKeys.valueType.stringHint") },
    { value: "int", label: t("configKeys.valueType.int"), hint: t("configKeys.valueType.intHint") },
    { value: "decimal", label: t("configKeys.valueType.decimal"), hint: t("configKeys.valueType.decimalHint") },
    { value: "bool", label: t("configKeys.valueType.bool"), hint: t("configKeys.valueType.boolHint") },
    { value: "string[]", label: t("configKeys.valueType.stringArray"), hint: t("configKeys.valueType.stringArrayHint") },
    { value: "int[]", label: t("configKeys.valueType.intArray"), hint: t("configKeys.valueType.intArrayHint") },
    { value: "decimal[]", label: t("configKeys.valueType.decimalArray"), hint: t("configKeys.valueType.decimalArrayHint") },
    { value: "bool[]", label: t("configKeys.valueType.boolArray"), hint: t("configKeys.valueType.boolArrayHint") },
    { value: "json", label: t("configKeys.valueType.json"), hint: t("configKeys.valueType.jsonHint") },
  ];
}

function isJsonTextType(t: ConfigValueType): boolean {
  return t.endsWith("[]") || t === "json";
}

function prettyExposure(e: string, t: TFunc): string {
  if (e === "public") return t("configKeys.exposure.public");
  if (e === "private") return t("configKeys.exposure.private");
  if (e === "secret") return t("configKeys.exposure.secret");
  return e || "-";
}

function exposureDescription(e: string, t: TFunc): string {
  if (e === "public") {
    return t("configKeys.exposure.publicDesc");
  }
  if (e === "private") {
    return t("configKeys.exposure.privateDesc");
  }
  if (e === "secret") {
    return t("configKeys.exposure.secretDesc");
  }
  return t("configKeys.exposure.defaultDesc");
}

function typeLabel(vt: string, t: TFunc): string {
  const types = getValueTypes(t);
  const hit = types.find((x) => x.value === vt);
  return hit ? hit.label : vt || "-";
}

function typeHint(vt: string, t: TFunc): string {
  const types = getValueTypes(t);
  const hit = types.find((x) => x.value === vt);
  return hit ? hit.hint : "";
}

function isProdApp(app: App | null | undefined): boolean {
  if (!app) return false;
  return app.type === "prod";
}

function safeValueJsonFromConfigValue(v: unknown): unknown {
  // Supports older shapes too.
  // - new: { valueJson: ... }
  // - old: { value: ... }
  if (!v || typeof v !== "object") return undefined;
  const obj = v as Record<string, unknown>;
  if (Object.prototype.hasOwnProperty.call(obj, "valueJson")) return obj.valueJson;
  if (Object.prototype.hasOwnProperty.call(obj, "value")) return obj.value;
  return undefined;
}

function formatScalarForInput(value: unknown, t: ConfigValueType): string {
  if (value === undefined) return "";
  if (value === null) return "";
  if (t === "string") return String(value);
  if (t === "int" || t === "decimal") return String(value);
  return String(value);
}

function formatJsonForTextarea(value: unknown): string {
  if (value === undefined) return "";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return "";
  }
}

function parseAndValidate(rawText: string, vt: ConfigValueType, t: TFunc): { ok: boolean; value?: any; error?: string } {
  if (vt === "string") {
    return { ok: true, value: rawText };
  }

  if (vt === "bool") {
    return { ok: false, error: t("configKeys.validation.boolNotText") };
  }

  if (vt === "int") {
    const s = (rawText ?? "").trim();
    if (s === "") return { ok: false, error: t("configKeys.validation.enterInteger") };
    const n = Number(s);
    if (!Number.isFinite(n)) return { ok: false, error: t("configKeys.validation.invalidNumber") };
    if (!Number.isInteger(n)) return { ok: false, error: t("configKeys.validation.mustBeInteger") };
    return { ok: true, value: n };
  }

  if (vt === "decimal") {
    const s = (rawText ?? "").trim();
    if (s === "") return { ok: false, error: t("configKeys.validation.enterNumber") };
    const n = Number(s);
    if (!Number.isFinite(n)) return { ok: false, error: t("configKeys.validation.invalidNumber") };
    return { ok: true, value: n };
  }

  const txt = (rawText ?? "").trim();
  if (!txt) return { ok: false, error: t("configKeys.validation.enterJson") };

  let parsed: any;
  try {
    parsed = JSON.parse(txt);
  } catch {
    return { ok: false, error: t("configKeys.validation.invalidJson") };
  }
  if (parsed === null) return { ok: false, error: t("configKeys.validation.nullNotAllowed") };

  switch (vt) {
    case "string[]":
      if (!Array.isArray(parsed)) return { ok: false, error: t("configKeys.validation.mustBeArray") };
      if (!parsed.every((x) => typeof x === "string")) return { ok: false, error: t("configKeys.validation.allStrings") };
      return { ok: true, value: parsed };

    case "bool[]":
      if (!Array.isArray(parsed)) return { ok: false, error: t("configKeys.validation.mustBeArray") };
      if (!parsed.every((x) => typeof x === "boolean")) return { ok: false, error: t("configKeys.validation.allBooleans") };
      return { ok: true, value: parsed };

    case "int[]":
      if (!Array.isArray(parsed)) return { ok: false, error: t("configKeys.validation.mustBeArray") };
      if (!parsed.every((x) => typeof x === "number" && Number.isFinite(x) && Number.isInteger(x))) {
        return { ok: false, error: t("configKeys.validation.allIntegers") };
      }
      return { ok: true, value: parsed };

    case "decimal[]":
      if (!Array.isArray(parsed)) return { ok: false, error: t("configKeys.validation.mustBeArray") };
      if (!parsed.every((x) => typeof x === "number" && Number.isFinite(x))) {
        return { ok: false, error: t("configKeys.validation.allNumbers") };
      }
      return { ok: true, value: parsed };

    case "json":
      return { ok: true, value: parsed };

    default:
      return { ok: false, error: t("configKeys.validation.unsupportedType") };
  }
}

function ExposureInfoAlert(props: { exposure: ConfigExposure; secretReady: boolean; t: TFunc }) {
  const { exposure, secretReady } = props;

  if (exposure === "public") {
    return (
      <Alert severity="info">
        <Trans i18nKey="configKeys.exposureInfo.public" components={tc} />
      </Alert>
    );
  }

  if (exposure === "secret") {
    return (
      <Alert severity={secretReady ? "warning" : "error"}>
        <Stack spacing={0.5}>
          <Typography variant="body2"><Trans i18nKey="configKeys.exposureInfo.secret" components={tc} /></Typography>
          {!secretReady ? (
            <Typography variant="body2"><Trans i18nKey="configKeys.exposureInfo.secretSetup" components={tc} /></Typography>
          ) : null}
        </Stack>
      </Alert>
    );
  }

  return (
    <Alert severity="info">
      <Trans i18nKey="configKeys.exposureInfo.private" components={tc} />
    </Alert>
  );
}

function ConfigKeysAbout(props: { secretReady: boolean; expanded: boolean; onToggle: () => void; t: TFunc }) {
  const { secretReady, expanded, onToggle, t } = props;

  return (
    <Paper variant="outlined">
      <Box
        sx={{
          px: 2,
          py: 1.5,
          display: "flex",
          alignItems: "center",
          gap: 1,
          cursor: "pointer",
          "&:hover": { bgcolor: "action.hover" },
        }}
        onClick={onToggle}
      >
        <Box component="span" sx={{ color: "info.main" }}><Lightbulb size={14} strokeWidth={1.75} /></Box>
        <Typography variant="body2" sx={{ flex: 1 }}><Trans i18nKey="configKeys.about.title" components={tc} /></Typography>
        <Button
          size="small"
          variant="outlined"
          onClick={(e) => { e.stopPropagation(); onToggle(); }}
          sx={{ minWidth: 0, py: 0.25, px: 1.25, fontSize: 12, textTransform: "none" }}
        >
          {expanded ? t("configKeys.about.hide") : t("configKeys.about.learnMore")}
        </Button>
      </Box>
      <Collapse in={expanded}>
        <Divider />
        <Box sx={{ px: 2, py: 1.25 }}>
          <Stack spacing={0.5}>
            <Typography variant="caption" color="text.secondary" sx={{ mb: 0.25 }}>
              <Trans i18nKey="configKeys.about.exposureControls" components={tc} />
            </Typography>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
              <StatusChip label={t("configKeys.exposure.public")} severity="primary" />
              <Typography variant="caption" color="text.secondary">{t("configKeys.about.publicSafe")}</Typography>
            </Stack>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
              <StatusChip label={t("configKeys.exposure.private")} />
              <Typography variant="caption" color="text.secondary">{t("configKeys.about.privateServer")}</Typography>
            </Stack>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
              <StatusChip label={t("configKeys.exposure.secret")} severity="warning" />
              <Typography variant="caption" color="text.secondary">{t("configKeys.about.secretEncrypted")}</Typography>
            </Stack>
            {!secretReady && (
              <Alert severity="warning" sx={{ mt: 0.75, py: 0.25 }}>
                {t("configKeys.about.secretsRequire")}
              </Alert>
            )}
          </Stack>
        </Box>
      </Collapse>
    </Paper>
  );
}

type DraftEntry = {
  isUnset: boolean;

  // bool (switch)
  boolValue?: boolean;

  // scalar typed text input (string/int/decimal)
  scalarText?: string;

  // JSON textarea input (arrays/json)
  jsonText?: string;

  // local validation state
  error?: string | null;
};

type PublicKeyRecord = {
  id: string;
  createdAt: string;
  publicKeyJwk: JsonWebKey;
  fingerprint: string;
};

type WorkspaceKeyResponse = {
  key: PublicKeyRecord | null;
};

// ---------------------
// Browser encryption (secret envelope)
// ---------------------

type SecretEnvelopeV1 = {
  v: 1;
  alg: "ECDH-P256+HKDF-SHA256+AES-256-GCM";
  fingerprintSha256: string;
  ephemeralPublicKeyJwk: JsonWebKey;
  ivB64: string;
  ciphertextB64: string;
};

function assertWebCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error("WebCrypto not available in this browser context");
  return subtle;
}

type U8 = Uint8Array<ArrayBuffer>;

function utf8Bytes(s: string): U8 {
  const u8 = new TextEncoder().encode(s); // Uint8Array (typed as ArrayBufferLike in some TS versions)
  // Copy into a new Uint8Array backed by an actual ArrayBuffer, then assert the generic.
  return new Uint8Array(u8) as U8;
}

function b64EncodeBytes(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function bytesFromArrayBuffer(buf: ArrayBuffer): Uint8Array {
  return new Uint8Array(buf);
}

async function importWorkspacePublicKeyEcdhP256(jwk: JsonWebKey): Promise<CryptoKey> {
  const subtle = assertWebCrypto();
  return await subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    [] // public key usage
  );
}

async function generateEphemeralEcdhP256(): Promise<CryptoKeyPair> {
  const subtle = assertWebCrypto();
  return await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
}

async function deriveAesGcmKeyFromEcdh(sharedSecret: ArrayBuffer, fingerprintSha256: string): Promise<CryptoKey> {
  const subtle = assertWebCrypto();

  // HKDF over the ECDH shared secret:
  // - salt: fixed domain separator
  // - info: fingerprint (bind ciphertext to the active workspace key)
  const hkdfKey = await subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);

  return await subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: utf8Bytes("manyrows:secrets:v1"),
      info: utf8Bytes(`workspace-fingerprint:${fingerprintSha256}`),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
}

async function encryptSecretValueToEnvelope(
  value: unknown,
  workspacePublicJwk: JsonWebKey,
  fingerprintSha256: string
): Promise<SecretEnvelopeV1> {
  const subtle = assertWebCrypto();

  // Plaintext bytes (JSON)
  const plaintextJson = JSON.stringify(value);
  const plaintext = utf8Bytes(plaintextJson);

  // ECDH (ephemeral)
  const wsPub = await importWorkspacePublicKeyEcdhP256(workspacePublicJwk);
  const eph = await generateEphemeralEcdhP256();

  const ephPubJwk = (await subtle.exportKey("jwk", eph.publicKey)) as JsonWebKey;

  // P-256 -> 256-bit shared secret
  const shared = await subtle.deriveBits({ name: "ECDH", public: wsPub }, eph.privateKey, 256);

  // AES-256-GCM key via HKDF
  const aesKey = await deriveAesGcmKeyFromEcdh(shared, fingerprintSha256);

  // AES-GCM encrypt
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);

  const ctBuf = await subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plaintext);
  const ct = bytesFromArrayBuffer(ctBuf);

  return {
    v: 1,
    alg: "ECDH-P256+HKDF-SHA256+AES-256-GCM",
    fingerprintSha256,
    ephemeralPublicKeyJwk: ephPubJwk,
    ivB64: b64EncodeBytes(iv),
    ciphertextB64: b64EncodeBytes(ct),
  };
}

// ---------------------
// Export helpers
// ---------------------

function downloadFile(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function escapeCsvField(value: string): string {
  if (value.includes(",") || value.includes('"') || value.includes("\n")) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

// ---------------------
// Component
// ---------------------

interface Props {
  project: Product;
  workspace: Workspace;
  appId?: string;
}

export default function ConfigKeys({ project, appId: fixedAppId }: Props) {
  const { t } = useTranslation();
  const { enqueueSnackbar } = useSnackbar();

  const base = `/admin/workspace/${project.workspaceId}/products/${project.id}`;

  const [loading, setLoading] = React.useState<boolean>(false);
  const [saving, setSaving] = React.useState<boolean>(false);
  const [error, setError] = React.useState<string | null>(null);

  // Workspace encryption key (public) for secrets
  const [workspaceEncKey, setWorkspaceEncKey] = React.useState<PublicKeyRecord | null>(null);

  // Apps MUST be displayed exactly as returned from the API (no extra labels)
  const [apps, setApps] = React.useState<App[]>([]);
  const [keys, setKeys] = React.useState<ConfigKey[]>([]);
  const [values, setValues] = React.useState<ConfigValue[]>([]);

  // Keep as string (not null) so MUI select behaves predictably
  const [selectedAppId, setSelectedAppId] = React.useState<string>(fixedAppId || "");

  React.useEffect(() => {
    if (fixedAppId) setSelectedAppId(fixedAppId);
  }, [fixedAppId]);

  const secretReady = !!workspaceEncKey?.publicKeyJwk && !!workspaceEncKey?.fingerprint;

  const keysTotal = keys.length;
  const editLocked = false;

  // Prod confirm dialog state
  const [prodConfirmOpen, setProdConfirmOpen] = React.useState(false);
  const [pendingAppId, setPendingAppId] = React.useState<string>("");

  // Draft state is per (configKeyId, appId)
  const [draft, setDraft] = React.useState<Record<string, DraftEntry>>({});
  const [dirty, setDirty] = React.useState<Set<string>>(new Set());

  // Create key dialog state
  const [createOpen, setCreateOpen] = React.useState(false);
  const [createKey, setCreateKey] = React.useState("");
  const [createDescription, setCreateDescription] = React.useState<string>("");
  const [createExposure, setCreateExposure] = React.useState<ConfigExposure>("private");
  const [createValueType, setCreateValueType] = React.useState<ConfigValueType>("string");

  // Delete key dialog state
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [selectedKey, setSelectedKey] = React.useState<ConfigKey | null>(null);

  // Search
  const [searchQuery, setSearchQuery] = React.useState("");

  // Top-level tab: 0 = config keys, 1 = workspace encryption key
  const [tabIndex, setTabIndex] = React.useState(0);

  // Help section expanded - persisted in localStorage so users don't
  // have to re-collapse it on every visit.
  const [helpExpanded, setHelpExpanded] = React.useState<boolean>(() => {
    try {
      return localStorage.getItem("manyrows:configKeys:helpExpanded") === "1";
    } catch {
      return false;
    }
  });
  React.useEffect(() => {
    try {
      localStorage.setItem("manyrows:configKeys:helpExpanded", helpExpanded ? "1" : "0");
    } catch {
      // ignore quota / private mode
    }
  }, [helpExpanded]);

  // Export menu
  const [exportAnchorEl, setExportAnchorEl] = React.useState<null | HTMLElement>(null);
  const exportMenuOpen = Boolean(exportAnchorEl);

  function handleExportCsv() {
    setExportAnchorEl(null);
    const appNames = apps.map((e) => appTypeLabel(e));
    const header = ["Key", "Description", "Exposure", "ValueType", "Status", ...appNames];
    const rows: string[][] = [];

    for (const k of keys) {
      const row: string[] = [
        k.key,
        k.description || "",
        k.exposure || "",
        k.valueType || "",
        k.status || "",
      ];
      for (const app of apps) {
        const v = values.find((cv) => cv.configKeyId === k.id && cv.appId === app.id);
        if (!v) {
          row.push("");
        } else if (k.exposure === "secret") {
          row.push("(secret)");
        } else {
          try {
            row.push(v.value !== undefined && v.value !== null ? JSON.stringify(v.value) : "");
          } catch {
            row.push("");
          }
        }
      }
      rows.push(row);
    }

    const csv = [header.map(escapeCsvField).join(","), ...rows.map((r) => r.map(escapeCsvField).join(","))].join("\n");
    downloadFile(csv, `config-keys-${project.id}.csv`, "text/csv;charset=utf-8");
  }

  function handleExportJson() {
    setExportAnchorEl(null);
    const result = {
      configKeys: keys.map((k) => {
        const vals: Record<string, unknown> = {};
        for (const app of apps) {
          const v = values.find((cv) => cv.configKeyId === k.id && cv.appId === app.id);
          if (!v) continue;
          if (k.exposure === "secret") continue;
          vals[appTypeLabel(app)] = v.value !== undefined ? v.value : null;
        }
        return {
          key: k.key,
          description: k.description || null,
          exposure: k.exposure,
          valueType: k.valueType,
          status: k.status,
          values: vals,
        };
      }),
    };
    downloadFile(JSON.stringify(result, null, 2), `config-keys-${project.id}.json`, "application/json");
  }

  function snackError(msg: string) {
    enqueueSnackbar(msg, { variant: "error" });
  }

  function snackSuccess(msg: string) {
    enqueueSnackbar(msg, { variant: "success" });
  }

  async function apiJson<T>(
    path: string,
    init?: {
      method?: string;
      data?: unknown;
      params?: Record<string, unknown>;
      headers?: Record<string, string>;
    }
  ): Promise<T> {
    try {
      const res = await axios.request({
        url: path,
        method: init?.method || "GET",
        data: init?.data,
        params: init?.params,
        headers: init?.headers,
        withCredentials: true,
        validateStatus: () => true,
      });

      if (res.status < 200 || res.status >= 300) {
        throw Object.assign(new Error(res.statusText || "Request failed"), {
          isAxiosError: true,
          response: res,
        });
      }

      if (res.status === 204 || res.status === 205) {
        return null as unknown as T;
      }

      return (res.data ?? null) as T;
    } catch (e) {
      throw new Error(extractApiError(e));
    }
  }

  async function loadWorkspaceEncryptionKey() {
    try {
      const res = await apiJson<WorkspaceKeyResponse>(`/admin/workspace/${project.workspaceId}/encryption-key`);
      setWorkspaceEncKey(res?.key ?? null);
    } catch {
      // If endpoint not ready or returns error, treat as not set (UI still works for non-secret)
      setWorkspaceEncKey(null);
    }
  }

  async function refreshAll(opts?: { showSuccess?: boolean }) {
    setLoading(true);
    setError(null);
    try {
      const [envRes, keyRes, valRes] = await Promise.all([
        apiJson<{ apps: App[] }>(`${base}/apps`),
        apiJson<{ configKeys: ConfigKey[] }>(`${base}/configKeys`),
        apiJson<{ configValues: ConfigValue[] }>(`${base}/configValues`),
      ]);

      const nextApps = envRes?.apps || [];
      const nextKeys = keyRes?.configKeys || [];
      const nextVals = valRes?.configValues || [];

      setApps(nextApps);
      setKeys(nextKeys);
      setValues(nextVals || []);

      // Ensure selected app stays valid (default to first returned app)
      setSelectedAppId((prev) => {
        if (fixedAppId) return fixedAppId;
        if (prev && nextApps.some((e) => e.id === prev)) return prev;
        return nextApps.length > 0 ? nextApps[0].id : "";
      });

      // Clear drafts
      setDraft({});
      setDirty(new Set());
      setSelectedKey(null);
      setPendingAppId("");
      setProdConfirmOpen(false);

      // Also refresh workspace encryption key (non-blocking)
      void loadWorkspaceEncryptionKey();

      if (opts?.showSuccess) snackSuccess(t("configKeys.snackbar.refreshed"));
    } catch (e) {
      const msg = extractApiError(e, t("configKeys.snackbar.loadFailed"));
      setError(msg);
      snackError(msg);
    } finally {
      setLoading(false);
    }
  }

  React.useEffect(() => {
    void refreshAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [project.id]);

  // Helpers
  function keyAppId(configKeyId: string, appId: string) {
    return `${configKeyId}::${appId}`;
  }

  function findValue(configKeyId: string, appId: string): ConfigValue | null {
    return values.find((v) => v.configKeyId === configKeyId && v.appId === appId) || null;
  }

  function getDraftForSelectedApp(configKeyId: string): DraftEntry {
    if (!selectedAppId) return { isUnset: false, scalarText: "", error: null };
    const id = keyAppId(configKeyId, selectedAppId);
    return draft[id] || { isUnset: false, scalarText: "", error: null };
  }

  function markDirty(id: string) {
    setDirty((prev) => {
      const out = new Set(prev);
      out.add(id);
      return out;
    });
  }

  function setDraftForSelectedApp(configKeyId: string, next: Partial<DraftEntry>) {
    if (!selectedAppId) return;
    const id = keyAppId(configKeyId, selectedAppId);

    setDraft((prev) => {
      const cur: DraftEntry = prev[id] || { isUnset: false, scalarText: "", error: null };
      const updated: DraftEntry = { ...cur, ...next };

      // If unset toggled on, clear value fields
      if (updated.isUnset) {
        updated.boolValue = undefined;
        updated.scalarText = undefined;
        updated.jsonText = undefined;
        updated.error = null;
      }

      return { ...prev, [id]: updated };
    });

    markDirty(id);
  }

  function clearDirty(id: string) {
    setDirty((prev) => {
      if (!prev.has(id)) return prev;
      const next = new Set(prev);
      next.delete(id);
      return next;
    });
  }

  function clearDraft(id: string) {
    setDraft((prev) => {
      if (!prev[id]) return prev;
      const next = { ...prev };
      delete next[id];
      return next;
    });
    clearDirty(id);
  }

  async function handleCreateKey() {
    setError(null);

    const k = createKey.trim();

    if (!isValidKey(k)) {
      const msg = t("configKeys.snackbar.invalidKey");
      setError(msg);
      snackError(msg);
      return;
    }

    const desc = createDescription.trim();
    const descOrNull = desc ? desc : null;

    try {
      await apiJson<{ configKey: ConfigKey }>(`${base}/configKeys`, {
        method: "POST",
        data: {
          key: k,
          description: descOrNull,
          exposure: createExposure,
          valueType: createValueType,
          status: "active",
        },
      });

      setCreateOpen(false);
      setCreateKey("");
      setCreateDescription("");
      setCreateExposure("private");
      setCreateValueType("string");

      snackSuccess(t("configKeys.snackbar.created"));
      await refreshAll();
    } catch (e) {
      const msg = extractApiError(e, t("configKeys.snackbar.createFailed"));
      setError(msg);
      snackError(msg);
    }
  }

  async function handleDeleteKey() {
    if (!selectedKey) return;
    setError(null);
    try {
      await apiJson(`${base}/configKeys/${selectedKey.id}`, { method: "DELETE" });
      setDeleteOpen(false);
      setSelectedKey(null);
      snackSuccess(t("configKeys.snackbar.deleted"));
      await refreshAll();
    } catch (e) {
      const msg = extractApiError(e, t("configKeys.snackbar.deleteFailed"));
      setError(msg);
      snackError(msg);
    }
  }

  function openDelete(k: ConfigKey) {
    setSelectedKey(k);
    setDeleteOpen(true);
  }

  function closeDelete() {
    setDeleteOpen(false);
    setSelectedKey(null);
  }

  function ensureDraftInitializedForSelectedApp(k: ConfigKey) {
    if (!selectedAppId) return;
    const id = keyAppId(k.id, selectedAppId);
    if (draft[id]) return;

    const v = findValue(k.id, selectedAppId);
    const exposure = (k.exposure as ConfigExposure) || "private";
    const vt = (k.valueType as ConfigValueType) || "string";

    // For secrets: we never prefill anything, but we DO want the row existence check to work via values list.
    const existingValue = safeValueJsonFromConfigValue(v);

    const initial: DraftEntry = {
      isUnset: false,
      error: null,
    };

    if (vt === "bool") {
      initial.boolValue = exposure !== "secret" && typeof existingValue === "boolean" ? existingValue : false;
    } else if (isJsonTextType(vt)) {
      initial.jsonText = exposure !== "secret" && v ? formatJsonForTextarea(existingValue) : "";
    } else {
      initial.scalarText = exposure !== "secret" && v ? formatScalarForInput(existingValue, vt) : "";
    }

    setDraft((prev) => ({ ...prev, [id]: initial }));
  }

  // Initialize drafts for all keys when selectedAppId or keys change
  React.useEffect(() => {
    if (!selectedAppId) return;
    for (const k of keys) {
      ensureDraftInitializedForSelectedApp(k);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedAppId, keys]);

  function valueRowExistsForApp(k: ConfigKey, appId: string): boolean {
    if (!appId) return false;
    return !!findValue(k.id, appId);
  }

  function validateDraftForKey(k: ConfigKey, d: DraftEntry): { ok: boolean; value?: any; error?: string } {
    const vt = (k.valueType as ConfigValueType) || "string";

    if (d.isUnset) return { ok: true, value: undefined };

    if (vt === "bool") {
      return { ok: true, value: !!d.boolValue };
    }

    if (isJsonTextType(vt)) {
      const res = parseAndValidate(d.jsonText ?? "", vt, t);
      if (!res.ok) return { ok: false, error: res.error || t("configKeys.validation.invalidValue") };
      return { ok: true, value: res.value };
    }

    const res = parseAndValidate(d.scalarText ?? "", vt, t);
    if (!res.ok) return { ok: false, error: res.error || t("configKeys.validation.invalidValue") };
    return { ok: true, value: res.value };
  }

  async function saveOne(configKeyId: string) {
    if (!selectedAppId) return;
    if (editLocked) return;

    const appId = selectedAppId;
    const id = keyAppId(configKeyId, appId);
    const k = keys.find((kk) => kk.id === configKeyId);
    if (!k) return;

    const d = draft[id];
    if (!d) return;

    setSaving(true);
    setError(null);

    try {
      // Unset always wins
      if (d.isUnset) {
        await apiJson(`${base}/configKeys/${configKeyId}/apps/${appId}`, { method: "DELETE" });
        clearDraft(id);
        snackSuccess(t("configKeys.snackbar.saved"));
        await refreshAll();
        return;
      }

      const exposure = (k.exposure as ConfigExposure) || "private";
      const validated = validateDraftForKey(k, d);
      if (!validated.ok) {
        setDraftForSelectedApp(k.id, { error: validated.error || t("configKeys.validation.invalidValue") });
        throw new Error(validated.error || t("configKeys.validation.invalidValue"));
      }

      if (exposure === "secret") {
        if (!secretReady) {
          throw new Error(t("configKeys.snackbar.encryptionKeyRequired"));
        }

        const app = await encryptSecretValueToEnvelope(
          validated.value,
          workspaceEncKey!.publicKeyJwk,
          workspaceEncKey!.fingerprint
        );

        await apiJson(`${base}/configKeys/${configKeyId}/apps/${appId}`, {
          method: "PUT",
          data: { secret: app },
        });

        // Write-only UX: clear local input after saving
        setDraftForSelectedApp(k.id, {
          boolValue: undefined,
          scalarText: "",
          jsonText: "",
          error: null,
        });
      } else {
        await apiJson(`${base}/configKeys/${configKeyId}/apps/${appId}`, {
          method: "PUT",
          data: { value: validated.value },
        });

        clearDraft(id);
      }

      snackSuccess(t("configKeys.snackbar.saved"));
      await refreshAll();
    } catch (e) {
      const msg = extractApiError(e, t("configKeys.snackbar.saveFailed"));
      setError(msg);
      snackError(msg);
    } finally {
      setSaving(false);
    }
  }

  async function saveAll() {
    if (!selectedAppId) return;
    if (dirty.size === 0) return;
    if (editLocked) return;

    setSaving(true);
    setError(null);

    try {
      for (const id of dirty) {
        const [configKeyId, appId] = id.split("::");
        if (appId !== selectedAppId) continue;

        const k = keys.find((kk) => kk.id === configKeyId);
        if (!k) continue;

        const d = draft[id];
        if (!d) continue;

        if (d.isUnset) {
          await apiJson(`${base}/configKeys/${configKeyId}/apps/${appId}`, { method: "DELETE" });
          continue;
        }

        const exposure = (k.exposure as ConfigExposure) || "private";
        const validated = validateDraftForKey(k, d);
        if (!validated.ok) {
          setDraftForSelectedApp(k.id, { error: validated.error || t("configKeys.validation.invalidValue") });
          throw new Error(`${k.key}: ${validated.error || t("configKeys.validation.invalidValue")}`);
        }

        if (exposure === "secret") {
          if (!secretReady) {
            throw new Error(t("configKeys.snackbar.encryptionKeyRequired"));
          }

          const app = await encryptSecretValueToEnvelope(
            validated.value,
            workspaceEncKey!.publicKeyJwk,
            workspaceEncKey!.fingerprint
          );

          await apiJson(`${base}/configKeys/${configKeyId}/apps/${appId}`, {
            method: "PUT",
            data: { secret: app },
          });
        } else {
          await apiJson(`${base}/configKeys/${configKeyId}/apps/${appId}`, {
            method: "PUT",
            data: { value: validated.value },
          });
        }
      }

      snackSuccess(t("configKeys.snackbar.saved"));
      await refreshAll();
    } catch (e) {
      const msg = extractApiError(e, t("configKeys.snackbar.saveFailed"));
      setError(msg);
      snackError(msg);
    } finally {
      setSaving(false);
    }
  }

  const hasApps = apps.length > 0;

  function applyEnvSwitch(nextAppId: string) {
    setSelectedAppId(nextAppId);
    setDraft({});
    setDirty(new Set());
  }

  function requestEnvSwitch(nextAppId: string) {
    if (!nextAppId || nextAppId === selectedAppId) return;

    const nextApp = apps.find((e) => e.id === nextAppId) || null;
    if (isProdApp(nextApp)) {
      setPendingAppId(nextAppId);
      setProdConfirmOpen(true);
      return;
    }

    applyEnvSwitch(nextAppId);
  }

  function confirmProdSwitch() {
    const next = pendingAppId;
    setProdConfirmOpen(false);
    setPendingAppId("");
    if (!next) return;
    applyEnvSwitch(next);
  }

  function cancelProdSwitch() {
    setProdConfirmOpen(false);
    setPendingAppId("");
  }

  const pendingApp = React.useMemo(() => {
    return apps.find((e) => e.id === pendingAppId) || null;
  }, [apps, pendingAppId]);

  function renderValueEditor(k: ConfigKey, d: DraftEntry, exists: boolean) {
    const exposure = (k.exposure as ConfigExposure) || "private";
    const vt = (k.valueType as ConfigValueType) || "string";

    const unsetDisabled = editLocked || !selectedAppId || !exists;
    const disableInputs = editLocked || !!d.isUnset;

    const helper =
      exposure === "secret"
        ? secretReady
          ? t("configKeys.writeOnlyHelper")
          : t("configKeys.secretsRequireKeyShort")
        : typeHint(vt, t) || "";

    // Compact unset toggle
    const unsetToggle = exists && (
      <FormControlLabel
        control={
          <Switch
            size="small"
            checked={!!d.isUnset}
            onChange={(ev) => {
              if (unsetDisabled) return;
              setDraftForSelectedApp(k.id, { isUnset: ev.target.checked, error: null });
            }}
            disabled={unsetDisabled}
          />
        }
        label={<Typography variant="caption">{t("configKeys.unsetValue")}</Typography>}
        sx={{ mr: 0 }}
      />
    );

    if (vt === "bool") {
      return (
        <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap" useFlexGap>
          <FormControlLabel
            control={
              <Switch
                size="small"
                checked={!!d.boolValue}
                onChange={(ev) => setDraftForSelectedApp(k.id, { boolValue: ev.target.checked, error: null })}
                disabled={disableInputs || (exposure === "secret" && !secretReady)}
              />
            }
            label={<Typography variant="body2">{d.boolValue ? t("configKeys.enabled") : t("configKeys.disabled")}</Typography>}
          />
          {unsetToggle}
          {helper && (
            <Typography variant="caption" color="text.secondary">
              {helper}
            </Typography>
          )}
        </Stack>
      );
    }

    if (isJsonTextType(vt)) {
      return (
        <Stack spacing={0.5}>
          <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap" useFlexGap>
            {unsetToggle}
            {helper && (
              <Typography variant="caption" color="text.secondary">
                {helper}
              </Typography>
            )}
          </Stack>

          <TextField
            size="small"
            disabled={disableInputs || (exposure === "secret" && !secretReady)}
            value={d.jsonText ?? ""}
            onChange={(ev) => setDraftForSelectedApp(k.id, { jsonText: ev.target.value, error: null })}
            fullWidth
            multiline
            minRows={2}
            maxRows={6}
            placeholder={
              vt.endsWith("[]")
                ? vt.startsWith("string") ? `["a", "b"]` : vt.startsWith("bool") ? `[true, false]` : `[1, 2, 3]`
                : `{"key": "value"}`
            }
            error={!!d.error}
            helperText={d.error || undefined}
            inputProps={{ style: { fontFamily: "var(--font-mono)", fontSize: 13 } }}
          />
        </Stack>
      );
    }

    // scalar: string/int/decimal
    const inputType = vt === "string" ? "text" : "number";
    const step = vt === "decimal" ? "any" : vt === "int" ? "1" : undefined;

    return (
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1} alignItems={{ xs: "stretch", sm: "center" }}>
        <TextField
          size="small"
          disabled={disableInputs || (exposure === "secret" && !secretReady)}
          value={d.scalarText ?? ""}
          onChange={(ev) => setDraftForSelectedApp(k.id, { scalarText: ev.target.value, error: null })}
          type={inputType}
          inputProps={{ step, style: { fontFamily: vt === "string" ? undefined : "monospace" } }}
          placeholder={vt === "string" ? t("configKeys.enterValuePlaceholder") : vt === "int" ? "123" : "12.34"}
          error={!!d.error}
          helperText={d.error || helper || undefined}
          sx={{ flex: 1, minWidth: 200 }}
        />
        {unsetToggle}
      </Stack>
    );
  }

  const filteredKeys = React.useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return keys;
    return keys.filter(k =>
      k.key.toLowerCase().includes(q) ||
      (k.description || "").toLowerCase().includes(q)
    );
  }, [keys, searchQuery]);

  const groupedKeys = React.useMemo(() => groupConfigKeys(filteredKeys), [filteredKeys]);

  // Count how many apps have value set for a key
  function countAppsWithValue(configKeyId: string): number {
    return values.filter((v) => v.configKeyId === configKeyId).length;
  }

  function copyKeyToClipboard(key: string) {
    navigator.clipboard.writeText(key);
    enqueueSnackbar(t("configKeys.keyCopied"), { variant: "success" });
  }

  return (
    <Box>
      <PageHeader title={t("configKeys.title")} mb={2} />

      <Box sx={{ borderBottom: 1, borderColor: "divider", mb: 2.5 }}>
        <Tabs value={tabIndex} onChange={(_, v) => setTabIndex(v)} aria-label={t("configKeys.tabsAriaLabel")}>
          <Tab label={t("configKeys.tabs.config")} id="configkeys-tab-0" />
          <Tab label={t("configKeys.tabs.encryption")} id="configkeys-tab-1" />
        </Tabs>
      </Box>

      {tabIndex === 1 ? (
        <EncryptionKeyTab
          workspaceId={project.workspaceId}
          onSaved={() => void loadWorkspaceEncryptionKey()}
        />
      ) : (
      <Stack spacing={2.5}>
        {/* Status row */}
        <Stack direction="row" alignItems="center" spacing={1} flexWrap="wrap" useFlexGap>
          <Box sx={{ flex: 1, minWidth: 0 }} />

          <Chip
            size="small"
            variant="outlined"
            label={t("configKeys.keysCount", { count: keysTotal })}
          />

          <Tooltip title={secretReady ? t("configKeys.secretsReadyTooltip") : t("configKeys.secretsNotReadyTooltip")}>
            <Chip
              size="small"
              icon={secretReady ? <CircleCheck size={14} strokeWidth={1.75} /> : <TriangleAlert size={14} strokeWidth={1.75} />}
              label={secretReady ? t("configKeys.secretsReady") : t("configKeys.secretsNotReady")}
              color={secretReady ? "success" : "warning"}
              variant={secretReady ? "filled" : "outlined"}
            />
          </Tooltip>

          <Tooltip title={t("configKeys.refresh")}>
            <span>
              <IconButton size="small" onClick={() => void refreshAll({ showSuccess: true })} disabled={loading || saving} aria-label={t("configKeys.refresh")}>
                <RefreshCw size={14} strokeWidth={1.75} />
              </IconButton>
            </span>
          </Tooltip>

          <Button
            size="small"
            variant="outlined"
            startIcon={<Download size={14} strokeWidth={1.75} />}
            onClick={(e) => setExportAnchorEl(e.currentTarget)}
            disabled={loading || keys.length === 0}
          >
            {t("configKeys.export")}
          </Button>
          <Menu
            anchorEl={exportAnchorEl}
            open={exportMenuOpen}
            onClose={() => setExportAnchorEl(null)}
          >
            <MenuItem onClick={handleExportCsv}>
              <ListItemIcon><Download size={14} strokeWidth={1.75} /></ListItemIcon>
              <ListItemText>{t("configKeys.exportCsv")}</ListItemText>
            </MenuItem>
            <MenuItem onClick={handleExportJson}>
              <ListItemIcon><Download size={14} strokeWidth={1.75} /></ListItemIcon>
              <ListItemText>{t("configKeys.exportJson")}</ListItemText>
            </MenuItem>
          </Menu>

          <Button
            size="small"
            variant="contained"
            disableElevation
            startIcon={<Plus size={14} strokeWidth={1.75} />}
            onClick={() => setCreateOpen(true)}
            disabled={loading || saving}
          >
            {t("configKeys.newKey")}
          </Button>

          {dirty.size > 0 && (
            <Button
              size="small"
              variant="outlined"
              color="warning"
              startIcon={<Save size={14} strokeWidth={1.75} />}
              onClick={() => void saveAll()}
              disabled={editLocked || saving || !selectedAppId}
            >
              {t("configKeys.saveAll", { count: dirty.size })}
            </Button>
          )}
        </Stack>

        {/* App switcher (project-level only - app-level pages
            already show the app in the breadcrumb, so we skip the row). */}
        {!fixedAppId && (
          <Stack direction="row" spacing={1} alignItems="center">
            <Typography variant="body2" color="text.secondary">
              {t("configKeys.editing")}
            </Typography>
            <TextField
              size="small"
              select
              value={selectedAppId}
              onChange={(e) => requestEnvSwitch(e.target.value)}
              disabled={!hasApps || loading || saving}
              sx={{ minWidth: 200 }}
            >
              {apps.map((app) => (
                <MenuItem key={app.id} value={app.id}>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <Typography variant="body2">{appTypeLabel(app)}</Typography>
                    {isProdApp(app) && (
                      <StatusChip size="xs" label={t("configKeys.prod")} severity="error" />
                    )}
                  </Stack>
                </MenuItem>
              ))}
            </TextField>
          </Stack>
        )}

        {/* Help section */}
        <ConfigKeysAbout
          secretReady={secretReady}
          expanded={helpExpanded}
          onToggle={() => setHelpExpanded(!helpExpanded)}
          t={t}
        />

        {/* Search */}
        {keys.length > 0 && (
          <TextField
            size="small"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder={t("configKeys.searchPlaceholder")}
            sx={{ maxWidth: 320 }}
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <Search size={14} strokeWidth={1.75} />
                  </InputAdornment>
                ),
                endAdornment: searchQuery ? (
                  <InputAdornment position="end">
                    <IconButton size="small" onClick={() => setSearchQuery("")}>
                      <X size={14} strokeWidth={1.75} />
                    </IconButton>
                  </InputAdornment>
                ) : undefined,
              },
            }}
          />
        )}

        {error && <Alert severity="error">{error}</Alert>}

        {loading && (
          <Stack direction="row" spacing={1} alignItems="center" justifyContent="center" sx={{ py: 4 }}>
            <CircularProgress size={20} />
            <Typography variant="body2" color="text.secondary">
              {t("configKeys.loading")}
            </Typography>
          </Stack>
        )}

        {/* Empty state */}
        {!loading && keys.length === 0 && (
          <Paper variant="outlined" sx={{ borderRadius: 2, p: 4, textAlign: "center" }}>
            <Stack spacing={2} alignItems="center">
              <Box component="span" sx={{ color: "text.disabled" }}><Settings size={48} strokeWidth={1.75} /></Box>
              <Typography variant="h6" color="text.secondary">
                {t("configKeys.empty.title")}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 400 }}>
                {t("configKeys.empty.description")}
              </Typography>
              <Stack direction="row" spacing={1} flexWrap="wrap" justifyContent="center" useFlexGap>
                <Chip size="small" label="API_BASE_URL" variant="outlined" sx={{ fontFamily: "var(--font-mono)" }} />
                <Chip size="small" label="MAX_UPLOAD_SIZE" variant="outlined" sx={{ fontFamily: "var(--font-mono)" }} />
                <Chip size="small" label="STRIPE_SECRET_KEY" variant="outlined" sx={{ fontFamily: "var(--font-mono)" }} />
              </Stack>
              <Button
                variant="contained"
                disableElevation
                startIcon={<Plus size={14} strokeWidth={1.75} />}
                onClick={() => setCreateOpen(true)}
              >
                {t("configKeys.empty.createFirst")}
              </Button>
            </Stack>
          </Paper>
        )}

        {/* No search results */}
        {!loading && keys.length > 0 && filteredKeys.length === 0 && (
          <Alert severity="info">{t("configKeys.noSearchResults")}</Alert>
        )}

        {/* Grouped keys */}
        {!loading && filteredKeys.length > 0 && (
          <Stack spacing={2}>
            {[...groupedKeys.entries()].map(([groupName, groupKeys]) => (
              <Box key={groupName}>
                {/* Group header */}
                <Typography
                  sx={{
                    display: "block",
                    mb: 1,
                    ml: 0.5,
                    fontFamily: "var(--font-mono)",
                    textTransform: "uppercase",
                    letterSpacing: "0.14em",
                    fontSize: 10,
                    fontWeight: 500,
                    color: "text.disabled",
                  }}
                >
                  {groupName} ({groupKeys.length})
                </Typography>

                {/* Keys in group */}
                <Stack spacing={1}>
                  {groupKeys.map((k) => {
                    const appId = selectedAppId || "";
                    const rowId = appId ? `${k.id}::${appId}` : "";

                    const d = selectedAppId ? getDraftForSelectedApp(k.id) : null;
                    const isDirty = rowId ? dirty.has(rowId) : false;
                    const exists = selectedAppId ? valueRowExistsForApp(k, selectedAppId) : false;

                    const exposure = (k.exposure as ConfigExposure) || "private";
                    const vt = (k.valueType as ConfigValueType) || "string";
                    const appsWithValue = countAppsWithValue(k.id);

                    const rowError =
                      d && selectedAppId && isDirty && !d.isUnset
                        ? (() => {
                            try {
                              const validated = validateDraftForKey(k, d);
                              return validated.ok ? null : validated.error || t("configKeys.validation.invalidValue");
                            } catch {
                              return t("configKeys.validation.invalidValue");
                            }
                          })()
                        : null;

                    const secretBlocked = exposure === "secret" && !secretReady;
                    const saveDisabled =
                      editLocked || saving || !selectedAppId || !rowId || !dirty.has(rowId) || !!rowError || secretBlocked;

                    return (
                      <Paper
                        key={k.id}
                        variant="outlined"
                        sx={{
                          borderRadius: 2,
                          overflow: "hidden",
                          borderColor: isDirty ? "warning.main" : exists ? "success.light" : undefined,
                          borderWidth: isDirty || exists ? 2 : 1,
                        }}
                      >
                        {/* Key header row */}
                        <Box
                          sx={{
                            px: 2,
                            py: 0.75,
                            bgcolor: exists
                              ? exposure === "secret"
                                ? alpha("#F59E0B", 0.05)
                                : alpha("#16A34A", 0.05)
                              : "transparent",
                          }}
                        >
                          <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                            {/* Key name */}
                            <Typography
                              variant="body2"
                              sx={{ fontFamily: "var(--font-mono)", fontWeight: 600 }}
                            >
                              {k.key}
                            </Typography>

                            <Tooltip title={t("configKeys.copyKeyTooltip")}>
                              <IconButton size="small" onClick={() => copyKeyToClipboard(k.key)} aria-label={t("configKeys.copyKeyTooltip")}>
                                <Copy size={14} strokeWidth={1.75} />
                              </IconButton>
                            </Tooltip>

                            {/* Badges */}
                            <Tooltip title={exposureDescription(exposure, t)}>
                              <span>
                                <StatusChip
                                  label={prettyExposure(exposure, t)}
                                  severity={
                                    exposure === "public" ? "primary"
                                      : exposure === "secret" ? "warning"
                                      : "neutral"
                                  }
                                />
                              </span>
                            </Tooltip>

                            <StatusChip label={typeLabel(vt, t)} uppercase={false} />

                            {/* App coverage indicator */}
                            <Tooltip title={t("configKeys.appValueTooltip", { count: appsWithValue, total: apps.length })}>
                              <span>
                                <StatusChip
                                  label={t("configKeys.appsValue", { count: appsWithValue, total: apps.length })}
                                  uppercase={false}
                                  severity={
                                    appsWithValue === apps.length ? "success"
                                      : appsWithValue > 0 ? "info"
                                      : "muted"
                                  }
                                />
                              </span>
                            </Tooltip>

                            {isDirty && (
                              <Chip
                                size="small"
                                label={t("configKeys.unsaved")}
                                color="warning"
                                variant="filled"
                                sx={{ height: 20, fontSize: 11 }}
                              />
                            )}

                            <Box sx={{ flex: 1 }} />

                            {/* Actions */}
                            <Stack direction="row" spacing={0.5}>
                              <Tooltip title={saveDisabled ? (secretBlocked ? t("configKeys.configureEncryptionFirst") : rowError || t("configKeys.saveTooltip")) : t("configKeys.saveTooltip")}>
                                <span>
                                  <IconButton size="small" onClick={() => void saveOne(k.id)} disabled={saveDisabled} aria-label={t("configKeys.saveTooltip")}>
                                    {isDirty && !saveDisabled ? <Box component="span" sx={{ color: "warning.main" }}><Save size={14} strokeWidth={1.75} /></Box> : <Save size={14} strokeWidth={1.75} />}
                                  </IconButton>
                                </span>
                              </Tooltip>

                              <Tooltip title={t("configKeys.deleteKeyTooltip")}>
                                <span>
                                  <IconButton size="small" onClick={() => openDelete(k)} disabled={saving} aria-label={t("configKeys.deleteKeyTooltip")}>
                                    <Trash2 size={14} strokeWidth={1.75} />
                                  </IconButton>
                                </span>
                              </Tooltip>
                            </Stack>
                          </Stack>

                          {/* Description */}
                          {k.description && (
                            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.25 }}>
                              {k.description}
                            </Typography>
                          )}
                        </Box>

                        {/* Value editor */}
                        <Box sx={{ px: 2, pt: 0, pb: 0.75 }}>
                          {!selectedAppId ? (
                            <Typography variant="body2" color="text.secondary">
                              {t("configKeys.selectEnvToEdit")}
                            </Typography>
                          ) : d ? (
                            <Stack spacing={0.5}>
                              {renderValueEditor(k, { ...d, error: rowError ?? d.error ?? null }, exists)}
                              {rowError && (
                                <Alert severity="warning" sx={{ py: 0.5 }}>
                                  {rowError}
                                </Alert>
                              )}
                              {secretBlocked && (
                                <Alert severity="warning" sx={{ py: 0.5 }}>
                                  {t("configKeys.secretsRequireKey")}
                                </Alert>
                              )}
                            </Stack>
                          ) : null}
                        </Box>
                      </Paper>
                    );
                  })}
                </Stack>
              </Box>
            ))}
          </Stack>
        )}
      </Stack>
      )}

      {/* PROD confirm dialog */}
      <Dialog open={prodConfirmOpen} onClose={cancelProdSwitch} maxWidth="xs" fullWidth>
        <DialogTitle>{t("configKeys.prodConfirm.title")}</DialogTitle>
        <DialogContent>
          <Stack spacing={1}>
            <Typography variant="body2" color="text.secondary"><Trans i18nKey="configKeys.prodConfirm.description" values={{ app: appTypeLabel(pendingApp) || "Production" }} components={tc} /></Typography>
            <Alert severity="warning">{t("configKeys.prodConfirm.warning")}</Alert>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={cancelProdSwitch} disabled={saving}>
            {t("configKeys.prodConfirm.cancel")}
          </Button>
          <Button onClick={confirmProdSwitch} variant="contained" disableElevation disabled={saving}>
            {t("configKeys.prodConfirm.confirm")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Create key dialog */}
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>{t("configKeys.dialog.createTitle")}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <TextField
              autoFocus
              label={t("configKeys.dialog.keyLabel")}
              value={createKey}
              onChange={(e) => setCreateKey(e.target.value)}
              placeholder={t("configKeys.dialog.keyPlaceholder")}
              fullWidth
              helperText={t("configKeys.dialog.keyHelper")}
            />

            <TextField
              label={t("configKeys.dialog.descriptionLabel")}
              value={createDescription}
              onChange={(e) => setCreateDescription(e.target.value)}
              placeholder={t("configKeys.dialog.descriptionPlaceholder")}
              fullWidth
            />

            <TextField
              select
              label={t("configKeys.dialog.exposureLabel")}
              value={createExposure}
              onChange={(e) => setCreateExposure(e.target.value as ConfigExposure)}
              fullWidth
            >
              <MenuItem value="private">{t("configKeys.exposure.private")}</MenuItem>
              <MenuItem value="public">{t("configKeys.exposure.public")}</MenuItem>
              <MenuItem value="secret">{t("configKeys.exposure.secret")}</MenuItem>
            </TextField>

            <TextField
              select
              label={t("configKeys.dialog.valueTypeLabel")}
              value={createValueType}
              onChange={(e) => setCreateValueType(e.target.value as ConfigValueType)}
              fullWidth
            >
              {getValueTypes(t).map((vt) => (
                <MenuItem key={vt.value} value={vt.value}>
                  {vt.label} - {vt.hint}
                </MenuItem>
              ))}
            </TextField>

            <ExposureInfoAlert exposure={createExposure} secretReady={secretReady} t={t} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)} disabled={saving}>
            {t("configKeys.dialog.cancel")}
          </Button>
          <Button onClick={() => void handleCreateKey()} variant="contained" disableElevation disabled={saving}>
            {t("configKeys.dialog.create")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete key dialog */}
      <Dialog open={deleteOpen} onClose={closeDelete} maxWidth="xs" fullWidth>
        <DialogTitle>{t("configKeys.dialog.deleteTitle")}</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary">
            {t("configKeys.dialog.deleteDescription")}
          </Typography>
          {selectedKey && (
            <Typography sx={{ mt: 1, fontFamily: "var(--font-mono)" }}>{selectedKey.key}</Typography>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={closeDelete} disabled={saving}>
            {t("configKeys.dialog.cancel")}
          </Button>
          <Button onClick={() => void handleDeleteKey()} color="error" variant="contained" disableElevation disabled={saving}>
            {t("configKeys.dialog.delete")}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
