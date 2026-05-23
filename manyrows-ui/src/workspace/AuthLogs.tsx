import * as React from "react";
import axios from "axios";
import { extractApiError } from "../lib/apiError.ts";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  CircularProgress,
  Drawer,
  IconButton,
  InputAdornment,
  ListItemText,
  MenuItem,
  Paper,
  Select,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import Eyebrow from "../components/Eyebrow.tsx";
import {
  RefreshCw,
  Search,
  X,
  Filter,
  FileSpreadsheet,
  CircleCheck,
  CircleAlert,
  LogIn,
  LogOut,
  KeyRound,
  Shield,
  ShieldCheck,
  Bot,
  User,
  Globe,
  Monitor,
  Link2,
  type LucideIcon,
} from "lucide-react";
import PageHeader from "../components/PageHeader.tsx";
import { useTranslation } from "react-i18next";
import { useSnackbar } from "notistack";

interface Props {
  workspaceId: string;
  appId?: string;
}

type AuthLog = {
  id: string;
  workspaceId: string;
  appId?: string | null;
  createdAt: string;

  event: string;
  method?: string;
  outcome: "success" | "failed";
  failureReason?: string;

  subjectUserId?: string | null;
  subjectAccountId?: string | null;
  emailAttempted?: string;

  actorType: "self" | "admin" | "api_key" | "system";
  actorAccountId?: string | null;
  actorApiKeyId?: string | null;
  actorLabel?: string;

  ip?: string;
  userAgent?: string;
  sessionId?: string | null;
  requestId?: string;

  metadata?: any;
};

// isLoopbackOrPrivate detects loopback / private / link-local IPs so
// ipDisplay can render them with a friendlier "localhost" label instead
// of an arcane "::1". Covers IPv4 loopback (127.0.0.0/8), IPv4 private
// ranges (10/8, 172.16/12, 192.168/16), link-local (169.254/16), IPv6
// loopback (::1), and IPv6 unique-local (fc00::/7) / link-local (fe80::/10).
function isLoopbackOrPrivate(ip: string): boolean {
  if (!ip) return false;
  if (ip === "::1" || ip === "127.0.0.1") return true;
  if (ip.startsWith("127.")) return true;
  if (ip.startsWith("10.")) return true;
  if (ip.startsWith("192.168.")) return true;
  if (ip.startsWith("169.254.")) return true;
  if (ip.startsWith("172.")) {
    // 172.16.0.0 – 172.31.255.255
    const parts = ip.split(".");
    const second = Number(parts[1]);
    if (second >= 16 && second <= 31) return true;
  }
  const lower = ip.toLowerCase();
  if (lower.startsWith("fe80:")) return true; // link-local
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // unique-local fc00::/7
  return false;
}

// ipDisplay turns a raw IP string into the cell label. Loopback /
// private addresses render as "localhost" so dev/test rows don't clutter
// the table with arcane "::1"s; real public IPs render verbatim.
function ipDisplay(ip: string | undefined): { text: string; muted: boolean; tooltip?: string } {
  if (!ip) return { text: "-", muted: true };
  if (isLoopbackOrPrivate(ip)) return { text: "localhost", muted: true, tooltip: ip };
  return { text: ip, muted: false };
}

type AuthLogsResponse = {
  logs: AuthLog[];
  total: number;
  page: number;
  pageSize: number;
};

// EVENT_VOCAB / METHOD_VOCAB / FAILURE_VOCAB mirror the closed sets in
// manyrows-core/core/authLog.go. Keep these in sync - the admin UI
// surfaces them as filter dropdowns and chips. If a server-side row
// arrives with a value not in this list, the renderer just shows the
// raw string (forward-compatible for added events).
// Each vocab entry carries a labelKey (i18n) alongside the default
// English label. Render sites call t(labelKey, { defaultValue: label }).
// The `value` is the wire/enum value and is NEVER translated. Proper-noun
// methods (Google, Microsoft, etc.) keep their name as the locale value.
const EVENT_VOCAB: { value: string; label: string; labelKey: string }[] = [
  { value: "register.success", label: "Register success", labelKey: "authLogs.event.register.success" },
  { value: "register.failed", label: "Register failed", labelKey: "authLogs.event.register.failed" },
  { value: "login.success", label: "Login success", labelKey: "authLogs.event.login.success" },
  { value: "login.failed", label: "Login failed", labelKey: "authLogs.event.login.failed" },
  { value: "logout", label: "Logout", labelKey: "authLogs.event.logout" },
  { value: "session.revoked", label: "Session revoked", labelKey: "authLogs.event.session.revoked" },
  { value: "sessions.pruned", label: "Sessions pruned", labelKey: "authLogs.event.sessions.pruned" },
  { value: "password.set", label: "Password set", labelKey: "authLogs.event.password.set" },
  { value: "password.changed", label: "Password changed", labelKey: "authLogs.event.password.changed" },
  { value: "password.cleared", label: "Password cleared", labelKey: "authLogs.event.password.cleared" },
  { value: "password.reset_requested", label: "Password reset requested", labelKey: "authLogs.event.password.resetRequested" },
  { value: "password.reset_completed", label: "Password reset completed", labelKey: "authLogs.event.password.resetCompleted" },
  { value: "email.change_requested", label: "Email change requested", labelKey: "authLogs.event.email.changeRequested" },
  { value: "email.changed", label: "Email changed", labelKey: "authLogs.event.email.changed" },
  { value: "totp.enabled", label: "TOTP enabled", labelKey: "authLogs.event.totp.enabled" },
  { value: "totp.disabled", label: "TOTP disabled", labelKey: "authLogs.event.totp.disabled" },
  { value: "totp.failed", label: "TOTP failed", labelKey: "authLogs.event.totp.failed" },
  { value: "passkey.registered", label: "Passkey registered", labelKey: "authLogs.event.passkey.registered" },
  { value: "passkey.used", label: "Passkey used", labelKey: "authLogs.event.passkey.used" },
  { value: "passkey.deleted", label: "Passkey deleted", labelKey: "authLogs.event.passkey.deleted" },
  { value: "passkey.admin_revoked", label: "Passkey admin-revoked", labelKey: "authLogs.event.passkey.adminRevoked" },
  { value: "oauth.linked", label: "OAuth linked", labelKey: "authLogs.event.oauth.linked" },
  { value: "account.locked", label: "Account locked", labelKey: "authLogs.event.account.locked" },
  { value: "account.status_changed", label: "Account status changed", labelKey: "authLogs.event.account.statusChanged" },
];

const METHOD_VOCAB: { value: string; label: string; labelKey: string }[] = [
  { value: "password", label: "Password", labelKey: "authLogs.method.password" },
  { value: "google", label: "Google", labelKey: "authLogs.method.google" },
  { value: "microsoft", label: "Microsoft", labelKey: "authLogs.method.microsoft" },
  { value: "apple", label: "Apple", labelKey: "authLogs.method.apple" },
  { value: "github", label: "GitHub", labelKey: "authLogs.method.github" },
  { value: "kakao", label: "Kakao", labelKey: "authLogs.method.kakao" },
  { value: "naver", label: "Naver", labelKey: "authLogs.method.naver" },
  { value: "passkey", label: "Passkey", labelKey: "authLogs.method.passkey" },
  { value: "totp", label: "TOTP", labelKey: "authLogs.method.totp" },
  { value: "email_otp", label: "Email OTP", labelKey: "authLogs.method.emailOtp" },
  { value: "magic_link", label: "Magic Link", labelKey: "authLogs.method.magicLink" },
];

const ACTOR_TYPE_VOCAB: { value: AuthLog["actorType"]; label: string; labelKey: string; icon: LucideIcon }[] = [
  { value: "self", label: "User self-service", labelKey: "authLogs.actor.self", icon: User },
  { value: "admin", label: "Admin", labelKey: "authLogs.actor.admin", icon: ShieldCheck },
  { value: "system", label: "System", labelKey: "authLogs.actor.system", icon: Bot },
  { value: "api_key", label: "API key", labelKey: "authLogs.actor.apiKey", icon: KeyRound },
];

// PRESETS encode the "what should I look at right now" first-line filters
// for an admin glancing at the page. They map to filter state, not to
// special server endpoints - same shape as a manually-applied filter.
type Preset = {
  id: "all" | "suspicious" | "admin" | "oauth" | "failed";
  label: string;
  labelKey: string;
};
const PRESETS: Preset[] = [
  { id: "all", label: "All events", labelKey: "authLogs.preset.all" },
  { id: "suspicious", label: "Suspicious", labelKey: "authLogs.preset.suspicious" },
  { id: "admin", label: "Admin actions", labelKey: "authLogs.preset.admin" },
  { id: "oauth", label: "OAuth only", labelKey: "authLogs.preset.oauth" },
  { id: "failed", label: "Failed only", labelKey: "authLogs.preset.failed" },
];

function fmtDateTime(d: string | number | Date | null | undefined): string {
  if (!d) return "-";
  const date = d instanceof Date ? d : new Date(d);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function fmtRelative(d: string | number | Date | null | undefined, t: (key: string, opts?: Record<string, unknown>) => string): string {
  if (!d) return "";
  const date = d instanceof Date ? d : new Date(d);
  if (Number.isNaN(date.getTime())) return "";
  const diff = Date.now() - date.getTime();
  if (diff < 60_000) return t("sessions.justNow");
  if (diff < 3_600_000) return t("sessions.minutesAgo", { count: Math.floor(diff / 60_000) });
  if (diff < 86_400_000) return t("sessions.hoursAgo", { count: Math.floor(diff / 3_600_000) });
  return t("sessions.daysAgo", { count: Math.floor(diff / 86_400_000) });
}

// useDebouncedValue keeps the email/IP search inputs from firing a
// network request on every keystroke. 350ms matches the rest of the
// admin app's free-text filter inputs.
function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = React.useState(value);
  React.useEffect(() => {
    const t = window.setTimeout(() => setDebounced(value), delayMs);
    return () => window.clearTimeout(t);
  }, [value, delayMs]);
  return debounced;
}

// uaSummary turns a 200-char user-agent string into "Chrome on macOS"
// for table display. Read-time only - we never freeze the parsed value
// because parsers improve over time and stale parses are worse than no
// parse. Roll-our-own is fine for the handful of mainstream
// browser/OS combos worth distinguishing.
function uaSummary(ua: string | undefined): string {
  if (!ua) return "";
  const u = ua.toLowerCase();
  let browser = "Other";
  if (u.includes("edg/")) browser = "Edge";
  else if (u.includes("chrome/")) browser = "Chrome";
  else if (u.includes("firefox/")) browser = "Firefox";
  else if (u.includes("safari/") && !u.includes("chrome/")) browser = "Safari";
  let os = "Other";
  if (u.includes("windows")) os = "Windows";
  else if (u.includes("mac os") || u.includes("macintosh")) os = "macOS";
  else if (u.includes("iphone") || u.includes("ipad")) os = "iOS";
  else if (u.includes("android")) os = "Android";
  else if (u.includes("linux")) os = "Linux";
  return `${browser} on ${os}`;
}

// methodPalette returns muted brand colors per auth method so the
// table is scannable at a glance - Google rows pop blue, Apple rows
// stay slate, etc. Keep colors light enough that the dark text reads
// as a soft chip, not a button. Add new methods here as the
// AuthLogMethod enum grows.
function methodPalette(method: string | undefined): { bg: string; fg: string } | null {
  if (!method) return null;
  switch (method) {
    case "password":  return { bg: "#FEF3C7", fg: "#92400E" }; // amber
    case "google":    return { bg: "#DBEAFE", fg: "#1E40AF" }; // google blue
    case "microsoft": return { bg: "#CFFAFE", fg: "#155E75" }; // microsoft cyan
    case "apple":     return { bg: "#E5E7EB", fg: "#1F2937" }; // slate
    case "github":    return { bg: "#1F2937", fg: "#F9FAFB" }; // dark
    case "kakao":     return { bg: "#FEE500", fg: "#3C1E1E" }; // kakao yellow / brown
    case "naver":     return { bg: "#03C75A", fg: "#FFFFFF" }; // naver green
    case "passkey":   return { bg: "#EDE9FE", fg: "#5B21B6" }; // violet
    case "totp":      return { bg: "#CCFBF1", fg: "#115E59" }; // teal
    case "email_otp":  return { bg: "#E0E7FF", fg: "#3730A3" }; // indigo
    case "magic_link": return { bg: "#FCE7F3", fg: "#9D174D" }; // pink - distinct from email_otp's indigo
    default:           return { bg: "#F3F4F6", fg: "#374151" };
  }
}

// eventPalette categorizes events into broad colour bands so a scan
// down the column gives you "auth attempts" vs "account hygiene" vs
// "suspicious lockouts" without reading the text. Failure-side events
// (login.failed, totp.failed, account.locked) stay red regardless of
// category to avoid undercutting the row's outcome chip.
function eventPalette(event: string): { bg: string; fg: string } {
  if (event === "login.failed" || event === "totp.failed" || event === "account.locked" || event === "register.failed") {
    return { bg: "#FEE2E2", fg: "#991B1B" }; // red
  }
  if (event === "login.success") return { bg: "#D1FAE5", fg: "#065F46" }; // green
  if (event === "register.success") return { bg: "#DBEAFE", fg: "#1E40AF" }; // blue (new account!)
  if (event === "logout") return { bg: "#F3F4F6", fg: "#374151" }; // neutral
  if (event.startsWith("password.")) return { bg: "#FEF3C7", fg: "#92400E" }; // amber
  if (event.startsWith("passkey.")) return { bg: "#EDE9FE", fg: "#5B21B6" }; // violet
  if (event.startsWith("totp.")) return { bg: "#CCFBF1", fg: "#115E59" }; // teal
  if (event.startsWith("email.")) return { bg: "#E0E7FF", fg: "#3730A3" }; // indigo
  if (event.startsWith("session")) return { bg: "#F3F4F6", fg: "#374151" }; // neutral
  if (event.startsWith("oauth.")) return { bg: "#DBEAFE", fg: "#1E40AF" }; // blue
  if (event.startsWith("account.")) return { bg: "#FED7AA", fg: "#9A3412" }; // orange (admin admin)
  return { bg: "#F3F4F6", fg: "#374151" };
}

function eventIcon(event: string): LucideIcon {
  if (event.startsWith("login.")) return LogIn;
  if (event === "logout") return LogOut;
  if (event.startsWith("password.")) return KeyRound;
  if (event.startsWith("passkey.")) return Shield;
  if (event.startsWith("totp.")) return Shield;
  return Filter;
}

// presetParams maps a preset choice to query-param overrides. Returns an
// object that the load() function spreads into its base params; nil means
// "no preset, use whatever the manual filters are set to".
function presetParams(p: Preset["id"]): Record<string, string | string[]> | null {
  switch (p) {
    case "suspicious":
      // Failed logins + lockouts + admin password clears - the same
      // first-line incident-triage filter you'd want during a wake-up
      // page. Last 24h is implied by the parent's time-range, which
      // we don't override here.
      return {
        outcome: "failed",
      };
    case "admin":
      return { actorType: "admin" };
    case "oauth":
      return { method: ["google", "microsoft", "apple", "github", "kakao", "naver"] };
    case "failed":
      return { outcome: "failed" };
    default:
      return null;
  }
}

export default function AuthLogs({ workspaceId, appId }: Props) {
  const baseURL = `/admin/workspace/${workspaceId}/auth/logs`;
  const { t } = useTranslation();
  const { enqueueSnackbar } = useSnackbar();

  // URL query-param pre-filters. Lets the User detail dialog deep-link
  // here with ?subjectUserId=<uuid> for the per-user activity view, and
  // future correlation drilldowns (?sessionId=, ?requestId=) without
  // adding extra props to this component.
  const initialURLParams = React.useMemo(() => new URLSearchParams(window.location.search), []);
  const initialSubjectUserId = initialURLParams.get("subjectUserId") || "";
  const initialSessionId = initialURLParams.get("sessionId") || "";
  const initialRequestId = initialURLParams.get("requestId") || "";

  // Server-driven state.
  const [logs, setLogs] = React.useState<AuthLog[]>([]);
  const [total, setTotal] = React.useState(0);
  const [loading, setLoading] = React.useState(false);
  const [err, setErr] = React.useState<string | null>(null);

  // Filters.
  const [preset, setPreset] = React.useState<Preset["id"]>("all");
  const [eventsSel, setEventsSel] = React.useState<string[]>([]);
  const [methodsSel, setMethodsSel] = React.useState<string[]>([]);
  const [outcome, setOutcome] = React.useState<"" | "success" | "failed">("");
  const [actorType, setActorType] = React.useState<"" | AuthLog["actorType"]>("");
  const [emailLike, setEmailLike] = React.useState("");
  const emailDebounced = useDebouncedValue(emailLike, 350);
  const [subjectUserId] = React.useState<string>(initialSubjectUserId);
  const [sessionId] = React.useState<string>(initialSessionId);
  const [requestId] = React.useState<string>(initialRequestId);

  // Pagination.
  const [page, setPage] = React.useState(0);
  const [pageSize, setPageSize] = React.useState(50);

  // Auto-refresh.
  const [autoRefresh, setAutoRefresh] = React.useState(false);

  // Drill-in panel.
  const [selected, setSelected] = React.useState<AuthLog | null>(null);

  const load = React.useCallback(async () => {
    if (!workspaceId) {
      setLogs([]);
      setTotal(0);
      return;
    }
    setErr(null);
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.set("page", String(page));
      params.set("pageSize", String(pageSize));
      if (appId) params.set("appId", appId);

      // Preset overrides come first, then per-control filters get a
      // chance to add or refine. A preset that sets `outcome=failed`
      // can still be narrowed by the user setting `event=login.failed`.
      const overrides = presetParams(preset);
      if (overrides) {
        for (const [k, v] of Object.entries(overrides)) {
          if (Array.isArray(v)) v.forEach((x) => params.append(k, x));
          else params.set(k, v);
        }
      }

      eventsSel.forEach((e) => params.append("event", e));
      methodsSel.forEach((m) => params.append("method", m));
      if (outcome && !overrides?.outcome) params.set("outcome", outcome);
      if (actorType) params.set("actorType", actorType);
      if (emailDebounced.trim()) params.set("emailLike", emailDebounced.trim());
      if (subjectUserId) params.set("subjectUserId", subjectUserId);
      if (sessionId) params.set("sessionId", sessionId);
      if (requestId) params.set("requestId", requestId);

      const res = await axios.get<AuthLogsResponse>(`${baseURL}?${params.toString()}`);
      setLogs(res.data?.logs ?? []);
      setTotal(res.data?.total ?? 0);
    } catch (e) {
      setErr(extractApiError(e, t("authLogs.loadFailed", { defaultValue: "Failed to load auth logs" })));
    } finally {
      setLoading(false);
    }
  }, [workspaceId, baseURL, appId, page, pageSize, preset, eventsSel, methodsSel, outcome, actorType, emailDebounced, subjectUserId, sessionId, requestId, t]);

  React.useEffect(() => {
    void load();
  }, [load]);

  // Auto-refresh poll. 10s is the documented default - a busy admin
  // watching for incident activity gets near-realtime feedback without
  // hammering the server. WebSocket would be overkill for this.
  React.useEffect(() => {
    if (!autoRefresh) return;
    const id = window.setInterval(() => void load(), 10_000);
    return () => window.clearInterval(id);
  }, [autoRefresh, load]);

  const stats = React.useMemo(() => {
    const failed = logs.filter((l) => l.outcome === "failed").length;
    const ips = new Set(logs.map((l) => l.ip).filter(Boolean));
    const ipCounts: Record<string, number> = {};
    logs.forEach((l) => {
      if (!l.ip) return;
      ipCounts[l.ip] = (ipCounts[l.ip] ?? 0) + 1;
    });
    let topIP = "";
    let topIPCount = 0;
    for (const [ip, c] of Object.entries(ipCounts)) {
      if (c > topIPCount) {
        topIP = ip;
        topIPCount = c;
      }
    }
    const failedRate = logs.length === 0 ? 0 : Math.round((failed / logs.length) * 100);
    return { failed, ips: ips.size, topIP, topIPCount, failedRate };
  }, [logs]);

  const exportCSV = () => {
    if (logs.length === 0) {
      enqueueSnackbar(t("authLogs.noRowsToExport", { defaultValue: "No rows to export" }), { variant: "info" });
      return;
    }
    const cols = ["createdAt", "event", "method", "outcome", "failureReason", "emailAttempted", "actorType", "ip", "userAgent", "sessionId", "requestId"] as const;
    const header = cols.join(",");
    const rows = logs.map((l) =>
      cols.map((c) => csvCell((l as Record<string, unknown>)[c])).join(","),
    );
    const blob = new Blob([header + "\n" + rows.join("\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `auth-logs-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <Box>
      <PageHeader
        title={t("authLogs.title", { defaultValue: "Auth Logs" })}
        action={
          <Stack direction="row" spacing={1} alignItems="center">
            <Stack direction="row" spacing={0.5} alignItems="center">
              <Switch size="small" checked={autoRefresh} onChange={(_, v) => setAutoRefresh(v)} />
              <Typography variant="caption" color="text.secondary">{t("authLogs.autoRefresh", { defaultValue: "Auto-refresh" })}</Typography>
            </Stack>
            <Button size="small" variant="outlined" startIcon={<FileSpreadsheet size={14} strokeWidth={1.75} />} onClick={exportCSV}>
              CSV
            </Button>
            <IconButton size="small" onClick={() => void load()} disabled={loading}>
              <RefreshCw size={14} strokeWidth={1.75} />
            </IconButton>
          </Stack>
        }
      />

      {/* Anomaly strip - totals + failed % + unique IPs + top IP. Surfaces
          the spikes you'd otherwise miss while scrolling rows. */}
      <Stack direction="row" spacing={2} sx={{ mb: 2, flexWrap: "wrap" }}>
        <StatCard label={t("authLogs.stat.totalInView", { defaultValue: "Total in view" })} value={String(logs.length)} sub={t("authLogs.stat.ofTotal", { count: total, defaultValue: "of {{count}}" })} />
        <StatCard label={t("authLogs.stat.failed", { defaultValue: "Failed" })} value={`${stats.failedRate}%`} sub={t("authLogs.stat.rows", { count: stats.failed, defaultValue: "{{count}} rows" })} severity={stats.failedRate >= 30 ? "error" : stats.failedRate >= 10 ? "warning" : "neutral"} />
        <StatCard label={t("authLogs.stat.uniqueIps", { defaultValue: "Unique IPs" })} value={String(stats.ips)} />
        <StatCard label={t("authLogs.stat.topIp", { defaultValue: "Top IP" })} value={stats.topIP || "-"} sub={stats.topIPCount > 0 ? t("authLogs.stat.rows", { count: stats.topIPCount, defaultValue: "{{count}} rows" }) : ""} />
      </Stack>

      {/* Preset chips */}
      <Stack direction="row" spacing={1} sx={{ mb: 2, flexWrap: "wrap" }}>
        {PRESETS.map((p) => {
          const active = preset === p.id;
          return (
            <Chip
              key={p.id}
              label={t(p.labelKey, { defaultValue: p.label })}
              variant="outlined"
              onClick={() => {
                setPreset(p.id);
                setPage(0);
              }}
              size="small"
              sx={{
                height: 24,
                fontSize: 11.5,
                fontWeight: 500,
                cursor: "pointer",
                ...(active
                  ? {
                      bgcolor: "text.primary",
                      color: "background.default",
                      borderColor: "text.primary",
                      "&:hover": { bgcolor: "text.primary" },
                    }
                  : {
                      color: "text.secondary",
                      "&:hover": { bgcolor: "action.hover", color: "text.primary" },
                    }),
              }}
            />
          );
        })}
      </Stack>

      {/* Manual filter row */}
      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Stack direction="row" spacing={2} sx={{ flexWrap: "wrap" }}>
          <Select<string[]>
            multiple
            displayEmpty
            size="small"
            value={eventsSel}
            onChange={(e) => {
              setEventsSel(typeof e.target.value === "string" ? [e.target.value] : e.target.value);
              setPage(0);
            }}
            renderValue={(s) => (s.length === 0 ? <em>{t("authLogs.filter.eventAny", { defaultValue: "Event (any)" })}</em> : t("authLogs.filter.eventCount", { count: s.length, defaultValue: "{{count}} events" }))}
            sx={{ minWidth: 160 }}
          >
            {EVENT_VOCAB.map((e) => (
              <MenuItem key={e.value} value={e.value}>
                <Checkbox size="small" checked={eventsSel.includes(e.value)} sx={{ py: 0, mr: 1 }} />
                <ListItemText primary={t(e.labelKey, { defaultValue: e.label })} />
              </MenuItem>
            ))}
          </Select>

          <Select<string[]>
            multiple
            displayEmpty
            size="small"
            value={methodsSel}
            onChange={(e) => {
              setMethodsSel(typeof e.target.value === "string" ? [e.target.value] : e.target.value);
              setPage(0);
            }}
            renderValue={(s) => (s.length === 0 ? <em>{t("authLogs.filter.methodAny", { defaultValue: "Method (any)" })}</em> : t("authLogs.filter.methodCount", { count: s.length, defaultValue: "{{count}} methods" }))}
            sx={{ minWidth: 160 }}
          >
            {METHOD_VOCAB.map((m) => (
              <MenuItem key={m.value} value={m.value}>
                <Checkbox size="small" checked={methodsSel.includes(m.value)} sx={{ py: 0, mr: 1 }} />
                <ListItemText primary={t(m.labelKey, { defaultValue: m.label })} />
              </MenuItem>
            ))}
          </Select>

          <Select
            size="small"
            displayEmpty
            value={outcome}
            onChange={(e) => {
              setOutcome((e.target.value as "" | "success" | "failed") || "");
              setPage(0);
            }}
            sx={{ minWidth: 130 }}
          >
            <MenuItem value="">
              <em>{t("authLogs.filter.outcome", { defaultValue: "Outcome" })}</em>
            </MenuItem>
            <MenuItem value="success">{t("authLogs.outcome.success", { defaultValue: "Success" })}</MenuItem>
            <MenuItem value="failed">{t("authLogs.outcome.failed", { defaultValue: "Failed" })}</MenuItem>
          </Select>

          <Select
            size="small"
            displayEmpty
            value={actorType}
            onChange={(e) => {
              setActorType((e.target.value as "" | AuthLog["actorType"]) || "");
              setPage(0);
            }}
            sx={{ minWidth: 150 }}
          >
            <MenuItem value="">
              <em>{t("authLogs.filter.actor", { defaultValue: "Actor" })}</em>
            </MenuItem>
            {ACTOR_TYPE_VOCAB.map((a) => (
              <MenuItem key={a.value} value={a.value}>
                {t(a.labelKey, { defaultValue: a.label })}
              </MenuItem>
            ))}
          </Select>

          <TextField
            size="small"
            placeholder={t("authLogs.filter.emailContains", { defaultValue: "Email contains…" })}
            value={emailLike}
            onChange={(e) => {
              setEmailLike(e.target.value);
              setPage(0);
            }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <Search size={14} strokeWidth={1.75} />
                </InputAdornment>
              ),
              endAdornment: emailLike ? (
                <InputAdornment position="end">
                  <IconButton size="small" onClick={() => setEmailLike("")}>
                    <X size={14} strokeWidth={1.75} />
                  </IconButton>
                </InputAdornment>
              ) : null,
            }}
            sx={{ minWidth: 220 }}
          />

          <Box sx={{ flexGrow: 1 }} />
          <Typography variant="caption" color="text.secondary" alignSelf="center">
            {loading ? t("common.loadingShort", { defaultValue: "Loading…" }) : t("authLogs.totalCount", { count: total, defaultValue: "{{count}} total" })}
          </Typography>
        </Stack>
      </Paper>

      {err && <Alert severity="error" sx={{ mb: 2 }}>{err}</Alert>}

      {/* Table */}
      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>{t("authLogs.col.when", { defaultValue: "When" })}</TableCell>
              <TableCell>{t("authLogs.col.event", { defaultValue: "Event" })}</TableCell>
              <TableCell>{t("authLogs.col.method", { defaultValue: "Method" })}</TableCell>
              <TableCell>{t("authLogs.col.outcome", { defaultValue: "Outcome" })}</TableCell>
              <TableCell>{t("authLogs.col.subject", { defaultValue: "Subject" })}</TableCell>
              <TableCell>{t("authLogs.col.actor", { defaultValue: "Actor" })}</TableCell>
              <TableCell>{t("authLogs.col.ip", { defaultValue: "IP" })}</TableCell>
              <TableCell>{t("authLogs.col.device", { defaultValue: "Device" })}</TableCell>
              <TableCell>{t("authLogs.col.reason", { defaultValue: "Reason" })}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading && logs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} align="center" sx={{ py: 4 }}>
                  <CircularProgress size={24} />
                </TableCell>
              </TableRow>
            ) : logs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} align="center" sx={{ py: 4 }}>
                  <Typography variant="body2" color="text.secondary">
                    {t("authLogs.noResults", { defaultValue: "No auth events match these filters." })}
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              logs.map((l) => (
                <TableRow key={l.id} hover sx={{ cursor: "pointer" }} onClick={() => setSelected(l)}>
                  <TableCell>
                    <Tooltip title={fmtDateTime(l.createdAt)}>
                      <span>{fmtRelative(l.createdAt, t)}</span>
                    </Tooltip>
                  </TableCell>
                  <TableCell>
                    {(() => {
                      const p = eventPalette(l.event);
                      const EvIcon = eventIcon(l.event);
                      return (
                        <Chip
                          size="small"
                          icon={<EvIcon size={12} strokeWidth={1.75} color={p.fg} />}
                          label={l.event}
                          sx={{ bgcolor: p.bg, color: p.fg, fontWeight: 500, "& .MuiChip-icon": { ml: 0.75, color: p.fg } }}
                        />
                      );
                    })()}
                  </TableCell>
                  <TableCell>
                    {l.method ? (() => {
                      const p = methodPalette(l.method);
                      return p ? (
                        <Chip
                          size="small"
                          label={l.method}
                          sx={{ bgcolor: p.bg, color: p.fg, fontWeight: 500, textTransform: "capitalize" }}
                        />
                      ) : <Chip size="small" label={l.method} variant="outlined" />;
                    })() : "-"}
                  </TableCell>
                  <TableCell>
                    {l.outcome === "success" ? (
                      <Box sx={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 0.5,
                        bgcolor: "success.main",
                        color: "common.white",
                        px: 1,
                        py: 0.25,
                        borderRadius: 999,
                        fontSize: 12,
                        fontWeight: 600,
                      }}>
                        <CircleCheck size={14} strokeWidth={1.75} />
                        {t("authLogs.outcomeChip.success", { defaultValue: "success" })}
                      </Box>
                    ) : (
                      <Box sx={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 0.5,
                        bgcolor: "error.main",
                        color: "common.white",
                        px: 1,
                        py: 0.25,
                        borderRadius: 999,
                        fontSize: 12,
                        fontWeight: 600,
                      }}>
                        <CircleAlert size={14} strokeWidth={1.75} />
                        {t("authLogs.outcomeChip.failed", { defaultValue: "failed" })}
                      </Box>
                    )}
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">
                      {l.actorLabel || l.emailAttempted || (l.subjectUserId ? l.subjectUserId.slice(0, 8) : "-")}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    {l.actorType === "self" ? (
                      <Typography variant="caption" color="text.secondary">{t("authLogs.actorSelf", { defaultValue: "self" })}</Typography>
                    ) : (
                      (() => {
                        const ActorIcon = ACTOR_TYPE_VOCAB.find((a) => a.value === l.actorType)?.icon ?? User;
                        return (
                          <Stack direction="row" spacing={0.5} alignItems="center">
                            <ActorIcon size={14} strokeWidth={1.75} />
                            <Typography variant="caption">{l.actorType}</Typography>
                          </Stack>
                        );
                      })()
                    )}
                  </TableCell>
                  <TableCell>
                    {(() => {
                      const d = ipDisplay(l.ip);
                      const cell = (
                        <Typography variant="caption" sx={{ color: d.muted ? "text.disabled" : "text.primary", fontStyle: d.muted ? "italic" : "normal" }}>
                          {d.text}
                        </Typography>
                      );
                      return d.tooltip ? <Tooltip title={d.tooltip}>{cell}</Tooltip> : cell;
                    })()}
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption" color="text.secondary">{uaSummary(l.userAgent)}</Typography>
                  </TableCell>
                  <TableCell>
                    {l.failureReason ? (
                      <Chip
                        size="small"
                        label={l.failureReason}
                        variant="outlined"
                        sx={{
                          height: 20,
                          fontSize: 10.5,
                          fontFamily: "var(--font-mono)",
                          letterSpacing: "0.04em",
                          fontWeight: 600,
                          borderColor: "warning.main",
                          color: "warning.main",
                        }}
                      />
                    ) : (
                      "-"
                    )}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Pagination */}
      <Stack direction="row" spacing={1} sx={{ mt: 2 }} alignItems="center" justifyContent="flex-end">
        <Typography variant="caption" color="text.secondary">
          {t("authLogs.pageOf", { page: page + 1, total: Math.max(1, Math.ceil(total / pageSize)), defaultValue: "Page {{page}} of {{total}}" })}
        </Typography>
        <Select size="small" value={pageSize} onChange={(e) => { setPageSize(Number(e.target.value)); setPage(0); }}>
          {[25, 50, 100, 200].map((n) => (
            <MenuItem key={n} value={n}>{t("authLogs.perPage", { count: n, defaultValue: "{{count}} / page" })}</MenuItem>
          ))}
        </Select>
        <Button size="small" disabled={page === 0 || loading} onClick={() => setPage((p) => Math.max(0, p - 1))}>
          {t("authLogs.previous", { defaultValue: "Previous" })}
        </Button>
        <Button size="small" disabled={(page + 1) * pageSize >= total || loading} onClick={() => setPage((p) => p + 1)}>
          {t("authLogs.next", { defaultValue: "Next" })}
        </Button>
      </Stack>

      {/* Drill-in drawer */}
      <Drawer anchor="right" open={!!selected} onClose={() => setSelected(null)} PaperProps={{ sx: { width: 520 } }}>
        {selected && (() => {
          const ev = eventPalette(selected.event);
          const mp = methodPalette(selected.method);
          const ipd = ipDisplay(selected.ip);
          const isSuccess = selected.outcome === "success";
          // Hero band: pulls the row's identity (event color + outcome
          // sentiment) into a coloured banner so the drawer feels like
          // it belongs to the row you clicked, not a generic side panel.
          return (
            <Box>
              {/* HERO */}
              <Box sx={{
                bgcolor: ev.bg,
                color: ev.fg,
                p: 3,
                borderBottom: "1px solid rgba(0,0,0,0.08)",
                position: "relative",
              }}>
                <IconButton size="small" onClick={() => setSelected(null)} sx={{ position: "absolute", top: 8, right: 8, color: ev.fg }}>
                  <X size={16} strokeWidth={1.75} />
                </IconButton>
                <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 1 }}>
                  <Box sx={{
                    width: 40, height: 40, borderRadius: 999,
                    bgcolor: "rgba(255,255,255,0.55)",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    color: ev.fg,
                  }}>
                    {(() => { const Ic = eventIcon(selected.event); return <Ic size={18} strokeWidth={1.75} />; })()}
                  </Box>
                  <Box>
                    <Typography sx={{
                      color: ev.fg,
                      fontFamily: "var(--font-mono)",
                      fontWeight: 600,
                      fontSize: 14,
                      letterSpacing: "-0.005em",
                      lineHeight: 1.2,
                    }}>{selected.event}</Typography>
                    <Typography sx={{
                      color: ev.fg,
                      opacity: 0.75,
                      fontFamily: "var(--font-mono)",
                      fontSize: 11,
                      mt: 0.25,
                    }}>
                      {fmtRelative(selected.createdAt, t)} · {fmtDateTime(selected.createdAt)}
                    </Typography>
                  </Box>
                </Stack>
                <Stack direction="row" spacing={0.75} sx={{ mt: 1.5, flexWrap: "wrap" }}>
                  <Box sx={{
                    display: "inline-flex", alignItems: "center", gap: 0.5,
                    bgcolor: isSuccess ? "success.main" : "error.main",
                    color: "common.white",
                    px: 1.25, py: 0.4, borderRadius: 999, fontSize: 12, fontWeight: 600,
                  }}>
                    {isSuccess ? <CircleCheck size={14} strokeWidth={1.75} /> : <CircleAlert size={14} strokeWidth={1.75} />}
                    {selected.outcome}
                  </Box>
                  {selected.method && mp && (
                    <Chip size="small" label={selected.method}
                      sx={{ bgcolor: mp.bg, color: mp.fg, fontWeight: 500, textTransform: "capitalize" }} />
                  )}
                  {selected.failureReason && (
                    <Chip size="small" label={selected.failureReason}
                      sx={{ bgcolor: "rgba(220,38,38,0.12)", color: "#991B1B", fontWeight: 500 }} />
                  )}
                </Stack>
              </Box>

              {/* BODY */}
              <Stack spacing={0} sx={{ p: 0 }}>
                <DrawerSection icon={User} title={t("authLogs.drawer.who", { defaultValue: "Who" })} accent="#6366F1">
                  <DrawerKV label={t("authLogs.drawer.subject", { defaultValue: "Subject" })} value={selected.actorLabel || selected.emailAttempted || "-"} mono={false} />
                  {selected.subjectUserId && (
                    <DrawerKV label={t("authLogs.drawer.userId", { defaultValue: "User ID" })} value={selected.subjectUserId} mono />
                  )}
                  <DrawerKV
                    label={t("authLogs.drawer.actor", { defaultValue: "Actor" })}
                    value={
                      (() => {
                        const ActorIcon = ACTOR_TYPE_VOCAB.find((a) => a.value === selected.actorType)?.icon ?? User;
                        return (
                      <Stack direction="row" spacing={0.5} alignItems="center">
                        <ActorIcon size={14} strokeWidth={1.75} color="#6366F1" />
                        <Typography variant="body2">{selected.actorType}</Typography>
                        {selected.actorAccountId && (
                          <Typography variant="caption" color="text.secondary" sx={{ ml: 0.5 }}>· {selected.actorAccountId.slice(0, 8)}</Typography>
                        )}
                      </Stack>
                        );
                      })()
                    }
                  />
                </DrawerSection>

                <DrawerSection icon={Globe} title={t("authLogs.drawer.where", { defaultValue: "Where" })} accent="#0EA5E9">
                  <DrawerKV
                    label={t("authLogs.col.ip", { defaultValue: "IP" })}
                    value={
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Typography variant="body2" sx={{
                          color: ipd.muted ? "text.disabled" : "text.primary",
                          fontStyle: ipd.muted ? "italic" : "normal",
                          fontFamily: ipd.muted ? "inherit" : "monospace",
                          fontSize: ipd.muted ? 14 : 13,
                        }}>
                          {ipd.text}
                        </Typography>
                        {ipd.tooltip && (
                          <Typography variant="caption" color="text.secondary">({ipd.tooltip})</Typography>
                        )}
                      </Stack>
                    }
                  />
                </DrawerSection>

                <DrawerSection icon={Monitor} title={t("authLogs.col.device", { defaultValue: "Device" })} accent="#10B981">
                  <DrawerKV label={t("authLogs.drawer.browser", { defaultValue: "Browser" })} value={uaSummary(selected.userAgent) || "-"} />
                  {selected.userAgent && (
                    <Box sx={{ mt: 0.5 }}>
                      <Typography variant="caption" color="text.secondary" sx={{ wordBreak: "break-all", fontFamily: "var(--font-mono)", fontSize: 11 }}>
                        {selected.userAgent}
                      </Typography>
                    </Box>
                  )}
                </DrawerSection>

                {(selected.sessionId || selected.requestId) && (
                  <DrawerSection icon={Link2} title={t("authLogs.drawer.correlation", { defaultValue: "Correlation" })} accent="#A855F7">
                    {selected.sessionId && (
                      <DrawerKV
                        label={t("authLogs.drawer.session", { defaultValue: "Session" })}
                        value={
                          <Box>
                            <Typography variant="body2" sx={{ fontFamily: "var(--font-mono)", fontSize: 12, wordBreak: "break-all" }}>
                              {selected.sessionId}
                            </Typography>
                            <Button size="small" sx={{ mt: 0.5, textTransform: "none" }} onClick={() => {
                              const sp = new URLSearchParams(window.location.search);
                              sp.set("sessionId", selected.sessionId!);
                              sp.delete("subjectUserId");
                              sp.delete("requestId");
                              window.location.search = sp.toString();
                            }}>
                              {t("authLogs.drawer.showSessionEvents", { defaultValue: "Show all events for this session →" })}
                            </Button>
                          </Box>
                        }
                      />
                    )}
                    {selected.requestId && (
                      <DrawerKV
                        label={t("authLogs.drawer.request", { defaultValue: "Request" })}
                        value={
                          <Box>
                            <Typography variant="body2" sx={{ fontFamily: "var(--font-mono)", fontSize: 12, wordBreak: "break-all" }}>
                              {selected.requestId}
                            </Typography>
                            <Button size="small" sx={{ mt: 0.5, textTransform: "none" }} onClick={() => {
                              const sp = new URLSearchParams(window.location.search);
                              sp.set("requestId", selected.requestId!);
                              sp.delete("sessionId");
                              sp.delete("subjectUserId");
                              window.location.search = sp.toString();
                            }}>
                              {t("authLogs.drawer.showRequestEvents", { defaultValue: "Show all events for this request →" })}
                            </Button>
                          </Box>
                        }
                      />
                    )}
                  </DrawerSection>
                )}

                {selected.metadata && (
                  <DrawerSection icon={Filter} title={t("authLogs.drawer.metadata", { defaultValue: "Metadata" })} accent="#F59E0B">
                    <Box component="pre" sx={{
                      bgcolor: "#0F172A",
                      color: "#E2E8F0",
                      p: 1.5,
                      fontSize: 11,
                      lineHeight: 1.5,
                      fontFamily: "var(--font-mono)",
                      overflowX: "auto",
                      borderRadius: 1.5,
                      m: 0,
                    }}>
                      {JSON.stringify(selected.metadata, null, 2)}
                    </Box>
                  </DrawerSection>
                )}
              </Stack>
            </Box>
          );
        })()}
      </Drawer>
    </Box>
  );
}

function StatCard({ label, value, sub, severity }: { label: string; value: string; sub?: string; severity?: "error" | "warning" | "neutral" }) {
  const color = severity === "error" ? "error.main" : severity === "warning" ? "warning.main" : "text.primary";
  return (
    <Paper variant="outlined" sx={{ px: 2, py: 1.5, minWidth: 140 }}>
      <Eyebrow>{label}</Eyebrow>
      <Typography
        sx={{
          color,
          fontFamily: "var(--font-mono)",
          fontFeatureSettings: '"tnum"',
          fontSize: 22,
          fontWeight: 500,
          letterSpacing: "-0.01em",
          lineHeight: 1.2,
          mt: 0.5,
        }}
      >
        {value}
      </Typography>
      {sub && <Typography variant="caption" color="text.secondary">{sub}</Typography>}
    </Paper>
  );
}

// DrawerSection wraps a labelled block in the drill-in drawer with a
// coloured icon header and a soft top border. The accent colour echoes
// the section's role (who/where/device/correlation/metadata) so the
// drawer reads as five distinct cards rather than one wall of text.
function DrawerSection({ icon: Icon, title, accent, children }: { icon: LucideIcon; title: string; accent: string; children: React.ReactNode }) {
  return (
    <Box sx={{ px: 3, py: 2, borderTop: "1px solid rgba(0,0,0,0.06)" }}>
      <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1.5 }}>
        <Box sx={{
          width: 22, height: 22, borderRadius: 1,
          bgcolor: accent + "1F", color: accent,
          display: "grid", placeItems: "center",
        }}>
          <Icon size={12} strokeWidth={1.75} />
        </Box>
        <Typography sx={{
          color: accent,
          fontFamily: "var(--font-mono)",
          fontWeight: 600,
          textTransform: "uppercase",
          letterSpacing: "0.14em",
          fontSize: 10,
        }}>
          {title}
        </Typography>
      </Stack>
      <Stack spacing={1.25}>{children}</Stack>
    </Box>
  );
}

// DrawerKV renders a label/value pair in the drawer. Values may be a
// string or a React node (for chips, links, multi-line content).
function DrawerKV({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <Box>
      <Typography sx={{
        display: "block",
        fontFamily: "var(--font-mono)",
        fontSize: 10,
        fontWeight: 500,
        letterSpacing: "0.14em",
        textTransform: "uppercase",
        color: "text.disabled",
        mb: 0.25,
      }}>
        {label}
      </Typography>
      {typeof value === "string" ? (
        <Typography variant="body2" sx={{ fontFamily: mono ? "var(--font-mono)" : "inherit", fontSize: mono ? 12 : 14, wordBreak: "break-all" }}>
          {value}
        </Typography>
      ) : value}
    </Box>
  );
}

function csvCell(v: unknown): string {
  if (v === null || v === undefined) return "";
  const s = typeof v === "string" ? v : String(v);
  if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}
