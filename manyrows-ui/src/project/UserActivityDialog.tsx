import * as React from "react";
import axios from "axios";
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
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
  useTheme,
} from "@mui/material";
import { Check, KeyRound, Activity, Link2, Trash2, X } from "lucide-react";
import Eyebrow from "../components/Eyebrow.tsx";
import { LineChart } from "@mui/x-charts/LineChart";
import { useTranslation } from "react-i18next";
interface Props {
  open: boolean;
  onClose: () => void;
  workspaceId: string;
  projectId: string;
  appId: string;
  userId: string;
  userEmail: string;
}

interface ActivityEvent {
  status: "success" | "failed";
  method: string;
  failureReason?: string;
  ip?: string;
  userAgent?: string;
  createdAt: string;
}

interface ActivityResponse {
  userId: string;
  rangeDays: number;
  logins: number;
  loginsPrev: number;
  failures: number;
  failuresPrev: number;
  lastLoginAt?: string;
  lastLoginIp?: string;
  lastLoginUa?: string;
  lastLoginMethod?: string;
  activeSessions: number;
  daily: { date: string; count: number }[];
  recentEvents: ActivityEvent[];
}

function formatRelative(iso: string): string {
  const d = new Date(iso);
  const diff = Date.now() - d.getTime();
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  if (sec < 86400 * 30) return `${Math.floor(sec / 86400)}d ago`;
  return d.toLocaleDateString();
}

function formatAbsolute(iso: string): string {
  return new Date(iso).toLocaleString();
}

function StatCard({
  label,
  value,
  loading,
  hint,
}: {
  label: string;
  value: string | number;
  loading: boolean;
  hint?: string;
}) {
  return (
    <Box sx={{ flex: 1, minWidth: 120, p: 1.5, border: "1px solid", borderColor: "divider", borderRadius: 1 }}>
      <Eyebrow>{label}</Eyebrow>
      <Typography
        sx={{
          fontFamily: "var(--font-mono)",
          fontFeatureSettings: '"tnum"',
          fontSize: 20,
          fontWeight: 500,
          letterSpacing: "-0.01em",
          lineHeight: 1.2,
          mt: 0.5,
        }}
      >
        {loading ? <CircularProgress size={16} /> : value}
      </Typography>
      {hint && (
        <Typography variant="caption" color="text.secondary" noWrap title={hint}>
          {hint}
        </Typography>
      )}
    </Box>
  );
}

export default function UserActivityDialog({
  open,
  onClose,
  workspaceId,
  projectId,
  appId,
  userId,
  userEmail,
}: Props) {
  const { t } = useTranslation();
  const theme = useTheme();

  const [loading, setLoading] = React.useState(false);
  const [err, setErr] = React.useState("");
  const [data, setData] = React.useState<ActivityResponse | null>(null);

  React.useEffect(() => {
    if (!open || !userId) return;
    let cancelled = false;
    setLoading(true);
    setErr("");
    setData(null);

    const url = `/admin/workspace/${workspaceId}/projects/${projectId}/apps/${appId}/users/${userId}/activity`;
    axios
      .get<ActivityResponse>(url, { params: { range: "30d" } })
      .then((res) => {
        if (cancelled) return;
        setData(res.data);
      })
      .catch((e) => {
        if (cancelled) return;
        setErr(e?.response?.data?.error || e?.message || t("userActivity.failedToLoad", { defaultValue: "Failed to load activity" }));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [open, workspaceId, projectId, appId, userId]);

  const labels = data?.daily.map((p) => {
    const d = new Date(p.date + "T00:00:00Z");
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
  }) ?? [];

  const totalDaily = data?.daily.reduce((acc, p) => acc + p.count, 0) ?? 0;

  type AdminPasskey = {
    id: string;
    name?: string;
    transports: string[];
    authenticatorName?: string;
    backupEligible: boolean;
    createdAt: string;
    lastUsedAt?: string;
  };
  const [passkeys, setPasskeys] = React.useState<AdminPasskey[]>([]);
  const [passkeysLoading, setPasskeysLoading] = React.useState(false);
  const [revokingId, setRevokingId] = React.useState<string | null>(null);

  const passkeysURL = `/admin/workspace/${workspaceId}/projects/${projectId}/apps/${appId}/users/${userId}/passkeys`;

  React.useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setPasskeysLoading(true);
    axios
      .get<{ passkeys: AdminPasskey[] }>(passkeysURL)
      .then((res) => { if (!cancelled) setPasskeys(res.data?.passkeys ?? []); })
      .catch(() => { /* tolerate - passkeys may not be enabled */ })
      .finally(() => { if (!cancelled) setPasskeysLoading(false); });
    return () => { cancelled = true; };
  }, [open, passkeysURL]);

  const revokePasskey = async (id: string) => {
    setRevokingId(id);
    try {
      await axios.delete(`${passkeysURL}/${encodeURIComponent(id)}`);
      setPasskeys((ps) => ps.filter((p) => p.id !== id));
    } finally {
      setRevokingId(null);
    }
  };

  type AdminIdentity = {
    provider: string;
    providerEmail?: string;
    createdAt: string;
    lastLoginAt: string;
  };
  const PROVIDER_LABEL: Record<string, string> = {
    google: "Google",
    apple: "Apple",
    microsoft: "Microsoft",
    github: "GitHub",
  };
  const [identities, setIdentities] = React.useState<AdminIdentity[]>([]);
  const [identitiesLoading, setIdentitiesLoading] = React.useState(false);
  const [revokingProvider, setRevokingProvider] = React.useState<string | null>(null);

  const identitiesURL = `/admin/workspace/${workspaceId}/projects/${projectId}/apps/${appId}/users/${userId}/identities`;

  React.useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setIdentitiesLoading(true);
    axios
      .get<{ identities: AdminIdentity[] }>(identitiesURL)
      .then((res) => { if (!cancelled) setIdentities(res.data?.identities ?? []); })
      .catch(() => { /* tolerate - user may have no linked identities */ })
      .finally(() => { if (!cancelled) setIdentitiesLoading(false); });
    return () => { cancelled = true; };
  }, [open, identitiesURL]);

  const revokeIdentity = async (provider: string) => {
    setRevokingProvider(provider);
    try {
      await axios.delete(`${identitiesURL}/${encodeURIComponent(provider)}`);
      setIdentities((ids) => ids.filter((i) => i.provider !== provider));
    } finally {
      setRevokingProvider(null);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle>
        <Stack direction="row" alignItems="center" spacing={1}>
          <Activity size={14} strokeWidth={1.75} />
          <Typography sx={{ fontSize: 17, fontWeight: 600, letterSpacing: "-0.005em" }}>
            {t("userActivity.title", { defaultValue: "Activity" })}
          </Typography>
          <Typography variant="body2" color="text.secondary" noWrap title={userEmail}>
            · {userEmail}
          </Typography>
        </Stack>
      </DialogTitle>
      <DialogContent dividers>
        {err && <Alert severity="error" sx={{ mb: 2 }}>{err}</Alert>}

        <Stack spacing={2}>
          {/* Stat cards */}
          <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap", gap: 1 }}>
            <StatCard
              label={t("userActivity.logins", { defaultValue: "Logins (30d)" })}
              value={data?.logins ?? "-"}
              loading={loading}
            />
            <StatCard
              label={t("userActivity.failures", { defaultValue: "Failures (30d)" })}
              value={data?.failures ?? "-"}
              loading={loading}
            />
            <StatCard
              label={t("userActivity.activeSessions", { defaultValue: "Active sessions" })}
              value={data?.activeSessions ?? "-"}
              loading={loading}
            />
            <StatCard
              label={t("userActivity.lastLogin", { defaultValue: "Last login" })}
              value={data?.lastLoginAt ? formatRelative(data.lastLoginAt) : "-"}
              loading={loading}
              hint={data?.lastLoginAt ? `${data.lastLoginMethod || "?"} · ${data.lastLoginIp || ""}` : undefined}
            />
          </Stack>

          {/* Sparkline */}
          <Box>
            <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
              {t("userActivity.dailyLogins", { defaultValue: "Daily logins (last 30 days)" })}
            </Typography>
            {loading ? (
              <Box sx={{ height: 140, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <CircularProgress size={24} />
              </Box>
            ) : totalDaily === 0 ? (
              <Box sx={{ height: 140, display: "flex", alignItems: "center", justifyContent: "center", color: "text.disabled" }}>
                <Typography variant="caption">
                  {t("userActivity.noLogins", { defaultValue: "No logins in the last 30 days" })}
                </Typography>
              </Box>
            ) : (
              <LineChart
                xAxis={[{ scaleType: "point", data: labels }]}
                series={[
                  {
                    data: data?.daily.map((p) => p.count) ?? [],
                    color: theme.palette.primary.main,
                    area: true,
                    showMark: false,
                  },
                ]}
                height={140}
                margin={{ top: 8, right: 8, bottom: 24, left: 32 }}
                grid={{ horizontal: true }}
                hideLegend
              />
            )}
          </Box>

          {/* Recent events */}
          <Box>
            <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
              {t("userActivity.recentEvents", { defaultValue: "Recent events" })}
            </Typography>
            {loading ? (
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", py: 2 }}>
                <CircularProgress size={20} />
              </Box>
            ) : !data?.recentEvents?.length ? (
              <Typography variant="caption" color="text.disabled">
                {t("userActivity.noEvents", { defaultValue: "No events recorded yet" })}
              </Typography>
            ) : (
              <TableContainer sx={{ maxHeight: 280 }}>
                <Table size="small" stickyHeader>
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ width: 36 }} />
                      <TableCell>{t("userActivity.method", { defaultValue: "Method" })}</TableCell>
                      <TableCell>{t("userActivity.when", { defaultValue: "When" })}</TableCell>
                      <TableCell>{t("userActivity.ip", { defaultValue: "IP" })}</TableCell>
                      <TableCell>{t("userActivity.detail", { defaultValue: "Detail" })}</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {data.recentEvents.map((ev, i) => (
                      <TableRow key={i}>
                        <TableCell>
                          {ev.status === "success" ? (
                            <Check size={14} strokeWidth={2} color={theme.palette.success.main} />
                          ) : (
                            <X size={14} strokeWidth={2} color={theme.palette.error.main} />
                          )}
                        </TableCell>
                        <TableCell>
                          <Chip label={ev.method || "-"} size="small" variant="outlined" />
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption" title={formatAbsolute(ev.createdAt)}>
                            {formatRelative(ev.createdAt)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption" sx={{ fontFamily: "var(--font-mono)" }}>
                            {ev.ip || "-"}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          {ev.failureReason ? (
                            <Chip
                              label={ev.failureReason}
                              size="small"
                              variant="outlined"
                              sx={{
                                fontFamily: "var(--font-mono)",
                                fontSize: 10.5,
                                fontWeight: 600,
                                borderColor: "error.main",
                                color: "error.main",
                              }}
                            />
                          ) : (
                            <Typography variant="caption" color="text.disabled">
                              -
                            </Typography>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Box>

          {/* Connected social accounts (Google/Apple/Microsoft/GitHub) */}
          <Box>
            <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
              <Link2 size={14} strokeWidth={1.75} />
              {t("userActivity.connectedAccounts", { defaultValue: "Connected accounts" })}
            </Typography>
            {identitiesLoading ? (
              <Box sx={{ py: 1, display: "flex", justifyContent: "center" }}><CircularProgress size={20} /></Box>
            ) : identities.length === 0 ? (
              <Typography variant="caption" color="text.disabled">
                {t("userActivity.noIdentities", { defaultValue: "No social accounts linked" })}
              </Typography>
            ) : (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>{t("userActivity.identityProvider", { defaultValue: "Provider" })}</TableCell>
                      <TableCell>{t("userActivity.identityEmail", { defaultValue: "Provider email" })}</TableCell>
                      <TableCell>{t("userActivity.identityLastLogin", { defaultValue: "Last sign-in" })}</TableCell>
                      <TableCell align="right" />
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {identities.map((i) => (
                      <TableRow key={i.provider} hover>
                        <TableCell>
                          <Typography variant="body2">{PROVIDER_LABEL[i.provider] ?? i.provider}</Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">{i.providerEmail || "-"}</Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">{formatRelative(i.lastLoginAt)}</Typography>
                        </TableCell>
                        <TableCell align="right">
                          <Button
                            size="small"
                            color="error"
                            disabled={revokingProvider === i.provider}
                            startIcon={revokingProvider === i.provider ? <CircularProgress size={12} /> : <Trash2 size={12} strokeWidth={1.75} />}
                            onClick={() => revokeIdentity(i.provider)}
                          >
                            {t("userActivity.disconnect", { defaultValue: "Disconnect" })}
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Box>

          {/* Passkeys */}
          <Box>
            <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
              <KeyRound size={14} strokeWidth={1.75} />
              {t("userActivity.passkeys", { defaultValue: "Passkeys" })}
            </Typography>
            {passkeysLoading ? (
              <Box sx={{ py: 1, display: "flex", justifyContent: "center" }}><CircularProgress size={20} /></Box>
            ) : passkeys.length === 0 ? (
              <Typography variant="caption" color="text.disabled">
                {t("userActivity.noPasskeys", { defaultValue: "No passkeys registered" })}
              </Typography>
            ) : (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>{t("userActivity.passkeyName", { defaultValue: "Name" })}</TableCell>
                      <TableCell>{t("userActivity.passkeyAdded", { defaultValue: "Added" })}</TableCell>
                      <TableCell>{t("userActivity.passkeyLastUsed", { defaultValue: "Last used" })}</TableCell>
                      <TableCell align="right" />
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {passkeys.map((p) => (
                      <TableRow key={p.id} hover>
                        <TableCell>
                          {p.name || p.authenticatorName || <Typography variant="caption" color="text.disabled">{t("userActivity.unnamed", { defaultValue: "Unnamed" })}</Typography>}
                          {p.backupEligible && <Chip label={t("userActivity.synced", { defaultValue: "synced" })} size="small" sx={{ ml: 1, height: 18, fontSize: 10 }} />}
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">{formatRelative(p.createdAt)}</Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">{p.lastUsedAt ? formatRelative(p.lastUsedAt) : "-"}</Typography>
                        </TableCell>
                        <TableCell align="right">
                          <Button
                            size="small"
                            color="error"
                            disabled={revokingId === p.id}
                            startIcon={revokingId === p.id ? <CircularProgress size={12} /> : <Trash2 size={12} strokeWidth={1.75} />}
                            onClick={() => revokePasskey(p.id)}
                          >
                            {t("userActivity.revoke", { defaultValue: "Revoke" })}
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Box>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t("common.close")}</Button>
      </DialogActions>
    </Dialog>
  );
}
