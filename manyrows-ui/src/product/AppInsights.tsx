import * as React from "react";
import axios from "axios";
import {
  Alert,
  Box,
  Card,
  CardContent,
  CircularProgress,
  Stack,
  Tab,
  Tabs,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
  useTheme,
} from "@mui/material";
import Eyebrow from "../components/Eyebrow.tsx";
import PageHeader from "../components/PageHeader.tsx";
import { LineChart } from "@mui/x-charts/LineChart";
import { BarChart } from "@mui/x-charts/BarChart";
import { PieChart } from "@mui/x-charts/PieChart";
import { useTranslation } from "react-i18next";
import { ArrowUp, ArrowDown, Minus, Activity } from "lucide-react";

import type { Product } from "../core.ts";

interface Props {
  project: Product;
  appId: string;
}

type RangeKey = "7d" | "30d" | "90d";

interface SummaryResp {
  rangeDays: number;
  totalUsers: number;
  newUsers: number;
  newUsersPrev: number;
  activeUsers: number;
  activeUsersPrev: number;
  loginFailures: number;
  loginFailuresPrev: number;
}

interface TimeseriesPoint {
  date: string;
  count: number;
}
interface TimeseriesResp {
  metric: string;
  points: TimeseriesPoint[];
}

interface ActivityPoint {
  date: string;
  dau: number;
  wau: number;
  mau: number;
}
interface ActivityResp {
  points: ActivityPoint[];
}

interface SourceItem {
  source: string;
  count: number;
}
interface SourceResp {
  items: SourceItem[];
}

function sourceLabel(source: string, t: (key: string, opts?: Record<string, unknown>) => string): string {
  // Known sources get a translatable label; unknown ones fall through to the
  // raw value so new server-side sources don't render as gibberish.
  switch (source) {
    case "registered":
      return t("appInsights.source.registered", { defaultValue: "Registered" });
    case "invited":
      return t("appInsights.source.invited", { defaultValue: "Invited" });
    case "google":
      return t("appInsights.source.google", { defaultValue: "Google" });
    default:
      return source;
  }
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toString();
}

function formatDateLabel(iso: string): string {
  // "2026-04-25" → "Apr 25"
  const d = new Date(iso + "T00:00:00Z");
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
}

function StatCard({
  label,
  value,
  prev,
  invertColor,
  loading,
}: {
  label: string;
  value: number | undefined;
  prev?: number | undefined;
  invertColor?: boolean;
  loading: boolean;
}) {
  const theme = useTheme();
  const { t } = useTranslation();
  const hasDelta = !loading && typeof value === "number" && typeof prev === "number";
  const delta = hasDelta ? value! - prev! : 0;
  const pct = hasDelta && prev! > 0 ? Math.round((delta / prev!) * 100) : null;

  let direction: "up" | "down" | "flat" = "flat";
  if (hasDelta && delta > 0) direction = "up";
  else if (hasDelta && delta < 0) direction = "down";

  // Default: up = good (green), down = bad (red).
  // invertColor flips it: e.g. login failures, where up is bad.
  let color: "success.main" | "error.main" | "text.secondary" = "text.secondary";
  if (direction === "up") color = invertColor ? "error.main" : "success.main";
  else if (direction === "down") color = invertColor ? "success.main" : "error.main";

  return (
    <Card sx={{ flex: 1, minWidth: 180 }}>
      <CardContent sx={{ "&:last-child": { pb: 2 } }}>
        <Eyebrow>{label}</Eyebrow>
        <Typography
          sx={{
            mt: 1,
            fontFamily: "var(--font-mono)",
            fontFeatureSettings: '"tnum"',
            fontSize: 28,
            fontWeight: 500,
            letterSpacing: "-0.02em",
            lineHeight: 1.1,
            color: theme.palette.text.primary,
          }}
        >
          {loading ? <CircularProgress size={18} /> : value !== undefined ? formatNumber(value) : "-"}
        </Typography>
        {hasDelta && (
          <Stack direction="row" alignItems="center" spacing={0.75} sx={{ mt: 0.5, color }}>
            {direction === "up" ? (
              <ArrowUp size={12} strokeWidth={2} />
            ) : direction === "down" ? (
              <ArrowDown size={12} strokeWidth={2} />
            ) : (
              <Minus size={12} strokeWidth={2} />
            )}
            <Typography variant="caption" sx={{ fontWeight: 600 }}>
              {delta === 0 ? t("appInsights.noChange", { defaultValue: "no change" }) : `${delta > 0 ? "+" : ""}${formatNumber(delta)}`}
              {pct !== null && delta !== 0 && ` (${pct > 0 ? "+" : ""}${pct}%)`}
            </Typography>
          </Stack>
        )}
      </CardContent>
    </Card>
  );
}

function ChartCard({
  title,
  height = 260,
  children,
}: {
  title: string;
  height?: number;
  children: React.ReactNode;
}) {
  return (
    <Card sx={{ flex: 1, minWidth: 320, display: "flex", flexDirection: "column" }}>
      <CardContent sx={{ display: "flex", flexDirection: "column", flex: 1, "&:last-child": { pb: 2 } }}>
        <Eyebrow sx={{ mb: 1.5 }}>{title}</Eyebrow>
        <Box sx={{ flex: 1, minHeight: height, display: "flex", alignItems: "center", justifyContent: "center" }}>
          {children}
        </Box>
      </CardContent>
    </Card>
  );
}

function EmptyState({ message }: { message: string }) {
  return (
    <Stack alignItems="center" spacing={1} sx={{ color: "text.disabled" }}>
      <Activity size={28} strokeWidth={1.5} />
      <Typography variant="caption">{message}</Typography>
    </Stack>
  );
}

export default function AppInsights({ project, appId }: Props) {
  const { t } = useTranslation();
  const theme = useTheme();

  const [range, setRange] = React.useState<RangeKey>("30d");
  const [tab, setTab] = React.useState(0);
  const [loading, setLoading] = React.useState(true);
  const [err, setErr] = React.useState("");

  const [summary, setSummary] = React.useState<SummaryResp | undefined>();
  const [signups, setSignups] = React.useState<TimeseriesPoint[]>([]);
  const [logins, setLogins] = React.useState<TimeseriesPoint[]>([]);
  const [cumulative, setCumulative] = React.useState<TimeseriesPoint[]>([]);
  const [failures, setFailures] = React.useState<TimeseriesPoint[]>([]);
  const [activity, setActivity] = React.useState<ActivityPoint[]>([]);
  const [sources, setSources] = React.useState<SourceItem[]>([]);

  const baseURL = `/admin/workspace/${project.workspaceId}/products/${project.id}/apps/${appId}/insights`;

  React.useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setErr("");

    Promise.all([
      axios.get<SummaryResp>(`${baseURL}/summary`, { params: { range } }),
      axios.get<TimeseriesResp>(`${baseURL}/timeseries`, { params: { metric: "signups", range } }),
      axios.get<TimeseriesResp>(`${baseURL}/timeseries`, { params: { metric: "logins", range } }),
      axios.get<TimeseriesResp>(`${baseURL}/timeseries`, { params: { metric: "cumulative_users", range } }),
      axios.get<TimeseriesResp>(`${baseURL}/timeseries`, { params: { metric: "login_failures", range } }),
      axios.get<ActivityResp>(`${baseURL}/activity`, { params: { range } }),
      axios.get<SourceResp>(`${baseURL}/sources`),
    ])
      .then(([summaryRes, signupsRes, loginsRes, cumRes, failRes, actRes, srcRes]) => {
        if (cancelled) return;
        setSummary(summaryRes.data);
        setSignups(signupsRes.data.points || []);
        setLogins(loginsRes.data.points || []);
        setCumulative(cumRes.data.points || []);
        setFailures(failRes.data.points || []);
        setActivity(actRes.data.points || []);
        setSources(srcRes.data.items || []);
      })
      .catch((e) => {
        if (cancelled) return;
        setErr(e?.response?.data?.error || e?.message || t("appInsights.failedToLoad", { defaultValue: "Failed to load insights" }));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [baseURL, range]);

  const labels = signups.map((p) => formatDateLabel(p.date));
  const activityLabels = activity.map((p) => formatDateLabel(p.date));

  const totalSourceCount = sources.reduce((acc, s) => acc + s.count, 0);

  // Color palette consistent with the rest of the admin UI.
  const palette = {
    primary: theme.palette.primary.main,
    success: theme.palette.success.main,
    warning: theme.palette.warning.main,
    error: theme.palette.error.main,
    info: theme.palette.info.main,
  };

  return (
    <Stack spacing={2}>
      <PageHeader
        title={t("appInsights.title", { defaultValue: "Insights" })}
        mb={0}
        action={
          <ToggleButtonGroup
            size="small"
            value={range}
            exclusive
            onChange={(_, v) => {
              if (v) setRange(v);
            }}
            sx={{
              "& .MuiToggleButton-root": {
                fontFamily: "var(--font-mono)",
                textTransform: "uppercase",
                letterSpacing: "0.1em",
                fontSize: 11,
                fontWeight: 500,
                px: 1.5,
                py: 0.5,
                color: "text.secondary",
                borderColor: "divider",
                "&.Mui-selected": {
                  bgcolor: "text.primary",
                  color: "background.default",
                  "&:hover": { bgcolor: "text.primary" },
                },
              },
            }}
          >
            <ToggleButton value="7d">{t("appInsights.range.7d", { defaultValue: "7d" })}</ToggleButton>
            <ToggleButton value="30d">{t("appInsights.range.30d", { defaultValue: "30d" })}</ToggleButton>
            <ToggleButton value="90d">{t("appInsights.range.90d", { defaultValue: "90d" })}</ToggleButton>
          </ToggleButtonGroup>
        }
      />

      {err && <Alert severity="error">{err}</Alert>}

      {/* Stat cards */}
      <Stack direction="row" spacing={2} sx={{ flexWrap: "wrap", gap: 2, "&>*": { flexGrow: 1, flexBasis: { xs: "100%", sm: "calc(50% - 8px)", md: "calc(25% - 12px)" } } }}>
        <StatCard
          label={t("appInsights.cards.totalUsers", { defaultValue: "Total users" })}
          value={summary?.totalUsers}
          loading={loading}
        />
        <StatCard
          label={t("appInsights.cards.newUsers", { range })}
          value={summary?.newUsers}
          prev={summary?.newUsersPrev}
          loading={loading}
        />
        <StatCard
          label={t("appInsights.cards.activeUsers", { range })}
          value={summary?.activeUsers}
          prev={summary?.activeUsersPrev}
          loading={loading}
        />
        <StatCard
          label={t("appInsights.cards.loginFailures", { range })}
          value={summary?.loginFailures}
          prev={summary?.loginFailuresPrev}
          invertColor
          loading={loading}
        />
      </Stack>

      {/* Chart tabs - one chart per tab. Range toggle above applies to all. */}
      <Tabs
        value={tab}
        onChange={(_, v) => setTab(v)}
        variant="scrollable"
        scrollButtons="auto"
        sx={{ borderBottom: 1, borderColor: "divider" }}
      >
        <Tab label={t("appInsights.tabs.signups", { defaultValue: "Signups" })} sx={{ textTransform: "none", fontWeight: 600 }} />
        <Tab label={t("appInsights.tabs.logins", { defaultValue: "Logins" })} sx={{ textTransform: "none", fontWeight: 600 }} />
        <Tab label={t("appInsights.tabs.activity", { defaultValue: "Active users" })} sx={{ textTransform: "none", fontWeight: 600 }} />
        <Tab label={t("appInsights.tabs.cumulative", { defaultValue: "Cumulative users" })} sx={{ textTransform: "none", fontWeight: 600 }} />
        <Tab label={t("appInsights.tabs.failures", { defaultValue: "Login failures" })} sx={{ textTransform: "none", fontWeight: 600 }} />
        <Tab label={t("appInsights.tabs.sources", { defaultValue: "Sources" })} sx={{ textTransform: "none", fontWeight: 600 }} />
      </Tabs>

      {tab === 0 && (
        <ChartCard title={t("appInsights.charts.signups", { defaultValue: "Signups per day" })} height={360}>
          {signups.length === 0 ? (
            <EmptyState message={t("appInsights.empty.signups", { defaultValue: "No signups yet" })} />
          ) : (
            <LineChart
              xAxis={[{ scaleType: "point", data: labels }]}
              series={[{ data: signups.map((p) => p.count), color: palette.primary, area: true, showMark: false, label: t("appInsights.series.signups", { defaultValue: "Signups" }) }]}
              height={360}
              margin={{ top: 10, right: 16, bottom: 28, left: 36 }}
              grid={{ horizontal: true }}
              hideLegend
            />
          )}
        </ChartCard>
      )}

      {tab === 1 && (
        <ChartCard title={t("appInsights.charts.logins", { defaultValue: "Logins per day" })} height={360}>
          {logins.length === 0 || logins.every((p) => p.count === 0) ? (
            <EmptyState message={t("appInsights.empty.logins", { defaultValue: "No login data - events start collecting once users sign in" })} />
          ) : (
            <LineChart
              xAxis={[{ scaleType: "point", data: labels }]}
              series={[{ data: logins.map((p) => p.count), color: palette.success, area: true, showMark: false, label: t("appInsights.series.logins", { defaultValue: "Logins" }) }]}
              height={360}
              margin={{ top: 10, right: 16, bottom: 28, left: 36 }}
              grid={{ horizontal: true }}
              hideLegend
            />
          )}
        </ChartCard>
      )}

      {tab === 2 && (
        <ChartCard title={t("appInsights.charts.activity", { defaultValue: "Active users (daily / weekly / monthly)" })} height={360}>
          {activity.length === 0 || activity.every((p) => p.dau === 0 && p.wau === 0 && p.mau === 0) ? (
            <EmptyState message={t("appInsights.empty.activity", { defaultValue: "No activity data yet" })} />
          ) : (
            <LineChart
              xAxis={[{ scaleType: "point", data: activityLabels }]}
              series={[
                { data: activity.map((p) => p.dau), color: palette.primary, label: "DAU", showMark: false },
                { data: activity.map((p) => p.wau), color: palette.warning, label: "WAU", showMark: false },
                { data: activity.map((p) => p.mau), color: palette.info, label: "MAU", showMark: false },
              ]}
              height={360}
              margin={{ top: 10, right: 16, bottom: 28, left: 36 }}
              grid={{ horizontal: true }}
            />
          )}
        </ChartCard>
      )}

      {tab === 3 && (
        <ChartCard title={t("appInsights.charts.cumulative", { defaultValue: "Cumulative users" })} height={360}>
          {cumulative.length === 0 ? (
            <EmptyState message={t("appInsights.empty.cumulative", { defaultValue: "No data yet" })} />
          ) : (
            <LineChart
              xAxis={[{ scaleType: "point", data: labels }]}
              series={[{ data: cumulative.map((p) => p.count), color: palette.info, area: true, showMark: false, label: t("appInsights.series.users", { defaultValue: "Users" }) }]}
              height={360}
              margin={{ top: 10, right: 16, bottom: 28, left: 36 }}
              grid={{ horizontal: true }}
              hideLegend
            />
          )}
        </ChartCard>
      )}

      {tab === 4 && (
        <ChartCard title={t("appInsights.charts.failures", { defaultValue: "Login failures per day" })} height={360}>
          {failures.length === 0 || failures.every((p) => p.count === 0) ? (
            <EmptyState message={t("appInsights.empty.failures", { defaultValue: "No login failures recorded" })} />
          ) : (
            <BarChart
              xAxis={[{ scaleType: "band", data: labels }]}
              series={[{ data: failures.map((p) => p.count), color: palette.error, label: t("appInsights.series.failures", { defaultValue: "Failures" }) }]}
              height={360}
              margin={{ top: 10, right: 16, bottom: 28, left: 36 }}
              grid={{ horizontal: true }}
              hideLegend
            />
          )}
        </ChartCard>
      )}

      {tab === 5 && (
        <ChartCard title={t("appInsights.charts.sources", { defaultValue: "Signup source breakdown" })} height={360}>
          {sources.length === 0 || totalSourceCount === 0 ? (
            <EmptyState message={t("appInsights.empty.sources", { defaultValue: "No users yet" })} />
          ) : (
            <PieChart
              series={[
                {
                  data: sources.map((s, i) => ({
                    id: i,
                    value: s.count,
                    label: sourceLabel(s.source, t),
                  })),
                  innerRadius: 80,
                  outerRadius: 140,
                  paddingAngle: 2,
                  cornerRadius: 4,
                  highlightScope: { fade: "global", highlight: "item" },
                  faded: { innerRadius: 80, additionalRadius: -10, color: "gray" },
                },
              ]}
              height={360}
              margin={{ top: 10, right: 16, bottom: 10, left: 16 }}
            />
          )}
        </ChartCard>
      )}
    </Stack>
  );
}
