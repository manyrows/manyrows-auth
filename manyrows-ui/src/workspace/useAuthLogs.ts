import * as React from "react";
import axios from "axios";
import { useTranslation } from "react-i18next";
import { extractApiError } from "../lib/apiError.ts";
import { useDebouncedValue } from "../hooks/useDebouncedValue.ts";

// Data layer for the Auth Logs screen: the paged log read API and the
// useAuthLogs hook that owns the filter/paging state, the URL-param-driven
// pre-filters, auto-refresh, and the load lifecycle. Split out of AuthLogs.tsx
// so that (large) file stays presentation-focused (mirrors the useAppUsers /
// useSessions splits).

export type AuthLog = {
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

  // Raw server metadata blob; rendered only via truthiness + JSON.stringify.
  // Kept as `any` (preserved from the original inline type) because the
  // `{selected.metadata && ...}` render needs it to satisfy ReactNode.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  metadata?: any;
};

export type PresetId = "all" | "suspicious" | "admin" | "oauth" | "failed";

type AuthLogsResponse = {
  logs: AuthLog[];
  total: number;
  page: number;
  pageSize: number;
};

// presetParams maps a preset choice to query-param overrides. Returns an
// override map (merged on top of the per-control filters) or null for "all".
function presetParams(p: PresetId): Record<string, string | string[]> | null {
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

// useAuthLogs owns the filter/paging state, the URL-param pre-filters, the
// auto-refresh poll and the load lifecycle. Returns state + setters with the
// same names the component used inline, plus load() for the refresh control.
export function useAuthLogs(workspaceId: string, appId: string | undefined) {
  const baseURL = `/admin/workspace/${workspaceId}/auth/logs`;
  const { t } = useTranslation();

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
  const [preset, setPreset] = React.useState<PresetId>("all");
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

  return {
    logs,
    total,
    loading,
    err,
    preset,
    setPreset,
    eventsSel,
    setEventsSel,
    methodsSel,
    setMethodsSel,
    outcome,
    setOutcome,
    actorType,
    setActorType,
    emailLike,
    setEmailLike,
    subjectUserId,
    sessionId,
    requestId,
    page,
    setPage,
    pageSize,
    setPageSize,
    autoRefresh,
    setAutoRefresh,
    load,
  };
}
