import * as React from "react";
import axios from "axios";
import { useSnackbar } from "notistack";
import { useTranslation } from "react-i18next";
import { useDebouncedValue } from "../hooks/useDebouncedValue.ts";

// Data layer for the Sessions screen: the session read/mutation API and the
// useSessions hook that owns the paged list, the debounced email filter, the
// paging state and the load lifecycle. Split out of Sessions.tsx so that file
// stays presentation-focused (mirrors the useAppUsers split).

type SessionApp = {
  id: string;
  name: string;
};

export type SessionResource = {
  id: string;
  userId: string;
  createdAt: string;
  expiresAt: string;
  lastSeenAt: string;
  userAgent: string;
  ip: string;
  user?: { id: string; email: string } | null;
  app?: SessionApp | null;
};

type SessionsResponse = {
  sessions: SessionResource[];
  total: number;
};

export function getErrMessage(err: unknown, t: (key: string) => string): string {
  const errObj = (err ?? {}) as { response?: { status?: number; data?: unknown } };
  const status = errObj.response?.status;
  const data = errObj.response?.data;

  if (typeof data === "string" && data.trim().length > 0) return data;
  if (status === 400) return t("error.badRequest");
  if (status === 401) return t("error.notSignedIn");
  if (status === 403) return t("error.noPermission");
  if (status === 404) return t("error.workspaceNotFound");
  return t("error.generic");
}

async function fetchSessions(
  workspaceId: string,
  limit: number,
  offset: number,
  email?: string,
  appId?: string,
): Promise<SessionsResponse> {
  const r = await axios.get(`/admin/workspace/${workspaceId}/sessions`, {
    params: { limit, offset, email: email?.trim() || undefined, appId: appId || undefined },
  });
  return r.data;
}

export async function deleteSession(workspaceId: string, sessionId: string): Promise<void> {
  await axios.delete(`/admin/workspace/${workspaceId}/sessions/${sessionId}`);
}

export async function deleteSessionsByAccount(workspaceId: string, accountId: string, excludeSessionId?: string): Promise<void> {
  await axios.delete(`/admin/workspace/${workspaceId}/sessions`, {
    params: { accountId, exclude: excludeSessionId || undefined },
  });
}

export async function pruneExpiredSessions(workspaceId: string): Promise<{ deleted: number }> {
  const r = await axios.post(`/admin/workspace/${workspaceId}/sessions/prune`);
  return r.data;
}

// useSessions owns the paged session list, the debounced email filter, the
// paging state and the load lifecycle. Returns state + setters with the same
// names the component used inline, plus load() for the mutation handlers to
// call after a revoke/prune.
export function useSessions(workspaceId: string, appId: string | undefined, initialEmail: string | undefined) {
  const { enqueueSnackbar } = useSnackbar();
  const { t } = useTranslation();

  const [sessions, setSessions] = React.useState<SessionResource[]>([]);
  const [total, setTotal] = React.useState(0);

  const [page, setPage] = React.useState(0);
  const [rowsPerPage, setRowsPerPage] = React.useState(25);

  const [loading, setLoading] = React.useState(false);
  const [errorText, setErrorText] = React.useState<string | null>(null);

  // email search (debounced)
  const [emailInput, setEmailInput] = React.useState(initialEmail || "");
  const email = useDebouncedValue(emailInput.trim(), 350);

  const offset = page * rowsPerPage;

  const load = React.useCallback(async () => {
    if (!workspaceId) return;

    setLoading(true);
    setErrorText(null);
    try {
      const data = await fetchSessions(workspaceId, rowsPerPage, offset, email, appId);
      setSessions(Array.isArray(data.sessions) ? data.sessions : []);
      setTotal(typeof data.total === "number" ? data.total : 0);
    } catch (err) {
      const msg = getErrMessage(err, t);
      setErrorText(msg);
      enqueueSnackbar(msg, { variant: "error" });
      setSessions([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [workspaceId, rowsPerPage, offset, email, appId, enqueueSnackbar]);

  React.useEffect(() => {
    load();
  }, [load]);

  React.useEffect(() => {
    setPage(0);
  }, [workspaceId]);

  // Reset to first page when search changes
  React.useEffect(() => {
    setPage(0);
  }, [email]);

  const onChangePage = (_: unknown, nextPage: number) => setPage(nextPage);

  const onChangeRowsPerPage = (e: React.ChangeEvent<HTMLInputElement>) => {
    const next = parseInt(e.target.value, 10);
    setRowsPerPage(Number.isFinite(next) ? next : 25);
    setPage(0);
  };

  return {
    sessions,
    total,
    page,
    setPage,
    rowsPerPage,
    loading,
    errorText,
    emailInput,
    setEmailInput,
    email,
    load,
    onChangePage,
    onChangeRowsPerPage,
  };
}
