import * as React from "react";
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
  Divider,
  IconButton,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  Tooltip,
  TextField,
  InputAdornment,
  Typography,
} from "@mui/material";
import Eyebrow from "../components/Eyebrow.tsx";
import PageHeader from "../components/PageHeader.tsx";
import EmptyState from "../components/EmptyState.tsx";
import { Monitor, Smartphone, Tablet, Laptop, Trash2, Search, X, RefreshCw, Sparkles, TriangleAlert } from "lucide-react";
import { useSnackbar } from "notistack";
import { useTranslation } from "react-i18next";
import {
  type SessionResource,
  getErrMessage,
  deleteSession,
  deleteSessionsByAccount,
  pruneExpiredSessions,
  useSessions,
} from "./useSessions.ts";

interface Props {
  workspaceId: string;
  currentSessionId?: string;
  appId?: string;
  initialEmail?: string;
}

function fmtDateTime(d: string | number | Date | null | undefined): string {
  if (!d) return "-";
  const date = d instanceof Date ? d : new Date(d);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function fmtRelativeTime(d: string | number | Date | null | undefined, t: (key: string, opts?: Record<string, unknown>) => string): { text: string; isExpiringSoon: boolean; isExpired: boolean } {
  if (!d) return { text: "-", isExpiringSoon: false, isExpired: false };
  const date = d instanceof Date ? d : new Date(d);
  if (Number.isNaN(date.getTime())) return { text: "-", isExpiringSoon: false, isExpired: false };

  const now = new Date();
  const diffMs = date.getTime() - now.getTime();
  const diffMins = Math.round(diffMs / 60000);
  const diffHours = Math.round(diffMs / 3600000);
  const diffDays = Math.round(diffMs / 86400000);

  const isExpired = diffMs < 0;
  const isExpiringSoon = !isExpired && diffMs < 48 * 60 * 60 * 1000; // 48 hours

  let text: string;
  if (isExpired) {
    const absDays = Math.abs(diffDays);
    const absHours = Math.abs(diffHours);
    const absMins = Math.abs(diffMins);
    if (absDays >= 1) text = `${t("sessions.expired")} ${t("sessions.daysAgo", { count: absDays })}`;
    else if (absHours >= 1) text = `${t("sessions.expired")} ${t("sessions.hoursAgo", { count: absHours })}`;
    else text = `${t("sessions.expired")} ${t("sessions.minutesAgo", { count: absMins })}`;
  } else if (diffDays >= 1) {
    text = t("sessions.inDays", { count: diffDays });
  } else if (diffHours >= 1) {
    text = t("sessions.inHours", { count: diffHours });
  } else {
    text = t("sessions.inMinutes", { count: diffMins });
  }

  return { text, isExpiringSoon, isExpired };
}

function fmtTimeAgo(d: string | number | Date | null | undefined, t: (key: string, opts?: Record<string, unknown>) => string): string {
  if (!d) return "-";
  const date = d instanceof Date ? d : new Date(d);
  if (Number.isNaN(date.getTime())) return "-";

  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.round(diffMs / 60000);
  const diffHours = Math.round(diffMs / 3600000);
  const diffDays = Math.round(diffMs / 86400000);

  if (diffDays >= 1) return t("sessions.daysAgo", { count: diffDays });
  if (diffHours >= 1) return t("sessions.hoursAgo", { count: diffHours });
  if (diffMins >= 1) return t("sessions.minutesAgo", { count: diffMins });
  return t("sessions.justNow");
}

type ParsedUA = {
  browser: string;
  os: string;
  device: "mobile" | "tablet" | "desktop";
  summary: string;
};

function parseUserAgent(ua: string | null | undefined, unknownDevice: string = "Unknown device", unknownLabel: string = "Unknown"): ParsedUA {
  if (!ua || typeof ua !== "string") {
    return { browser: unknownLabel, os: unknownLabel, device: "desktop", summary: unknownDevice };
  }

  let browser = unknownLabel;
  let os = unknownLabel;
  let device: "mobile" | "tablet" | "desktop" = "desktop";

  // Detect browser
  if (ua.includes("Firefox/")) {
    browser = "Firefox";
  } else if (ua.includes("Edg/")) {
    browser = "Edge";
  } else if (ua.includes("Chrome/") && !ua.includes("Chromium/")) {
    browser = "Chrome";
  } else if (ua.includes("Safari/") && !ua.includes("Chrome/")) {
    browser = "Safari";
  } else if (ua.includes("Opera/") || ua.includes("OPR/")) {
    browser = "Opera";
  }

  // Detect OS
  if (ua.includes("iPhone") || ua.includes("iPad") || ua.includes("iOS")) {
    os = ua.includes("iPad") ? "iPadOS" : "iOS";
    device = ua.includes("iPad") ? "tablet" : "mobile";
  } else if (ua.includes("Android")) {
    os = "Android";
    device = ua.includes("Mobile") ? "mobile" : "tablet";
  } else if (ua.includes("Mac OS X") || ua.includes("macOS")) {
    os = "macOS";
  } else if (ua.includes("Windows")) {
    os = "Windows";
  } else if (ua.includes("Linux")) {
    os = "Linux";
  }

  const summary = browser !== unknownLabel && os !== unknownLabel
    ? `${browser} on ${os}`
    : browser !== unknownLabel
      ? browser
      : os !== unknownLabel
        ? os
        : unknownDevice;

  return { browser, os, device, summary };
}

function safeText(v: unknown): string {
  if (typeof v === "string" && v.trim().length > 0) return v;
  return "-";
}

function DeviceIcon({ device }: { device: "mobile" | "tablet" | "desktop" }) {
  const Icon = device === "mobile" ? Smartphone : device === "tablet" ? Tablet : Laptop;
  return <Box component="span" sx={{ color: "primary.main", display: "inline-flex" }}><Icon size={18} strokeWidth={1.5} /></Box>;
}

export default function Sessions(props: Props) {
  const { workspaceId, currentSessionId, appId } = props;
  const { enqueueSnackbar } = useSnackbar();
  const { t } = useTranslation();

  const {
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
  } = useSessions(workspaceId, appId, props.initialEmail);

  // detail dialog
  const [selectedSession, setSelectedSession] = React.useState<SessionResource | null>(null);

  // delete dialog state
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [deleteTarget, setDeleteTarget] = React.useState<SessionResource | null>(null);
  const [deleting, setDeleting] = React.useState(false);

  // bulk delete dialog state
  const [bulkDeleteOpen, setBulkDeleteOpen] = React.useState(false);
  const [bulkDeleteTarget, setBulkDeleteTarget] = React.useState<SessionResource | null>(null);
  const [bulkDeleting, setBulkDeleting] = React.useState(false);

  // prune expired dialog state
  const [pruneOpen, setPruneOpen] = React.useState(false);
  const [pruning, setPruning] = React.useState(false);

  const displayAccount = (s: SessionResource) =>
    s.user?.email?.trim() || s.userId;

  const openDelete = (s: SessionResource) => {
    setDeleteTarget(s);
    setDeleteOpen(true);
  };

  const closeDelete = () => {
    if (deleting) return;
    setDeleteOpen(false);
    setDeleteTarget(null);
  };

  const confirmDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await deleteSession(workspaceId, deleteTarget.id);
      enqueueSnackbar(t("sessions.sessionRevoked"), { variant: "success" });

      setDeleting(false);
      setDeleteOpen(false);
      setDeleteTarget(null);
      await load();
    } catch (err) {
      const msg = getErrMessage(err, t);
      enqueueSnackbar(msg, { variant: "error" });
      setDeleting(false);
    }
  };

  const openBulkDelete = (s: SessionResource) => {
    setBulkDeleteTarget(s);
    setBulkDeleteOpen(true);
  };

  const closeBulkDelete = () => {
    if (bulkDeleting) return;
    setBulkDeleteOpen(false);
    setBulkDeleteTarget(null);
  };

  const confirmBulkDelete = async () => {
    if (!bulkDeleteTarget) return;
    setBulkDeleting(true);
    try {
      await deleteSessionsByAccount(workspaceId, bulkDeleteTarget.userId, currentSessionId);
      enqueueSnackbar(t("sessions.allSessionsRevoked"), { variant: "success" });

      setBulkDeleting(false);
      setBulkDeleteOpen(false);
      setBulkDeleteTarget(null);
      await load();
    } catch (err) {
      const msg = getErrMessage(err, t);
      enqueueSnackbar(msg, { variant: "error" });
      setBulkDeleting(false);
    }
  };

  const openPrune = () => setPruneOpen(true);

  const closePrune = () => {
    if (pruning) return;
    setPruneOpen(false);
  };

  const confirmPrune = async () => {
    setPruning(true);
    try {
      const result = await pruneExpiredSessions(workspaceId);
      const count = result?.deleted ?? 0;
      enqueueSnackbar(
        count > 0
          ? t("sessions.pruneSuccess", { count })
          : t("sessions.pruneNone"),
        { variant: count > 0 ? "success" : "info" },
      );
      setPruning(false);
      setPruneOpen(false);
      await load();
    } catch (err) {
      const msg = getErrMessage(err, t);
      enqueueSnackbar(msg, { variant: "error" });
      setPruning(false);
    }
  };

  const clearSearch = () => {
    setEmailInput("");
    setPage(0);
  };

  return (
    <Box>
      <Stack spacing={2.5}>
        <PageHeader
          title={t("sessions.title")}
          action={
            <>
              <Chip
                size="small"
                variant="outlined"
                label={t("sessions.active", { count: total })}
              />
              <Button
                size="small"
                variant="outlined"
                startIcon={<Sparkles size={14} strokeWidth={1.75} />}
                onClick={openPrune}
                disabled={loading || pruning}
              >
                {t("sessions.pruneExpired")}
              </Button>
              <Tooltip title={t("common.refresh")}>
                <span>
                  <IconButton size="small" onClick={load} disabled={loading} aria-label={t("common.refresh")}>
                    {loading ? <CircularProgress size={16} /> : <RefreshCw size={14} strokeWidth={1.75} />}
                  </IconButton>
                </span>
              </Tooltip>
            </>
          }
        />

        {/* Search */}
        <TextField
          size="small"
          placeholder={t("sessions.searchPlaceholder")}
          value={emailInput}
          onChange={(e) => setEmailInput(e.target.value)}
          sx={{ maxWidth: 360 }}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <Box component="span" sx={{ color: "text.disabled", display: "inline-flex" }}><Search size={14} strokeWidth={1.75} /></Box>
              </InputAdornment>
            ),
            endAdornment: emailInput ? (
              <InputAdornment position="end">
                <IconButton size="small" onClick={clearSearch} aria-label={t("common.clear", { defaultValue: "Clear" })}>
                  <X size={14} strokeWidth={1.75} />
                </IconButton>
              </InputAdornment>
            ) : undefined,
          }}
        />

        {errorText && <Alert severity="error">{errorText}</Alert>}

        {/* Sessions list */}
        {loading && sessions.length === 0 ? (
          <Paper variant="outlined" sx={{ p: 4, borderRadius: 2, textAlign: "center" }}>
            <CircularProgress size={24} sx={{ mb: 1 }} />
            <Typography variant="body2" color="text.secondary">
              {t("sessions.loading")}
            </Typography>
          </Paper>
        ) : !errorText && sessions.length === 0 ? (
          <EmptyState
            icon={<Monitor size={18} strokeWidth={1.75} />}
            title={email ? t("sessions.noMatchingSessions", { email }) : t("sessions.noActiveSessions")}
            action={
              email ? (
                <Button size="small" variant="outlined" onClick={clearSearch} sx={{ borderRadius: 2, textTransform: "none" }}>
                  {t("sessions.clearFilter")}
                </Button>
              ) : undefined
            }
          />
        ) : (
          <>
            <TableContainer component={Paper} variant="outlined" sx={{ borderRadius: 2, position: "relative", opacity: loading ? 0.5 : 1, transition: "opacity 150ms ease" }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 600, fontSize: 12 }}>{t("sessions.columnUser")}</TableCell>
                    <TableCell sx={{ fontWeight: 600, fontSize: 12, width: 160 }}>{t("sessions.columnUserId", "User ID")}</TableCell>
                    <TableCell sx={{ fontWeight: 600, fontSize: 12 }}>{t("sessions.columnDevice")}</TableCell>
                    <TableCell sx={{ fontWeight: 600, fontSize: 12 }}>{t("sessions.columnIP")}</TableCell>
                    <TableCell sx={{ fontWeight: 600, fontSize: 12 }}>{t("sessions.columnCreated")}</TableCell>
                    <TableCell sx={{ fontWeight: 600, fontSize: 12 }}>{t("sessions.columnLastSeen")}</TableCell>
                    <TableCell sx={{ fontWeight: 600, fontSize: 12 }}>{t("sessions.columnExpires")}</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {sessions.map((s) => {
                    const parsedUA = parseUserAgent(s.userAgent, t("sessions.unknownDevice"), t("sessions.unknown"));
                    const expiry = fmtRelativeTime(s.expiresAt, t);

                    return (
                      <TableRow
                        key={s.id}
                        hover
                        onClick={() => setSelectedSession(s)}
                        sx={{
                          cursor: "pointer",
                          "&:last-child td": { borderBottom: 0 },
                        }}
                      >
                        <TableCell>
                          <Stack direction="row" spacing={0.75} alignItems="center">
                            <DeviceIcon device={parsedUA.device} />
                            <Typography sx={{ fontSize: 13, fontWeight: 500 }} noWrap>
                              {s.user?.email?.trim() || displayAccount(s)}
                            </Typography>
                          </Stack>
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption" color="text.disabled" noWrap title={s.userId} sx={{ fontFamily: "var(--font-mono)", fontSize: "0.7rem" }}>
                            {s.userId}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" color="text.secondary" noWrap sx={{ fontSize: 13 }}>
                            {parsedUA.summary}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" noWrap sx={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "text.secondary" }}>
                            {safeText(s.ip)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Tooltip title={fmtDateTime(s.createdAt)}>
                            <Typography variant="body2" noWrap sx={{ fontSize: 12, color: "text.secondary" }}>
                              {fmtTimeAgo(s.createdAt, t)}
                            </Typography>
                          </Tooltip>
                        </TableCell>
                        <TableCell>
                          <Tooltip title={fmtDateTime(s.lastSeenAt)}>
                            <Typography variant="body2" noWrap sx={{ fontSize: 12, color: "text.secondary" }}>
                              {fmtTimeAgo(s.lastSeenAt, t)}
                            </Typography>
                          </Tooltip>
                        </TableCell>
                        <TableCell>
                          <Tooltip title={fmtDateTime(s.expiresAt)}>
                            <Stack direction="row" spacing={0.5} alignItems="center">
                              {expiry.isExpiringSoon && !expiry.isExpired && (
                                <Box component="span" sx={{ color: "warning.main", display: "inline-flex" }}><TriangleAlert size={14} strokeWidth={1.75} /></Box>
                              )}
                              <Typography
                                variant="body2"
                                noWrap
                                sx={{
                                  fontSize: 12,
                                  color: expiry.isExpired
                                    ? "error.main"
                                    : expiry.isExpiringSoon
                                      ? "warning.main"
                                      : "text.secondary",
                                  fontWeight: expiry.isExpiringSoon || expiry.isExpired ? 500 : 400,
                                }}
                              >
                                {expiry.text}
                              </Typography>
                            </Stack>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>

            <TablePagination
              component="div"
              count={total}
              page={page}
              onPageChange={onChangePage}
              rowsPerPage={rowsPerPage}
              onRowsPerPageChange={onChangeRowsPerPage}
              rowsPerPageOptions={[10, 25, 50, 100]}
              labelRowsPerPage={t("sessions.perPage")}
            />
          </>
        )}
      </Stack>

      {/* Session detail dialog */}
      <Dialog
        open={!!selectedSession}
        onClose={() => setSelectedSession(null)}
        maxWidth="sm"
        fullWidth
      >
        {selectedSession && (() => {
          const s = selectedSession;
          const emailAddr = s.user?.email?.trim() || null;
          const parsedUA = parseUserAgent(s.userAgent, t("sessions.unknownDevice"), t("sessions.unknown"));
          const expiry = fmtRelativeTime(s.expiresAt, t);

          return (
            <>
              <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 1, pr: 6 }}>
                <DeviceIcon device={parsedUA.device} />
                {emailAddr || displayAccount(s)}
                <IconButton
                  size="small"
                  onClick={() => setSelectedSession(null)}
                  sx={{ position: "absolute", right: 12, top: 12 }}
                >
                  <X size={14} strokeWidth={1.75} />
                </IconButton>
              </DialogTitle>
              <DialogContent>
                <Stack spacing={2}>
                  <Stack spacing={1.5}>
                    {s.user?.email?.trim() && (
                      <DetailRow label={t("sessions.user")} value={s.user.email.trim()} />
                    )}
                    <DetailRow label={t("sessions.columnUserId", "User ID")} value={s.userId} mono />
                    <DetailRow label={t("sessions.device")} value={parsedUA.summary} />
                    <DetailRow label={t("sessions.ipAddress")} value={safeText(s.ip)} mono />
                    <DetailRow label={t("sessions.created")} value={fmtDateTime(s.createdAt)} />
                    <DetailRow label={t("sessions.lastSeen")} value={fmtDateTime(s.lastSeenAt)} />
                    <DetailRow
                      label={t("sessions.expires")}
                      value={`${fmtDateTime(s.expiresAt)} (${expiry.text})`}
                      color={expiry.isExpired ? "error.main" : expiry.isExpiringSoon ? "warning.main" : undefined}
                    />
                    {s.app && (
                      // Server already composes the display name into
                      // s.app.name (project + env type), so the UI
                      // doesn't need to recompute here.
                      <DetailRow label={t("sessions.app")} value={s.app.name} />
                    )}
                  </Stack>

                  {s.userAgent && (
                    <>
                      <Divider />
                      <Eyebrow>{t("sessions.userAgent")}</Eyebrow>
                      <Box
                        sx={{
                          px: 1.5,
                          py: 1,
                          borderRadius: 1.5,
                          bgcolor: "action.disabledBackground",
                          fontFamily: "var(--font-mono)",
                          fontSize: 11,
                          color: "text.secondary",
                          whiteSpace: "pre-wrap",
                          wordBreak: "break-word",
                        }}
                      >
                        {s.userAgent}
                      </Box>
                    </>
                  )}

                  <Divider />

                  <Stack direction="row" spacing={1}>
                    <Button
                      variant="outlined"
                      color="error"
                      size="small"
                      startIcon={<Trash2 size={14} strokeWidth={1.75} />}
                      disabled={deleting || bulkDeleting}
                      onClick={() => {
                        setSelectedSession(null);
                        openDelete(s);
                      }}
                      sx={{ borderRadius: 2, textTransform: "none" }}
                    >
                      {t("sessions.revokeSession")}
                    </Button>
                    <Button
                      variant="outlined"
                      color="warning"
                      size="small"
                      startIcon={<Monitor size={14} strokeWidth={1.75} />}
                      disabled={deleting || bulkDeleting}
                      onClick={() => {
                        setSelectedSession(null);
                        openBulkDelete(s);
                      }}
                      sx={{ borderRadius: 2, textTransform: "none" }}
                    >
                      {t("sessions.revokeAllSessions")}
                    </Button>
                  </Stack>
                </Stack>
              </DialogContent>
            </>
          );
        })()}
      </Dialog>

      {/* Single session revoke dialog */}
      <Dialog
        open={deleteOpen}
        onClose={closeDelete}
        maxWidth="xs"
        fullWidth
       
      >
        <DialogTitle sx={{ pb: 1 }}>{t("sessions.revokeSessionConfirm")}</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary">
            {t("sessions.revokeSessionDescription")}
          </Typography>
          {deleteTarget && (
            <Typography variant="body2" sx={{ mt: 1, fontWeight: 500 }}>
              {deleteTarget.user?.email?.trim() || displayAccount(deleteTarget)}
            </Typography>
          )}
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={closeDelete} disabled={deleting}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="contained"
            color="error"
            onClick={confirmDelete}
            disabled={!deleteTarget || deleting}
           
          >
            {deleting ? t("sessions.revoking") : t("sessions.revokeSession")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Prune expired sessions dialog */}
      <Dialog
        open={pruneOpen}
        onClose={closePrune}
        maxWidth="xs"
        fullWidth
       
      >
        <DialogTitle sx={{ pb: 1 }}>{t("sessions.pruneConfirmTitle")}</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary">
            {t("sessions.pruneConfirmDescription")}
          </Typography>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={closePrune} disabled={pruning}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="contained"
            color="error"
            onClick={confirmPrune}
            disabled={pruning}
           
          >
            {pruning ? t("sessions.revoking") : t("sessions.pruneExpired")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Bulk revoke dialog */}
      <Dialog
        open={bulkDeleteOpen}
        onClose={closeBulkDelete}
        maxWidth="xs"
        fullWidth
       
      >
        <DialogTitle sx={{ pb: 1 }}>{t("sessions.revokeAllConfirm")}</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary">
            {t("sessions.revokeAllDescription")}
          </Typography>
          {bulkDeleteTarget && (
            <Typography variant="body2" sx={{ mt: 1, fontWeight: 500 }}>
              {bulkDeleteTarget.user?.email?.trim() || displayAccount(bulkDeleteTarget)}
            </Typography>
          )}
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={closeBulkDelete} disabled={bulkDeleting}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="contained"
            color="error"
            onClick={confirmBulkDelete}
            disabled={!bulkDeleteTarget || bulkDeleting}
           
          >
            {bulkDeleting ? t("sessions.revoking") : t("sessions.revokeAllSessions")}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

function DetailRow({ label, value, mono, color }: { label: string; value: string; mono?: boolean; color?: string }) {
  return (
    <Stack direction="row" spacing={2} alignItems="baseline">
      <Typography
        sx={{
          fontFamily: "var(--font-mono)",
          textTransform: "uppercase",
          letterSpacing: "0.14em",
          fontSize: 10,
          fontWeight: 500,
          color: "text.disabled",
          minWidth: 80,
          flexShrink: 0,
        }}
      >
        {label}
      </Typography>
      <Typography
        variant="body2"
        sx={{
          ...(mono && { fontFamily: "var(--font-mono)", fontSize: 12 }),
          ...(color && { color }),
        }}
      >
        {value}
      </Typography>
    </Stack>
  );
}
