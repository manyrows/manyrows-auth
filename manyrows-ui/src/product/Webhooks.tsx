import * as React from "react";
import { apiJson } from "../lib/api.ts";
import { useSnackbar } from "notistack";
import { useTranslation } from "react-i18next";
import type { Product, Workspace } from "../core.ts";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControlLabel,
  IconButton,
  Paper,
  Stack,
  Switch,
  TextField,
  Tooltip,
  Typography,
  MenuItem,
} from "@mui/material";
import Eyebrow from "../components/Eyebrow.tsx";
import PageHeader from "../components/PageHeader.tsx";
import EmptyState from "../components/EmptyState.tsx";
import StatusChip from "../components/StatusChip.tsx";
import { Webhook, Plus, Trash2, SquarePen, Copy, RefreshCw, RotateCcw, History } from "lucide-react";

// ── Types ──

interface Webhook {
  id: string;
  appId: string;
  url: string;
  secret?: string;
  events: string[];
  status: string;
  description: string;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

interface Delivery {
  id: string;
  webhookId: string;
  event: string;
  payload: unknown;
  status: string;
  statusCode: number | null;
  responseBody: string | null;
  attempts: number;
  nextRetryAt: string | null;
  createdAt: string;
  completedAt: string | null;
}

// ── Event categories ──

// EVENT_CATEGORIES mirrors the set of event names the backend's
// dispatchWebhook helper actually emits (see manyrows-core/api/*.go).
// Keep in sync when new dispatch sites are added; an unlisted event
// is silently undeliverable through the UI even if the server fires it.
const EVENT_CATEGORIES: Record<string, string[]> = {
  auth: ["user.login", "user.register", "user.logout", "user.passkey_register", "user.passkey_delete"],
  password: ["user.password_change", "user.password_reset"],
  account: ["user.created", "user.delete", "user.email_change"],
};


const MAX_WEBHOOKS = 1;

// ── Component ──

interface Props {
  project: Product;
  workspace: Workspace;
  appId: string;
}

export default function Webhooks({ project, appId }: Props) {
  const { t } = useTranslation();
  const { enqueueSnackbar } = useSnackbar();

  const base = `/admin/workspace/${project.workspaceId}/products/${project.id}/apps/${appId}`;

  const [loading, setLoading] = React.useState(false);
  const [webhooks, setWebhooks] = React.useState<Webhook[]>([]);
  const [error, setError] = React.useState<string | null>(null);

  // Webhook health summary (24h delivery counts + recent failures).
  type WebhookHealth = {
    totalWebhooks: number;
    activeWebhooks: number;
    deliveries24h: number;
    successes24h: number;
    failures24h: number;
    pendingRetries: number;
    recentFailures: {
      id: string;
      webhookId: string;
      webhookUrl: string;
      event: string;
      statusCode?: number;
      attempts: number;
      createdAt: string;
    }[];
  };
  const [health, setHealth] = React.useState<WebhookHealth | null>(null);
  const [healthLoading, setHealthLoading] = React.useState(false);
  const [showFailures, setShowFailures] = React.useState(false);

  // Create dialog
  const [createOpen, setCreateOpen] = React.useState(false);
  const [createUrl, setCreateUrl] = React.useState("");
  const [createDesc, setCreateDesc] = React.useState("");
  const [createEvents, setCreateEvents] = React.useState<string[]>([]);
  const [createSaving, setCreateSaving] = React.useState(false);

  // Secret dialog (shown after create)
  const [secretOpen, setSecretOpen] = React.useState(false);
  const [secretValue, setSecretValue] = React.useState("");

  // Edit dialog
  const [editOpen, setEditOpen] = React.useState(false);
  const [editWebhook, setEditWebhook] = React.useState<Webhook | null>(null);
  const [editUrl, setEditUrl] = React.useState("");
  const [editDesc, setEditDesc] = React.useState("");
  const [editEvents, setEditEvents] = React.useState<string[]>([]);
  const [editStatus, setEditStatus] = React.useState("active");
  const [editSaving, setEditSaving] = React.useState(false);

  // Delete dialog
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [deleteWebhook, setDeleteWebhook] = React.useState<Webhook | null>(null);
  const [deleteSaving, setDeleteSaving] = React.useState(false);

  // Deliveries dialog
  const [deliveriesOpen, setDeliveriesOpen] = React.useState(false);
  const [deliveriesWebhook, setDeliveriesWebhook] = React.useState<Webhook | null>(null);
  const [deliveries, setDeliveries] = React.useState<Delivery[]>([]);
  const [deliveriesLoading, setDeliveriesLoading] = React.useState(false);
  const [deliveriesOffset, setDeliveriesOffset] = React.useState(0);
  const [hasMoreDeliveries, setHasMoreDeliveries] = React.useState(false);
  const [retryingId, setRetryingId] = React.useState<string | null>(null);
  const [deliveryStatusFilter, setDeliveryStatusFilter] = React.useState<string>("all");

  // ── Load ──

  async function loadWebhooks(opts?: { showSuccess?: boolean }) {
    setLoading(true);
    setError(null);
    try {
      const res = await apiJson<Webhook[]>(`${base}/webhooks`);
      setWebhooks(res || []);
      if (opts?.showSuccess) enqueueSnackbar(t("common.refresh"), { variant: "success" });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : t("webhooks.failedToLoad");
      setError(msg);
      enqueueSnackbar(msg, { variant: "error" });
    } finally {
      setLoading(false);
    }
  }

  async function loadHealth() {
    setHealthLoading(true);
    try {
      const res = await apiJson<WebhookHealth>(`${base}/webhooks/health`);
      setHealth(res);
    } catch {
      // Non-fatal - health is best-effort, the webhooks list still works
      setHealth(null);
    } finally {
      setHealthLoading(false);
    }
  }

  React.useEffect(() => {
    void loadWebhooks();
    void loadHealth();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appId]);

  // ── Create ──

  function openCreate() {
    setCreateUrl("");
    setCreateDesc("");
    setCreateEvents([]);
    setCreateOpen(true);
  }

  function isValidWebhookUrl(url: string): boolean {
    try {
      const u = new URL(url.trim());
      return u.protocol === "https:" || u.protocol === "http:";
    } catch {
      return false;
    }
  }

  async function handleCreate() {
    if (!isValidWebhookUrl(createUrl)) {
      enqueueSnackbar(t("webhooks.urlHelper"), { variant: "error" });
      return;
    }
    if (createEvents.length === 0) {
      enqueueSnackbar(t("webhooks.selectEvent"), { variant: "error" });
      return;
    }
    setCreateSaving(true);
    try {
      const res = await apiJson<Webhook>(`${base}/webhooks`, {
        method: "POST",
        data: {
          url: createUrl.trim(),
          description: createDesc.trim() || null,
          events: createEvents,
        },
      });
      setCreateOpen(false);

      // Show secret if returned
      if (res?.secret) {
        setSecretValue(res.secret);
        setSecretOpen(true);
      }

      await loadWebhooks();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : t("webhooks.failedToCreate");
      enqueueSnackbar(msg, { variant: "error" });
    } finally {
      setCreateSaving(false);
    }
  }

  // ── Edit ──

  function openEdit(wh: Webhook) {
    setEditWebhook(wh);
    setEditUrl(wh.url);
    setEditDesc(wh.description || "");
    setEditEvents([...wh.events]);
    setEditStatus(wh.status);
    setEditOpen(true);
  }

  async function handleEdit() {
    if (!editWebhook) return;
    if (!isValidWebhookUrl(editUrl)) {
      enqueueSnackbar(t("webhooks.urlHelper"), { variant: "error" });
      return;
    }
    if (editEvents.length === 0) {
      enqueueSnackbar(t("webhooks.selectEvent"), { variant: "error" });
      return;
    }
    setEditSaving(true);
    try {
      await apiJson(`${base}/webhooks/${editWebhook.id}`, {
        method: "PATCH",
        data: {
          url: editUrl.trim(),
          description: editDesc.trim() || null,
          events: editEvents,
          status: editStatus,
        },
      });
      setEditOpen(false);
      setEditWebhook(null);
      await loadWebhooks();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : t("webhooks.failedToUpdate");
      enqueueSnackbar(msg, { variant: "error" });
    } finally {
      setEditSaving(false);
    }
  }

  // ── Delete ──

  function openDelete(wh: Webhook) {
    setDeleteWebhook(wh);
    setDeleteOpen(true);
  }

  async function handleDelete() {
    if (!deleteWebhook) return;
    setDeleteSaving(true);
    try {
      await apiJson(`${base}/webhooks/${deleteWebhook.id}`, { method: "DELETE" });
      setDeleteOpen(false);
      setDeleteWebhook(null);
      await loadWebhooks();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : t("webhooks.failedToDelete");
      enqueueSnackbar(msg, { variant: "error" });
    } finally {
      setDeleteSaving(false);
    }
  }

  // ── Deliveries ──

  async function openDeliveries(wh: Webhook) {
    setDeliveriesWebhook(wh);
    setDeliveries([]);
    setDeliveriesOffset(0);
    setHasMoreDeliveries(false);
    setDeliveryStatusFilter("all");
    setDeliveriesOpen(true);
    await fetchDeliveries(wh.id, 0, true);
  }

  async function fetchDeliveries(webhookId: string, offset: number, reset: boolean) {
    setDeliveriesLoading(true);
    try {
      const res = await apiJson<Delivery[]>(`${base}/webhooks/${webhookId}/deliveries`, {
        params: { limit: 20, offset },
      });
      const list = res || [];
      if (reset) {
        setDeliveries(list);
      } else {
        setDeliveries((prev) => [...prev, ...list]);
      }
      setDeliveriesOffset(offset + list.length);
      setHasMoreDeliveries(list.length === 20);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : t("webhooks.failedToLoadDeliveries");
      enqueueSnackbar(msg, { variant: "error" });
    } finally {
      setDeliveriesLoading(false);
    }
  }

  async function handleRetry(delivery: Delivery) {
    if (!deliveriesWebhook) return;
    setRetryingId(delivery.id);
    try {
      await apiJson(`${base}/webhooks/${deliveriesWebhook.id}/deliveries/${delivery.id}/retry`, {
        method: "POST",
      });
      enqueueSnackbar(t("webhooks.retryQueued"), { variant: "success" });
      // Refresh deliveries
      await fetchDeliveries(deliveriesWebhook.id, 0, true);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : t("webhooks.retryFailed");
      enqueueSnackbar(msg, { variant: "error" });
    } finally {
      setRetryingId(null);
    }
  }

  // ── Event checkbox helpers ──

  function toggleEvent(setEvents: React.Dispatch<React.SetStateAction<string[]>>, event: string) {
    setEvents((prev) => (prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event]));
  }

  function toggleCategory(events: string[], setEvents: React.Dispatch<React.SetStateAction<string[]>>, category: string) {
    const catEvents = EVENT_CATEGORIES[category] || [];
    const allChecked = catEvents.every((e) => events.includes(e));
    if (allChecked) {
      setEvents((prev) => prev.filter((e) => !catEvents.includes(e)));
    } else {
      setEvents((prev) => {
        const next = new Set(prev);
        for (const e of catEvents) next.add(e);
        return [...next];
      });
    }
  }

  function renderEventCheckboxes(events: string[], setEvents: React.Dispatch<React.SetStateAction<string[]>>) {
    return (
      <Stack spacing={1.5}>
        {Object.entries(EVENT_CATEGORIES).map(([cat, catEvents]) => {
          const allChecked = catEvents.every((e) => events.includes(e));
          const someChecked = catEvents.some((e) => events.includes(e));
          return (
            <Box key={cat}>
              <FormControlLabel
                control={
                  <Checkbox
                    size="small"
                    checked={allChecked}
                    indeterminate={someChecked && !allChecked}
                    onChange={() => toggleCategory(events, setEvents, cat)}
                  />
                }
                label={
                  <Typography
                    sx={{
                      fontFamily: "var(--font-mono)",
                      textTransform: "uppercase",
                      letterSpacing: "0.14em",
                      fontSize: 11,
                      fontWeight: 500,
                      color: "text.disabled",
                    }}
                  >
                    {t(`webhooks.eventCategories.${cat}`)}
                  </Typography>
                }
              />
              <Box sx={{ pl: 3 }}>
                {catEvents.map((ev) => (
                  <FormControlLabel
                    key={ev}
                    control={
                      <Checkbox
                        size="small"
                        checked={events.includes(ev)}
                        onChange={() => toggleEvent(setEvents, ev)}
                      />
                    }
                    label={
                      <Typography sx={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "text.secondary" }}>
                        {ev}
                      </Typography>
                    }
                    sx={{ display: "block" }}
                  />
                ))}
              </Box>
            </Box>
          );
        })}
      </Stack>
    );
  }

  // ── Delivery status helpers ──

  function deliveryStatusLabel(status: string): string {
    if (status === "success") return t("webhooks.deliverySuccess");
    if (status === "failed") return t("webhooks.deliveryFailed");
    return t("webhooks.deliveryPending");
  }

  // ── Copy to clipboard ──

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
    enqueueSnackbar(t("webhooks.copied"), { variant: "success" });
  }

  // ── Format date ──

  function fmtDate(s: string | null | undefined): string {
    if (!s) return "-";
    try {
      return new Date(s).toLocaleString();
    } catch {
      return s;
    }
  }

  const atLimit = webhooks.length >= MAX_WEBHOOKS;

  const filteredDeliveries = React.useMemo(() => {
    if (deliveryStatusFilter === "all") return deliveries;
    return deliveries.filter(d => d.status === deliveryStatusFilter);
  }, [deliveries, deliveryStatusFilter]);

  // ── Render ──

  return (
    <Box>
      <Stack spacing={2.5}>
        <PageHeader
          title={t("webhooks.title")}
          action={
            <>
              <Button
                size="small"
                variant="contained"
                disableElevation
                startIcon={<Plus size={14} strokeWidth={2} />}
                onClick={openCreate}
                disabled={loading || atLimit}
              >
                {t("webhooks.create")}
              </Button>
              <StatusChip
                label={t("webhooks.used", { count: webhooks.length, max: MAX_WEBHOOKS })}
                uppercase={false}
              />
              <Tooltip title={t("common.refresh")}>
                <span>
                  <IconButton size="small" onClick={() => void loadWebhooks({ showSuccess: true })} disabled={loading}>
                    <RefreshCw size={14} strokeWidth={1.75} />
                  </IconButton>
                </span>
              </Tooltip>
            </>
          }
        />

        <Typography variant="body2" color="text.secondary">
          {t("webhooks.description")}
        </Typography>

        {/* Health: stat cards + recent failures (collapsible) */}
        {(health || healthLoading) && (
          <Box>
            {/* CSS grid with auto-fit avoids the awkward 3+1 wrap the
                prior flex-wrap produced when 4 cards didn't fit but 3
                did. Cards stay equal-width and collapse to 2-up / 1-up
                only when the viewport actually demands it. */}
            <Box sx={{ display: "grid", gap: 1.5, gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))" }}>
              <Paper variant="outlined" sx={{ p: 1.5, borderRadius: 2 }}>
                <Eyebrow>{t("webhooks.health.active", { defaultValue: "Active webhooks" })}</Eyebrow>
                <Typography
                  sx={{
                    fontFamily: "var(--font-mono)",
                    fontFeatureSettings: '"tnum"',
                    fontSize: 22,
                    fontWeight: 500,
                    letterSpacing: "-0.01em",
                    lineHeight: 1.15,
                    mt: 0.5,
                  }}
                >
                  {healthLoading ? <CircularProgress size={14} /> : `${health?.activeWebhooks ?? 0} / ${health?.totalWebhooks ?? 0}`}
                </Typography>
              </Paper>
              <Paper variant="outlined" sx={{ p: 1.5, borderRadius: 2 }}>
                <Eyebrow>{t("webhooks.health.deliveries24h", { defaultValue: "Deliveries (24h)" })}</Eyebrow>
                <Typography
                  sx={{
                    fontFamily: "var(--font-mono)",
                    fontFeatureSettings: '"tnum"',
                    fontSize: 22,
                    fontWeight: 500,
                    letterSpacing: "-0.01em",
                    lineHeight: 1.15,
                    mt: 0.5,
                  }}
                >
                  {healthLoading ? <CircularProgress size={14} /> : (health?.deliveries24h ?? 0)}
                </Typography>
                {health && health.deliveries24h > 0 && (
                  <Typography variant="caption" color="success.main">
                    {health.successes24h} {t("webhooks.health.ok", { defaultValue: "ok" })}
                  </Typography>
                )}
              </Paper>
              <Paper variant="outlined" sx={{ p: 1.5, borderRadius: 2 }}>
                <Eyebrow>{t("webhooks.health.failures24h", { defaultValue: "Failures (24h)" })}</Eyebrow>
                <Typography
                  sx={{
                    fontFamily: "var(--font-mono)",
                    fontFeatureSettings: '"tnum"',
                    fontSize: 22,
                    fontWeight: 500,
                    letterSpacing: "-0.01em",
                    lineHeight: 1.15,
                    mt: 0.5,
                    color: (health?.failures24h ?? 0) > 0 ? "error.main" : "text.primary",
                  }}
                >
                  {healthLoading ? <CircularProgress size={14} /> : (health?.failures24h ?? 0)}
                </Typography>
                {health && health.failures24h > 0 && (
                  <Button
                    size="small"
                    onClick={() => setShowFailures((v) => !v)}
                    sx={{ p: 0, minWidth: 0, textTransform: "none", fontSize: 11 }}
                  >
                    {showFailures ? t("common.hide", { defaultValue: "Hide" }) : t("webhooks.health.viewFailures", { defaultValue: "View recent" })}
                  </Button>
                )}
              </Paper>
              <Paper variant="outlined" sx={{ p: 1.5, borderRadius: 2 }}>
                <Eyebrow>{t("webhooks.health.pending", { defaultValue: "Pending retries" })}</Eyebrow>
                <Typography
                  sx={{
                    fontFamily: "var(--font-mono)",
                    fontFeatureSettings: '"tnum"',
                    fontSize: 22,
                    fontWeight: 500,
                    letterSpacing: "-0.01em",
                    lineHeight: 1.15,
                    mt: 0.5,
                    color: (health?.pendingRetries ?? 0) > 0 ? "warning.main" : "text.primary",
                  }}
                >
                  {healthLoading ? <CircularProgress size={14} /> : (health?.pendingRetries ?? 0)}
                </Typography>
              </Paper>
            </Box>

            {showFailures && health && health.recentFailures.length > 0 && (
              <Paper variant="outlined" sx={{ mt: 1.5, borderRadius: 2, overflow: "hidden" }}>
                <Box sx={{ px: 1.5, py: 1, bgcolor: "action.hover", borderBottom: "1px solid", borderColor: "divider" }}>
                  <Typography variant="caption" sx={{ fontWeight: 600 }}>
                    {t("webhooks.health.recentFailuresTitle", { defaultValue: "Recent failures" })}
                  </Typography>
                </Box>
                <Box sx={{ maxHeight: 280, overflowY: "auto" }}>
                  {health.recentFailures.map((f) => (
                    <Box
                      key={f.id}
                      sx={{
                        px: 1.5,
                        py: 1,
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        gap: 2,
                        borderBottom: "1px solid",
                        borderColor: "divider",
                        "&:last-child": { borderBottom: 0 },
                      }}
                    >
                      <Stack sx={{ flex: 1, minWidth: 0 }} spacing={0.25}>
                        <Typography variant="caption" sx={{ fontWeight: 600 }} noWrap title={f.event}>
                          {f.event}
                        </Typography>
                        <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "var(--font-mono)", fontSize: 10 }} noWrap title={f.webhookUrl}>
                          {f.webhookUrl}
                        </Typography>
                      </Stack>
                      <Stack direction="row" spacing={1} alignItems="center">
                        {typeof f.statusCode === "number" && (
                          <StatusChip
                            label={f.statusCode}
                            severity="error"
                            uppercase={false}
                          />
                        )}
                        <StatusChip
                          label={t("webhooks.health.attempts", { defaultValue: "{{count}} attempts", count: f.attempts })}
                          uppercase={false}
                          severity="muted"
                        />
                        <Typography variant="caption" color="text.secondary">
                          {new Date(f.createdAt).toLocaleString()}
                        </Typography>
                      </Stack>
                    </Box>
                  ))}
                </Box>
              </Paper>
            )}
          </Box>
        )}

        {atLimit && (
          <Alert severity="info">{t("webhooks.maxWebhooks")}</Alert>
        )}

        {error && <Alert severity="error">{error}</Alert>}

        {loading && (
          <Stack direction="row" spacing={1} alignItems="center" justifyContent="center" sx={{ py: 4 }}>
            <CircularProgress size={20} />
            <Typography variant="body2" color="text.secondary">
              {t("common.loading")}
            </Typography>
          </Stack>
        )}

        {/* Empty state */}
        {!loading && webhooks.length === 0 && (
          <EmptyState
            icon={<Webhook size={18} strokeWidth={1.75} />}
            title={t("webhooks.noWebhooks")}
            description={t("webhooks.noWebhooksDesc", { defaultValue: "Receive HTTP callbacks when events happen in this app - sign-ins, sign-ups, sessions, and more." })}
            action={
              <Button
                variant="contained"
                disableElevation
                startIcon={<Plus size={14} strokeWidth={2} />}
                onClick={openCreate}
                sx={{ textTransform: "none" }}
              >
                {t("webhooks.create")}
              </Button>
            }
          />
        )}

        {/* Webhook list */}
        {!loading && webhooks.length > 0 && (
          <Stack spacing={0}>
            <Paper variant="outlined" sx={{ borderRadius: 2, overflow: "hidden" }}>
              {webhooks.map((wh, idx) => (
                <React.Fragment key={wh.id}>
                  {idx > 0 && <Divider />}
                  <Box sx={{ px: 2, py: 1.5 }}>
                    <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                      <Typography
                        variant="body2"
                        sx={{ fontFamily: "var(--font-mono)", fontWeight: 500, flex: 1, minWidth: 200, wordBreak: "break-all", fontSize: 12.5 }}
                      >
                        {wh.url}
                      </Typography>

                      <StatusChip
                        label={wh.status === "active" ? t("webhooks.statusActive") : t("webhooks.statusDisabled")}
                        severity={wh.status === "active" ? "success" : "neutral"}
                      />

                      <StatusChip
                        label={`${wh.events.length} ${t("webhooks.events").toLowerCase()}`}
                        uppercase={false}
                      />

                      <Tooltip title={t("webhooks.deliveries")}>
                        <IconButton size="small" onClick={() => void openDeliveries(wh)}>
                          <History size={14} strokeWidth={1.75} />
                        </IconButton>
                      </Tooltip>

                      <Tooltip title={t("webhooks.edit")}>
                        <IconButton size="small" onClick={() => openEdit(wh)}>
                          <SquarePen size={14} strokeWidth={1.75} />
                        </IconButton>
                      </Tooltip>

                      <Tooltip title={t("webhooks.delete")}>
                        <IconButton size="small" onClick={() => openDelete(wh)}>
                          <Trash2 size={14} strokeWidth={1.75} />
                        </IconButton>
                      </Tooltip>
                    </Stack>

                    {wh.description && (
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
                        {wh.description}
                      </Typography>
                    )}

                    <Typography
                      sx={{
                        display: "block",
                        mt: 0.25,
                        fontFamily: "var(--font-mono)",
                        fontSize: 10.5,
                        color: "text.disabled",
                      }}
                    >
                      {t("webhooks.created")}: {fmtDate(wh.createdAt)}
                    </Typography>
                  </Box>
                </React.Fragment>
              ))}
            </Paper>
          </Stack>
        )}
      </Stack>

      {/* ── Create dialog ── */}
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>{t("webhooks.create")}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <TextField
              autoFocus
              label={t("webhooks.url")}
              value={createUrl}
              onChange={(e) => setCreateUrl(e.target.value)}
              placeholder="https://example.com/webhook"
              helperText={t("webhooks.urlHelper")}
              fullWidth
            />

            <TextField
              label={t("webhooks.descriptionField")}
              value={createDesc}
              onChange={(e) => setCreateDesc(e.target.value)}
              fullWidth
            />

            <Eyebrow sx={{ mt: 1 }}>{t("webhooks.events")}</Eyebrow>
            {renderEventCheckboxes(createEvents, setCreateEvents)}
            {createEvents.length === 0 && (
              <Alert severity="warning">{t("webhooks.selectEvent")}</Alert>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)} disabled={createSaving}>
            {t("common.cancel")}
          </Button>
          <Button onClick={() => void handleCreate()} variant="contained" disableElevation disabled={createSaving}>
            {t("common.create")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Secret dialog ── */}
      <Dialog open={secretOpen} onClose={() => setSecretOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>{t("webhooks.secret")}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <Alert severity="warning">{t("webhooks.secretWarning")}</Alert>
            <Stack direction="row" spacing={1} alignItems="center">
              <TextField
                value={secretValue}
                fullWidth
                slotProps={{
                  input: { readOnly: true, sx: { fontFamily: "var(--font-mono)", fontSize: 13 } },
                }}
              />
              <Tooltip title={t("common.copy")}>
                <IconButton onClick={() => copyToClipboard(secretValue)}>
                  <Copy size={14} strokeWidth={1.75} />
                </IconButton>
              </Tooltip>
            </Stack>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSecretOpen(false)} variant="contained" disableElevation>
            {t("common.close")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Edit dialog ── */}
      <Dialog open={editOpen} onClose={() => setEditOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>{t("webhooks.edit")}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <TextField
              autoFocus
              label={t("webhooks.url")}
              value={editUrl}
              onChange={(e) => setEditUrl(e.target.value)}
              placeholder="https://example.com/webhook"
              helperText={t("webhooks.urlHelper")}
              fullWidth
            />

            <TextField
              label={t("webhooks.descriptionField")}
              value={editDesc}
              onChange={(e) => setEditDesc(e.target.value)}
              fullWidth
            />

            <Stack direction="row" spacing={1} alignItems="center">
              <Eyebrow sx={{ mt: 1 }}>{t("webhooks.status")}</Eyebrow>
              <Switch
                checked={editStatus === "active"}
                onChange={(e) => setEditStatus(e.target.checked ? "active" : "disabled")}
              />
              <Typography variant="body2">
                {editStatus === "active" ? t("webhooks.statusActive") : t("webhooks.statusDisabled")}
              </Typography>
            </Stack>

            <Eyebrow sx={{ mt: 1 }}>{t("webhooks.events")}</Eyebrow>
            {renderEventCheckboxes(editEvents, setEditEvents)}
            {editEvents.length === 0 && (
              <Alert severity="warning">{t("webhooks.selectEvent")}</Alert>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditOpen(false)} disabled={editSaving}>
            {t("common.cancel")}
          </Button>
          <Button onClick={() => void handleEdit()} variant="contained" disableElevation disabled={editSaving}>
            {t("common.save")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Delete dialog ── */}
      <Dialog open={deleteOpen} onClose={() => setDeleteOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>{t("webhooks.delete")}</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary">
            {t("webhooks.deleteConfirmation")}
          </Typography>
          {deleteWebhook && (
            <Typography sx={{ mt: 1, fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>
              {deleteWebhook.url}
            </Typography>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteOpen(false)} disabled={deleteSaving}>
            {t("common.cancel")}
          </Button>
          <Button onClick={() => void handleDelete()} color="error" variant="contained" disableElevation disabled={deleteSaving}>
            {t("common.delete")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Deliveries dialog ── */}
      <Dialog open={deliveriesOpen} onClose={() => setDeliveriesOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          <Stack direction="row" spacing={1.5} alignItems="baseline">
            <span>{t("webhooks.deliveries")}</span>
            {deliveriesWebhook && (
              <Typography
                sx={{
                  fontFamily: "var(--font-mono)",
                  fontSize: 11.5,
                  color: "text.secondary",
                }}
              >
                {deliveriesWebhook.url}
              </Typography>
            )}
          </Stack>
        </DialogTitle>
        <DialogContent>
          {deliveries.length > 0 && (
            <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 2 }}>
              <TextField
                size="small"
                select
                value={deliveryStatusFilter}
                onChange={(e) => setDeliveryStatusFilter(e.target.value)}
                sx={{ minWidth: 150 }}
                label={t("webhooks.deliveryFilterLabel")}
              >
                <MenuItem value="all">{t("webhooks.deliveryFilterAll")}</MenuItem>
                <MenuItem value="success">{t("webhooks.deliveryFilterSuccess")}</MenuItem>
                <MenuItem value="failed">{t("webhooks.deliveryFilterFailed")}</MenuItem>
                <MenuItem value="pending">{t("webhooks.deliveryFilterPending")}</MenuItem>
              </TextField>
              {deliveryStatusFilter !== "all" && (
                <Chip
                  size="small"
                  label={`${filteredDeliveries.length} / ${deliveries.length}`}
                  variant="outlined"
                />
              )}
            </Stack>
          )}

          {deliveriesLoading && deliveries.length === 0 && (
            <Stack direction="row" spacing={1} alignItems="center" justifyContent="center" sx={{ py: 4 }}>
              <CircularProgress size={20} />
              <Typography variant="body2" color="text.secondary">
                {t("common.loading")}
              </Typography>
            </Stack>
          )}

          {!deliveriesLoading && deliveries.length === 0 && (
            <Typography variant="body2" color="text.secondary" sx={{ py: 2, textAlign: "center" }}>
              {t("webhooks.noDeliveries")}
            </Typography>
          )}

          {deliveries.length > 0 && filteredDeliveries.length === 0 && (
            <Typography variant="body2" color="text.secondary" sx={{ py: 2, textAlign: "center" }}>
              {t("webhooks.noFilteredDeliveries")}
            </Typography>
          )}

          {filteredDeliveries.length > 0 && (
            <Stack spacing={0}>
              <Paper variant="outlined" sx={{ borderRadius: 2, overflow: "hidden" }}>
                {filteredDeliveries.map((d, idx) => (
                  <React.Fragment key={d.id}>
                    {idx > 0 && <Divider />}
                    <Box sx={{ px: 2, py: 1.5 }}>
                      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                        <StatusChip label={d.event} uppercase={false} />

                        <StatusChip
                          label={deliveryStatusLabel(d.status)}
                          severity={
                            d.status === "success" ? "success"
                              : d.status === "failed" ? "error"
                              : "warning"
                          }
                        />

                        {d.statusCode != null && (
                          <StatusChip
                            label={`${t("webhooks.deliveryStatusCode")}: ${d.statusCode}`}
                            uppercase={false}
                          />
                        )}

                        <Box sx={{ flex: 1 }} />

                        <Typography variant="caption" color="text.disabled">
                          {fmtDate(d.createdAt)}
                        </Typography>

                        {d.completedAt && (
                          <Typography variant="caption" color="text.disabled">
                            {fmtDate(d.completedAt)}
                          </Typography>
                        )}

                        {d.status === "failed" && (
                          <Tooltip title={t("webhooks.deliveryRetry")}>
                            <span>
                              <IconButton
                                size="small"
                                onClick={() => void handleRetry(d)}
                                disabled={retryingId === d.id}
                              >
                                <RotateCcw size={14} strokeWidth={1.75} />
                              </IconButton>
                            </span>
                          </Tooltip>
                        )}
                      </Stack>
                    </Box>
                  </React.Fragment>
                ))}
              </Paper>

              {hasMoreDeliveries && (
                <Box sx={{ textAlign: "center", pt: 2 }}>
                  <Button
                    size="small"
                    onClick={() => {
                      if (deliveriesWebhook) {
                        void fetchDeliveries(deliveriesWebhook.id, deliveriesOffset, false);
                      }
                    }}
                    disabled={deliveriesLoading}
                  >
                    {deliveriesLoading ? <CircularProgress size={16} sx={{ mr: 1 }} /> : null}
                    {t("webhooks.loadMore")}
                  </Button>
                </Box>
              )}
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeliveriesOpen(false)}>
            {t("common.close")}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
