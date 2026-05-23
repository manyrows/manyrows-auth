import * as React from "react";
import axios from "axios";
import { extractApiError } from "../lib/apiError.ts";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Divider,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  IconButton,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { Plus, SquarePen, Trash2 } from "lucide-react";
import { useTranslation } from "react-i18next";

const MAX_ENTRIES = 50;

function sanitizeErrorMsg(msg: string): string {
  const clean = msg.replace(/<[^>]*>/g, "");
  return clean.length > 200 ? clean.slice(0, 200) + "\u2026" : clean;
}

interface IPAllowlistEntry {
  id: string;
  appId: string;
  ipRange: string;
  description?: string;
  createdAt: string;
}

interface Props {
  workspaceId: string;
  productId: string;
  appId: string;
  open?: boolean;
  onClose?: () => void;
  inline?: boolean;
}

function extractEntries(data: unknown): IPAllowlistEntry[] {
  if (Array.isArray(data)) return data as IPAllowlistEntry[];
  if (data && typeof data === "object" && Array.isArray((data as { entries?: unknown }).entries)) {
    return (data as { entries: IPAllowlistEntry[] }).entries;
  }
  return [];
}

export default function AppIPAllowlist({ workspaceId, productId, appId, open = true, onClose, inline }: Props) {
  const { t } = useTranslation();
  const basePath = `/admin/workspace/${workspaceId}/products/${productId}/apps/${appId}/ipAllowlist`;

  const [entries, setEntries] = React.useState<IPAllowlistEntry[]>([]);
  const [loading, setLoading] = React.useState(false);

  const [createOpen, setCreateOpen] = React.useState(false);
  const [newIPRange, setNewIPRange] = React.useState("");
  const [newDescription, setNewDescription] = React.useState("");

  const [deleteEntry, setDeleteEntry] = React.useState<IPAllowlistEntry | null>(null);

  const [editEntry, setEditEntry] = React.useState<IPAllowlistEntry | null>(null);
  const [editIPRange, setEditIPRange] = React.useState("");
  const [editDescription, setEditDescription] = React.useState("");

  const [errorMsg, setErrorMsg] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);

  const loadEntries = React.useCallback(async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await axios.get(basePath);
      setEntries(extractEntries(res.data));
    } catch (e) {
      setErrorMsg(sanitizeErrorMsg(extractApiError(e, t("error.generic"))));
      setEntries([]);
    } finally {
      setLoading(false);
    }
  }, [basePath, t]);

  React.useEffect(() => {
    if (open) loadEntries();
  }, [open, loadEntries]);

  const atLimit = entries.length >= MAX_ENTRIES;

  const openCreate = () => {
    setErrorMsg(null);
    setNewIPRange("");
    setNewDescription("");
    setCreateOpen(true);
  };

  const closeCreate = () => {
    setCreateOpen(false);
    setNewIPRange("");
    setNewDescription("");
    setErrorMsg(null);
  };

  const createEntry = async () => {
    if (atLimit || saving) return;
    const ipRange = newIPRange.trim();
    if (!ipRange) return;
    setSaving(true);
    try {
      await axios.post(basePath, {
        ipRange,
        description: newDescription.trim(),
      });
      setCreateOpen(false);
      setNewIPRange("");
      setNewDescription("");
      await loadEntries();
    } catch (e) {
      setErrorMsg(sanitizeErrorMsg(extractApiError(e, t("error.generic"))));
    } finally {
      setSaving(false);
    }
  };

  const confirmDelete = async () => {
    if (!deleteEntry || saving) return;
    setSaving(true);
    try {
      await axios.delete(`${basePath}/${deleteEntry.id}`);
      setDeleteEntry(null);
      await loadEntries();
    } catch (e) {
      setDeleteEntry(null);
      setErrorMsg(sanitizeErrorMsg(extractApiError(e, t("error.generic"))));
    } finally {
      setSaving(false);
    }
  };

  const openEdit = (entry: IPAllowlistEntry) => {
    setErrorMsg(null);
    setEditEntry(entry);
    setEditIPRange(entry.ipRange);
    setEditDescription(entry.description || "");
  };

  const closeEdit = () => {
    setEditEntry(null);
    setEditIPRange("");
    setEditDescription("");
    setErrorMsg(null);
  };

  const saveEdit = async () => {
    if (!editEntry || saving) return;
    const ipRange = editIPRange.trim();
    if (!ipRange) return;
    setSaving(true);
    try {
      await axios.patch(`${basePath}/${editEntry.id}`, {
        ipRange,
        description: editDescription.trim(),
      });
      setEditEntry(null);
      setEditIPRange("");
      setEditDescription("");
      await loadEntries();
    } catch (e) {
      setErrorMsg(sanitizeErrorMsg(extractApiError(e, t("error.generic"))));
    } finally {
      setSaving(false);
    }
  };

  const content = (
    <Stack spacing={2} sx={{ pt: inline ? 0 : 1 }}>
      <Typography variant="body2" color="text.secondary">
        {t("ipAllowlist.description")}
        <br />
        {t("ipAllowlist.hint")}
      </Typography>

      <Stack direction="row" spacing={1} alignItems="center">
        <Typography variant="caption" color="text.secondary">
          {t("ipAllowlist.used", { count: entries.length, max: MAX_ENTRIES })}
        </Typography>
        <Box sx={{ flex: 1 }} />
        <Button
          disableElevation
          size="small"
          variant="contained"
          startIcon={<Plus size={14} strokeWidth={1.75} />}
          onClick={openCreate}
          disabled={atLimit}
        >
          {t("ipAllowlist.addIP")}
        </Button>
      </Stack>

      {errorMsg && <Alert severity="error">{errorMsg}</Alert>}

      {atLimit && (
        <Alert severity="warning">
          {t("ipAllowlist.limitReached", { max: MAX_ENTRIES })}
        </Alert>
      )}

      <Card variant="outlined">
        <CardContent sx={{ p: 0 }}>
          {entries.length === 0 && !loading && (
            <Box sx={{ p: 2 }}>
              <Typography variant="body2" color="text.secondary">
                {t("ipAllowlist.noEntries")}
              </Typography>
            </Box>
          )}

          {entries.map((e, idx) => (
            <React.Fragment key={e.id}>
              {idx > 0 && <Divider />}
              <Stack direction="row" alignItems="center" spacing={2} sx={{ p: 2 }}>
                <Box sx={{ flexGrow: 1, minWidth: 0 }}>
                  <Typography
                    sx={{ fontFamily: "var(--font-mono)", fontSize: 12.5, fontWeight: 500 }}
                    noWrap
                    title={e.ipRange}
                  >
                    {e.ipRange}
                  </Typography>
                  {e.description ? (
                    <Typography variant="caption" color="text.secondary" sx={{ mt: 0.25, display: "block" }}>
                      {e.description}
                    </Typography>
                  ) : (
                    <Typography
                      sx={{
                        fontFamily: "var(--font-mono)",
                        fontSize: 10.5,
                        color: "text.disabled",
                        mt: 0.25,
                      }}
                    >
                      {t("ipAllowlist.added", { date: e.createdAt ? new Date(e.createdAt).toLocaleDateString() : "-" })}
                    </Typography>
                  )}
                </Box>
                <IconButton size="small" onClick={() => openEdit(e)} aria-label={t("common.edit")}>
                  <SquarePen size={14} strokeWidth={1.75} />
                </IconButton>
                <IconButton size="small" color="error" onClick={() => setDeleteEntry(e)} aria-label={t("common.delete")}>
                  <Trash2 size={14} strokeWidth={1.75} />
                </IconButton>
              </Stack>
            </React.Fragment>
          ))}
        </CardContent>
      </Card>
    </Stack>
  );

  return (
    <>
      {inline ? content : (
        <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
          <DialogTitle>{t("ipAllowlist.title")}</DialogTitle>
          <DialogContent>{content}</DialogContent>
          <DialogActions>
            <Button onClick={onClose}>{t("common.close")}</Button>
          </DialogActions>
        </Dialog>
      )}

      {/* Create dialog */}
      <Dialog open={createOpen} onClose={closeCreate} maxWidth="sm" fullWidth>
        <DialogTitle>{t("ipAllowlist.addTitle")}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <DialogContentText>{t("ipAllowlist.addDescription")}</DialogContentText>
            {errorMsg && <Alert severity="error">{errorMsg}</Alert>}
            <TextField
              label={t("ipAllowlist.ipLabel")}
              size="small"
              fullWidth
              autoFocus
              placeholder={t("ipAllowlist.ipPlaceholder")}
              value={newIPRange}
              onChange={(e) => setNewIPRange(e.target.value)}
              disabled={atLimit}
              onKeyDown={(e) => { if (e.key === "Enter") createEntry(); }}
            />
            <TextField
              label={t("ipAllowlist.descriptionLabel")}
              size="small"
              fullWidth
              placeholder={t("ipAllowlist.descriptionPlaceholder")}
              value={newDescription}
              onChange={(e) => setNewDescription(e.target.value)}
              disabled={atLimit}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={closeCreate}>{t("common.cancel")}</Button>
          <Button variant="contained" onClick={createEntry} disabled={atLimit || !newIPRange.trim() || saving}>
            {t("common.add")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit dialog */}
      <Dialog open={!!editEntry} onClose={closeEdit} maxWidth="sm" fullWidth>
        <DialogTitle>{t("ipAllowlist.editTitle")}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <DialogContentText>{t("ipAllowlist.editDescription")}</DialogContentText>
            {errorMsg && <Alert severity="error">{errorMsg}</Alert>}
            <TextField
              label={t("ipAllowlist.ipLabel")}
              size="small"
              fullWidth
              autoFocus
              placeholder={t("ipAllowlist.ipPlaceholder")}
              value={editIPRange}
              onChange={(e) => setEditIPRange(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") saveEdit(); }}
            />
            <TextField
              label={t("ipAllowlist.descriptionLabel")}
              size="small"
              fullWidth
              placeholder={t("ipAllowlist.descriptionPlaceholder")}
              value={editDescription}
              onChange={(e) => setEditDescription(e.target.value)}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={closeEdit}>{t("common.cancel")}</Button>
          <Button variant="contained" onClick={saveEdit} disabled={!editIPRange.trim() || saving}>
            {t("common.save")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete dialog */}
      <Dialog open={!!deleteEntry} onClose={() => setDeleteEntry(null)}>
        <DialogTitle>{t("ipAllowlist.removeTitle")}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {deleteEntry ? t("ipAllowlist.removeDescription", { ip: deleteEntry.ipRange }) : ""}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteEntry(null)}>{t("common.cancel")}</Button>
          <Button color="error" variant="contained" onClick={confirmDelete} disabled={saving}>
            {t("common.remove")}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
