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
import type { CorsOrigin } from "../core.ts";

const MAX_ORIGINS = 20;

function sanitizeErrorMsg(msg: string): string {
  const clean = msg.replace(/<[^>]*>/g, "");
  return clean.length > 200 ? clean.slice(0, 200) + "\u2026" : clean;
}

interface Props {
  workspaceId: string;
  productId: string;
  appId: string;
  open?: boolean;
  onClose?: () => void;
  inline?: boolean;
}

function extractOrigins(data: unknown): CorsOrigin[] {
  if (Array.isArray(data)) return data as CorsOrigin[];
  if (data && typeof data === "object") {
    const obj = data as { corsOrigins?: unknown; origins?: unknown };
    if (Array.isArray(obj.corsOrigins)) return obj.corsOrigins as CorsOrigin[];
    if (Array.isArray(obj.origins)) return obj.origins as CorsOrigin[];
  }
  return [];
}

export default function AppCorsOrigins({ workspaceId, productId, appId, open = true, onClose, inline }: Props) {
  const { t } = useTranslation();
  const basePath = `/admin/workspace/${workspaceId}/products/${productId}/apps/${appId}/corsOrigins`;

  const [origins, setOrigins] = React.useState<CorsOrigin[]>([]);
  const [loading, setLoading] = React.useState(false);

  const [createOpen, setCreateOpen] = React.useState(false);
  const [newOrigin, setNewOrigin] = React.useState("");

  const [deleteOrigin, setDeleteOrigin] = React.useState<CorsOrigin | null>(null);

  const [editOrigin, setEditOrigin] = React.useState<CorsOrigin | null>(null);
  const [editValue, setEditValue] = React.useState("");

  const [errorMsg, setErrorMsg] = React.useState<string | null>(null);

  const loadOrigins = React.useCallback(async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await axios.get(basePath);
      setOrigins(extractOrigins(res.data));
    } catch (e) {
      setErrorMsg(sanitizeErrorMsg(extractApiError(e, t("error.generic"))));
      setOrigins([]);
    } finally {
      setLoading(false);
    }
  }, [basePath, t]);

  React.useEffect(() => {
    if (open) loadOrigins();
  }, [open, loadOrigins]);

  const atLimit = origins.length >= MAX_ORIGINS;

  const openCreate = () => {
    setErrorMsg(null);
    setNewOrigin("");
    setCreateOpen(true);
  };

  const closeCreate = () => {
    setCreateOpen(false);
    setNewOrigin("");
    setErrorMsg(null);
  };

  const createOrigin = async () => {
    if (atLimit) return;
    const origin = newOrigin.trim();
    if (!origin) return;
    try {
      await axios.post(basePath, { origin });
      setCreateOpen(false);
      setNewOrigin("");
      await loadOrigins();
    } catch (e) {
      setErrorMsg(sanitizeErrorMsg(extractApiError(e, t("error.generic"))));
    }
  };

  const confirmDelete = async () => {
    if (!deleteOrigin) return;
    try {
      await axios.delete(`${basePath}/${deleteOrigin.id}`);
      setDeleteOrigin(null);
      await loadOrigins();
    } catch (e) {
      setDeleteOrigin(null);
      setErrorMsg(sanitizeErrorMsg(extractApiError(e, t("error.generic"))));
    }
  };

  const openEdit = (o: CorsOrigin) => {
    setErrorMsg(null);
    setEditOrigin(o);
    setEditValue(o.origin);
  };

  const closeEdit = () => {
    setEditOrigin(null);
    setEditValue("");
    setErrorMsg(null);
  };

  const saveEdit = async () => {
    if (!editOrigin) return;
    const origin = editValue.trim();
    if (!origin) return;
    try {
      await axios.patch(`${basePath}/${editOrigin.id}`, { origin });
      setEditOrigin(null);
      setEditValue("");
      await loadOrigins();
    } catch (e) {
      setErrorMsg(sanitizeErrorMsg(extractApiError(e, t("error.generic"))));
    }
  };

  const content = (
    <Stack spacing={2} sx={{ pt: inline ? 0 : 1 }}>
      <Typography variant="body2" color="text.secondary">
        {t("cors.description")}
        <br />
        {t("cors.hint")}
      </Typography>

      <Stack direction="row" spacing={1} alignItems="center">
        <Typography variant="caption" color="text.secondary">
          {t("cors.used", { count: origins.length, max: MAX_ORIGINS })}
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
          {t("cors.addOrigin")}
        </Button>
      </Stack>

      {errorMsg && <Alert severity="error">{errorMsg}</Alert>}

      {atLimit && (
        <Alert severity="warning">
          {t("cors.limitReached", { max: MAX_ORIGINS })}
        </Alert>
      )}

      <Card variant="outlined">
        <CardContent sx={{ p: 0 }}>
          {origins.length === 0 && !loading && (
            <Box sx={{ p: 2 }}>
              <Typography variant="body2" color="text.secondary">
                {t("cors.noOrigins")}
              </Typography>
            </Box>
          )}

          {origins.map((o, idx) => (
            <React.Fragment key={o.id}>
              {idx > 0 && <Divider />}
              <Stack direction="row" alignItems="center" spacing={2} sx={{ p: 2 }}>
                <Box sx={{ flexGrow: 1, minWidth: 0 }}>
                  <Typography
                    sx={{ fontFamily: "var(--font-mono)", fontSize: 12.5, fontWeight: 500 }}
                    noWrap
                    title={o.origin}
                  >
                    {o.origin}
                  </Typography>
                  <Typography
                    sx={{
                      fontFamily: "var(--font-mono)",
                      fontSize: 10.5,
                      color: "text.disabled",
                      mt: 0.25,
                    }}
                  >
                    {t("cors.added", { date: o.createdAt ? new Date(o.createdAt).toLocaleDateString() : "-" })}
                  </Typography>
                </Box>
                <IconButton size="small" onClick={() => openEdit(o)} aria-label={t("common.edit")}>
                  <SquarePen size={14} strokeWidth={1.75} />
                </IconButton>
                <IconButton size="small" color="error" onClick={() => setDeleteOrigin(o)} aria-label={t("common.delete")}>
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
          <DialogTitle>{t("cors.title")}</DialogTitle>
          <DialogContent>{content}</DialogContent>
          <DialogActions>
            <Button onClick={onClose}>{t("common.close")}</Button>
          </DialogActions>
        </Dialog>
      )}

      {/* Create dialog */}
      <Dialog open={createOpen} onClose={closeCreate} maxWidth="sm" fullWidth>
        <DialogTitle>{t("cors.addTitle")}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <DialogContentText>{t("cors.addDescription")}</DialogContentText>
            {errorMsg && <Alert severity="error">{errorMsg}</Alert>}
            <TextField
              label={t("cors.originLabel")}
              size="small"
              fullWidth
              autoFocus
              placeholder={t("cors.originPlaceholder", "https://example.com")}
              value={newOrigin}
              onChange={(e) => setNewOrigin(e.target.value)}
              disabled={atLimit}
              onKeyDown={(e) => { if (e.key === "Enter") createOrigin(); }}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={closeCreate}>{t("common.cancel")}</Button>
          <Button variant="contained" onClick={createOrigin} disabled={atLimit || !newOrigin.trim()}>
            {t("common.add")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit dialog */}
      <Dialog open={!!editOrigin} onClose={closeEdit} maxWidth="sm" fullWidth>
        <DialogTitle>{t("cors.editTitle")}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <DialogContentText>{t("cors.editDescription")}</DialogContentText>
            {errorMsg && <Alert severity="error">{errorMsg}</Alert>}
            <TextField
              label={t("cors.originLabel")}
              size="small"
              fullWidth
              autoFocus
              placeholder={t("cors.originPlaceholder", "https://example.com")}
              value={editValue}
              onChange={(e) => setEditValue(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") saveEdit(); }}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={closeEdit}>{t("common.cancel")}</Button>
          <Button variant="contained" onClick={saveEdit} disabled={!editValue.trim()}>
            {t("common.save")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete dialog */}
      <Dialog open={!!deleteOrigin} onClose={() => setDeleteOrigin(null)}>
        <DialogTitle>{t("cors.deleteTitle")}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {deleteOrigin ? t("cors.deleteDescription", { origin: deleteOrigin.origin }) : ""}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteOrigin(null)}>{t("common.cancel")}</Button>
          <Button color="error" variant="contained" onClick={confirmDelete}>
            {t("common.delete")}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
