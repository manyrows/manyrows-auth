import * as React from "react";
import axios from "axios";
import { extractApiError } from "../lib/apiError.ts";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Divider,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  FormControl,
  IconButton,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { Plus, Trash2, SquarePen, Copy, RotateCcw } from "lucide-react";
import PageHeader from "../components/PageHeader.tsx";
import { useTranslation } from "react-i18next";
import { useSnackbar } from "notistack";
import type {APIKey} from "../core.ts";

const MAX_KEYS = 5;

interface Props {
  workspaceId: string;
  appId?: string;
}

interface NewApiKeyResponse {
  id: string;
  name: string;
  key: string; // full key shown once
  scope?: string;
  expiresAt?: string | null;
}

export default function ApiKeys({ workspaceId, appId }: Props) {
  const { t } = useTranslation();
  const { enqueueSnackbar } = useSnackbar();
  const [keys, setKeys] = React.useState<APIKey[]>([]);
  const [loading, setLoading] = React.useState(false);

  const [createOpen, setCreateOpen] = React.useState(false);
  const [newName, setNewName] = React.useState("");
  const [newScope, setNewScope] = React.useState("read_write");
  const [newExpiryDays, setNewExpiryDays] = React.useState(0); // 0 = never

  const [deleteKey, setDeleteKey] = React.useState<APIKey | null>(null);
  const [rotateKey, setRotateKey] = React.useState<APIKey | null>(null);

  const [editKey, setEditKey] = React.useState<APIKey | null>(null);
  const [editName, setEditName] = React.useState("");

  const [createdKey, setCreatedKey] = React.useState<NewApiKeyResponse | null>(
    null,
  );
  const [createdMode, setCreatedMode] = React.useState<"create" | "rotate">("create");
  const [copied, setCopied] = React.useState(false);

  const basePath = `/admin/workspace/${workspaceId}/apiKeys`;

  const isExpired = (key: APIKey) =>
    !!key.expiresAt && new Date(key.expiresAt).getTime() < Date.now();

  const expiryLabel = (key: APIKey): string => {
    if (!key.expiresAt) return t("apiKeys.noExpiry");
    if (isExpired(key)) return t("apiKeys.expired");
    return t("apiKeys.expiresOn", {
      date: new Date(key.expiresAt).toLocaleDateString(),
    });
  };

  const loadKeys = async () => {
    setLoading(true);
    try {
      const res = await axios.get(basePath, { params: { appId: appId || undefined } });
      setKeys(Array.isArray(res.data) ? res.data : []);
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("error.generic")), { variant: "error" });
    } finally {
      setLoading(false);
    }
  };

  React.useEffect(() => {
    loadKeys();
  }, [workspaceId, appId]);

  const openCreate = () => {
    setNewName("");
    setNewScope("read_write");
    setNewExpiryDays(0);
    setCreateOpen(true);
  };

  const closeCreate = () => {
    setCreateOpen(false);
    setNewName("");
  };

  const createKey = async () => {
    if (keys.length >= MAX_KEYS) return;

    const name = newName.trim();
    if (!name) return;

    try {
      const res = await axios.post<NewApiKeyResponse>(
        basePath,
        {
          name,
          appId: appId || undefined,
          scope: newScope,
          expiresInDays: newExpiryDays > 0 ? newExpiryDays : undefined,
        },
      );

      setCreateOpen(false);
      setNewName("");
      setCopied(false);
      setCreatedMode("create");
      setCreatedKey(res.data);
      loadKeys();
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("error.generic")), { variant: "error" });
    }
  };

  const confirmRotate = async () => {
    if (!rotateKey) return;
    try {
      const res = await axios.post<NewApiKeyResponse>(
        `${basePath}/${rotateKey.id}/rotate`,
      );
      setRotateKey(null);
      setCopied(false);
      setCreatedMode("rotate");
      setCreatedKey(res.data);
      loadKeys();
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("error.generic")), { variant: "error" });
      setRotateKey(null);
    }
  };

  const confirmDelete = async () => {
    if (!deleteKey) return;

    try {
      await axios.delete(`${basePath}/${deleteKey.id}`);

      setDeleteKey(null);
      loadKeys();
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("error.generic")), { variant: "error" });
    }
  };

  const openEdit = (key: APIKey) => {
    setEditName(key.name);
    setEditKey(key);
  };

  const closeEdit = () => {
    setEditKey(null);
    setEditName("");
  };

  const confirmEdit = async () => {
    if (!editKey) return;
    const name = editName.trim();
    if (!name) return;

    try {
      await axios.patch(
        `${basePath}/${editKey.id}`,
        { name },
      );
      closeEdit();
      loadKeys();
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("error.generic")), { variant: "error" });
    }
  };

  const handleCopy = async () => {
    if (!createdKey?.key) return;
    try {
      await navigator.clipboard.writeText(createdKey.key);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      setCopied(false);
    }
  };

  const atLimit = keys.length >= MAX_KEYS;

  return (
    <Box sx={{ maxWidth: 720 }}>
      <Stack spacing={2.5}>
        <PageHeader
          title={t("apiKeys.title")}
          subtitle={t("apiKeys.description")}
          action={
            <Button
              size="small"
              disableElevation
              variant="contained"
              startIcon={<Plus size={14} strokeWidth={2} />}
              onClick={openCreate}
              disabled={atLimit}
            >
              {t("apiKeys.newKey")}
            </Button>
          }
        />

        <Typography variant="caption" color="text.secondary">
          {t("apiKeys.used", { count: keys.length, max: MAX_KEYS })}
        </Typography>

        {atLimit && (
          <Alert severity="warning">
            {t("apiKeys.limitReached", { max: MAX_KEYS })}
          </Alert>
        )}

        {/* List */}
        <Card variant="outlined">
          <CardContent sx={{ p: 0 }}>
            {keys.length === 0 && !loading && (
              <Box sx={{ p: 2 }}>
                <Typography variant="body2" color="text.secondary">
                  {t("apiKeys.noKeys")}
                </Typography>
              </Box>
            )}

            {keys.map((key, idx) => (
              <React.Fragment key={key.id}>
                {idx > 0 && <Divider />}
                <Stack
                  direction="row"
                  alignItems="center"
                  spacing={2}
                  sx={{ p: 2 }}
                >
                  <Box sx={{ flexGrow: 1, minWidth: 0 }}>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Typography sx={{ fontSize: 13.5, fontWeight: 600 }} noWrap>
                        {key.name}
                      </Typography>
                      {key.scope === "read" && (
                        <Chip
                          size="small"
                          variant="outlined"
                          label={t("apiKeys.readOnlyBadge")}
                          sx={{ height: 18, fontSize: 10 }}
                        />
                      )}
                    </Stack>
                    <Typography
                      sx={{
                        fontFamily: "var(--font-mono)",
                        fontSize: 11,
                        color: "text.disabled",
                        mt: 0.25,
                      }}
                      noWrap
                    >
                      mr_{key.prefix}••••••••
                    </Typography>
                    <Typography
                      sx={{
                        fontSize: 11,
                        color: isExpired(key) ? "error.main" : "text.disabled",
                        mt: 0.25,
                      }}
                      noWrap
                    >
                      {expiryLabel(key)}
                    </Typography>
                  </Box>

                  <IconButton
                    size="small"
                    title={t("apiKeys.rotate")}
                    onClick={() => setRotateKey(key)}
                  >
                    <RotateCcw size={14} strokeWidth={1.75} />
                  </IconButton>

                  <IconButton
                    size="small"
                    onClick={() => openEdit(key)}
                  >
                    <SquarePen size={14} strokeWidth={1.75} />
                  </IconButton>

                  <IconButton
                    size="small"
                    color="error"
                    onClick={() => setDeleteKey(key)}
                  >
                    <Trash2 size={14} strokeWidth={1.75} />
                  </IconButton>
                </Stack>
              </React.Fragment>
            ))}
          </CardContent>
        </Card>
      </Stack>

      {/* Create dialog */}
      <Dialog open={createOpen} onClose={closeCreate} maxWidth="sm" fullWidth>
        <DialogTitle>{t("apiKeys.createTitle")}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <DialogContentText>
              {t("apiKeys.createDescription")}
            </DialogContentText>

            {atLimit && (
              <Alert severity="warning">
                {t("apiKeys.limitReachedCreate", { max: MAX_KEYS })}
              </Alert>
            )}

            <TextField
              label={t("apiKeys.keyName")}
              size="small"
              fullWidth
              autoFocus
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              disabled={atLimit}
              onKeyDown={(e) => {
                if (e.key === "Enter") createKey();
              }}
            />

            <FormControl fullWidth size="small" disabled={atLimit}>
              <InputLabel>{t("apiKeys.scope")}</InputLabel>
              <Select
                label={t("apiKeys.scope")}
                value={newScope}
                onChange={(e) => setNewScope(e.target.value)}
              >
                <MenuItem value="read_write">{t("apiKeys.scopeReadWrite")}</MenuItem>
                <MenuItem value="read">{t("apiKeys.scopeRead")}</MenuItem>
              </Select>
            </FormControl>
            <Typography variant="caption" color="text.secondary" sx={{ mt: -1 }}>
              {t("apiKeys.scopeHint")}
            </Typography>

            <FormControl fullWidth size="small" disabled={atLimit}>
              <InputLabel>{t("apiKeys.expiry")}</InputLabel>
              <Select
                label={t("apiKeys.expiry")}
                value={String(newExpiryDays)}
                onChange={(e) => setNewExpiryDays(Number(e.target.value))}
              >
                <MenuItem value="0">{t("apiKeys.expiryNever")}</MenuItem>
                <MenuItem value="30">{t("apiKeys.expiry30")}</MenuItem>
                <MenuItem value="90">{t("apiKeys.expiry90")}</MenuItem>
                <MenuItem value="365">{t("apiKeys.expiry365")}</MenuItem>
              </Select>
            </FormControl>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={closeCreate}>{t("common.cancel")}</Button>
          <Button
            variant="contained"
            onClick={createKey}
            disabled={atLimit || !newName.trim()}
          >
            {t("common.create")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* New key dialog (shown once) */}
      <Dialog
        open={!!createdKey}
        onClose={() => setCreatedKey(null)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          {createdMode === "rotate"
            ? t("apiKeys.rotatedTitle")
            : t("apiKeys.createdTitle")}
        </DialogTitle>
        <DialogContent>
          <Stack spacing={2}>
            <DialogContentText>
              {t("apiKeys.createdDescription")}
            </DialogContentText>

            {copied && <Alert severity="success">{t("apiKeys.copiedToClipboard")}</Alert>}

            <Box
              sx={{
                p: 1.5,
                borderRadius: 2,
                border: "1px solid",
                borderColor: "divider",
                bgcolor: "background.default",
                fontFamily: "var(--font-mono)",
                fontSize: 13,
                overflowX: "auto",
                whiteSpace: "nowrap",
              }}
            >
              {createdKey?.key}
            </Box>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreatedKey(null)}>{t("common.close")}</Button>
          <Button
            variant="contained"
            startIcon={<Copy size={14} strokeWidth={1.75} />}
            onClick={handleCopy}
          >
            {t("common.copy")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete dialog */}
      <Dialog open={!!deleteKey} onClose={() => setDeleteKey(null)}>
        <DialogTitle>{t("apiKeys.deleteTitle")}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {deleteKey
              ? t("apiKeys.deleteDescription", { name: deleteKey.name })
              : ""}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteKey(null)}>{t("common.cancel")}</Button>
          <Button color="error" variant="contained" onClick={confirmDelete}>
            {t("common.delete")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Rotate dialog */}
      <Dialog open={!!rotateKey} onClose={() => setRotateKey(null)}>
        <DialogTitle>{t("apiKeys.rotateTitle")}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {rotateKey ? t("apiKeys.rotateDescription", { name: rotateKey.name }) : ""}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRotateKey(null)}>{t("common.cancel")}</Button>
          <Button color="warning" variant="contained" onClick={confirmRotate}>
            {t("apiKeys.rotate")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit dialog */}
      <Dialog open={!!editKey} onClose={closeEdit} maxWidth="sm" fullWidth>
        <DialogTitle>{t("apiKeys.editTitle")}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <DialogContentText>
              {t("apiKeys.editDescription")}
            </DialogContentText>

            <TextField
              label={t("apiKeys.keyName")}
              size="small"
              fullWidth
              autoFocus
              value={editName}
              onChange={(e) => setEditName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") confirmEdit();
              }}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={closeEdit}>{t("common.cancel")}</Button>
          <Button
            variant="contained"
            onClick={confirmEdit}
            disabled={!editName.trim()}
          >
            {t("common.save")}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
