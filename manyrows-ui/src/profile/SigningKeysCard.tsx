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
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Stack,
  Tooltip,
  Typography,
} from "@mui/material";
import { Copy, KeyRound, RefreshCw, Trash2 } from "lucide-react";
import { useTranslation } from "react-i18next";
// JWT signing-key rotation panel. Super-admin only. Lives in the
// profile screen because there's no separate "install settings"
// surface today - keeps the route count low.
//
// Maps to three endpoints (manyrows-core/api/securityHandler.go):
//   GET    /admin/security/signing-keys
//   POST   /admin/security/signing-keys/rotate
//   POST   /admin/security/signing-keys/retire-previous
//
// The card stays mounted but renders null for non-super accounts so
// the parent Profile.tsx doesn't need to conditional-include it.

interface SigningKeyInfo {
  kid: string;
}

interface SigningKeyStatus {
  current: SigningKeyInfo;
  previous?: SigningKeyInfo | null;
}

export default function SigningKeysCard({ isSuper }: { isSuper: boolean }) {
  const { t } = useTranslation();
  const [status, setStatus] = React.useState<SigningKeyStatus | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [rotateOpen, setRotateOpen] = React.useState(false);
  const [retireOpen, setRetireOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  const fetchStatus = React.useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await axios.get<SigningKeyStatus>("/admin/security/signing-keys");
      setStatus(res.data);
    } catch (e) {
      setError(extractApiError(e, t("signingKeys.failedToLoad")));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    if (isSuper) {
      fetchStatus();
    }
  }, [isSuper, fetchStatus]);

  if (!isSuper) {
    return null;
  }

  async function doRotate() {
    setBusy(true);
    setError(null);
    try {
      const res = await axios.post<SigningKeyStatus>("/admin/security/signing-keys/rotate");
      setStatus(res.data);
      setRotateOpen(false);
    } catch (e) {
      setError(extractApiError(e, t("signingKeys.rotationFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function doRetire() {
    setBusy(true);
    setError(null);
    try {
      const res = await axios.post<SigningKeyStatus>("/admin/security/signing-keys/retire-previous");
      setStatus(res.data);
      setRetireOpen(false);
    } catch (e) {
      setError(extractApiError(e, t("signingKeys.retirementFailed")));
    } finally {
      setBusy(false);
    }
  }

  function copy(text: string) {
    navigator.clipboard.writeText(text).catch(() => {
      /* silent - clipboard permission denied */
    });
  }

  return (
    <Card variant="outlined">
      <CardContent sx={{ p: { xs: 2, sm: 3 } }}>
        <Stack spacing={2}>
          <Stack direction="row" alignItems="flex-start" spacing={1.5}>
            <Box sx={{ flex: 1, minWidth: 0 }}>
              <Typography
                sx={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 1,
                  fontFamily: "var(--font-mono)",
                  textTransform: "uppercase",
                  letterSpacing: "0.14em",
                  fontSize: 10,
                  fontWeight: 500,
                  color: "text.disabled",
                  mb: 0.5,
                }}
              >
                <KeyRound size={9} strokeWidth={1.75} />
                {t("signingKeys.eyebrow")}
              </Typography>
              <Typography sx={{ fontSize: 16, fontWeight: 600, letterSpacing: "-0.005em" }}>
                {t("signingKeys.title")}
              </Typography>
            </Box>
            <Chip
              label={t("signingKeys.superAdmin")}
              size="small"
              color="warning"
              variant="outlined"
              sx={{
                fontFamily: "var(--font-mono)",
                textTransform: "uppercase",
                letterSpacing: "0.08em",
                fontSize: 9.5,
                fontWeight: 600,
                height: 20,
              }}
            />
          </Stack>

          <Typography variant="body2" color="text.secondary">
            {t("signingKeys.description")}
          </Typography>

          {error && (
            <Alert severity="error">
              {error}
            </Alert>
          )}

          {loading && !status ? (
            <Box sx={{ display: "flex", justifyContent: "center", py: 2 }}>
              <CircularProgress size={24} />
            </Box>
          ) : status ? (
            <Stack spacing={1.5}>
              <KeyRow label={t("signingKeys.current")} kid={status.current.kid} onCopy={() => copy(status.current.kid)} />
              {status.previous && (
                <KeyRow
                  label={t("signingKeys.previous")}
                  kid={status.previous.kid}
                  onCopy={() => copy(status.previous!.kid)}
                  faded
                />
              )}
            </Stack>
          ) : null}

          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            <Button
              variant="outlined"
              startIcon={<RefreshCw size={14} strokeWidth={1.75} />}
              onClick={() => setRotateOpen(true)}
              disabled={busy || loading}
            >
              {t("signingKeys.rotate")}
            </Button>
            <Button
              variant="outlined"
              color="error"
              startIcon={<Trash2 size={14} strokeWidth={1.75} />}
              onClick={() => setRetireOpen(true)}
              disabled={busy || loading || !status?.previous}
            >
              {t("signingKeys.retirePrevious")}
            </Button>
          </Stack>
        </Stack>
      </CardContent>

      <Dialog
        open={rotateOpen}
        onClose={() => !busy && setRotateOpen(false)}
        fullWidth
        maxWidth="sm"
       
      >
        <DialogTitle>{t("signingKeys.rotateDialog.title")}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t("signingKeys.rotateDialog.body1")}
          </DialogContentText>
          <DialogContentText sx={{ mt: 2 }}>
            {t("signingKeys.rotateDialog.body2")}
          </DialogContentText>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
          <Button onClick={() => setRotateOpen(false)} disabled={busy}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="contained"
            color="warning"
            onClick={doRotate}
            disabled={busy}
            startIcon={busy ? <CircularProgress size={16} /> : <RefreshCw size={14} strokeWidth={1.75} />}

          >
            {t("signingKeys.rotateNow")}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={retireOpen}
        onClose={() => !busy && setRetireOpen(false)}
        fullWidth
        maxWidth="sm"
       
      >
        <DialogTitle>{t("signingKeys.retireDialog.title")}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t("signingKeys.retireDialog.body")}
          </DialogContentText>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
          <Button onClick={() => setRetireOpen(false)} disabled={busy}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="contained"
            color="error"
            onClick={doRetire}
            disabled={busy}
            startIcon={busy ? <CircularProgress size={16} /> : <Trash2 size={14} strokeWidth={1.75} />}

          >
            {t("signingKeys.retire")}
          </Button>
        </DialogActions>
      </Dialog>
    </Card>
  );
}

function KeyRow({
  label,
  kid,
  onCopy,
  faded = false,
}: {
  label: string;
  kid: string;
  onCopy: () => void;
  faded?: boolean;
}) {
  const { t } = useTranslation();
  return (
    <Stack
      direction="row"
      alignItems="center"
      spacing={1.5}
      sx={{
        opacity: faded ? 0.75 : 1,
        py: 1,
        px: 1.5,
        borderRadius: 2,
        bgcolor: "action.hover",
      }}
    >
      <Typography
        variant="caption"
        sx={{ fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5, minWidth: 64 }}
      >
        {label}
      </Typography>
      <Typography variant="body2" sx={{ fontFamily: "var(--font-mono)", flex: 1, overflow: "hidden", textOverflow: "ellipsis" }}>
        {kid}
      </Typography>
      <Tooltip title={t("signingKeys.copyKid")}>
        <Button
          size="small"
          onClick={onCopy}
          sx={{ minWidth: 0, p: 0.5 }}
          aria-label={t("signingKeys.copyKidAria")}
        >
          <Copy size={14} strokeWidth={1.75} />
        </Button>
      </Tooltip>
    </Stack>
  );
}
