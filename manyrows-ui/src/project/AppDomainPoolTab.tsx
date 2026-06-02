import * as React from "react";
import axios from "axios";
import { useTranslation } from "react-i18next";
import { Link as RouterLink } from "react-router-dom";
import {
  Box,
  Button,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { extractApiError } from "../lib/apiError.ts";
import type { App } from "./AppAuthMethods.tsx";

type WorkspacePool = { id: string; workspaceId: string; name: string; appCount: number; userCount: number };

const cardSx = {
  border: "1px solid",
  borderColor: "divider",
  borderRadius: 2,
  bgcolor: "background.paper",
  px: { xs: 2, sm: 2.5 },
  py: 2,
} as const;

// normalizeDomain strips an accidental scheme/trailing slash — the server
// stores a bare hostname and prepends https:// itself.
function normalizeDomain(s: string): string {
  return s.trim().replace(/^https?:\/\//, "").replace(/\/+$/, "");
}

// AppDomainPoolTab is the "Domain & user pool" tab of the Auth settings page:
// the app's custom auth domain (editable) and which user pool backs its auth
// (repointable). Moved off App Settings so auth config lives with auth.
export default function AppDomainPoolTab({
  app,
  cardURL,
  workspaceId,
  onSaved,
  onSuccess,
  onError,
}: {
  app: App;
  cardURL: string; // /admin/workspace/{ws}/projects/{prod}/apps/{appId}
  workspaceId: string;
  onSaved: (a: App) => void;
  onSuccess: () => void;
  onError: (e: unknown) => void;
}) {
  const { t } = useTranslation();
  const [authDomain, setAuthDomain] = React.useState(app.authDomain ?? "");
  const [saving, setSaving] = React.useState(false);

  const [pools, setPools] = React.useState<WorkspacePool[]>([]);
  const [repointOpen, setRepointOpen] = React.useState(false);
  const [repointTargetId, setRepointTargetId] = React.useState("");
  const [repointSaving, setRepointSaving] = React.useState(false);
  const [repointErr, setRepointErr] = React.useState<string | null>(null);

  React.useEffect(() => setAuthDomain(app.authDomain ?? ""), [app.authDomain]);

  React.useEffect(() => {
    let alive = true;
    axios
      .get<{ pools: WorkspacePool[] }>(`/admin/workspace/${workspaceId}/userPools`)
      .then((res) => alive && setPools(res.data?.pools ?? []))
      .catch(() => alive && setPools([]));
    return () => {
      alive = false;
    };
  }, [workspaceId]);

  const currentPool = app.userPoolId ? pools.find((p) => p.id === app.userPoolId) ?? null : null;
  const dirty = normalizeDomain(authDomain) !== (app.authDomain ?? "");

  const save = async () => {
    setSaving(true);
    try {
      const res = await axios.patch<App>(`${cardURL}/`, { authDomain: normalizeDomain(authDomain) });
      onSaved(res.data);
      setAuthDomain(res.data.authDomain ?? "");
      onSuccess();
    } catch (e) {
      onError(e);
    } finally {
      setSaving(false);
    }
  };

  const submitRepoint = async () => {
    if (!repointTargetId || repointTargetId === app.userPoolId) {
      setRepointOpen(false);
      return;
    }
    setRepointSaving(true);
    setRepointErr(null);
    try {
      await axios.post(`${cardURL}/userPool`, { userPoolId: repointTargetId });
      const next = await axios.get<App>(`${cardURL}/`);
      onSaved(next.data);
      onSuccess();
      setRepointOpen(false);
    } catch (e) {
      setRepointErr(extractApiError(e, t("apps.repointFailed", { defaultValue: "Could not repoint app." })));
    } finally {
      setRepointSaving(false);
    }
  };

  return (
    <Box sx={{ maxWidth: 640 }}>
      <Box sx={cardSx}>
        <Stack spacing={2.5}>
          {/* Auth domain */}
          <Box>
            <Typography sx={{ fontSize: 12, fontWeight: 600, color: "text.secondary", mb: 0.5 }}>
              {t("apps.detail.authDomain", { defaultValue: "Auth domain" })}
            </Typography>
            <TextField
              value={authDomain}
              onChange={(e) => setAuthDomain(e.target.value)}
              size="small"
              fullWidth
              placeholder="auth.yourdomain.com"
            />
            <Typography sx={{ fontSize: 11.5, color: "text.disabled", mt: 0.5 }}>
              {t("apps.detail.authDomainHelp", {
                defaultValue: "Custom domain that serves this app's hosted auth pages (optional).",
              })}
            </Typography>
          </Box>

          {/* User pool */}
          <Box>
            <Typography sx={{ fontSize: 12, fontWeight: 600, color: "text.secondary", mb: 0.5 }}>
              {t("apps.detail.userPool", { defaultValue: "User pool" })}
            </Typography>
            <Stack direction="row" spacing={1} alignItems="center">
              {app.userPoolId ? (
                <RouterLink
                  to={`/app/workspace/${workspaceId}/userPools/${app.userPoolId}`}
                  style={{ textDecoration: "none" }}
                >
                  <Typography sx={{ fontSize: 13, color: "primary.main", "&:hover": { textDecoration: "underline" } }}>
                    {currentPool?.name ?? app.userPoolId}
                  </Typography>
                </RouterLink>
              ) : (
                <Typography sx={{ fontSize: 13 }}>-</Typography>
              )}
              {currentPool && (
                <Typography sx={{ fontSize: 11.5, color: "text.secondary" }}>
                  ({currentPool.appCount}{" "}
                  {currentPool.appCount === 1
                    ? t("apps.detail.appSingular", { defaultValue: "app" })
                    : t("apps.detail.appPlural", { defaultValue: "apps" })}
                  )
                </Typography>
              )}
              <Button
                size="small"
                variant="text"
                onClick={() => {
                  setRepointTargetId("");
                  setRepointErr(null);
                  setRepointOpen(true);
                }}
                sx={{ ml: 0.5 }}
              >
                {t("apps.detail.changePool", { defaultValue: "Change" })}
              </Button>
            </Stack>
            <Typography sx={{ fontSize: 11.5, color: "text.disabled", mt: 0.5 }}>
              {t("apps.detail.userPoolHelp", {
                defaultValue: "The pool of users this environment authenticates against.",
              })}
            </Typography>
          </Box>

          <Box>
            <Button
              variant="contained"
              disableElevation
              onClick={() => void save()}
              disabled={saving || !dirty}
              startIcon={saving ? <CircularProgress size={14} color="inherit" /> : undefined}
            >
              {t("common.save", { defaultValue: "Save" })}
            </Button>
          </Box>
        </Stack>
      </Box>

      {/* Repoint dialog */}
      <Dialog open={repointOpen} onClose={() => !repointSaving && setRepointOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>{t("apps.detail.changePoolTitle", { defaultValue: "Change user pool" })}</DialogTitle>
        <DialogContent>
          <Typography sx={{ fontSize: 12.5, color: "text.secondary", mb: 1.5 }}>
            {t("apps.detail.changePoolHint", {
              defaultValue: "Point this environment at a different pool of users. Existing sessions may be invalidated.",
            })}
          </Typography>
          <TextField
            select
            fullWidth
            size="small"
            label={t("apps.detail.userPool", { defaultValue: "User pool" })}
            value={repointTargetId}
            onChange={(e) => setRepointTargetId(e.target.value)}
          >
            {pools.map((p) => (
              <MenuItem key={p.id} value={p.id} disabled={p.id === app.userPoolId}>
                {p.name}
                {p.id === app.userPoolId ? ` (${t("apps.detail.currentPool", { defaultValue: "current" })})` : ""}
              </MenuItem>
            ))}
          </TextField>
          {repointErr && (
            <Typography color="error" sx={{ fontSize: 13, mt: 1 }}>
              {repointErr}
            </Typography>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRepointOpen(false)} disabled={repointSaving}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button
            variant="contained"
            disableElevation
            onClick={() => void submitRepoint()}
            disabled={repointSaving || !repointTargetId || repointTargetId === app.userPoolId}
            startIcon={repointSaving ? <CircularProgress size={14} color="inherit" /> : undefined}
          >
            {t("apps.detail.changePool", { defaultValue: "Change" })}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
