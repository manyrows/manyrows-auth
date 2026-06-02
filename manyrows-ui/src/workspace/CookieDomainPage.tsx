import * as React from "react";
import axios from "axios";
import {
  Box,
  Button,
  Stack,
  TextField,
} from "@mui/material";
import type { Workspace } from "../core.ts";
import { extractApiError } from "../lib/apiError.ts";
import { useSnackbar } from "notistack";
import { useTranslation, Trans } from "react-i18next";
import PageHeader from "../components/PageHeader.tsx";

interface Props {
  workspace: Workspace;
  onUpdated?: (ws: Workspace) => void;
}

// CookieDomainPage sets the workspace-level Domain attribute used
// for session cookies. Empty string clears it; the browser then
// scopes the cookie to the exact host that set it. Per-app override
// lives under App → Security → Sessions.
export default function CookieDomainPage({ workspace, onUpdated }: Props) {
  const { enqueueSnackbar } = useSnackbar();
  const { t } = useTranslation();
  const [value, setValue] = React.useState<string>(workspace.cookieDomain ?? "");
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    setValue(workspace.cookieDomain ?? "");
  }, [workspace.cookieDomain]);

  const trimmed = value.trim();
  const dirty = trimmed !== (workspace.cookieDomain ?? "");

  // Soft format hint - full validation runs server-side.
  const looksWrong = trimmed !== "" && (trimmed.includes(" ") || trimmed.includes("/") || !trimmed.includes("."));

  async function save() {
    setSaving(true);
    try {
      const res = await axios.put<Workspace>(
        `/admin/workspace/${workspace.id}/cookie-domain`,
        { cookieDomain: trimmed },
      );
      onUpdated?.(res.data);
      enqueueSnackbar(t("cookieDomain.saved"), { variant: "success" });
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("common.failedToSave")), { variant: "error" });
    } finally {
      setSaving(false);
    }
  }

  return (
    <Box>
      <Stack spacing={2} sx={{ maxWidth: 680 }}>
        <PageHeader
          title={t("cookieDomain.title")}
          subtitle={
            <Trans
              i18nKey="cookieDomain.subtitle"
              components={{
                code: <code />,
                sample: (
                  <Box component="code" sx={{ fontFamily: "var(--font-mono)", bgcolor: "action.hover", px: 0.5, py: 0.1, borderRadius: 0.5 }} />
                ),
              }}
            />
          }
          size={28}
          mb={0}
        />

        <TextField
          label={t("cookieDomain.label")}
          placeholder=".yourdomain.com"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          fullWidth
          size="small"
          error={looksWrong}
          helperText={
            looksWrong
              ? t("cookieDomain.invalid")
              : t("cookieDomain.emptyHint")
          }
          disabled={saving}
        />

        <Stack direction="row" spacing={1} justifyContent="flex-end">
          <Button
            variant="contained"
            disableElevation
            onClick={save}
            disabled={!dirty || saving || looksWrong}
            sx={{ textTransform: "none" }}
          >
            {saving ? t("common.saving") : t("common.save")}
          </Button>
        </Stack>
      </Stack>
    </Box>
  );
}
