import * as React from "react";
import axios from "axios";
import {
  Alert,
  Box,
  Button,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { useTranslation, Trans } from "react-i18next";
import type { App } from "./AppAuthMethods.tsx";
import SaveBar from "../components/SaveBar.tsx";

interface Props {
  app: App;
  cardURL: string;
  workspaceCookieDomain?: string | null;
  onSaved: (a: App) => void;
  onSuccess: () => void;
  onError: (e: unknown) => void;
}

// Per-app override for the session-cookie Domain attribute. When set,
// takes precedence over Workspace → Settings → Cookie domain. Useful
// when one ManyRows install hosts apps on different parent domains
// (e.g. one workspace running app.acme.com and app.widgets.io).
export default function AppCookieDomainCard({
  app,
  cardURL,
  workspaceCookieDomain,
  onSaved,
  onSuccess,
  onError,
}: Props) {
  const { t } = useTranslation();
  const [value, setValue] = React.useState<string>(app.cookieDomain ?? "");
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    setValue(app.cookieDomain ?? "");
  }, [app.cookieDomain]);

  const trimmed = value.trim();
  const dirty = trimmed !== (app.cookieDomain ?? "");

  const resetFromApp = React.useCallback(() => {
    setValue(app.cookieDomain ?? "");
  }, [app.cookieDomain]);

  // Soft format hint - full validation runs server-side.
  const looksWrong =
    trimmed !== "" && (trimmed.includes(" ") || trimmed.includes("/") || !trimmed.includes("."));

  // When AuthDomain is set (e.g. auth.drumkingdom.com) and no CookieDomain
  // override has been configured, the session cookies end up host-only on
  // the auth host. /api/* requests landing on the customer's parent domain
  // (drumkingdom.com) don't carry the cookie and 401. Drop the leftmost
  // label as a sane default - works for the typical "auth.<root>" shape
  // and is conservative for deeper nesting (would suggest "app.example.com"
  // rather than the full eTLD+1 "example.com"), which a customer can widen.
  const suggestedDomain = React.useMemo(() => {
    const auth = (app.authDomain ?? "").trim();
    if (!auth || !auth.includes(".")) return "";
    const labels = auth.split(".");
    if (labels.length < 3) return ""; // already an eTLD+1, nothing to drop.
    return labels.slice(1).join(".");
  }, [app.authDomain]);
  const showSuggestion = !trimmed && suggestedDomain !== "";

  async function save() {
    setSaving(true);
    try {
      const res = await axios.put<App>(`${cardURL}/cookie-domain`, {
        cookieDomain: trimmed,
      });
      onSaved(res.data);
      onSuccess();
    } catch (e) {
      onError(e);
    } finally {
      setSaving(false);
    }
  }

  const wsValue = (workspaceCookieDomain ?? "").trim();

  return (
    <Stack spacing={2} sx={{ maxWidth: 680 }}>
      <Box>
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
            mb: 0.75,
          }}
        >
          {t("cookieDomain.overline", { defaultValue: "Sessions" })}
        </Typography>
        <Typography sx={{ fontSize: 15, fontWeight: 600, letterSpacing: "-0.005em" }}>
          {t("cookieDomain.title", { defaultValue: "Cookie domain" })}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, maxWidth: 620 }}>
          <Trans i18nKey="cookieDomain.description" components={{ code: <code /> }}>
            Per-app override for the session-cookie <code>Domain</code> attribute. When set, this takes precedence over the workspace value - useful if you have apps on different parent domains in the same install.
          </Trans>
        </Typography>
      </Box>

        <Alert severity="info" sx={{ fontSize: 13 }}>
          <strong>{t("cookieDomain.workspaceValueLabel", { defaultValue: "Workspace value:" })}</strong>{" "}
          {wsValue ? (
            <Box component="code" sx={{ fontFamily: "var(--font-mono)", bgcolor: "action.hover", px: 0.5, py: 0.1, borderRadius: 0.5 }}>
              {wsValue}
            </Box>
          ) : (
            <em>{t("cookieDomain.workspaceValueNotSet", { defaultValue: "not set (browser scopes cookies to the exact host)" })}</em>
          )}
          {t("cookieDomain.workspaceValueSuffix", { defaultValue: ". Anything you enter below overrides this for this app only. Leave blank to inherit the workspace value." })}
        </Alert>

        {showSuggestion && (
          <Alert
            severity="warning"
            sx={{ fontSize: 13 }}
            action={
              <Button color="inherit" size="small" onClick={() => setValue(suggestedDomain)}>
                {t("cookieDomain.useSuggestion", { domain: suggestedDomain, defaultValue: "Use {{domain}}" })}
              </Button>
            }
          >
            <Trans
              i18nKey="cookieDomain.suggestionBody"
              values={{ authDomain: app.authDomain, suggested: suggestedDomain, sibling: `staging.${suggestedDomain}` }}
              components={{
                strong: <strong />,
                code: <Box component="code" sx={{ fontFamily: "var(--font-mono)", bgcolor: "action.hover", px: 0.5, py: 0.1, borderRadius: 0.5 }} />,
              }}
            >
              {"<strong>Auth domain is set to <code>{{authDomain}}</code>.</strong> Without a Cookie domain, session cookies are scoped host-only to that subdomain - your API endpoints on <code>{{suggested}}</code> won't see them. Set Cookie domain to <code>{{suggested}}</code> so the cookies ride to both. Note: any sibling subdomain (e.g. <code>{{sibling}}</code>) will also receive the cookie."}
            </Trans>
          </Alert>
        )}

        <TextField
          label={t("cookieDomain.fieldLabel", { defaultValue: "Cookie domain (override)" })}
          placeholder=".thisapp.com"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          fullWidth
          size="small"
          error={looksWrong}
          helperText={
            looksWrong
              ? t("cookieDomain.fieldInvalid", { defaultValue: "Must be a hostname (no spaces or slashes) and typically contain a dot." })
              : t("cookieDomain.fieldHelp", { defaultValue: "Empty = inherit from workspace." })
          }

          disabled={saving}
        />

      <SaveBar dirty={dirty} saving={saving} onSave={save} onDiscard={resetFromApp} disabled={looksWrong} />
    </Stack>
  );
}
