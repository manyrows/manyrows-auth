import * as React from "react";
import axios from "axios";
import { FormControlLabel, Stack, Switch, Typography } from "@mui/material";
import { useTranslation } from "react-i18next";
import type { App } from "./AppAuthMethods.tsx";
import SaveBar from "../components/SaveBar.tsx";

interface Props {
  app: App;
  cardURL: string;
  onSaved: (a: App) => void;
  onSuccess: () => void;
  onError: (e: unknown) => void;
}

export default function AppBruteForceCard({ app, cardURL, onSaved, onSuccess, onError }: Props) {
  const { t } = useTranslation();

  // Default true: protection is on unless the app explicitly disabled it.
  const current = app.bruteForceProtectionEnabled !== false;
  const [enabled, setEnabled] = React.useState(current);
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    setEnabled(app.bruteForceProtectionEnabled !== false);
  }, [app.bruteForceProtectionEnabled]);

  const dirty = enabled !== current;

  const resetFromApp = React.useCallback(() => {
    setEnabled(app.bruteForceProtectionEnabled !== false);
  }, [app.bruteForceProtectionEnabled]);

  async function save() {
    setSaving(true);
    try {
      const res = await axios.put<App>(`${cardURL}/brute-force-protection-config`, { enabled });
      onSaved(res.data);
      onSuccess();
    } catch (e) {
      onError(e);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Stack spacing={3} sx={{ maxWidth: 680 }}>
      <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 620 }}>
        {t("bruteForce.intro", {
          defaultValue:
            "Detects and blocks repeated failed login attempts to prevent unauthorized access through credential guessing. Applies to this app's user sign-in only.",
        })}
      </Typography>

      <FormControlLabel
        control={
          <Switch
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            disabled={saving}
          />
        }
        label={
          <Stack spacing={0}>
            <Typography variant="body2" sx={{ fontWeight: 500 }}>
              {t("bruteForce.enableLabel", { defaultValue: "Brute force protection" })}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {t("bruteForce.enableDesc", {
                defaultValue:
                  "When off, failed-login lockout and login rate limiting are disabled for this app. Other abuse protections (password reset, magic link, email send limits) stay active.",
              })}
            </Typography>
          </Stack>
        }
        sx={{ alignItems: "flex-start", ml: 0 }}
      />

      <SaveBar dirty={dirty} saving={saving} onSave={save} onDiscard={resetFromApp} />
    </Stack>
  );
}
