import * as React from "react";
import axios from "axios";
import { Box, FormControlLabel, Stack, Switch, TextField, Typography } from "@mui/material";
import { useTranslation } from "react-i18next";
import Eyebrow from "../components/Eyebrow.tsx";
import type { App } from "./AppAuthMethods.tsx";
import SaveBar from "../components/SaveBar.tsx";

interface Props {
  app: App;
  cardURL: string;
  onSaved: (a: App) => void;
  onSuccess: () => void;
  onError: (e: unknown) => void;
}

export default function AppConsentCard({ app, cardURL, onSaved, onSuccess, onError }: Props) {
  const { t } = useTranslation();
  const [requireConsent, setRequireConsent] = React.useState<boolean>(app.requireConsent ?? false);
  const [termsUrl, setTermsUrl] = React.useState<string>(app.termsUrl ?? "");
  const [privacyUrl, setPrivacyUrl] = React.useState<string>(app.privacyUrl ?? "");
  const [consentVersion, setConsentVersion] = React.useState<string>(app.consentVersion ?? "");
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    setRequireConsent(app.requireConsent ?? false);
    setTermsUrl(app.termsUrl ?? "");
    setPrivacyUrl(app.privacyUrl ?? "");
    setConsentVersion(app.consentVersion ?? "");
  }, [app.requireConsent, app.termsUrl, app.privacyUrl, app.consentVersion]);

  const dirty =
    requireConsent !== (app.requireConsent ?? false) ||
    termsUrl !== (app.termsUrl ?? "") ||
    privacyUrl !== (app.privacyUrl ?? "") ||
    consentVersion !== (app.consentVersion ?? "");

  const resetFromApp = React.useCallback(() => {
    setRequireConsent(app.requireConsent ?? false);
    setTermsUrl(app.termsUrl ?? "");
    setPrivacyUrl(app.privacyUrl ?? "");
    setConsentVersion(app.consentVersion ?? "");
  }, [app.requireConsent, app.termsUrl, app.privacyUrl, app.consentVersion]);

  async function save() {
    setSaving(true);
    try {
      const res = await axios.put<App>(`${cardURL}/consent-config`, {
        requireConsent,
        termsUrl,
        privacyUrl,
        consentVersion,
      });
      onSaved(res.data);
      onSuccess();
    } catch (e) {
      onError(e);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Box>
      <Eyebrow>{t("consent.eyebrow", { defaultValue: "Legal / consent" })}</Eyebrow>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        {t("consent.intro", { defaultValue: "Require new users to accept your Terms and Privacy Policy at signup. Acceptance is recorded with the policy version and timestamp." })}
      </Typography>
      <Stack spacing={2}>
        <FormControlLabel
          control={<Switch checked={requireConsent} onChange={(e) => setRequireConsent(e.target.checked)} />}
          label={t("consent.requireToggle", { defaultValue: "Require consent at signup" })}
        />
        <TextField
          label={t("consent.termsUrl", { defaultValue: "Terms of Service URL" })}
          value={termsUrl}
          onChange={(e) => setTermsUrl(e.target.value)}
          fullWidth
          size="small"
        />
        <TextField
          label={t("consent.privacyUrl", { defaultValue: "Privacy Policy URL" })}
          value={privacyUrl}
          onChange={(e) => setPrivacyUrl(e.target.value)}
          fullWidth
          size="small"
        />
        <TextField
          label={t("consent.consentVersion", { defaultValue: "Consent version" })}
          helperText={t("consent.versionHint", { defaultValue: "Bump this when your terms change to require re-acceptance (e.g. v1, 2026-06)." })}
          value={consentVersion}
          onChange={(e) => setConsentVersion(e.target.value)}
          fullWidth
          size="small"
        />
      </Stack>
      <SaveBar dirty={dirty} saving={saving} onSave={save} onDiscard={resetFromApp} />
    </Box>
  );
}
