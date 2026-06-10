import * as React from "react";
import axios from "axios";
import {
  Alert,
  Box,
  FormControlLabel,
  MenuItem,
  Slider,
  Stack,
  Switch,
  TextField,
  Typography,
} from "@mui/material";
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

export default function AppPasswordPolicyCard({ app, cardURL, onSaved, onSuccess, onError }: Props) {
  const { t } = useTranslation();

  // Labels for the zxcvbn 0..4 score axis. Pulled from the library's own
  // docs - the same wording the strength meter shows the end user.
  const SCORE_LABELS = [
    { value: 0, label: t("passwordPolicy.score0", { defaultValue: "0 - Anything goes" }) },
    { value: 1, label: t("passwordPolicy.score1", { defaultValue: "1 - Reject obvious passwords" }) },
    { value: 2, label: t("passwordPolicy.score2", { defaultValue: "2 - Safe-ish (recommended)" }) },
    { value: 3, label: t("passwordPolicy.score3", { defaultValue: "3 - Strong" }) },
    { value: 4, label: t("passwordPolicy.score4", { defaultValue: "4 - Very strong" }) },
  ];

  const [minLength, setMinLength] = React.useState<number>(app.passwordMinLength);
  const [minScore, setMinScore] = React.useState<number>(app.passwordMinZxcvbnScore);
  const [reusePrevention, setReusePrevention] = React.useState<boolean>(app.passwordReusePrevention);
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    setMinLength(app.passwordMinLength);
    setMinScore(app.passwordMinZxcvbnScore);
    setReusePrevention(app.passwordReusePrevention);
  }, [app.passwordMinLength, app.passwordMinZxcvbnScore, app.passwordReusePrevention]);

  const dirty =
    minLength !== app.passwordMinLength ||
    minScore !== app.passwordMinZxcvbnScore ||
    reusePrevention !== app.passwordReusePrevention;

  const resetFromApp = React.useCallback(() => {
    setMinLength(app.passwordMinLength);
    setMinScore(app.passwordMinZxcvbnScore);
    setReusePrevention(app.passwordReusePrevention);
  }, [app.passwordMinLength, app.passwordMinZxcvbnScore, app.passwordReusePrevention]);

  async function save() {
    setSaving(true);
    try {
      const res = await axios.put<App>(`${cardURL}/password-policy`, {
        passwordMinLength: minLength,
        passwordMinZxcvbnScore: minScore,
        passwordReusePrevention: reusePrevention,
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
    <Stack spacing={3} sx={{ maxWidth: 680 }}>
      <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 620 }}>
        {t("passwordPolicy.intro", { defaultValue: "Applied when users set or reset a password. Existing passwords aren't re-checked - the policy only gates new ones." })}
      </Typography>

        <Alert severity="info" sx={{ fontSize: 13 }}>
          {t("passwordPolicy.zxcvbnInfo", { defaultValue: "We don't expose the deprecated \"must contain uppercase / digit / symbol\" knobs. Strength is scored with zxcvbn, which catches dictionary words, keyboard patterns, and personal-info reuse - the categories that actually fall to attacks." })}
        </Alert>

        <Box>
          <Stack direction="row" alignItems="baseline" justifyContent="space-between" sx={{ mb: 1 }}>
            <Eyebrow>{t("passwordPolicy.minLength", { defaultValue: "Minimum length" })}</Eyebrow>
            <Typography sx={{ fontFamily: "var(--font-mono)", fontSize: 13, fontWeight: 500 }}>
              {t("passwordPolicy.charactersCount", { count: minLength, defaultValue: "{{count}} characters" })}
            </Typography>
          </Stack>
          <Box sx={{ px: 1, pb: 3 }}>
            <Slider
              value={minLength}
              onChange={(_, v) => setMinLength(typeof v === "number" ? v : v[0])}
              min={8}
              max={64}
              step={1}
              marks={[
                { value: 8, label: "8" },
                { value: 12, label: "12" },
                { value: 16, label: "16" },
                { value: 32, label: "32" },
                { value: 64, label: "64" },
              ]}
              valueLabelDisplay="auto"
            />
          </Box>
          <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
            {t("passwordPolicy.minLengthHelp", { defaultValue: "NIST recommends a floor of 8. 12+ is stronger and still survivable for memorisation; 16+ assumes a password manager." })}
          </Typography>
        </Box>

        <Box>
          <Eyebrow sx={{ mb: 1 }}>{t("passwordPolicy.minScore", { defaultValue: "Minimum strength score (zxcvbn)" })}</Eyebrow>
          <TextField
            select
            value={minScore}
            onChange={(e) => setMinScore(Number(e.target.value))}
            size="small"
            fullWidth
          >
            {SCORE_LABELS.map((s) => (
              <MenuItem key={s.value} value={s.value}>{s.label}</MenuItem>
            ))}
          </TextField>
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
            {t("passwordPolicy.minScoreHelp", { defaultValue: "Score 2 rejects \"password123\", \"qwerty\", and trivial substitutions. Score 3+ starts blocking many human-memorable passwords - pair with a password-manager-only audience." })}
          </Typography>
        </Box>

        <Box>
          <FormControlLabel
            control={
              <Switch
                checked={reusePrevention}
                onChange={(e) => setReusePrevention(e.target.checked)}
              />
            }
            label={t("passwordPolicy.reuseToggle", { defaultValue: "Prevent password reuse" })}
          />
          <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
            {t("passwordPolicy.reuseHint", { defaultValue: "Blocks the 5 most recently used passwords when users set or reset a password." })}
          </Typography>
        </Box>

      <SaveBar dirty={dirty} saving={saving} onSave={save} onDiscard={resetFromApp} />
    </Stack>
  );
}
