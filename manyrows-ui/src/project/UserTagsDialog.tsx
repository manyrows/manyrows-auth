import * as React from "react";
import axios from "axios";
import { extractApiError } from "../lib/apiError.ts";
import {
  Alert,
  Autocomplete,
  Button,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { useTranslation } from "react-i18next";

interface Props {
  open: boolean;
  onClose: () => void;
  onSaved: (tags: string[]) => void;
  workspaceId: string;
  projectId: string;
  appId: string;
  userId: string;
  userEmail: string;
  initialTags: string[];
}

interface TagsResponse {
  tags: string[];
}

export default function UserTagsDialog({
  open,
  onClose,
  onSaved,
  workspaceId,
  projectId,
  appId,
  userId,
  userEmail,
  initialTags,
}: Props) {
  const { t } = useTranslation();

  const [value, setValue] = React.useState<string[]>(initialTags);
  const [suggestions, setSuggestions] = React.useState<string[]>([]);
  const [saving, setSaving] = React.useState(false);
  const [err, setErr] = React.useState("");

  // Reset when reopened with a different user.
  React.useEffect(() => {
    if (open) {
      setValue(initialTags);
      setErr("");
    }
  }, [open, initialTags]);

  // Load distinct tags across the app for autocomplete.
  React.useEffect(() => {
    if (!open) return;
    let cancelled = false;
    axios
      .get<TagsResponse>(`/admin/workspace/${workspaceId}/projects/${projectId}/apps/${appId}/tags`)
      .then((res) => {
        if (!cancelled) setSuggestions(res.data?.tags ?? []);
      })
      .catch(() => {
        // Non-fatal - autocomplete just won't suggest.
      });
    return () => {
      cancelled = true;
    };
  }, [open, workspaceId, projectId, appId]);

  const handleSave = async () => {
    setSaving(true);
    setErr("");
    try {
      const res = await axios.put<TagsResponse>(
        `/admin/workspace/${workspaceId}/projects/${projectId}/apps/${appId}/users/${userId}/tags`,
        { tags: value },
      );
      const cleaned = res.data?.tags ?? [];
      onSaved(cleaned);
      onClose();
    } catch (e) {
      setErr(extractApiError(e, t("userTags.saveFailed", { defaultValue: "Failed to save tags" })));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onClose={saving ? undefined : onClose} fullWidth maxWidth="sm">
      <DialogTitle>
        <Stack direction="row" spacing={1} alignItems="baseline">
          <Typography sx={{ fontSize: 17, fontWeight: 600, letterSpacing: "-0.005em" }}>
            {t("userTags.title", { defaultValue: "Tags" })}
          </Typography>
          <Typography variant="body2" color="text.secondary" noWrap title={userEmail}>
            · {userEmail}
          </Typography>
        </Stack>
      </DialogTitle>
      <DialogContent>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {t("userTags.help", {
            defaultValue: "Free-form labels - type to add, click × to remove. Tags are lowercased and trimmed automatically.",
          })}
        </Typography>

        {err && <Alert severity="error" sx={{ mb: 2 }}>{err}</Alert>}

        <Autocomplete
          multiple
          freeSolo
          options={suggestions}
          value={value}
          onChange={(_, next) => {
            // freeSolo can return strings or AutocompleteOption objects; we
            // only ever use strings here.
            setValue((next as string[]).map((s) => s.toLowerCase().trim()).filter(Boolean));
          }}
          renderTags={(tagValue, getTagProps) =>
            tagValue.map((option, index) => {
              const { key, ...rest } = getTagProps({ index });
              return (
                <Chip
                  key={key}
                  size="small"
                  label={option}
                  variant="outlined"
                  {...rest}
                />
              );
            })
          }
          renderInput={(params) => (
            <TextField
              {...params}
              variant="outlined"
              size="small"
              placeholder={t("userTags.addPlaceholder", { defaultValue: "Add tag and press Enter…" })}
            />
          )}
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={saving} color="inherit">
          {t("common.cancel")}
        </Button>
        <Button onClick={handleSave} disabled={saving} variant="contained">
          {saving ? <CircularProgress size={18} /> : t("common.save", { defaultValue: "Save" })}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
