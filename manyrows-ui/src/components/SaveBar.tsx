import { Box, Button, CircularProgress, Typography } from "@mui/material";
import { useTranslation } from "react-i18next";

interface Props {
  dirty: boolean;
  saving: boolean;
  onSave: () => void;
  onDiscard: () => void;
  disabled?: boolean;
}

// SaveBar floats at the bottom of the form column. It's always
// rendered so the Save affordance is visible at all times; when the
// form is pristine the bar fades to a muted "All saved" state and
// the buttons disable. position:sticky pins it to the viewport
// bottom while scrolling through a long form.
export default function SaveBar({ dirty, saving, onSave, onDiscard, disabled }: Props) {
  const { t } = useTranslation();
  const active = dirty || saving;
  return (
    <Box
      sx={{
        position: "sticky",
        bottom: 16,
        zIndex: 5,
        mt: 1,
        display: "flex",
        justifyContent: "flex-end",
        pointerEvents: "none",
      }}
    >
      <Box
        sx={{
          pointerEvents: "auto",
          display: "inline-flex",
          alignItems: "center",
          gap: 1,
          height: 44,
          pl: 2,
          pr: 0.75,
          borderRadius: 2.5,
          bgcolor: active ? "text.primary" : "background.paper",
          color: active ? "background.default" : "text.secondary",
          border: active ? "1px solid transparent" : "1px solid",
          borderColor: active ? "transparent" : "divider",
          boxShadow: active
            ? "0 8px 24px -10px rgba(13,10,8,0.28), 0 1px 2px rgba(13,10,8,0.06)"
            : "none",
          transition: "background-color 180ms ease, color 180ms ease, box-shadow 180ms ease, border-color 180ms ease",
        }}
      >
        <Typography sx={{ fontSize: 13, fontWeight: 500, mr: 1 }}>
          {active
            ? t("apps.dialog.unsavedChanges", { defaultValue: "Unsaved changes" })
            : t("apps.dialog.allSaved", { defaultValue: "All changes saved" })}
        </Typography>
        <Button
          onClick={onDiscard}
          disabled={!active || saving}
          size="small"
          sx={{
            color: active ? "rgba(250,250,248,0.7)" : "text.disabled",
            textTransform: "none",
            fontWeight: 600,
            fontSize: 12.5,
            px: 1.25,
            minHeight: 32,
            "&:hover": active
              ? { color: "background.default", bgcolor: "rgba(255,255,255,0.08)" }
              : undefined,
            "&.Mui-disabled": { color: active ? "rgba(250,250,248,0.4)" : "text.disabled" },
          }}
        >
          {t("apps.dialog.discard", { defaultValue: "Discard" })}
        </Button>
        <Button
          onClick={onSave}
          disabled={!active || saving || !!disabled}
          size="small"
          disableElevation
          startIcon={saving ? <CircularProgress size={14} sx={{ color: "text.primary" }} /> : null}
          // No MUI variant - full custom styling so the theme's
          // containedPrimary hover (color: #FFFFFF) doesn't blank
          // out the label against this light Save pill.
          sx={{
            bgcolor: active ? "background.default" : "action.hover",
            color: active ? "text.primary" : "text.disabled",
            textTransform: "none",
            fontWeight: 600,
            fontSize: 12.5,
            px: 1.5,
            minHeight: 32,
            border: 0,
            boxShadow: "none",
            "&:hover": {
              bgcolor: active ? "#FFFFFF" : "action.selected",
              color: active ? "text.primary" : "text.disabled",
              boxShadow: "none",
            },
            "&.Mui-disabled": {
              bgcolor: active ? "rgba(255,255,255,0.4)" : "action.hover",
              color: active ? "rgba(13,10,8,0.5)" : "text.disabled",
            },
          }}
        >
          {saving ? t("apps.dialog.saving") : t("apps.dialog.save")}
        </Button>
      </Box>
    </Box>
  );
}
