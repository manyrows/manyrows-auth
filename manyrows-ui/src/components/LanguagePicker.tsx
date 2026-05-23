import * as React from "react";
import { IconButton, ListItemIcon, ListItemText, Menu, MenuItem, Tooltip } from "@mui/material";
import { Check, Languages } from "lucide-react";
import axios from "axios";
import { useTranslation } from "react-i18next";

// Locales the admin panel ships. Each label is written in its own
// language (the universal convention for a language switcher), so it's
// recognisable regardless of the current UI language. Keep in sync with
// src/i18n/index.ts and the backend SupportedLanguages.
const LANGUAGES: { code: string; label: string }[] = [
  { code: "en", label: "English" },
  { code: "ko", label: "한국어" },
];

interface Props {
  // Persist the choice to the signed-in admin's account so it follows
  // them across devices and drives server-sent emails. Off on the login
  // page, where there's no session yet (locale lives in localStorage).
  persist?: boolean;
}

export default function LanguagePicker({ persist = false }: Props) {
  const { t, i18n } = useTranslation();
  const [anchor, setAnchor] = React.useState<null | HTMLElement>(null);
  const open = Boolean(anchor);

  const current = (i18n.resolvedLanguage || i18n.language || "en").split("-")[0];

  const choose = (code: string) => {
    setAnchor(null);
    if (code === current) return;
    void i18n.changeLanguage(code);
    if (persist) {
      // Best-effort: the screen is already in the new language, so a
      // failed save only means the choice won't follow the user
      // elsewhere. No need to surface an error for that.
      axios.post("/admin/profile/language", { language: code }).catch(() => {});
    }
  };

  return (
    <>
      <Tooltip title="Language / 언어">
        <IconButton
          onClick={(e) => setAnchor(e.currentTarget)}
          size="small"
          aria-label={t("common.changeLanguage")}
          aria-haspopup="true"
          aria-expanded={open ? "true" : undefined}
          sx={{
            color: "text.secondary",
            width: 30,
            height: 30,
            "&:hover": { color: "text.primary", bgcolor: "action.hover" },
            ...(open ? { bgcolor: "action.selected" } : null),
          }}
        >
          <Languages size={16} strokeWidth={1.75} />
        </IconButton>
      </Tooltip>
      <Menu
        anchorEl={anchor}
        open={open}
        onClose={() => setAnchor(null)}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        transformOrigin={{ vertical: "top", horizontal: "right" }}
        PaperProps={{
          elevation: 0,
          sx: { mt: 0.5, minWidth: 160, border: "1px solid", borderColor: "divider" },
        }}
      >
        {LANGUAGES.map((l) => (
          <MenuItem key={l.code} selected={l.code === current} onClick={() => choose(l.code)}>
            <ListItemIcon sx={{ minWidth: 28, color: "primary.main" }}>
              {l.code === current ? <Check size={14} strokeWidth={2.5} /> : null}
            </ListItemIcon>
            <ListItemText primaryTypographyProps={{ fontSize: 14 }}>{l.label}</ListItemText>
          </MenuItem>
        ))}
      </Menu>
    </>
  );
}
