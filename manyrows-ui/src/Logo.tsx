import type React from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import Box from "@mui/material/Box";
import Typography from "@mui/material/Typography";

/** Visual logo mark - no routing dependency, safe for auth pages. */
export const LogoMark: React.FC = () => {
  return (
    <Box sx={{ display: "inline-flex", alignItems: "center" }}>
      <Typography
        noWrap
        component="span"
        sx={{
          ml: 0.25,
          fontSize: 15,
          fontFamily: "monospace",
          fontWeight: 600,
          color: "text.primary",
          textDecoration: "none",
        }}
      >
        ManyRows{" "}
        <Box component="span" sx={{ color: "primary.main" }}>
          Auth
        </Box>
      </Typography>
    </Box>
  );
};

export const Logo: React.FC = () => {
  const nav = useNavigate();
  const { t } = useTranslation();

  const clickLogo = (ev?: React.MouseEvent<unknown>) => {
    if (ev) {
      ev.preventDefault();
      ev.stopPropagation();
    }
    nav("/app");
  };

  // <button> with reset styles instead of <Box onClick> - keyboard
  // users get Space/Enter activation and screen readers announce it as
  // a button. The MUI Box wrapper had a click handler with no a11y
  // affordance.
  return (
    <Box
      component="button"
      type="button"
      onClick={clickLogo}
      aria-label={t("nav.home")}
      sx={{
        cursor: "pointer",
        background: "none",
        border: "none",
        padding: 0,
        font: "inherit",
        color: "inherit",
      }}
    >
      <LogoMark />
    </Box>
  );
};
