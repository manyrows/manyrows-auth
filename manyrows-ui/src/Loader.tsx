import { Box, CircularProgress, Typography } from "@mui/material";
import { useTranslation } from "react-i18next";

export default function Loader() {
  const { t } = useTranslation();
  return (
    <Box
      sx={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 1.5,
        py: 8,
        color: "text.disabled",
      }}
    >
      <CircularProgress size={20} thickness={3} sx={{ color: "primary.main" }} />
      <Typography
        sx={{
          fontFamily: "var(--font-mono)",
          fontSize: 10.5,
          letterSpacing: "0.2em",
          textTransform: "uppercase",
        }}
      >
        {t("common.loadingShort")}
      </Typography>
    </Box>
  );
}
