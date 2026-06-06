import { Box, Button, Typography } from "@mui/material";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";

export default function NotFound() {
  const navigate = useNavigate();
  const { t } = useTranslation();

  return (
    <Box sx={{ textAlign: "center", py: 12, px: 2, maxWidth: 480, mx: "auto" }}>
      <Typography
        sx={{
          fontFamily: "var(--font-sans)",
          fontSize: 96,
          fontWeight: 500,
          letterSpacing: "-0.04em",
          lineHeight: 1,
          color: "text.primary",
        }}
      >
        404
      </Typography>
      <Typography
        sx={{
          fontFamily: "var(--font-sans)",
          fontSize: 24,
          fontWeight: 500,
          letterSpacing: "-0.02em",
          mt: 3,
          fontOpticalSizing: "auto",
        }}
      >
        {t("notFound.title")}
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mt: 1.5 }}>
        {t("notFound.description")}
      </Typography>
      <Button
        variant="contained"
        onClick={() => navigate("/app")}
        sx={{ mt: 4, borderRadius: 2, textTransform: "none" }}
      >
        {t("notFound.goHome")}
      </Button>
    </Box>
  );
}
