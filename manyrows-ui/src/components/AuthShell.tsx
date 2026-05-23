import * as React from "react";
import { Box, Typography } from "@mui/material";
import { useTranslation } from "react-i18next";
import { useAdminAuthConfig } from "../hooks/useAdminAuthConfig";

interface Props {
  children: React.ReactNode;
}

// Single-column shell for auth screens. Centred form, logo at the
// top, nothing else - the previous two-panel marketing layout was
// pulled because it leaks SaaS-product framing into self-hosted
// admin consoles where it makes no sense.
//
// Renders the server build version under the form. We pull it from
// the auth-config endpoint (already used by Register/Login) instead
// of /health because the vite dev proxy only forwards /admin and
// /api - /health would 200 with the SPA HTML and parse as "unknown".
export default function AuthShell({ children }: Props) {
  const { t } = useTranslation();
  const authCfg = useAdminAuthConfig();
  const version = authCfg?.version ?? "";

  return (
    <Box
      sx={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        bgcolor: "background.default",
        px: { xs: 3, sm: 5 },
        py: { xs: 5, sm: 6 },
      }}
    >
      <Box sx={{ width: "100%", maxWidth: 420 }}>
        {children}
        {version && (
          <Typography
            variant="caption"
            sx={{
              display: "block",
              textAlign: "center",
              mt: 2.5,
              color: "text.secondary",
              fontFamily: "var(--font-mono)",
              fontSize: 12,
              letterSpacing: "0.04em",
            }}
            title={t("common.serverBuild")}
          >
            ManyRows {version}
          </Typography>
        )}
      </Box>
    </Box>
  );
}
