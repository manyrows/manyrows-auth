import * as React from "react";
import type { Workspace } from "./core.ts";
import {
  Avatar,
  Box,
  Card,
  CardActionArea,
  CardContent,
  Stack,
  Typography,
} from "@mui/material";
import { Building2, ChevronRight } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useApp } from "./App.tsx";

function initials(nameOrSlug: string) {
  const s = (nameOrSlug || "?").trim();
  if (!s) return "?";
  const parts = s.split(/[ _.-]+/).filter(Boolean);
  const a = parts[0]?.[0] ?? s[0] ?? "?";
  const b = parts[1]?.[0] ?? "";
  return (a + b).toUpperCase();
}

export default function Home() {
  const { t } = useTranslation();
  const app = useApp();
  const navigate = useNavigate();

  const workspaces = app.appData.workspaces ?? [];

  // Self-hosted runs with a single auto-created workspace; the home
  // page redirects straight into it so the operator never sees an
  // empty picker.
  const willRedirectToSoloWorkspace = workspaces.length > 0;
  React.useEffect(() => {
    if (willRedirectToSoloWorkspace) {
      navigate(`/app/workspace/${workspaces[0].id}`, { replace: true });
    }
  }, [willRedirectToSoloWorkspace, workspaces, navigate]);

  // Suppress the picker render during the redirect window - useEffect
  // fires after the first paint, so without this guard the picker
  // flashes for one frame before the navigate kicks in.
  if (willRedirectToSoloWorkspace) {
    return null;
  }

  const openWorkspace = (ws: Workspace) => {
    navigate(`/app/workspace/${ws.id}`);
  };

  return (
    <Box sx={{ p: { xs: 2, sm: 3 }, minHeight: "100vh" }}>
      <Stack spacing={4} sx={{ maxWidth: 560, mx: "auto", pt: 6 }}>
        {/* Header */}
        <Box>
          <Typography
            sx={{
              display: "inline-flex",
              alignItems: "center",
              gap: 1,
              color: "text.disabled",
              fontFamily: "var(--font-mono)",
              fontWeight: 500,
              letterSpacing: "0.18em",
              fontSize: 10.5,
              mb: 1.25,
              textTransform: "uppercase",
            }}
          >
            <Box component="span" sx={{ width: 4, height: 4, borderRadius: "50%", bgcolor: "primary.main" }} />
            {workspaces.length > 0 ? t("home.workspaces") : t("wizard.getStarted.title")}
          </Typography>
          <Typography
            sx={{
              fontFamily: "var(--font-serif)",
              fontSize: 44,
              fontWeight: 500,
              letterSpacing: "-0.025em",
              lineHeight: 1.1,
              fontOpticalSizing: "auto",
              mb: 1,
              pb: "2px",
            }}
          >
            {t("home.welcomeBack")}
          </Typography>
          <Typography variant="body1" color="text.secondary">
            {workspaces.length > 0
              ? t("home.selectWorkspace")
              : t("home.createToStart")}
          </Typography>
        </Box>

        {/* Workspaces list */}
        {workspaces.length > 0 ? (
          <Stack spacing={1}>
            {workspaces.map((ws) => (
              <Card
                key={ws.id}
                variant="outlined"
                sx={{
                  borderRadius: 2,
                  transition: "border-color 160ms ease, transform 160ms ease",
                  "&:hover": {
                    borderColor: "primary.main",
                    transform: "translateY(-1px)",
                  },
                }}
              >
                <CardActionArea onClick={() => openWorkspace(ws)}>
                  <CardContent sx={{ p: 2.25 }}>
                    <Stack direction="row" alignItems="center" spacing={2}>
                      <Avatar
                        variant="rounded"
                        sx={{
                          width: 40,
                          height: 40,
                          fontSize: 13,
                          fontWeight: 700,
                          letterSpacing: "0.02em",
                          bgcolor: "primary.main",
                          color: "primary.contrastText",
                          borderRadius: 1.5,
                        }}
                      >
                        {initials(ws.name || ws.slug || "W")}
                      </Avatar>

                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Typography
                          sx={{
                            fontSize: 15,
                            fontWeight: 600,
                            letterSpacing: "-0.005em",
                          }}
                          noWrap
                        >
                          {ws.name}
                        </Typography>
                        <Typography
                          sx={{
                            fontSize: 12,
                            color: "text.secondary",
                            fontFamily: "var(--font-mono)",
                            mt: 0.25,
                          }}
                        >
                          {ws.slug}
                        </Typography>
                      </Box>

                      <Box
                        component="span"
                        sx={{
                          color: "text.disabled",
                          fontSize: 12,
                          transition: "transform 160ms ease, color 160ms ease",
                          ".MuiCardActionArea-root:hover &": {
                            transform: "translateX(2px)",
                            color: "primary.main",
                          },
                        }}
                      >
                        <ChevronRight size={14} strokeWidth={1.75} />
                      </Box>
                    </Stack>
                  </CardContent>
                </CardActionArea>
              </Card>
            ))}
          </Stack>
        ) : (
          /* Empty state */
          <Card
            variant="outlined"
            sx={{
              borderRadius: 3,
              borderStyle: "dashed",
              bgcolor: "action.hover",
            }}
          >
            <CardContent sx={{ py: 6, textAlign: "center" }}>
              <Avatar
                sx={{
                  width: 64,
                  height: 64,
                  mx: "auto",
                  mb: 2,
                  bgcolor: "action.selected",
                }}
              >
                <Box component="span" sx={{ color: "text.secondary" }}><Building2 size={48} strokeWidth={1.75} /></Box>
              </Avatar>
              <Typography sx={{ fontSize: 17, fontWeight: 600, letterSpacing: "-0.005em", mb: 1 }}>
                {t("home.noWorkspaceYet")}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                {t("home.createFirstWorkspace")}
              </Typography>
            </CardContent>
          </Card>
        )}
      </Stack>
    </Box>
  );
}
