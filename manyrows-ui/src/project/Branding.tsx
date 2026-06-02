import * as React from "react";
import { useTranslation } from "react-i18next";
import type { Project, Workspace } from "../core.ts";
import { Box, Button, Chip, Paper, Stack, Typography } from "@mui/material";
import PageHeader from "../components/PageHeader.tsx";
import { Palette, Sparkles, Check, Mail } from "lucide-react";

const SUPPORT_EMAIL = "support@manyrows.com";

interface Props {
  project: Project;
  workspace?: Workspace;
}

// Branding is a premium feature. The branded-theme system itself is not
// built yet, so this page is the upsell + concierge entry point: it tells
// the customer what custom branding covers and opens a pre-filled email so
// we can build the theme for them. See memory note
// "branding-customization-paid-deferred".
export default function Branding({ project }: Props) {
  const { t } = useTranslation();

  const features = [
    t("branding.feature.logo", { defaultValue: "Custom logo and favicon" }),
    t("branding.feature.colors", { defaultValue: "Brand colors and dark-mode palette" }),
    t("branding.feature.typography", { defaultValue: "Typography, spacing, and corner radius" }),
    t("branding.feature.removeBranding", { defaultValue: "Remove “Powered by ManyRows”" }),
    t("branding.feature.css", { defaultValue: "Custom CSS for a pixel-perfect match" }),
  ];

  const mailtoHref = React.useMemo(() => {
    const subject = t("branding.mailSubject", {
      defaultValue: "Branding request — {{project}}",
      project: project.name,
    });
    const body = t("branding.mailBody", {
      defaultValue:
        "Hi ManyRows team,\n\nWe'd like to brand our sign-in experience for \"{{project}}\". Here's what we have in mind:\n\n- Brand colors:\n- Logo (attach or link):\n- Fonts:\n- Anything else:\n\nThanks!",
      project: project.name,
    });
    return `mailto:${SUPPORT_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  }, [project.name, t]);

  return (
    <Box>
      <PageHeader
        title={t("branding.title", { defaultValue: "Branding" })}
        subtitle={t("branding.subtitle", {
          defaultValue:
            "Make the hosted sign-in, sign-up, and account screens look like your own project.",
        })}
        action={
          <Chip
            size="small"
            icon={<Sparkles size={12} strokeWidth={2} />}
            label={t("branding.premium", { defaultValue: "Premium" })}
            sx={{
              height: 24,
              fontSize: 10.5,
              fontWeight: 600,
              letterSpacing: "0.08em",
              fontFamily: "var(--font-mono)",
              textTransform: "uppercase",
              bgcolor: "transparent",
              color: "primary.main",
              border: "1px solid",
              borderColor: "primary.main",
              "& .MuiChip-icon": { color: "primary.main", ml: 0.75 },
            }}
          />
        }
      />

      <Paper
        variant="outlined"
        sx={{ borderRadius: 2, p: { xs: 3, sm: 4 }, maxWidth: 720 }}
      >
        <Stack spacing={2.5}>
          <Stack direction="row" spacing={2} alignItems="flex-start">
            <Box
              sx={{
                width: 40,
                height: 40,
                borderRadius: 1.5,
                display: "grid",
                placeItems: "center",
                color: "primary.main",
                border: "1px solid",
                borderColor: "divider",
                bgcolor: "background.paper",
                flexShrink: 0,
              }}
            >
              <Palette size={20} strokeWidth={1.75} />
            </Box>
            <Box sx={{ minWidth: 0 }}>
              <Typography
                sx={{
                  fontFamily: "var(--font-serif)",
                  fontSize: 20,
                  fontWeight: 500,
                  letterSpacing: "-0.02em",
                  lineHeight: 1.3,
                  fontOpticalSizing: "auto",
                }}
              >
                {t("branding.heroTitle", {
                  defaultValue: "Custom branding, built for you",
                })}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.75, maxWidth: 520 }}>
                {t("branding.heroBody", {
                  defaultValue:
                    "Tell us how you want your auth experience to look and we'll build a branded theme for your apps. It's a premium feature — reach out and we'll take it from there.",
                })}
              </Typography>
            </Box>
          </Stack>

          <Stack component="ul" spacing={1} sx={{ listStyle: "none", m: 0, p: 0 }}>
            {features.map((f) => (
              <Stack key={f} component="li" direction="row" spacing={1.25} alignItems="center">
                <Box component="span" sx={{ display: "inline-flex", color: "primary.main", flexShrink: 0 }}>
                  <Check size={15} strokeWidth={2.25} />
                </Box>
                <Typography variant="body2" sx={{ color: "text.primary" }}>
                  {f}
                </Typography>
              </Stack>
            ))}
          </Stack>

          <Box>
            <Button
              variant="contained"
              href={mailtoHref}
              startIcon={<Mail size={15} strokeWidth={1.75} />}
              disableElevation
              sx={{ borderRadius: 2, textTransform: "none", fontWeight: 600 }}
            >
              {t("branding.contactCta", { defaultValue: "Contact us about branding" })}
            </Button>
            <Typography variant="caption" color="text.disabled" sx={{ display: "block", mt: 1.25 }}>
              {t("branding.contactHint", {
                defaultValue: "Opens an email to {{email}} with your project details prefilled.",
                email: SUPPORT_EMAIL,
              })}
            </Typography>
          </Box>
        </Stack>
      </Paper>
    </Box>
  );
}
