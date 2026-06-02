import * as React from "react";
import { Box, Stack, Typography } from "@mui/material";

interface Props {
  /** Page title - rendered in Fraunces serif when a plain string. */
  title: React.ReactNode;
  /** Optional body-copy line below the title (description / explainer). */
  subtitle?: React.ReactNode;
  /** Optional row of meta beneath the title (slugs, chips, status). */
  meta?: React.ReactNode;
  /** Right-aligned action area - buttons, chips, icon buttons. */
  action?: React.ReactNode;
  /** Title size in pixels. Defaults to 28. */
  size?: number;
  /** Bottom margin in MUI spacing units. */
  mb?: number;
}

// PageHeader renders the editorial title block: a Fraunces serif title
// with a magenta rule mark, optional subtitle/meta, and right-aligned
// actions. Centralizes the redesign typography so each page stops
// reinventing its own h1 styling.
export default function PageHeader({
  title,
  subtitle,
  meta,
  action,
  size = 28,
  mb = 3.5,
}: Props) {
  return (
    <Stack
      direction={{ xs: "column", sm: "row" }}
      spacing={{ xs: 1.5, sm: 2 }}
      alignItems={{ xs: "stretch", sm: "flex-end" }}
      justifyContent="space-between"
      sx={{ mb }}
    >
      <Box sx={{ flex: 1, minWidth: 0 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.75, mb: (subtitle || meta) ? 1.25 : 0 }}>
          <Box
            sx={{
              width: 28,
              height: 2,
              bgcolor: "primary.main",
              borderRadius: 1,
              flexShrink: 0,
            }}
          />
          {typeof title === "string" ? (
            <Typography
              sx={{
                fontFamily: "var(--font-serif)",
                fontSize: size,
                fontWeight: 500,
                letterSpacing: "-0.025em",
                lineHeight: 1.2,
                fontOpticalSizing: "auto",
                wordBreak: "break-word",
                pb: "2px",
              }}
            >
              {title}
            </Typography>
          ) : (
            title
          )}
        </Box>

        {subtitle && (
          <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 720, mt: 0.25 }}>
            {subtitle}
          </Typography>
        )}

        {meta && (
          <Stack direction="row" spacing={1.5} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mt: subtitle ? 1.25 : 0 }}>
            {meta}
          </Stack>
        )}
      </Box>

      {action && (
        <Stack
          direction="row"
          spacing={1}
          alignItems="center"
          justifyContent={{ xs: "flex-start", sm: "flex-end" }}
          sx={{ flexShrink: 0 }}
        >
          {action}
        </Stack>
      )}
    </Stack>
  );
}
