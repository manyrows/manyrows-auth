import * as React from "react";
import { Box, Paper, Stack, Typography } from "@mui/material";

interface Props {
  /** Optional icon node (e.g. a lucide icon at 20-24px). */
  icon?: React.ReactNode;
  /** Short title, e.g. "No webhooks yet". */
  title: string;
  /** One-line description below the title. */
  description?: React.ReactNode;
  /** Action row - usually a "Create X" button. */
  action?: React.ReactNode;
  /** Override the max-width of the inner content column. */
  maxWidth?: number;
}

// EmptyState replaces the ad-hoc "<Paper textAlign='center' p:4>…"
// blocks scattered across admin pages. Uses a dashed border to read
// as "intentionally empty" rather than "broken card", with the same
// mono+serif vocabulary as the rest of the chrome.
export default function EmptyState({
  icon,
  title,
  description,
  action,
  maxWidth = 420,
}: Props) {
  return (
    <Paper
      variant="outlined"
      sx={{
        borderRadius: 2,
        borderStyle: "dashed",
        borderColor: "divider",
        py: 5,
        px: 3,
        textAlign: "center",
        bgcolor: "transparent",
      }}
    >
      <Stack spacing={1.25} alignItems="center" sx={{ maxWidth, mx: "auto" }}>
        {icon && (
          <Box
            sx={{
              width: 36,
              height: 36,
              borderRadius: 1.5,
              display: "grid",
              placeItems: "center",
              color: "text.disabled",
              border: "1px solid",
              borderColor: "divider",
              bgcolor: "background.paper",
              mb: 0.5,
            }}
          >
            {icon}
          </Box>
        )}
        <Typography
          sx={{
            fontFamily: "var(--font-serif)",
            fontSize: 20,
            fontWeight: 500,
            letterSpacing: "-0.02em",
            lineHeight: 1.2,
            fontOpticalSizing: "auto",
          }}
        >
          {title}
        </Typography>
        {description && (
          <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 360 }}>
            {description}
          </Typography>
        )}
        {action && <Box sx={{ mt: 1 }}>{action}</Box>}
      </Stack>
    </Paper>
  );
}
