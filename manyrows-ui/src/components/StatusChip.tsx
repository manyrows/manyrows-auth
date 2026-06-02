import * as React from "react";
import { Chip, type SxProps, type Theme } from "@mui/material";

export type ChipSeverity =
  | "neutral"   // text.secondary border + label (default)
  | "muted"     // text.disabled (for "Archived", "0 of N", etc.)
  | "primary"   // brand magenta (e.g. "Coming soon")
  | "success"   // green
  | "warning"   // orange
  | "error"     // red
  | "info";     // blue

interface Props {
  label: React.ReactNode;
  /** Severity coloring for the border + label. Defaults to "neutral". */
  severity?: ChipSeverity;
  /** Uppercase the label (mono caps). Defaults true. Pass false for raw values like "3/5". */
  uppercase?: boolean;
  /** Visual density. "xs" = 18px tall, "sm" = 20px tall (default), "md" = 22px tall. */
  size?: "xs" | "sm" | "md";
  /** Click handler - when set, the chip becomes clickable with hover state. */
  onClick?: () => void;
  /** Optional icon (rendered via MUI Chip's icon slot). */
  icon?: React.ReactElement;
  /** Pass-through sx for per-call layout tweaks (margin, ml: "auto", etc.). */
  sx?: SxProps<Theme>;
}

const severityColor: Record<ChipSeverity, string> = {
  neutral: "text.secondary",
  muted: "text.disabled",
  primary: "primary.main",
  success: "success.main",
  warning: "warning.main",
  error: "error.main",
  info: "info.main",
};

// StatusChip is the editorial status-pill vocabulary used everywhere
// in the admin: outlined chip, Geist Mono, optional uppercase, with
// severity-colored border + label. Replaces the repeated 11-line
// inline sx blocks across the codebase.
export default function StatusChip({
  label,
  severity = "neutral",
  uppercase = true,
  size = "sm",
  onClick,
  icon,
  sx,
}: Props) {
  const height = size === "xs" ? 18 : size === "md" ? 22 : 20;
  const fontSize = size === "xs" ? 9.5 : size === "md" ? 11 : 10;
  const color = severityColor[severity];
  const isSeverityVariant = severity !== "neutral" && severity !== "muted";

  return (
    <Chip
      size="small"
      label={label}
      variant="outlined"
      icon={icon}
      onClick={onClick}
      clickable={!!onClick}
      sx={[
        {
          height,
          fontSize,
          fontFamily: "var(--font-mono)",
          fontWeight: 600,
          letterSpacing: uppercase ? "0.08em" : 0,
          textTransform: uppercase ? "uppercase" : "none",
          color,
          ...(isSeverityVariant && { borderColor: color }),
        },
        ...(Array.isArray(sx) ? sx : [sx]),
      ]}
    />
  );
}
