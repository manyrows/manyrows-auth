import * as React from "react";
import { Box, Typography, type SxProps, type Theme } from "@mui/material";

interface Props {
  children: React.ReactNode;
  /**
   * Show a small magenta dot before the label. Used for page-level
   * eyebrows that sit above a serif title (PageHeader uses this).
   */
  dot?: boolean;
  /**
   * Extra sx overrides (mb, mt, ml, minWidth, etc.). Merged on top of
   * the base eyebrow style so layout tweaks per call-site stay local.
   */
  sx?: SxProps<Theme>;
}

// Eyebrow renders the editorial mono-uppercase section label used
// across the admin: 10px Geist Mono, weight 500, 0.14em tracking,
// text.disabled. Pass `dot` for the page-level variant with a magenta
// dot prefix; otherwise it's a plain inline-block label.
export default function Eyebrow({ children, dot, sx }: Props) {
  return (
    <Typography
      sx={[
        {
          display: dot ? "inline-flex" : "block",
          alignItems: "center",
          gap: dot ? 1 : 0,
          fontFamily: "var(--font-mono)",
          textTransform: "uppercase",
          letterSpacing: "0.14em",
          fontSize: 10,
          fontWeight: 500,
          color: "text.disabled",
        },
        ...(Array.isArray(sx) ? sx : [sx]),
      ]}
    >
      {dot && (
        <Box
          component="span"
          sx={{ width: 4, height: 4, borderRadius: "50%", bgcolor: "primary.main", flexShrink: 0 }}
        />
      )}
      {children}
    </Typography>
  );
}
