import { createTheme } from "@mui/material/styles";
import type { Shadows } from "@mui/material/styles";

function getTheme() {
  // Adaptive design tokens - light mode only
  const ink = "13, 10, 8"; // RGB triplet for rgba()
  const brand = "160, 53, 181"; // #A035B5 - vivid magenta

  // Surfaces: very light off-white background, true white paper, so cards lift
  const bgDefault = "#FAFAF8";
  const bgPaper = "#FFFFFF";
  const bgSubtle = "#F2F2F0";

  return createTheme({
    shape: { borderRadius: 8 },

    // Keep it flat
    shadows: Array(25).fill("none") as Shadows,

    palette: {
      mode: "light",
      primary: {
        main: "#A035B5",
        dark: "#7F2B91",
        light: "#C26EDC",
        contrastText: "#FFFFFF",
      },
      secondary: {
        main: "#D96F3A",
        dark: "#B0521F",
        light: "#E89B6E",
        contrastText: "#FFFFFF",
      },
      text: {
        primary: "#0D0A08",
        secondary: "#4A443D",
        disabled: "#8A8278",
      },
      divider: `rgba(${ink}, 0.05)`,
      background: {
        default: bgDefault,
        paper: bgPaper,
      },
      success: { main: "#3F8B3A", dark: "#2E6929", light: "#6BAF66" },
      warning: { main: "#C97A1A", dark: "#9C5C0E", light: "#E1A158" },
      error: { main: "#C0392B", dark: "#922F22", light: "#D66659" },
      info: { main: "#2563EB", dark: "#1D4ED8", light: "#60A5FA" },
      action: {
        // Neutral hover/selected - admin chrome should feel calm, not always-purple
        hover: `rgba(${ink}, 0.04)`,
        selected: `rgba(${ink}, 0.06)`,
        disabled: `rgba(${ink}, 0.30)`,
        disabledBackground: `rgba(${ink}, 0.05)`,
        focus: `rgba(${brand}, 0.16)`,
      },
    },

    typography: {
      fontSize: 13,
      fontFamily: [
        "Geist",
        "Inter Tight",
        "Inter",
        "ui-sans-serif",
        "system-ui",
        "-apple-system",
        "Segoe UI",
        "Roboto",
        "Helvetica",
        "Arial",
        "Apple Color Emoji",
        "Segoe UI Emoji",
      ].join(","),

      h1: { fontWeight: 700, letterSpacing: "-0.02em", fontSize: "2.4rem", lineHeight: 1.1 },
      h2: { fontWeight: 700, letterSpacing: "-0.02em", fontSize: "1.9rem", lineHeight: 1.15 },
      h3: { fontWeight: 650, letterSpacing: "-0.015em", fontSize: "1.5rem", lineHeight: 1.2 },
      h4: { fontWeight: 650, letterSpacing: "-0.01em", fontSize: "1.25rem", lineHeight: 1.25 },
      h5: { fontWeight: 600, letterSpacing: "-0.005em", fontSize: "1.05rem", lineHeight: 1.3 },
      h6: { fontWeight: 600, letterSpacing: "-0.005em", fontSize: "0.95rem", lineHeight: 1.35 },
      subtitle1: { fontWeight: 500 },
      subtitle2: { fontWeight: 500 },
      body1: { fontWeight: 400 },
      body2: { fontWeight: 400 },
      button: { textTransform: "none", fontWeight: 600, letterSpacing: 0 },
      caption: { fontWeight: 400, color: "#8A8278" },
      overline: { fontWeight: 600, letterSpacing: "0.12em", fontSize: 11 },
    },

    components: {
      MuiCssBaseline: {
        styleOverrides: {
          html: { WebkitFontSmoothing: "antialiased", MozOsxFontSmoothing: "grayscale" },
          body: {
            backgroundColor: bgDefault,
            fontFeatureSettings: '"ss01", "cv11"',
            // Font-family custom properties for places that want serif
            // display or mono via sx={{ fontFamily: "var(--font-serif)" }}.
            // The Typography defaults stay on the sans (Geist) stack.
            "--font-sans": 'Geist, "Inter Tight", Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
            "--font-serif": 'Fraunces, "Iowan Old Style", Georgia, serif',
            "--font-mono": '"Geist Mono", "JetBrains Mono", ui-monospace, Menlo, monospace',
          },
          // tabular-nums for numeric content
          "code, kbd, samp, pre, .mono, .tnum, table td, table th": {
            fontVariantNumeric: "tabular-nums",
          },
          "*::selection": { background: `rgba(${brand}, 0.18)` },
        },
      },

      MuiButtonBase: {
        defaultProps: { disableRipple: true },
      },

      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: "none",
            boxShadow: "none",
            border: `1px solid rgba(${ink}, 0.08)`,
          },
          rounded: { borderRadius: 12 },
        },
      },

      MuiCard: {
        styleOverrides: {
          root: {
            boxShadow: "none",
            borderRadius: 12,
            border: `1px solid rgba(${ink}, 0.08)`,
            transition: "border-color 160ms ease, transform 160ms ease",
            "&:hover": {
              borderColor: `rgba(${ink}, 0.18)`,
            },
          },
        },
      },

      MuiButton: {
        defaultProps: { disableElevation: true },
        styleOverrides: {
          root: {
            borderRadius: 8,
            paddingLeft: 14,
            paddingRight: 14,
            fontWeight: 600,
            boxShadow: "none",
            minHeight: 32,
            "&:focus-visible": {
              outline: `2px solid rgba(${brand}, 0.35)`,
              outlineOffset: 2,
            },
            "&.Mui-disabled": {
              color: `rgba(${ink}, 0.35)`,
            },
          },
          contained: {
            boxShadow: "none",
            "&:hover": { boxShadow: "none", backgroundColor: `rgba(${brand}, 0.92)` },
            "&:active": { boxShadow: "none" },
          },
          containedPrimary: {
            backgroundColor: "#0D0A08",
            color: "#FAFAF8",
            "&:hover": {
              backgroundColor: "#A035B5",
              color: "#FFFFFF",
            },
          },
          outlined: {
            borderColor: `rgba(${ink}, 0.20)`,
            color: "#0D0A08",
            "&:hover": {
              borderColor: `rgba(${ink}, 0.45)`,
              backgroundColor: `rgba(${ink}, 0.03)`,
            },
          },
          text: {
            color: "#0D0A08",
            "&:hover": { backgroundColor: `rgba(${ink}, 0.05)` },
          },
        },
      },

      MuiChip: {
        styleOverrides: {
          root: {
            borderRadius: 999,
            fontWeight: 600,
            height: 22,
            fontSize: 11,
            letterSpacing: "0.01em",
          },
          outlined: {
            borderColor: `rgba(${ink}, 0.18)`,
          },
          filled: {
            backgroundColor: `rgba(${ink}, 0.06)`,
            color: "#0D0A08",
          },
        },
      },

      MuiTextField: {
        defaultProps: { size: "small" },
      },
      MuiFormControl: {
        defaultProps: { size: "small" },
      },

      MuiDialog: {
        styleOverrides: {
          paper: {
            boxShadow: "none",
            border: `1px solid rgba(${ink}, 0.10)`,
            borderRadius: 14,
            backgroundColor: bgPaper,
          },
        },
      },

      MuiDialogTitle: {
        styleOverrides: {
          root: {
            // Dialog titles use the editorial serif so they feel
            // weighted but still calm - pairs with the Geist body
            // copy beneath.
            fontFamily: '"Fraunces", "Iowan Old Style", Georgia, serif',
            fontWeight: 500,
            fontSize: 22,
            letterSpacing: "-0.02em",
            lineHeight: 1.2,
            paddingTop: 20,
            paddingBottom: 10,
            fontOpticalSizing: "auto",
          },
        },
      },

      MuiMenu: {
        styleOverrides: {
          paper: {
            boxShadow: "none",
            border: `1px solid rgba(${ink}, 0.10)`,
            borderRadius: 10,
          },
          list: {
            paddingTop: 6,
            paddingBottom: 6,
          },
        },
      },

      MuiPopover: {
        styleOverrides: {
          paper: {
            boxShadow: "none",
            border: `1px solid rgba(${ink}, 0.10)`,
            borderRadius: 10,
          },
        },
      },

      MuiMenuItem: {
        styleOverrides: {
          root: {
            borderRadius: 6,
            marginLeft: 4,
            marginRight: 4,
            "&.Mui-selected": {
              backgroundColor: `rgba(${ink}, 0.06)`,
            },
            "&.Mui-selected:hover": {
              backgroundColor: `rgba(${ink}, 0.08)`,
            },
          },
        },
      },

      MuiListItemButton: {
        styleOverrides: {
          root: {
            borderRadius: 6,
            paddingTop: 5,
            paddingBottom: 5,
            position: "relative",
            transition: "background-color 120ms ease, color 120ms ease",
            "&.Mui-selected": {
              backgroundColor: `rgba(${ink}, 0.05)`,
              color: "#0D0A08",
              fontWeight: 600,
            },
            "&.Mui-selected::before": {
              content: '""',
              position: "absolute",
              left: -2,
              top: 6,
              bottom: 6,
              width: 2,
              borderRadius: 2,
              backgroundColor: "#A035B5",
            },
            "&.Mui-selected:hover": {
              backgroundColor: `rgba(${ink}, 0.07)`,
            },
            "&.Mui-selected .MuiListItemText-primary": {
              fontWeight: 600,
            },
            "&.Mui-selected .MuiListItemIcon-root": {
              color: "#A035B5",
            },
          },
        },
      },

      MuiTooltip: {
        styleOverrides: {
          tooltip: {
            borderRadius: 6,
            fontSize: 11.5,
            fontWeight: 500,
            padding: "6px 9px",
            backgroundColor: "rgba(13,10,8,0.92)",
            color: "#FAFAF8",
          },
          arrow: {
            color: "rgba(13,10,8,0.92)",
          },
        },
      },

      MuiAlert: {
        styleOverrides: {
          root: {
            borderRadius: 8,
            marginBottom: 10,
            border: `1px solid rgba(${ink}, 0.10)`,
            boxShadow: "none",
            "& .MuiAlert-icon": { fontSize: 18, marginRight: 10 },
            "& .MuiAlert-message": { fontSize: 13.5, padding: "6px 0", fontWeight: 400 },
          },
          standardInfo: {
            backgroundColor: "rgba(37,99,235,0.06)",
            color: "#0D0A08",
            "& .MuiAlert-icon": { color: "#2563EB" },
          },
          standardSuccess: {
            backgroundColor: "rgba(63,139,58,0.08)",
            color: "#0D0A08",
            "& .MuiAlert-icon": { color: "#3F8B3A" },
          },
          standardWarning: {
            backgroundColor: "rgba(201,122,26,0.10)",
            color: "#0D0A08",
            "& .MuiAlert-icon": { color: "#C97A1A" },
          },
          standardError: {
            backgroundColor: "rgba(192,57,43,0.08)",
            color: "#0D0A08",
            "& .MuiAlert-icon": { color: "#C0392B" },
          },
        },
      },

      MuiToolbar: {
        styleOverrides: {
          dense: { height: 48, minHeight: 48 },
        },
      },

      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            borderRadius: 8,
            backgroundColor: bgPaper,
            transition: "background-color 120ms ease, border-color 120ms ease",
            "&:hover .MuiOutlinedInput-notchedOutline": {
              borderColor: `rgba(${ink}, 0.30)`,
            },
            "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
              borderColor: "#A035B5",
              borderWidth: 1.5,
            },
            "&.Mui-focused": { boxShadow: "none" },
            "&.Mui-disabled": {
              backgroundColor: `rgba(${ink}, 0.03)`,
            },
            "&.Mui-disabled .MuiOutlinedInput-notchedOutline": {
              borderColor: `rgba(${ink}, 0.10)`,
            },
          },
          notchedOutline: { borderColor: `rgba(${ink}, 0.16)` },
          input: {
            paddingTop: 8,
            paddingBottom: 8,
          },
        },
      },

      MuiInputLabel: {
        styleOverrides: {
          root: {
            fontWeight: 500,
            color: "#4A443D",
            "&.Mui-focused": { color: "#A035B5" },
          },
        },
      },

      MuiIconButton: {
        styleOverrides: {
          root: {
            borderRadius: 8,
            "&:focus-visible": {
              outline: `2px solid rgba(${brand}, 0.35)`,
              outlineOffset: 2,
            },
            "&:hover": {
              backgroundColor: `rgba(${ink}, 0.05)`,
            },
          },
        },
      },

      MuiTableHead: {
        styleOverrides: {
          root: {
            "& .MuiTableCell-root": {
              fontFamily:
                '"Geist Mono", "JetBrains Mono", ui-monospace, Menlo, monospace',
              fontWeight: 500,
              fontSize: 10.5,
              letterSpacing: "0.14em",
              textTransform: "uppercase",
              color: "#8A8278",
              backgroundColor: bgSubtle,
              borderBottom: `1px solid rgba(${ink}, 0.10)`,
              paddingTop: 9,
              paddingBottom: 9,
            },
          },
        },
      },

      MuiTableCell: {
        styleOverrides: {
          root: {
            borderBottom: `1px solid rgba(${ink}, 0.06)`,
            fontVariantNumeric: "tabular-nums",
          },
          sizeSmall: {
            paddingTop: 9,
            paddingBottom: 9,
          },
        },
      },

      MuiTableRow: {
        styleOverrides: {
          root: {
            transition: "background-color 80ms ease",
            "&:hover td": {
              backgroundColor: `rgba(${ink}, 0.025)`,
            },
            "&:last-of-type td": {
              borderBottom: 0,
            },
          },
        },
      },

      MuiDivider: {
        styleOverrides: {
          root: { borderColor: `rgba(${ink}, 0.08)` },
        },
      },

      MuiTabs: {
        styleOverrides: {
          root: {
            minHeight: 40,
            borderBottom: `1px solid rgba(${ink}, 0.08)`,
          },
          indicator: {
            backgroundColor: "#A035B5",
            height: 2,
            borderRadius: "2px 2px 0 0",
          },
        },
      },

      MuiTab: {
        styleOverrides: {
          root: {
            // Tabs read as navigation, not captions: readable sans
            // sentence-case (the mono/uppercase eyebrow vocabulary is
            // reserved for static labels), with a 2px brand underline
            // marking the active pane.
            fontFamily: "var(--font-sans)",
            textTransform: "none",
            letterSpacing: 0,
            fontWeight: 500,
            fontSize: 13,
            minHeight: 40,
            minWidth: 0,
            paddingLeft: 14,
            paddingRight: 14,
            color: "#4A443D",
            borderRadius: "6px 6px 0 0",
            transition: "color 120ms ease, background-color 120ms ease",
            "&:hover": {
              color: "#0D0A08",
              backgroundColor: `rgba(${ink}, 0.04)`,
            },
            "&.Mui-selected": {
              color: "#0D0A08",
              fontWeight: 600,
            },
            "&.Mui-focusVisible": {
              outline: `2px solid rgba(${brand}, 0.35)`,
              outlineOffset: -2,
              borderRadius: 4,
            },
          },
        },
      },

      MuiSwitch: {
        styleOverrides: {
          root: {
            "& .MuiSwitch-track": {
              backgroundColor: `rgba(${ink}, 0.20)`,
              opacity: 1,
            },
            "& .Mui-checked + .MuiSwitch-track": {
              backgroundColor: "#A035B5 !important",
              opacity: "1 !important",
            },
          },
        },
      },

      MuiLinearProgress: {
        styleOverrides: {
          root: {
            borderRadius: 999,
            backgroundColor: `rgba(${ink}, 0.06)`,
          },
          bar: {
            backgroundColor: "#A035B5",
          },
        },
      },
    },
  });
}

export const theme = getTheme();
