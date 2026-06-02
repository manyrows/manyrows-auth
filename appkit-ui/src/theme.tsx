import * as React from "react";

// Public client-side theme knobs are intentionally limited to these three.
// Richer branding — fonts, corner radius, card background, custom CSS, and
// white-label (hiding "Powered by ManyRows") — is a paid feature delivered
// server-side via per-app config set in the admin panel and read in on load,
// NOT via this client prop. The free surface is kept deliberately small so
// that shipping the paid branding system later is additive, not a rug-pull.
// (See appHandler.go `hideBranding`, the reserved first paid lever.)
export interface AppKitThemeOptions {
  primaryColor?: string;
  backgroundColor?: string;
  colorMode?: "light" | "dark" | "auto";
}

interface AppKitThemeResolved {
  primaryColor: string;
  mode: "light" | "dark";
  vars: Record<string, string>;
}

function hexToRgb(hex: string): { r: number; g: number; b: number } | null {
  const m = hex.replace("#", "").match(/^([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i);
  if (!m) return null;
  return { r: parseInt(m[1], 16), g: parseInt(m[2], 16), b: parseInt(m[3], 16) };
}

export function resolveTheme(options?: AppKitThemeOptions, systemDark?: boolean): AppKitThemeResolved {
  const primaryColor = options?.primaryColor || "#1976d2";

  let mode: "light" | "dark" = "light";
  if (options?.colorMode === "dark") mode = "dark";
  else if (options?.colorMode === "auto" && systemDark) mode = "dark";

  const rgb = hexToRgb(primaryColor);
  const primaryHover = rgb
    ? `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, 0.08)`
    : "rgba(25, 118, 210, 0.08)";

  const colorVars: Record<string, string> =
    mode === "dark"
      ? {
          "--ak-color-primary": primaryColor,
          "--ak-color-primary-hover": primaryHover,
          "--ak-color-bg": options?.backgroundColor || "#121212",
          "--ak-color-surface": options?.backgroundColor || "#1e1e1e",
          "--ak-color-text": "#e0e0e0",
          "--ak-color-text-secondary": "#aaa",
          "--ak-color-text-disabled": "#666",
          "--ak-color-divider": "#333",
          "--ak-color-action-hover": "rgba(255, 255, 255, 0.08)",

          "--ak-color-error": "#f44336",
          "--ak-color-error-bg": "rgba(244, 67, 54, 0.15)",
          "--ak-color-error-text": "#ffcdd2",

          "--ak-color-success": "#66bb6a",
          "--ak-color-success-bg": "rgba(102, 187, 106, 0.15)",
          "--ak-color-success-text": "#c8e6c9",

          "--ak-color-info": "#29b6f6",
          "--ak-color-info-bg": "rgba(41, 182, 246, 0.15)",
          "--ak-color-info-text": "#b3e5fc",

          "--ak-color-warning": "#ffa726",
          "--ak-color-warning-bg": "rgba(255, 167, 38, 0.15)",
          "--ak-color-warning-text": "#ffe0b2",

          "--ak-color-grey-50": "#1a1a1a",
          "--ak-color-grey-100": "#2a2a2a",
          "--ak-color-grey-500": "#757575",
          "--ak-color-grey-900": "#f5f5f5",
        }
      : {
          "--ak-color-primary": primaryColor,
          "--ak-color-primary-hover": primaryHover,
          "--ak-color-bg": options?.backgroundColor || "#fff",
          "--ak-color-surface": options?.backgroundColor || "#fff",
          "--ak-color-text": "#212121",
          "--ak-color-text-secondary": "#666",
          "--ak-color-text-disabled": "#9e9e9e",
          "--ak-color-divider": "#e0e0e0",
          "--ak-color-action-hover": "rgba(0, 0, 0, 0.04)",

          "--ak-color-error": "#d32f2f",
          "--ak-color-error-bg": "#fdecea",
          "--ak-color-error-text": "#611a15",

          "--ak-color-success": "#2e7d32",
          "--ak-color-success-bg": "#edf7ed",
          "--ak-color-success-text": "#1e4620",

          "--ak-color-info": "#0288d1",
          "--ak-color-info-bg": "#e1f5fe",
          "--ak-color-info-text": "#014361",

          "--ak-color-warning": "#ed6c02",
          "--ak-color-warning-bg": "#fff4e5",
          "--ak-color-warning-text": "#663c00",

          "--ak-color-grey-50": "#fafafa",
          "--ak-color-grey-100": "#f5f5f5",
          "--ak-color-grey-500": "#9e9e9e",
          "--ak-color-grey-900": "#212121",
        };

  // Only primary color, background, and light/dark are host-settable today.
  // Fonts, corner radius, card background, and custom CSS are reserved for the
  // paid server-driven branding system (see AppKitThemeOptions). Card bg falls
  // back to surface via the CSS var(--ak-color-card-bg, var(--ak-color-surface)).
  const vars: Record<string, string> = { ...colorVars };

  return { primaryColor, mode, vars };
}

// Context for components to read theme values
const ThemeContext = React.createContext<AppKitThemeResolved>({
  primaryColor: "#1976d2",
  mode: "light",
  vars: {},
});

export function useAppKitTheme(): AppKitThemeResolved {
  return React.useContext(ThemeContext);
}

export function AppKitThemeProvider({
  theme,
  children,
}: {
  theme: AppKitThemeResolved;
  children: React.ReactNode;
}) {
  return (
    <ThemeContext.Provider value={theme}>
      <div className="ak-root" style={theme.vars as React.CSSProperties}>
        {children}
      </div>
    </ThemeContext.Provider>
  );
}
