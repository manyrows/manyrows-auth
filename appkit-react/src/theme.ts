import { createContext, useContext, useEffect, useState } from "react";

// ---------------------
// Color mode
// ---------------------

export type ColorMode = "light" | "dark" | "auto";

// ---------------------
// Token definitions
// ---------------------

export type ColorTokens = {
  surfacePrimary: string;
  surfaceSecondary: string;
  surfaceTertiary: string;
  surfaceOverlay: string;

  textPrimary: string;
  textSecondary: string;
  textTertiary: string;
  textDisabled: string;
  textOnPrimary: string;
  textOnError: string;

  borderDefault: string;
  borderSubtle: string;
  borderFocused: string;

  primary: string;
  primaryHover: string;
  primarySubtle: string;

  error: string;
  errorSubtle: string;
  errorBorder: string;

  success: string;
  successSubtle: string;
  successBorder: string;

  warning: string;
  warningSubtle: string;
  warningBorder: string;

  progressTrack: string;
  shadow: string;
  iconMuted: string;
  buttonDisabledBg: string;
};

const lightTokens: ColorTokens = {
  surfacePrimary: "#ffffff",
  surfaceSecondary: "#fafafa",
  surfaceTertiary: "#f0f0f0",
  surfaceOverlay: "rgba(0,0,0,0.5)",

  textPrimary: "#333333",
  textSecondary: "#555555",
  textTertiary: "#888888",
  textDisabled: "#bbbbbb",
  textOnPrimary: "#ffffff",
  textOnError: "#ffffff",

  borderDefault: "#dddddd",
  borderSubtle: "#eeeeee",
  borderFocused: "#1976d2",

  primary: "#1976d2",
  primaryHover: "#1565c0",
  primarySubtle: "#e3f2fd",

  error: "#d32f2f",
  errorSubtle: "#ffebee",
  errorBorder: "#ffcdd2",

  success: "#2e7d32",
  successSubtle: "#e8f5e9",
  successBorder: "#a5d6a7",

  warning: "#e65100",
  warningSubtle: "#fff3e0",
  warningBorder: "#ffcc80",

  progressTrack: "#e0e0e0",
  shadow: "rgba(0,0,0,0.2)",
  iconMuted: "#999999",
  buttonDisabledBg: "#bbbbbb",
};

const darkTokens: ColorTokens = {
  surfacePrimary: "#1e1e1e",
  surfaceSecondary: "#2a2a2a",
  surfaceTertiary: "#333333",
  surfaceOverlay: "rgba(0,0,0,0.7)",

  textPrimary: "#e0e0e0",
  textSecondary: "#b0b0b0",
  textTertiary: "#808080",
  textDisabled: "#555555",
  textOnPrimary: "#ffffff",
  textOnError: "#ffffff",

  borderDefault: "#444444",
  borderSubtle: "#333333",
  borderFocused: "#42a5f5",

  primary: "#42a5f5",
  primaryHover: "#64b5f6",
  primarySubtle: "rgba(66,165,245,0.15)",

  error: "#ef5350",
  errorSubtle: "rgba(239,83,80,0.12)",
  errorBorder: "rgba(239,83,80,0.3)",

  success: "#66bb6a",
  successSubtle: "rgba(102,187,106,0.12)",
  successBorder: "rgba(102,187,106,0.3)",

  warning: "#ffa726",
  warningSubtle: "rgba(255,167,38,0.12)",
  warningBorder: "rgba(255,167,38,0.3)",

  progressTrack: "#444444",
  shadow: "rgba(0,0,0,0.4)",
  iconMuted: "#666666",
  buttonDisabledBg: "#444444",
};

// ---------------------
// System color mode
// ---------------------

const MQ = "(prefers-color-scheme: dark)";

export function useSystemColorMode(): "light" | "dark" {
  const [mode, setMode] = useState<"light" | "dark">(() => {
    if (typeof window === "undefined") return "light";
    return window.matchMedia?.(MQ).matches ? "dark" : "light";
  });

  useEffect(() => {
    const mql = window.matchMedia?.(MQ);
    if (!mql) return;
    const handler = (e: MediaQueryListEvent) =>
      setMode(e.matches ? "dark" : "light");
    mql.addEventListener("change", handler);
    return () => mql.removeEventListener("change", handler);
  }, []);

  return mode;
}

// ---------------------
// Resolve tokens
// ---------------------

export function resolveTokens(
  mode: "light" | "dark",
  primaryColor?: string,
): ColorTokens {
  const base = mode === "dark" ? { ...darkTokens } : { ...lightTokens };
  if (primaryColor) {
    base.primary = primaryColor;
    base.borderFocused = primaryColor;
  }
  return base;
}

// ---------------------
// Theme context
// ---------------------

export type ThemeContextValue = {
  colorMode: "light" | "dark";
  tokens: ColorTokens;
};

const defaultValue: ThemeContextValue = {
  colorMode: "light",
  tokens: lightTokens,
};

export const ThemeCtx = createContext<ThemeContextValue>(defaultValue);

export function useTheme(): ThemeContextValue {
  return useContext(ThemeCtx);
}
