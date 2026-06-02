export const appTypeColors = {
  prod: "rgb(239, 68, 68)",
  staging: "rgb(251, 191, 36)",
  dev: "rgb(34, 197, 94)",
  custom: "rgb(99, 102, 241)",
  undefined: "rgb(148, 163, 184)",
} as const;

// Code block theme (catppuccin mocha)
export const codeTheme = {
  bg: "#1e1e2e",
  text: "#cdd6f4",
} as const;

// Alpha helper - use with any color string
export const alpha = (color: string, a: number) =>
  color.startsWith("#")
    ? `${color}${Math.round(a * 255).toString(16).padStart(2, "0")}`
    : color.replace("rgb(", "rgba(").replace(")", `, ${a})`);
