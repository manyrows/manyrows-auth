import { ThemeProvider, CssBaseline } from "@mui/material";
import { theme } from "./theme.tsx";

export default function ThemeModeProvider({ children }: { children: React.ReactNode }) {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      {children}
    </ThemeProvider>
  );
}
