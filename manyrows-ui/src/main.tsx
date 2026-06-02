import ReactDOM from 'react-dom/client'
import GlobalStyles from "@mui/material/GlobalStyles";
import Router from "./Router.tsx";
import {SnackbarProvider} from "notistack";
import ThemeModeProvider from "./ThemeModeProvider.tsx";
import './i18n';

if (import.meta.env.DEV) {
  document.title = "DEV " + document.title;
}

// Editorial pill for the DEFAULT variant only. Scoped via CSS class
// instead of SnackbarProvider's `style` prop because the latter
// applies inline styles to every variant — inline beats notistack's
// variantSuccess/variantError class colours by specificity, which
// repaints error/success toasts the same dark ink and makes them
// indistinguishable from info ones. notistack v3 attaches
// `.notistack-MuiContent-{variant}` to each Snackbar root.
const snackbarStyles = {
  ".notistack-MuiContent-default": {
    background: "#0D0A08",
    color: "#FAFAF8",
    borderRadius: 10,
    fontFamily: 'Geist, "Inter Tight", system-ui, -apple-system, sans-serif',
    fontSize: 13,
    fontWeight: 500,
    letterSpacing: "-0.005em",
    boxShadow: "0 8px 24px -10px rgba(13,10,8,0.28), 0 1px 2px rgba(13,10,8,0.06)",
    minWidth: 240,
    padding: "6px 14px",
  },
};

const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);
root.render(
  <ThemeModeProvider>
    <GlobalStyles styles={snackbarStyles} />
    <SnackbarProvider
      maxSnack={3}
      anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
      autoHideDuration={3500}
    >
      <Router />
    </SnackbarProvider>
  </ThemeModeProvider>
);
